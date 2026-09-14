import {
  Detector,
  DetectorContext,
  DetectorResult,
  VulnerabilityType,
} from '../types/index';
import {
  buildId,
  cvssFor,
  findNodes,
  memberCallInfo,
  nodeLine,
  nodeEndLine,
  snippet,
  walkAst,
  AstNode,
} from '../engine/detector-utils';
import { computeConfidence, buildAttackPath, evidenceSnippet } from '../engine/confidence';

/**
 * DETECTOR 6 — Flash-loan attack surface (SWC-107 / SWC-113 / SWC-109)
 *
 * Flags:
 *  1. Lending/borrow functions missing a reentrancy guard (cross-contract
 *     flash-loanable surface).
 *  2. Price derived from a single-block spot reserve (manipulable in the
 *     same tx as a flash loan).
 *  3. executors / callbacks (executeOperation, onFlashLoan) that move value
 *     without validating the caller against a trusted lender registry.
 *  4. No repayment integrity check after an unguarded external borrow call.
 */
export class FlashLoanDetector implements Detector {
  name = 'flash-loan';

  detect(context: DetectorContext): DetectorResult[] {
    const results: DetectorResult[] = [];
    if (!context.ast) return results;

    const fnNodes = findNodes(context.ast, 'FunctionDefinition');
    const sensitiveFns = ['borrow', 'flash', 'flashloan', 'flash_loan', 'lend', 'loan', 'liquidate'];

    // Check if the contract itself has a flash loan function (for exploit chain detection).
    const hasFlashFunction = fnNodes.some((fn) => {
      const n = ((fn.name as string) || '').toLowerCase();
      return n.includes('flash') || n.includes('onflashloan') || n.includes('executeoperation');
    });

    for (const fn of fnNodes) {
      const name = ((fn.name as string) || '').toLowerCase();
      if (!sensitiveFns.some((s) => name.includes(s))) continue;

      const fnName = (fn.name as string) || '';
      const modifiers: string[] = Array.isArray(fn.modifiers)
        ? (fn.modifiers as AstNode[]).map((m) =>
            typeof m.name === 'object' && m.name !== null
              ? ((m.name as AstNode).name as string)
              : (m.name as string)
          )
        : [];

      const startLine = nodeLine(fn);
      const endLine = nodeEndLine(fn);

      // The function pulls external value but has no guard.
      const hasExternalCall = this.functionHasCall(context, fn, 'call');
      const hasGuard = modifiers.includes('nonReentrant') || context.usesReentrancyGuard;

      // If function has guard → flag LOW or skip.
      if (hasExternalCall && hasGuard) {
        // Guarded flash-loan function — very low risk, skip or flag LOW.
        const confidence = computeConfidence(30, { guardPresent: true });
        const evidence: string[] = [
          evidenceSnippet(context.sourceCode, startLine, startLine),
          'Function has reentrancy guard — standard mitigations in place',
        ];
        // Don't flag at all — guarded functions are not a finding.
      }

      if (hasExternalCall && !hasGuard) {
        const repaymentCheck = this.hasRepaymentCheck(context, fn);
        const confidence = computeConfidence(80);
        const evidence: string[] = [
          evidenceSnippet(context.sourceCode, startLine, startLine),
          `Function ${fnName}() makes external low-level call without reentrancy guard`,
        ];
        if (!repaymentCheck) {
          evidence.push('No repayment integrity check detected after external call');
        }
        results.push({
          type: 'FLASH_LOAN' as VulnerabilityType,
          severity: 'HIGH',
          title: `Flash-loanable ${fnName}() without reentrancy guard`,
          description:
            `${fnName}() moves external value through a low-level call but lacks a ` +
            'reentrancy guard. An attacker can flash-borrow assets, re-enter the ' +
            'pool before balances settle, and drain liquidity in a single ' +
            'transaction — the classic Cream / Euler-brand read-only-reentrancy ' +
            'and flash-loan attack primitive.',
          confidence,
          evidence,
          attackPath: buildAttackPath([
            {
              label: 'Attacker initiates flash loan',
              description: 'Borrow maximum liquidity from Aave/dYdX in a single transaction',
            },
            {
              label: 'Re-enter unprotected function',
              description: 'The flash-loaned callback re-enters the vulnerable function before state updates',
            },
            {
              label: 'Manipulate pool state',
              description: 'Use re-entrancy to bypass balance checks and extract additional funds',
            },
            {
              label: 'Repay flash loan',
              description: 'Repay the original flash loan with the stolen surplus',
            },
          ]),
          lineStart: startLine,
          lineEnd: endLine,
          columnStart: 0,
          columnEnd: 0,
          codeSnippet: snippet(context.lines, startLine, Math.min(endLine, startLine + 14)),
          recommendation:
            'Add OpenZeppelin nonReentrant to every lending/borrow function, enforce ' +
            'the CEI pattern, snapshot balances, and validate repayment against the ' +
            'fee model before releasing funds. Use TWAP/Chainlink prices, never spot ' +
            'reserves, inside repayment logic.',
          remediatedCode: this.guardFunction(context, fnName, startLine, endLine),
          references: [
            'https://swcregistry.io/docs/SWC-107',
            'https://github.com/ethereum/consensys/smart-contract-best-practices',
            'https://aave.com/flash-loans/',
          ],
          swcId: 'SWC-107',
          cvssScore: cvssFor('HIGH'),
        });
      }

      // Single-block price dependency inside borrow/liquidate is exploitable
      // directly with a flash loan in the same transaction.
      if (this.functionReadsSpotPrice(context, fn)) {
        // If the contract also has a flash function, this is a compound exploit chain.
        const isCompoundChain = hasFlashFunction || name.includes('flash');
        const confidence = computeConfidence(85, { crossFunction: isCompoundChain });
        const evidence: string[] = [
          evidenceSnippet(context.sourceCode, startLine, startLine),
          `Function ${fnName}() reads spot price (getReserves/balanceOf/price)`,
        ];
        if (isCompoundChain) {
          evidence.push('Contract also contains a flash loan function — full exploit chain is self-contained');
        }
        results.push({
          type: 'FLASH_LOAN' as VulnerabilityType,
          severity: 'CRITICAL',
          title: `Spot-price dependency in ${fnName}() exploitable via flash loan`,
          description:
            `${fnName}() derives value from a single-block spot price ` +
            '(getReserves/balanceOf/`priceOracle` read). A flash loan lets an ' +
            'attacker move the pool balance, call borrow/liquidate at the skewed ' +
            'price, and repay within the same transaction — draining value with zero ' +
            'capital. This is the core of Curve / GMX / Platypus flash-loan exploits.',
          confidence,
          evidence,
          attackPath: buildAttackPath([
            {
              label: 'Attacker flash-borrows from Aave/dYdX',
              description: 'Obtain a large capital loan in a single transaction with zero upfront collateral',
            },
            {
              label: 'Manipulate DEX pool reserves',
              description: 'Swap flash-loaned tokens to skew the pool\'s getReserves() spot price',
            },
            {
              label: 'Call vulnerable function at skewed price',
              description: `${fnName}() reads the manipulated spot price for collateral valuation or liquidation`,
            },
            {
              label: 'Extract excess value',
              description: 'Borrow against inflated collateral or trigger liquidation at a favorable price',
            },
            {
              label: 'Repay flash loan',
              description: 'Return the original flash loan; profit is the delta between manipulated and fair price',
            },
          ]),
          lineStart: startLine,
          lineEnd: endLine,
          columnStart: 0,
          columnEnd: 0,
          codeSnippet: snippet(context.lines, startLine, Math.min(endLine, startLine + 14)),
          recommendation:
            'Compute prices from a time-weighted average (TWAP) or a Chainlink ' +
            'AggregatorV3Interface feed, never from the pool\'s own spot reserves. ' +
            'Add a minimum-oracle-age check and a max-price-deviation guard.',
          remediatedCode: this.twapPrice(context, fnName, startLine, endLine),
          references: [
            'https://swcregistry.io/docs/SWC-113',
            'https://uniswap.org/blog/uniswap-v3-oracles',
            'https://docs.chain.link/data-feeds',
          ],
          swcId: 'SWC-113',
          cvssScore: cvssFor('CRITICAL'),
        });
      }
    }

    // Callbacks from external flash-loan providers.
    const callbackNodes = findNodes(context.ast, 'FunctionDefinition');
    for (const cb of callbackNodes) {
      const cbName = (cb.name as string) || '';
      if (!['executeOperation', 'onFlashLoan', 'flashLoanCallback'].includes(cbName)) continue;
      const modifiers: string[] = Array.isArray(cb.modifiers)
        ? (cb.modifiers as AstNode[]).map((m) =>
            typeof m.name === 'object' && m.name !== null
              ? ((m.name as AstNode).name as string)
              : (m.name as string)
          )
        : [];
      const startLine = nodeLine(cb);

      const whitelabelCaller = this.callerValidated(context, cb);
      if (!whitelabelCaller) {
        const confidence = computeConfidence(70);
        const evidence: string[] = [
          evidenceSnippet(context.sourceCode, startLine, startLine),
          `${cbName}() does not validate msg.sender against a trusted flash-loan provider`,
        ];
        results.push({
          type: 'FLASH_LOAN' as VulnerabilityType,
          severity: 'HIGH',
          title: `${cbName}() does not validate the caller`,
          description:
            `${cbName}() executes arbitrary code with the pool's assets but never ` +
            'verifies that msg.sender is the trusted flash-loan provider. An attacker ' +
            'can invoke the callback directly and steal loaned funds.',
          confidence,
          evidence,
          attackPath: buildAttackPath([
            {
              label: 'Attacker deploys malicious contract',
              description: 'The attacker\'s contract calls the callback directly without going through the flash-loan provider',
            },
            {
              label: 'Callback executes with pool assets',
              description: 'The callback moves funds based on unvalidated assumptions about the caller',
            },
            {
              label: 'Funds transferred to attacker',
              description: 'The callback\'s logic sends assets to the attacker\'s address',
            },
          ]),
          lineStart: startLine,
          lineEnd: nodeEndLine(cb),
          columnStart: 0,
          columnEnd: 0,
          codeSnippet: snippet(context.lines, startLine, Math.min(nodeEndLine(cb), startLine + 10)),
          recommendation:
            'Require msg.sender == the registered lender (or a whitelist), surface it ' +
            'as a public immutable set at construction, and emit an event for every ' +
            'callback invocation.',
          remediatedCode: this.guardCallback(cbName, modifiers),
          references: ['https://swcregistry.io/docs/SWC-115'],
          swcId: 'SWC-115',
          cvssScore: cvssFor('HIGH'),
        });
      }
    }

    return this.dedupe(results);
  }

  private functionHasCall(context: DetectorContext, fn: AstNode, lowLevel: string): boolean {
    let found = false;
    walkAst(fn, (n) => {
      if (found) return;
      if (n.type === 'FunctionCall') {
        const info = memberCallInfo(n.expression);
        if (info && info.memberName === lowLevel) found = true;
      }
    });
    return found;
  }

  private hasRepaymentCheck(context: DetectorContext, fn: AstNode): boolean {
    let found = false;
    walkAst(fn, (n) => {
      if (found) return;
      if (n.type === 'FunctionCall') {
        const callee = n.expression as AstNode | undefined;
        if (callee && callee.type === 'Identifier' && (callee.name as string) === 'require') {
          const argText = JSON.stringify(n.arguments);
          if (/balance|repay|after|>=|==/.test(argText)) found = true;
        }
      }
    });
    return found;
  }

  private functionReadsSpotPrice(context: DetectorContext, fn: AstNode): boolean {
    let found = false;
    walkAst(fn, (n) => {
      if (found) return;
      if (n.type === 'FunctionCall') {
        const info = memberCallInfo(n.expression);
        if (info && ['getReserves', 'balanceOf', 'getBalanceToAmountOut', 'getAmountOut', 'priceOf'].includes(info.memberName)) {
          found = true;
        }
      }
      if (n.type === 'MemberAccess') {
        const member = n.memberName as string;
        if (member.toLowerCase().includes('price')) found = true;
      }
    });
    return found;
  }

  private callerValidated(context: DetectorContext, cb: AstNode): boolean {
    let found = false;
    walkAst(cb, (n) => {
      if (found) return;
      if (n.type === 'FunctionCall') {
        const callee = n.expression as AstNode | undefined;
        if (callee && callee.type === 'Identifier' && (callee.name as string) === 'require') {
          const args = JSON.stringify(n.arguments);
          if (/msg\.sender|lender|pool|provider/.test(args)) found = true;
        }
      }
    });
    return found;
  }

  private guardFunction(
    context: DetectorContext,
    fnName: string,
    startLine: number,
    endLine: number
  ): string {
    const body = snippet(context.lines, startLine, endLine);
    const fixed = body.replace(
      /(function\s+\w+\s*\([^)]*\))(\s*(?:public|external|internal|private))?/,
      (_m, sig: string, vis: string) => `${sig}${vis || ' public'} nonReentrant`
    );
    return `import "@openzeppelin/contracts/security/ReentrancyGuard.sol";

contract ${this.contractName(context)} is ReentrancyGuard {
${fixed
  .split('\n')
  .map((l) => `    ${l}`)
  .join('\n')}
}`;
  }

  private twapPrice(
    context: DetectorContext,
    fnName: string,
    startLine: number,
    endLine: number
  ): string {
    const body = snippet(context.lines, startLine, endLine);
    return `import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

contract ${this.contractName(context)} {
    AggregatorV3Interface public priceFeed;

    function currentPrice() public view returns (uint256) {
        ( , int256 answer, uint256 updatedAt, , ) = priceFeed.latestRoundData();
        require(block.timestamp - updatedAt < 3 hours, "stale price");
        require(answer > 0, "invalid price");
        return uint256(answer);
    }
}
${body
  .split('\n')
  .map((l) => `// FIXED: ${l}`)
  .join('\n')}`;
  }

  private guardCallback(cbName: string, modifiers: string[]): string {
    return `    function ${cbName}(
        address initiator,
        address token,
        uint256 amount,
        uint256 fee,
        bytes calldata _data
    ) external override returns (bool) {
        require(msg.sender == address(flashLoanProvider), "Unauthorized");
        // execute strategy
        return true;
    }`;
  }

  private dedupe(results: DetectorResult[]): DetectorResult[] {
    const map = new Map<string, DetectorResult>();
    for (const r of results) {
      const key = `${r.severity}_${r.lineStart}_${r.title}`;
      if (!map.has(key)) map.set(key, r);
    }
    return Array.from(map.values());
  }

  private contractName(context: DetectorContext): string {
    const m = context.sourceCode.match(/contract\s+(\w+)/);
    return m ? m[1] : '';
  }
}
