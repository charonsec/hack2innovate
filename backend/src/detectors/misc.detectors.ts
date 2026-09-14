import {
  Detector,
  DetectorContext,
  DetectorResult,
  VulnerabilityType,
} from '../types/index';
import {
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
 * Supplementary detectors covering the remaining SWC classes:
 *  - FRONT_RUNNING (SWC-114)
 *  - DELEGATECALL misuse (SWC-112)
 *  - UNINITIALIZED_STORAGE (SWC-109)
 */
export class FrontRunningDetector implements Detector {
  name = 'front-running';

  detect(context: DetectorContext): DetectorResult[] {
    const results: DetectorResult[] = [];
    if (!context.ast) return results;

    const fnNodes = findNodes(context.ast, 'FunctionDefinition');
    for (const fn of fnNodes) {
      const name = (fn.name as string) || '';
      const lower = name.toLowerCase();
      const fnStart = nodeLine(fn);
      const fnEnd = nodeEndLine(fn);

      // Must be a state-changing (non-view, non-pure) function.
      const isView = (fn.stateMutability as string) === 'view' || (fn.stateMutability as string) === 'pure';
      if (isView) continue;

      // Must have a name suggesting financial action.
      const hasFinancialAction = /(sell|redeem|swap|bid|offer|withdraw|claim|purchase|buy)/.test(lower);
      if (!hasFinancialAction) continue;

      // Must read a spot price.
      let readsSpotPrice = false;
      walkAst(fn, (n) => {
        if (readsSpotPrice) return;
        if (n.type === 'FunctionCall') {
          const info = memberCallInfo(n.expression);
          if (info && ['getReserves', 'balanceOf', 'getAmountOut', 'quote', 'getAmountsOut'].includes(info.memberName)) {
            readsSpotPrice = true;
          }
        }
      });
      if (!readsSpotPrice) continue;

      const confidence = computeConfidence(60);
      const evidence: string[] = [
        evidenceSnippet(context.sourceCode, fnStart, fnEnd),
        `Function ${name}() performs financial action and reads spot price`,
      ];
      if (/deadline|expiry|nonce/.test(lower)) {
        evidence.push('Function name references deadline/expiry — may lack explicit guard');
      }

      results.push({
        type: 'FRONT_RUNNING' as VulnerabilityType,
        severity: 'HIGH',
        title: `Front-runnable ${name}() — no deadline / slippage protection`,
        description:
          `${name}() executes a user-intent transaction (order, swap, bid, claim) ` +
          'without a user-set deadline or minimum-output (slippage) guard. A mempool ' +
          'searcher can front-run the transaction, capture the price delta, and make ' +
          'the victim settle at a materially worse rate.',
        confidence,
        evidence,
        attackPath: buildAttackPath([
          {
            label: 'Attacker monitors mempool',
            description: 'Watch for pending financial transactions that read spot prices',
          },
          {
            label: 'Attacker submits higher-gas front-run',
            description: 'Execute the same operation with a higher gas price to be included first',
          },
          {
            label: 'Spot price moves against victim',
            description: 'The front-run changes the pool state; the victim\'s transaction settles at the worse rate',
          },
          {
            label: 'Attacker captures profit',
            description: 'Back-run or simply profit from the price delta created by the front-run',
          },
        ]),
        lineStart: fnStart,
        lineEnd: Math.min(fnEnd, fnStart + 10),
        columnStart: 0,
        columnEnd: 0,
        codeSnippet: snippet(context.lines, fnStart, Math.min(fnEnd, fnStart + 10)),
        recommendation:
          'Accept a `deadline` parameter and revert when block.timestamp > deadline. ' +
          'Accept a `minAmountOut` and compare against realized output; revert on ' +
          'violation. Consider commit-reveal or private mempool submission for ' +
          'high-value orders.',
        remediatedCode: this.addDeadlineGuard(context, name, fnStart, fnEnd),
        references: [
          'https://swcregistry.io/docs/SWC-114',
          'https://ethereum.org/en/developers/tutorials/transactions-and-frontrunning/',
        ],
        swcId: 'SWC-114',
        cvssScore: cvssFor('HIGH'),
      });
    }
    return results;
  }

  private addDeadlineGuard(
    context: DetectorContext,
    name: string,
    startLine: number,
    endLine: number
  ): string {
    const sigMatch = context.lines[startLine - 1] || '';
    return `${sigMatch.trim()} // ADD: , uint256 deadline\n    // require(block.timestamp <= deadline, "expired");\n    // ADD: , uint256 minAmountOut\n    // require(amountOut >= minAmountOut, "slippage");`;
  }
}

export class DelegatecallDetector implements Detector {
  name = 'delegatecall';

  detect(context: DetectorContext): DetectorResult[] {
    const results: DetectorResult[] = [];
    if (!context.ast) return results;

    walkAst(context.ast, (n) => {
      if (n.type !== 'FunctionCall') return;
      const info = memberCallInfo(n.expression);
      if (!info) return;
      if (info.memberName !== 'delegatecall') return;

      const line = nodeLine(n);
      const base = info.base;
      const targetExpr =
        base && base.type === 'Identifier' ? `'${base.name}'` : 'an arbitrary address';

      // Determine if the target is user-supplied or mutable.
      const isUserSupplied = this.isUserSuppliedTarget(base);
      const funcText = snippet(context.lines, Math.max(1, line - 1), line + 3);
      const hasTrustedCheck = /require|whitelist|trusted|registry|isTrusted|approved/.test(funcText);

      // If target is a constant/immutable address or validated, skip or flag LOW.
      if (hasTrustedCheck && !isUserSupplied) {
        // Trusted, validated target — skip.
        return;
      }

      const confidence = isUserSupplied
        ? computeConfidence(85)
        : computeConfidence(30);
      const evidence: string[] = [
        evidenceSnippet(context.sourceCode, line, line),
        `delegatecall to ${targetExpr}`,
      ];
      if (isUserSupplied) {
        evidence.push('Target address is user-supplied or function parameter — no immutable validation');
      }
      if (hasTrustedCheck) {
        evidence.push('Some form of validation present but may be insufficient');
      }

      results.push({
        type: 'DELEGATECALL' as VulnerabilityType,
        severity: isUserSupplied ? 'CRITICAL' : 'HIGH',
        title: 'Untrusted delegatecall — storage-corruption risk',
        description:
          'A delegatecall executes code in the caller\'s storage context. Calling ' +
          `${targetExpr} without an immutable whitelist lets an attacker rewrite every ` +
          'storage slot of the contract (balances, owner, implementation) even though ' +
          'they never held ownership of the calling contract.',
        confidence,
        evidence,
        attackPath: isUserSupplied
          ? buildAttackPath([
              {
                label: 'Attacker supplies malicious contract address',
                description: 'The delegatecall target is derived from a function parameter or mutable state',
              },
              {
                label: 'Malicious code executes in caller context',
                description: 'The target\'s bytecode runs against the calling contract\'s storage layout',
              },
              {
                label: 'Arbitrary storage slot overwrite',
                description: 'The attacker\'s code writes to owner, balances, or implementation slots',
              },
              {
                label: 'Attacker gains control',
                description: 'Overwritten owner slot grants admin access; drained balances transfer funds',
              },
            ])
          : undefined,
        lineStart: line,
        lineEnd: line + 1,
        columnStart: 0,
        columnEnd: 0,
        codeSnippet: funcText,
        recommendation:
          'Delegate to an immutable, deployer-controlled implementation only. ' +
          'Validate the target against an on-chain registry, and treat delegatecall ' +
          'targets as full security boundaries.',
        remediatedCode:
          '    address expectedImpl = implementations[msg.sender];\n' +
          '    require(expectedImpl != address(0), "impl not allowed");\n' +
          '    (bool ok, bytes memory data) = expectedImpl.delegatecall(data);\n' +
          '    require(ok, "call failed");',
        references: ['https://swcregistry.io/docs/SWC-112'],
        swcId: 'SWC-112',
        cvssScore: cvssFor(isUserSupplied ? 'CRITICAL' : 'HIGH'),
      });
    });
    return results;
  }

  private isUserSuppliedTarget(base: AstNode | null): boolean {
    if (!base) return false;
    if (base.type === 'Identifier') {
      const name = (base.name as string) || '';
      // Immutable/constant patterns — not user-supplied.
      if (/^[A-Z][A-Z_]+$/.test(name)) return false; // ALL_CAPS constants
      return true; // Otherwise it's a variable that could be mutated
    }
    if (base.type === 'MemberAccess') {
      // e.g. this.implementation() or registry.target — mutable
      return true;
    }
    return true; // Literal addresses are constant, but complex expressions are treated as mutable
  }
}

export class UninitializedStorageDetector implements Detector {
  name = 'uninitialized-storage';

  detect(context: DetectorContext): DetectorResult[] {
    const results: DetectorResult[] = [];
    if (!context.ast) return results;

    walkAst(context.ast, (n) => {
      if (n.type !== 'VariableDeclarationStatement') return;
      const vars = n.variables as AstNode[] | undefined;
      const initial = n.initialValue as AstNode | undefined;
      if (!vars || !vars.length) return;
      const v = vars[0];
      const storageKeywords = (v.storageLocation as string) || '';
      if (storageKeywords !== 'storage') return;

      // Only flag storage variables that have no initializer.
      if (initial) return;

      // Only flag in non-view/pure functions.
      const fnLine = nodeLine(n);
      const enclosingFn = this.findEnclosingFunction(context, fnLine);
      if (enclosingFn) {
        const mutability = (enclosingFn.stateMutability as string) || '';
        if (mutability === 'view' || mutability === 'pure') return;
      }

      // Storage-pointers declared without an initializer are UB-critical.
      const line = nodeLine(n);
      const nameStr = (v.name as string) || '';
      const declText = snippet(context.lines, Math.max(1, line - 1), line + 1);

      const confidence = computeConfidence(70);
      const evidence: string[] = [
        evidenceSnippet(context.sourceCode, line, line),
        `Variable '${nameStr}' is declared as 'storage' with no initializer`,
      ];

      results.push({
        type: 'UNINITIALIZED_STORAGE' as VulnerabilityType,
        severity: 'HIGH',
        title: `Uninitialized storage pointer ${nameStr}`,
        description:
          `${nameStr} is declared as a storage reference but initialized from an ` +
          'untrusted/dynamic value (or not at all). Storage pointers reference ' +
          'arbitrary slots; assigning to them overwrites unrelated state variables ' +
          'such as balances or owner — the root cause of the OpenSea /uniswap ' +
          'storage-pointer bugs.',
        confidence,
        evidence,
        lineStart: line,
        lineEnd: line,
        columnStart: 0,
        columnEnd: 0,
        codeSnippet: declText,
        recommendation:
          'Initialize storage pointers only from known mappings/arrays, prefer ' +
          'memory for locals that mutate data, and use this pattern:\n' +
          '`SomeStruct storage s = arr[0];`  or  `SomeStruct storage s = mapping[key];`',
        remediatedCode: `    SomeStruct storage ref = someKnownMapping[key];  // bound, not default slot 0`,
        references: ['https://swcregistry.io/docs/SWC-109'],
        swcId: 'SWC-109',
        cvssScore: cvssFor('HIGH'),
      });
    });
    return results;
  }

  private findEnclosingFunction(context: DetectorContext, line: number): AstNode | null {
    if (!context.ast) return null;
    let found: AstNode | null = null;
    walkAst(context.ast, (n) => {
      if (found) return;
      if (n.type === 'FunctionDefinition') {
        const start = nodeLine(n);
        const end = nodeEndLine(n);
        if (line >= start && line <= end) {
          found = n;
        }
      }
    });
    return found;
  }
}
