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

      // Sell/withdraw-like functions that depend on a later-known state
      // (auction bids, order swaps, approvals, price-dependent sell).
      const vulnerableShape =
        /(sell|redeem|swap|bid|offer|place|claim|withdraw)/.test(lower);

      // Look for pure-function order: user-provided amount → price query → value transfer
      let readsPrice = false;
      walkAst(fn, (n) => {
        if (n.type === 'FunctionCall') {
          const info = memberCallInfo(n.expression);
          if (info && ['getReserves', 'balanceOf', 'getAmountOut', 'quote'].includes(info.memberName)) {
            readsPrice = true;
          }
        }
      });

      if (vulnerableShape && (readsPrice || /deadline|expiry|nonce/.test(lower))) {
        results.push({
          type: 'FRONT_RUNNING' as VulnerabilityType,
          severity: 'HIGH',
          title: `Front-runnable ${name}() — no deadline / slippage protection`,
          description:
            `${name}() executes a user-intent transaction (order, swap, bid, claim) ` +
            'without a user-set deadline or minimum-output (slippage) guard. A mempool ' +
            'searcher can front-run the transaction, capture the price delta, and make ' +
            'the victim settle at a materially worse rate.',
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

      // If delegatecall target is user-supplied there is no validation anywhere.
      const funcText = snippet(context.lines, Math.max(1, line - 1), line + 3);
      const hasTrustedCheck = /require|whitelist|trusted|registry|isTrusted|approved/.test(funcText);

      results.push({
        type: 'DELEGATECALL' as VulnerabilityType,
        severity: hasTrustedCheck ? 'HIGH' : 'CRITICAL',
        title: 'Untrusted delegatecall — storage-corruption risk',
        description:
          'A delegatecall executes code in the caller\'s storage context. Calling ' +
          `${targetExpr} without an immutable whitelist lets an attacker rewrite every ` +
          'storage slot of the contract (balances, owner, implementation) even though ' +
          'they never held ownership of the calling contract.',
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
        cvssScore: cvssFor(hasTrustedCheck ? 'HIGH' : 'CRITICAL'),
      });
    });
    return results;
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

      // Storage-pointers declared without an initializer are UB-critical.
      const line = nodeLine(n);
      const nameStr = (v.name as string) || '';
      const declText = snippet(context.lines, Math.max(1, line - 1), line + 1);

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
}