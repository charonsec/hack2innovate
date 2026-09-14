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

/**
 * DETECTOR 7 — Oracle manipulation (SWC-113 / SWC-116)
 *
 * Flags:
 *  1. Uniswap-V2-style spot price: getReserves() / sqrt ratio prices.
 *  2. token.balanceOf(address(this)) used as a price signal.
 *  3. Spot price from an AMM pool without TWAP (no _update/accumulator).
 *  4. No Chainlink aggregation anywhere while relying on pool math.
 */
export class OracleManipulationDetector implements Detector {
  name = 'oracle-manipulation';

  detect(context: DetectorContext): DetectorResult[] {
    const results: DetectorResult[] = [];
    if (!context.ast) return results;

    const hasChainlink = /AggregatorV3Interface|Chainlink|latestRoundData/.test(context.sourceCode);
    const hasTWAP = /TWAP|timeWeightedAverage|cumulative|priceCumulative|UniswapV3Oracle/.test(context.sourceCode);
    const stateVars = context.stateVariables.map((s) => s.name);

    const fnNodes = findNodes(context.ast, 'FunctionDefinition');
    const seenLines = new Set<number>();

    for (const fn of fnNodes) {
      const fnName = (fn.name as string) || '';
      const fnStart = nodeLine(fn);
      const fnEnd = nodeEndLine(fn);

      walkAst(fn, (n) => {
        if (n.type !== 'FunctionCall') return;
        const callInfo = memberCallInfo(n.expression);
        if (!callInfo) return;
        const member = callInfo.memberName;
        const base = callInfo.base;
        const baseName =
          base && base.type === 'Identifier'
            ? (base.name as string)
            : base && base.type === 'MemberAccess'
              ? (base.memberName as string)
              : '';

        if (member === 'getReserves' || (member === 'balanceOf' && baseName !== 'msg')) {
          const line = nodeLine(n);
          if (seenLines.has(line)) return;
          seenLines.add(line);

          const code = snippet(context.lines, Math.max(1, line - 2), line + 2);
          const useAsPrice = this.usedAsPrice(context, n, fn);

          if (!useAsPrice) {
            // still spot-price sensitive in swap math contexts
            if (!/balanceOf/.test(context.lines[line - 1] || '')) return;
          }

          const sev = hasTWAP ? 'MEDIUM' : 'HIGH';
          results.push({
            type: 'ORACLE_MANIPULATION' as VulnerabilityType,
            severity: sev,
            title: 'Spot-price oracle (single-block AMM price)',
            description:
              `${fnName}() computes pricing from a single-block spot source ` +
              `(${member} on ${baseName || 'pool'}) with ` +
              `${hasTWAP ? 'a partial mitigation' : 'no TWAP protection'}. ` +
              `An attacker flash-loans a large position, skews the pool, and executes ` +
              `any dependent pricing in the same block at the manipulated value.`,
            lineStart: line,
            lineEnd: line + 1,
            columnStart: 0,
            columnEnd: 0,
            codeSnippet: code,
            recommendation: hasTWAP
              ? 'Keep the TWAP, but add a max deviation guard vs. the reference price and a ' +
                'minimum elapsed-time check before the oracle is considered fresh.'
              : 'Replace the spot read with a time-weighted average price (TWAP) or a ' +
                'Chainlink AggregatorV3Interface feed. Add staleness and deviation guards. ' +
                'Never price solely off getReserves()/balanceOf().',
            remediatedCode: hasTWAP
              ? this.twapGuard(context, line)
              : this.chainlinkPrice(context, line),
            references: [
              'https://swcregistry.io/docs/SWC-113',
              'https://uniswap.org/blog/uniswap-v2-oracles',
              'https://blog.chain.link/uniswap-oracles/',
              'https://medium.com/@peckshield/price-oracle-manipulation-5b1c1ec7f47e',
            ],
            swcId: 'SWC-113',
            cvssScore: cvssFor(sev),
          });
          return;
        }

        // Reserved-check: percent / ratio reads off reserve members.
        if (/reserve|price|amountOut|quote/.test(member) && /getAmountOut|quote|reserves/.test(member)) {
          const line = nodeLine(n);
          if (seenLines.has(line)) return;
          seenLines.add(line);

          if (hasChainlink) return; // mitigated by an aggregated feed

          results.push({
            type: 'ORACLE_MANIPULATION' as VulnerabilityType,
            severity: 'HIGH',
            title: 'AMM spot-quote pricing function',
            description:
              `${fnName}() calls ${member}() on an automated-market-maker pool to price ` +
              'operations. Spot quotes reflect instantaneous imbalances and can be moved ' +
              'with a single large swap in the same block.',
            lineStart: line,
            lineEnd: line + 1,
            columnStart: 0,
            columnEnd: 0,
            codeSnippet: snippet(context.lines, Math.max(1, line - 2), line + 2),
            recommendation:
              'Use a time-weighted average price or Chainlink feed for every pricing ' +
              'decision; reserve spot quotes for informational display only.',
            remediatedCode: this.chainlinkPrice(context, line),
            references: ['https://swcregistry.io/docs/SWC-113'],
            swcId: 'SWC-113',
            cvssScore: cvssFor('HIGH'),
          });
        }
      });

      // priceOracle state variable read inside pricing function without feed usage.
      if (!hasChainlink) {
        for (const sv of stateVars) {
          if (!/oracle|price|feed/.test(sv)) continue;
          const readRegex = new RegExp(`\\b${this.escapeRegExp(sv)}\\b`);
          const line = context.lines
            .slice(fnStart - 1, fnEnd)
            .findIndex((l) => readRegex.test(l) && !l.trim().startsWith('//'));
          if (line < 0) continue;
          const absLine = fnStart + line;
          if (seenLines.has(absLine)) continue;
          seenLines.add(absLine);

          results.push({
            type: 'ORACLE_MANIPULATION' as VulnerabilityType,
            severity: 'MEDIUM',
            title: `Mutable price source '${sv}'`,
            description:
              `${fnName}() reads the mutable storage variable ${sv} for pricing. Without a ` +
              'hardened feed (Chainlink/Aggregator aggregator or TWAP accumulator), any ' +
              'write path to this variable — including admin keys or an attacker-set ' +
              'oracle — can price the contract arbitrarily.',
            lineStart: absLine,
            lineEnd: absLine,
            columnStart: 0,
            columnEnd: 0,
            codeSnippet: snippet(context.lines, absLine, absLine + 1),
            recommendation:
              'Store prices via Chainlink latestRoundData() with staleness + deviation ' +
              'guards, or maintain a TWAP accumulator. Audit and restrict every write ' +
              'path to the price variable.',
            remediatedCode: this.chainlinkPrice(context, absLine),
            references: ['https://swcregistry.io/docs/SWC-113'],
            swcId: 'SWC-113',
            cvssScore: cvssFor('MEDIUM'),
          });
        }
      }
    }

    // Whole-contract inline summary finding if spot dependence found and no feed.
    if (results.length && !hasChainlink && !hasTWAP) {
      const first = results[0];
      if (!seenLines.has(-1)) {
        seenLines.add(-1);
        results.push({
          type: 'ORACLE_MANIPULATION' as VulnerabilityType,
          severity: 'MEDIUM',
          title: 'No Chainlink / TWAP oracle integration detected',
          description:
            'The contract prices operations from spot markets and never references ' +
            'Chainlink AggregatorV3Interface or a TWAP accumulator. Every on-chain ' +
            'price is manipulable in the block it occurs.',
          lineStart: 1,
          lineEnd: Math.min(10, context.lines.length),
          columnStart: 0,
          columnEnd: 0,
          codeSnippet: snippet(context.lines, 1, Math.min(8, context.lines.length)),
          recommendation:
            'Introduce a hardened oracle: Chainlink data feed for reference prices plus ' +
            'an AMM TWAP fallback with deviation caps.',
          remediatedCode: this.chainlinkPrice(context, first.lineStart),
          references: ['https://swcregistry.io/docs/SWC-113'],
          swcId: 'SWC-113',
          cvssScore: cvssFor('MEDIUM'),
        });
      }
    }

    return results;
  }

  private usedAsPrice(context: DetectorContext, n: AstNode, fn: AstNode): boolean {
    const line = nodeLine(n);
    const windowText = context.lines
      .slice(Math.max(0, line - 3), Math.min(context.lines.length, line + 4))
      .join(' ');
    // Trust signals: division by ratio, multiplication, assignment to price vars.
    return (
      /price|value|rate|quote|swap|amount|profit|usd|worth/.test(windowText) &&
      /[*/=]/.test(windowText)
    );
  }

  private chainlinkPrice(context: DetectorContext, line: number): string {
    return `import "@chainlink/contracts/src/v0.8/interfaces/AggregatorV3Interface.sol";

contract ${this.contractName(context)} {
    AggregatorV3Interface public priceFeed;

    function getPrice() public view returns (uint256) {
        ( , int256 answer, uint256 updatedAt, , ) = priceFeed.latestRoundData();
        require(block.timestamp - updatedAt < 3 hours, "Stale price feed");
        require(answer > 0, "Negative or zero price");
        return uint256(answer);
    }
}`;
  }

  private twapGuard(context: DetectorContext, line: number): string {
    const raw = (context.lines[line - 1] || '').trim();
    return `    // TWAP stays in place; add freshness + deviation guards:
    require(block.timestamp - lastUpdate < TWAP_WINDOW, "TWAP stale");
    require(deviation(currentPrice, referencePrice) < MAX_DEVIATION, "price moved too far");
    // original: ${raw}`;
  }

  private escapeRegExp(value: string): string {
    return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  }

  private contractName(context: DetectorContext): string {
    const m = context.sourceCode.match(/contract\s+(\w+)/);
    return m ? m[1] : '';
  }
}