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

export class OracleManipulationDetector implements Detector {
  name = 'oracle-manipulation';

  detect(context: DetectorContext): DetectorResult[] {
    const results: DetectorResult[] = [];
    if (!context.ast) return results;

    const hasChainlink = /AggregatorV3Interface|Chainlink|latestRoundData/.test(context.sourceCode);
    const hasTWAP = /TWAP|timeWeightedAverage|cumulative|priceCumulative|UniswapV3Oracle/.test(context.sourceCode);
    const hasStalenessCheck = /stale|updatedAt|block\.timestamp\s*-\s*\w+\s*<|freshness|heartbeat|roundId/.test(context.sourceCode);
    const hasFlashLoanSurface = /flashLoan|flash[_]?loan|borrowFlash|flashMint|FLOAN|IERC3156/.test(context.sourceCode);
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

        // --- AMM spot price: getReserves / balanceOf used as price signal ---
        if (member === 'getReserves' || (member === 'balanceOf' && baseName !== 'msg')) {
          const line = nodeLine(n);
          if (seenLines.has(line)) return;
          seenLines.add(line);

          const fnBodySnippet = evidenceSnippet(context.sourceCode, fnStart, fnEnd);
          const useAsPrice = this.usedAsPrice(context, n, fn);

          if (!useAsPrice) {
            if (!/balanceOf/.test(context.lines[line - 1] || '')) return;
          }

          // Require arithmetic or state-change evidence to flag balanceOf as pricing
          if (member === 'balanceOf') {
            const lineText = context.lines[line - 1] || '';
            const hasArithmetic = /[*/+\-]=?/.test(lineText);
            const hasAssignment = /=\s*\w/.test(lineText) && !/==/.test(lineText);
            const hasStateVarTarget = stateVars.some(
              (sv) => lineText.includes(sv) && /=/.test(lineText)
            );
            if (!hasArithmetic && !hasAssignment && !hasStateVarTarget) return;
          }

          const hasFinancialImpact = this.detectFinancialImpact(context, fn);
          const severity = hasTWAP ? 'MEDIUM' : hasFinancialImpact ? 'HIGH' : 'MEDIUM';
          let base = hasTWAP ? 55 : 85;
          if (hasFinancialImpact) base += 10;
          const confidence = computeConfidence(base, {
            lineMatchesEvidence: true,
            financialImpact: hasFinancialImpact,
          });

          const attackPathSteps = [
            {
              label: 'ENTRY',
              description: 'Attacker initiates flash loan (if flash loan surface present) or deploys attacker contract',
              line,
            },
            {
              label: 'TRIGGER',
              description: `${fnName}() reads AMM spot price via ${member}() on ${baseName || 'pool'}`,
              line,
            },
            {
              label: 'EXPLOIT',
              description: 'Large swap skews pool reserves — manipulated spot price read by vulnerable contract',
              line,
            },
            {
              label: 'IMPACT',
              description: hasFinancialImpact
                ? 'Contract prices collateral/liquidation/borrow at manipulated value — attacker profits from mispriced assets'
                : 'Contract makes pricing decision at manipulated spot value',
              line,
            },
          ];
          if (hasFlashLoanSurface) {
            attackPathSteps.push({
              label: 'OUTCOME',
              description: 'Attacker exits flash loan with profit — pool reverts to fair price in next block',
              line,
            });
          }

          results.push({
            type: 'ORACLE_MANIPULATION' as VulnerabilityType,
            severity,
            title: 'Spot-price oracle (single-block AMM price)',
            description:
              `${fnName}() computes pricing from a single-block spot source ` +
              `(${member} on ${baseName || 'pool'}) with ` +
              `${hasTWAP ? 'a partial mitigation' : 'no TWAP protection'}. ` +
              `An attacker flash-loans a large position, skews the pool, and executes ` +
              `any dependent pricing in the same block at the manipulated value.` +
              (hasChainlink ? ' Note: Chainlink import detected but may not cover this price path.' : ''),
            confidence,
            evidence: [fnBodySnippet],
            attackPath: buildAttackPath(attackPathSteps),
            lineStart: line,
            lineEnd: line + 1,
            columnStart: 0,
            columnEnd: 0,
            codeSnippet: evidenceSnippet(context.sourceCode, Math.max(1, line - 2), line + 2),
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
            cvssScore: cvssFor(severity),
          });
          return;
        }

        // --- AMM spot-quote pricing function (getAmountOut / quote / reserves) ---
        if (/reserve|price|amountOut|quote/.test(member) && /getAmountOut|quote|reserves/.test(member)) {
          const line = nodeLine(n);
          if (seenLines.has(line)) return;
          seenLines.add(line);

          // Skip if Chainlink feed present AND staleness check detected — genuine mitigation
          if (hasChainlink && hasStalenessCheck) return;

          const fnBodySnippet = evidenceSnippet(context.sourceCode, fnStart, fnEnd);
          const hasFinancialImpact = this.detectFinancialImpact(context, fn);
          const base = hasChainlink ? 55 : 75;
          const confidence = computeConfidence(base, {
            lineMatchesEvidence: true,
            financialImpact: hasFinancialImpact,
          });

          const attackPathSteps = [
            {
              label: 'ENTRY',
              description: 'Attacker identifies contract uses AMM spot quote for pricing',
              line,
            },
            {
              label: 'TRIGGER',
              description: `${fnName}() calls ${member}() for pricing without TWAP or Chainlink guard`,
              line,
            },
            {
              label: 'EXPLOIT',
              description: 'Single large swap in same block moves the pool ratio — spot quote reflects manipulated price',
              line,
            },
            {
              label: 'IMPACT',
              description: hasFinancialImpact
                ? 'Contract mints/borrows/liquidates at wrong price — attacker extracts value'
                : 'Pricing decision based on manipulable spot quote',
              line,
            },
          ];
          if (hasFlashLoanSurface) {
            attackPathSteps.push({
              label: 'OUTCOME',
              description: 'Attacker exits flash loan with profit — pool reverts to fair price in next block',
              line,
            });
          }

          results.push({
            type: 'ORACLE_MANIPULATION' as VulnerabilityType,
            severity: hasChainlink ? 'MEDIUM' : 'HIGH',
            title: 'AMM spot-quote pricing function',
            description:
              `${fnName}() calls ${member}() on an automated-market-maker pool to price ` +
              'operations. Spot quotes reflect instantaneous imbalances and can be moved ' +
              'with a single large swap in the same block.' +
              (hasChainlink
                ? hasStalenessCheck
                  ? ' Chainlink import with staleness check detected — partial mitigation.'
                  : ' Chainlink import detected but no staleness check — partial mitigation.'
                : ''),
            confidence,
            evidence: [fnBodySnippet],
            attackPath: buildAttackPath(attackPathSteps),
            lineStart: line,
            lineEnd: line + 1,
            columnStart: 0,
            columnEnd: 0,
            codeSnippet: evidenceSnippet(context.sourceCode, Math.max(1, line - 2), line + 2),
            recommendation:
              'Use a time-weighted average price or Chainlink feed for every pricing ' +
              'decision; reserve spot quotes for informational display only.',
            remediatedCode: this.chainlinkPrice(context, line),
            references: ['https://swcregistry.io/docs/SWC-113'],
            swcId: 'SWC-113',
            cvssScore: cvssFor(hasChainlink ? 'MEDIUM' : 'HIGH'),
          });
        }
      });

      // --- Mutable price-source variable read in pricing context ---
      const writeFindings = new Set<number>();
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

        const fnBodySnippet = evidenceSnippet(context.sourceCode, fnStart, fnEnd);
        const lineText = context.lines[absLine - 1] || '';
        const isStateChange = /=\s*\S/.test(lineText) && !/==/.test(lineText);
        const hasMathOnValue = /[*/+\-]/.test(lineText);

        // --- FP suppression: guarded write paths & durable feeds ---
        // 1) Chainlink feed read via latestRoundData — durable oracle, not a spot read.
        if (/latestRoundData/.test(lineText)) continue;
        // 2) Hardened Chainlink feed with staleness check present — global mitigation.
        if (hasChainlink && hasStalenessCheck) continue;
        // 3) Admin-guarded write: Ownable/AccessControl contract and the enclosing
        //    function carries a guard modifier — write path is protected.
        if (context.usesOwnable || context.usesAccessControl) {
          const enclosing = context.functions.find(
            (f) => absLine >= f.lineStart && absLine <= f.lineEnd
          );
          const mods = (enclosing?.modifiers ?? []).join(' ').toLowerCase();
          if (/onlyowner|onlyrole|auth|admin|guard|owner/.test(mods)) continue;
        }

        // Write to the price variable: only an UNGUARDED setter is itself the
        // oracle-manipulation vector. Constructor init and guarded setters are
        // not spot-price manipulation — skip writes to reduce duplicate noise.
        if (isStateChange) {
          if (!fnName || fnName === 'constructor') continue;
          const isSetter = /^(set|update|change|configure|refresh|sync|put)/i.test(fnName);
          if (!isSetter) continue;
          if (writeFindings.has(fnStart)) continue;
          writeFindings.add(fnStart);

          const base = 80;
          const confidence = computeConfidence(base, {
            lineMatchesEvidence: true,
            financialImpact: true,
          });

          results.push({
            type: 'ORACLE_MANIPULATION' as VulnerabilityType,
            severity: 'HIGH',
            title: `Unguarded setter for price source '${sv}'`,
            description:
              `${fnName}() writes the mutable price variable ${sv} with no access ` +
              `control. Any caller can set ${sv} and price every operation that reads ` +
              `it — a direct oracle-manipulation vector.`,
            confidence,
            evidence: [fnBodySnippet, lineText.trim()],
            attackPath: buildAttackPath([
              {
                label: 'ENTRY',
                description: `Attacker calls unguarded setter ${fnName}()`,
                line: absLine,
              },
              {
                label: 'TRIGGER',
                description: `Attacker writes manipulated value to '${sv}'`,
                line: absLine,
              },
              {
                label: 'EXPLOIT',
                description: 'No ownership/role check gates the write path',
                line: absLine,
              },
              {
                label: 'IMPACT',
                description: 'Contract prices all downstream operations at attacker-controlled value',
                line: absLine,
              },
            ]),
            lineStart: absLine,
            lineEnd: absLine,
            columnStart: 0,
            columnEnd: 0,
            codeSnippet: evidenceSnippet(context.sourceCode, Math.max(1, absLine - 1), absLine + 1),
            recommendation:
              'Guard every write to the price variable with onlyOwner/onlyRole and use ' +
              'a verifiable on-chain feed. Never expose an open setter for a pricing value.',
            remediatedCode: this.chainlinkPrice(context, absLine),
            references: ['https://swcregistry.io/docs/SWC-113'],
            swcId: 'SWC-113',
            cvssScore: cvssFor('HIGH'),
          });
          continue;
        }

        // Read of a price variable: only report when the read feeds a financial
        // decision (mint/borrow/swap/liquidate...). Pure getters that merely expose
        // the price add no attack surface beyond the write path already reported.
        if (!this.detectFinancialImpact(context, fn)) continue;

        const base = 60;
        const confidence = computeConfidence(base, {
          lineMatchesEvidence: true,
          financialImpact: isStateChange || hasMathOnValue,
        });

        const attackPathSteps = [
          {
            label: 'ENTRY',
            description: `Attacker targets the set() function for mutable price variable '${sv}'`,
            line: absLine,
          },
          {
            label: 'TRIGGER',
            description: `${fnName}() reads mutable storage variable '${sv}' without Chainlink/TWAP verification`,
            line: absLine,
          },
          {
            label: 'EXPLOIT',
            description: `Attacker writes manipulated value to '${sv}' via admin key compromise or unprotected setter`,
            line: absLine,
          },
          {
            label: 'IMPACT',
            description: 'Contract computes collateral/liquidation/mint at attacker-controlled price',
            line: absLine,
          },
        ];
        if (hasFlashLoanSurface) {
          attackPathSteps.push({
            label: 'OUTCOME',
            description: 'Attacker flash-borrows, prices at manipulated oracle, exits with profit',
            line: absLine,
          });
        }

        results.push({
          type: 'ORACLE_MANIPULATION' as VulnerabilityType,
          severity: 'MEDIUM',
          title: `Mutable price source '${sv}'`,
          description:
            `${fnName}() reads the mutable storage variable ${sv} for pricing. Without a ` +
            'hardened feed (Chainlink/Aggregator aggregator or TWAP accumulator), any ' +
            'write path to this variable — including admin keys or an attacker-set ' +
            'oracle — can price the contract arbitrarily.',
          confidence,
          evidence: [fnBodySnippet],
          attackPath: buildAttackPath(attackPathSteps),
          lineStart: absLine,
          lineEnd: absLine,
          columnStart: 0,
          columnEnd: 0,
          codeSnippet: evidenceSnippet(context.sourceCode, absLine, absLine + 1),
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

    // --- AMM reserves-based pricing (local getAmountOut/quote functions) ---
    // Detect swap/trade functions that price from internal reserve state vars
    // (reserveA/reserveB, balances, token amounts read as spot) using arithmetic —
    // no Chainlink feed, no TWAP accumulator, no external oracle call involved.
    for (const fn of fnNodes) {
      const fnName = (fn.name as string) || '';
      const fnStart = nodeLine(fn);
      const fnEnd = nodeEndLine(fn);
      const fnNameLower = fnName.toLowerCase();
      const isTradingFn =
        /swap|trade|exchange|borrow|lend|mint|quote|amountout|price|claim|redeem/.test(
          fnNameLower
        );
      if (!isTradingFn) continue;

      const reserves = stateVars.filter((sv) => /^reserve|^tokenReserve|reserve\d/.test(sv));
      if (reserves.length === 0) continue;

      const bodyText = evidenceSnippet(context.sourceCode, fnStart, fnEnd);
      const usesArithmetic = /[*/\-+=]/.test(bodyText);
      const usesReserve = reserves.some((r) =>
        new RegExp(`\\b${this.escapeRegExp(r)}\\b`).test(bodyText)
      );
      const readsInternalPricing = /getAmountOut|getPrice|quote|consult|getReserves|reserves\(\)/.test(bodyText);
      // `reserve` also names plain accounting vars (e.g. token reserves in
      // mint/burn). Only flag when a real pricing function is applied to them.
      if (!usesArithmetic || !usesReserve || !readsInternalPricing || hasChainlink || hasTWAP) continue;

      const absLine = (() => {
        for (let i = fnStart - 1; i < fnEnd && i < context.lines.length; i++) {
          if (/reserve/.test(context.lines[i] || '')) return i + 1;
        }
        return fnStart;
      })();
      if (seenLines.has(absLine)) continue;
      seenLines.add(absLine);

      results.push({
        type: 'ORACLE_MANIPULATION' as VulnerabilityType,
        severity: 'HIGH',
        title: 'AMM reserves used as spot price in swap pricing',
        description:
          `${fnName}() prices swaps from internal reserve amounts ` +
          `(${reserves.join(', ')}) with no external feed. The reserves can be ` +
          'moved within a single block (flash loan / large swap), so every ' +
          'output of this pricing is manipulable.',
        confidence: computeConfidence(80, {
          lineMatchesEvidence: true,
          financialImpact: true,
        }),
        evidence: [bodyText],
        attackPath: buildAttackPath([
          {
            label: 'ENTRY',
            description: `Attacker triggers ${fnName}() while pool reserves are skewed`,
            line: absLine,
          },
          {
            label: 'TRIGGER',
            description: `Pricing reads ${reserves.join(', ')} as the spot price`,
            line: absLine,
          },
          {
            label: 'EXPLOIT',
            description: 'Single-block swap moves reserves — no TWAP/Chainlink delivery used',
            line: absLine,
          },
          {
            label: 'IMPACT',
            description: 'Trade executes at manipulated price',
            line: absLine,
          },
        ]),
        lineStart: absLine,
        lineEnd: absLine,
        columnStart: 0,
        columnEnd: 0,
        codeSnippet: evidenceSnippet(
          context.sourceCode,
          Math.max(1, absLine - 1),
          absLine + 1
        ),
        recommendation:
          'Use a time-weighted average price (TWAP) or a Chainlink feed for pricing, ' +
          'and enforce a slippage/deadline parameter on every swap.',
        remediatedCode: this.chainlinkPrice(context, absLine),
        references: ['https://swcregistry.io/docs/SWC-113'],
        swcId: 'SWC-113',
        cvssScore: cvssFor('HIGH'),
      });
    }

    // Whole-contract inline summary finding if spot dependence found and no feed.
    if (results.length && !hasChainlink && !hasTWAP) {
      const first = results[0];
      if (!seenLines.has(-1)) {
        seenLines.add(-1);
        const confidence = computeConfidence(50, {
          lineMatchesEvidence: false,
        });
        results.push({
          type: 'ORACLE_MANIPULATION' as VulnerabilityType,
          severity: 'MEDIUM',
          title: 'No Chainlink / TWAP oracle integration detected',
          description:
            'The contract prices operations from spot markets and never references ' +
            'Chainlink AggregatorV3Interface or a TWAP accumulator. Every on-chain ' +
            'price is manipulable in the block it occurs.',
          confidence,
          evidence: [evidenceSnippet(context.sourceCode, 1, Math.min(10, context.lines.length))],
          attackPath: buildAttackPath([
            {
              label: 'ENTRY',
              description: 'Attacker identifies contract with no hardened oracle',
              line: 1,
            },
            {
              label: 'TRIGGER',
              description: 'Contract reads AMM spot or mutable storage for all pricing decisions',
              line: 1,
            },
            {
              label: 'EXPLOIT',
              description: 'Any single-block manipulation (flash loan / large swap) moves the price used by the contract',
              line: 1,
            },
            {
              label: 'IMPACT',
              description: 'All pricing paths are vulnerable — collateral, liquidation, mint, borrow, fees',
              line: 1,
            },
          ]),
          lineStart: 1,
          lineEnd: Math.min(10, context.lines.length),
          columnStart: 0,
          columnEnd: 0,
          codeSnippet: evidenceSnippet(context.sourceCode, 1, Math.min(8, context.lines.length)),
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

  /**
   * Determines whether the return value of a getReserves/balanceOf call is
   * actually used for pricing (arithmetic, assignment to price state variable,
   * or feeding a financial decision). Tightened to reduce FPs.
   */
  private usedAsPrice(context: DetectorContext, n: AstNode, fn: AstNode): boolean {
    const line = nodeLine(n);
    const windowLines = context.lines.slice(
      Math.max(0, line - 3),
      Math.min(context.lines.length, line + 4)
    );
    const windowText = windowLines.join(' ');

    // Require explicit arithmetic on the derived value or assignment to a price variable
    const hasArithmetic = /[*/+\-]=?/.test(windowText.replace(/\/\/.*$/gm, ''));
    const hasAssignmentToPriceVar = /[a-zA-Z_]\w*\s*=\s*\S/.test(windowText) &&
      /price|rate|value|quote|cost/.test(windowText);
    const hasPriceKeywordInMath =
      (hasArithmetic && /price|value|rate|quote|amount|swap/.test(windowText));

    return hasArithmetic || hasAssignmentToPriceVar || hasPriceKeywordInMath;
  }

  /**
   * Detects whether the function performs a financial state transition
   * (mint, borrow, liquidate, deposit collateral, etc.).
   */
  private detectFinancialImpact(context: DetectorContext, fn: AstNode): boolean {
    const fnText = JSON.stringify(fn).toLowerCase();
    return /mint|burn|borrow|liquidat|collateral|deposit|withdraw|transfer|claim|repay/.test(fnText);
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
