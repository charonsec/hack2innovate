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
  nodeLine,
  snippet,
  walkAst,
  AstNode,
} from '../engine/detector-utils';

/**
 * DETECTOR 5 — Block timestamp dependence (SWC-116)
 *
 * Categories flagged:
 *  1. block.timestamp / now used for randomness.
 *  2. block.timestamp used in modulo conditions (miner-manipulable gate).
 *  3. Critical time-locks narrower than ~15 minutes.
 *  4. Reveal/commit games using block.timestamp as a source of entropy.
 */
export class TimestampDetector implements Detector {
  name = 'timestamp';

  detect(context: DetectorContext): DetectorResult[] {
    const results: DetectorResult[] = [];
    if (!context.ast) return results;

    const seen = new Set<string>();
    walkAst(context.ast, (n) => {
      if (n.type !== 'MemberAccess') return;
      const member = n.memberName as string;
      if (member !== 'timestamp' && member !== 'now') return;
      const base = n.expression as AstNode | undefined;
      const isBlock = base && base.type === 'Identifier' && (base.name as string) === 'block';
      const isNow = member === 'now';
      if (!isBlock && !isNow) return;

      const line = nodeLine(n);
      const lineText = (context.lines[line - 1] || '').trim();

      // Skip if merely used as a monotonic ordering nonce for events.
      if (/emit\s+\w+\s*\([^)]*block\.timestamp|block\.timestamp\s*\)\s*;/.test(lineText) &&
        !/require|if|>=|<=|==|%|keccak|abi\.encode/.test(lineText)) {
        return;
      }

      const key = `ts_${line}`;
      if (seen.has(key)) return;
      seen.add(key);

      const snippetText = snippet(context.lines, Math.max(1, line - 1), line + 1);

      // Randomness usage
      if (
        /(keccak|sha256|abi\.encode|uint256\(\s*block\.timestamp|mod|%\s*[0-9A-Fa-fx]|map|random)/.test(lineText) &&
        /[+%]|keccak|sha256|abi\.encode/.test(lineText)
      ) {
        results.push(this.build(context, line, snippetText, {
          sev: 'MEDIUM' as const,
          title: 'block.timestamp used as randomness source',
          description:
            'block.timestamp is set by the block proposer and can be shifted by a few ' +
            'seconds within the accepted drift window. Any randomness derived from it ' +
            '(keccak(block.timestamp), mod gates, lucky claims) is predictable and ' +
            'miner-manipulable, breaking lottery / raffle / win-lose mechanics.',
          rec:
            'Use Chainlink VRF (v2) or a commit-reveal scheme with a RANDAO-derived ' +
            'source. Never derive prizes or random selection from block.timestamp.',
          refs: ['https://swcregistry.io/docs/SWC-120', 'https://docs.chain.link/vrf'],
          swc: 'SWC-120',
        }));
        return;
      }

      // Timestamp modulo gate — miner can pick a favorable block.
      if (/\s%/.test(lineText.replace(/block\.timestamp/g, '')) || /block\.timestamp\s*%/.test(lineText)) {
        results.push(this.build(context, line, snippetText, {
          sev: 'MEDIUM' as const,
          title: 'Miner-manipulable block.timestamp modulo gate',
          description:
            'The condition uses `block.timestamp % N` — the miner that includes the ' +
            'transaction can delay or reorder blocks (within the drift window) until ' +
            'the modulo passes, giving the miner a decisive advantage over other users.',
          rec:
            'Use block.number for any periodic gate, or accept a commit-reveal scheme. ' +
            'Avoid `block.timestamp % N` style fairness gates.',
          refs: ['https://swcregistry.io/docs/SWC-116', 'https://ethereum.org/en/developers/docs/consensus-mechanisms/'],
          swc: 'SWC-116',
        }));
        return;
      }

      // Narrow time-lock: block.timestamp compared to expiration within 900s.
      if (/require|if|>=|<=|>|<|==|=/.test(lineText) && this.hasNarrowWindow(context, line)) {
        results.push(this.build(context, line, snippetText, {
          sev: 'LOW' as const,
          title: 'Short or predictable time-lock window',
          description:
            'A time-lock using block.timestamp with a window narrower than ~900 ' +
            'seconds (the block timestamp drift tolerance) can be gamed by miners, ' +
            'and short windows give attackers a narrow, predictable race to snipe.',
          rec:
            'Extend the delay, use block.number for relative delays, and combine with ' +
            'a commit-reveal pattern for fairness.',
          refs: ['https://swcregistry.io/docs/SWC-116'],
          swc: 'SWC-116',
        }));
        return;
      }

      // Generic timestamp dependence in a decision branch.
      if (/require|if|while|for/.test(lineText)) {
        results.push(this.build(context, line, snippetText, {
          sev: 'LOW' as const,
          title: 'block.timestamp-dependent logic branch',
          description:
            'Control flow depends on block.timestamp. While widely used for release ' +
            'schedules, miner-influenced timestamp drift can shift the exact moment a ' +
            'condition flips true — relevant for auctions, vesting and deadlines.',
          rec:
            'Prefer block.number for block-timescale logic. If absolute times are ' +
            'required, expect and tolerate +/- few-second drift.',
          refs: ['https://swcregistry.io/docs/SWC-116'],
          swc: 'SWC-116',
        }));
      }
    });

    return results;
  }

  private hasNarrowWindow(context: DetectorContext, line: number): boolean {
    const start = Math.max(1, line - 2);
    const end = Math.min(context.lines.length, line + 2);
    const window = context.lines.slice(start - 1, end).join(' ');
    // Look for blunt arithmetic offsets commonly used in short locks.
    const offsets = window.match(/block\.timestamp\s*[+\-]\s*(\d+)/g) || [];
    for (const off of offsets) {
      const num = parseInt((off.match(/(\d+)/) || ['0', '0'])[1], 10);
      if (!isNaN(num) && num > 0 && num < 900) return true;
    }
    return false;
  }

  private build(
    context: DetectorContext,
    line: number,
    code: string,
    opts: {
      sev: 'MEDIUM' | 'LOW';
      title: string;
      description: string;
      rec: string;
      refs: string[];
      swc: string;
    }
  ): DetectorResult {
    return {
      type: 'TIMESTAMP_DEPENDENCE' as VulnerabilityType,
      severity: opts.sev,
      title: opts.title,
      description: opts.description,
      lineStart: line,
      lineEnd: line + 1,
      columnStart: 0,
      columnEnd: 0,
      codeSnippet: code,
      recommendation: opts.rec,
      remediatedCode: this.fixedLine(context, line),
      references: opts.refs,
      swcId: opts.swc,
      cvssScore: cvssFor(opts.sev),
    };
  }

  private fixedLine(context: DetectorContext, line: number): string {
    const raw = (context.lines[line - 1] || '').replace(/\r$/, '');
    const replacement = raw.replace(/block\.timestamp/g, 'block.number');
    return replacement.includes('block.number')
      ? replacement
      : raw.replace(/block\.timestamp/g, '/* @audit prefer block.number */ block.timestamp');
  }
}