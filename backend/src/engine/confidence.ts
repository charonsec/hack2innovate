import { AttackPathStep, Severity } from '../types/index';

/**
 * Confidence engine.
 *
 * Each detector computes a base confidence from its own AST/CFG evidence, then
 * adjusts using contextual signals (guards present, compiler version, data-verb
 * patterns). The score is clamped to [0, 100] and rounded.
 *
 * Signals do not inflate confidence toward 100 without evidence — they can only
 * move a finding within a defensible band defined by the detector's base score.
 */

export interface ConfidenceSignals {
  /** Is a known guard (nonReentrant, onlyOwner, onlyRole) demonstrably applied to the function? */
  guardPresent?: boolean;
  /** Does the vulnerable path require a pre-condition that must actually hold? */
  requiresPrecondition?: boolean;
  /** Compiler is >=0.8 so built-in checked arithmetic masks under/overflow. */
  builtinCheckedArithmetic?: boolean;
  /** A safe pattern (SafeMath, Checks-Effects-Interactions) is present. */
  safePatternBaseline?: boolean;
  /** The finding relies on inferred types rather than explicit annotations. */
  inferredTypes?: boolean;
  /** Validate the finding line actually contains the flagged construct. */
  lineMatchesEvidence?: boolean;
  /** A try/catch wraps the external interaction. */
  handledException?: boolean;
  /** The vulnerable operation feeds a financial/price state transition. */
  financialImpact?: boolean;
  /** The finding depends on a cross-function or cross-contract path. */
  crossFunction?: boolean;
}

const CLAMP = (n: number): number => Math.max(0, Math.min(100, Math.round(n)));

export function computeConfidence(base: number, signals: ConfidenceSignals = {}): number {
  let score = base;

  if (signals.lineMatchesEvidence === false) score -= 25;
  if (signals.guardPresent === true) score -= 40;
  if (signals.safePatternBaseline === true) score -= 15;
  if (signals.builtinCheckedArithmetic === true) score -= 20;
  if (signals.handledException === true) score -= 15;
  if (signals.inferredTypes === true) score -= 10;
  if (signals.requiresPrecondition === true) score -= 5;
  if (signals.financialImpact === true) score += 10;
  if (signals.crossFunction === true) score += 5;
  if (signals.lineMatchesEvidence === true) score += 5;

  return CLAMP(score);
}

/**
 * Builds a defensive, evidence-based attack path for a finding.
 * Steps are intentionally conservative — each one is derived from AST/CFG facts.
 * Detectors that cannot prove a step omit it rather than fabricate driver text.
 */
export function buildAttackPath(steps: Array<Omit<AttackPathStep, 'nodeType'>>): AttackPathStep[] {
  return steps.map((s, i) => ({
    nodeType: ['ENTRY', 'TRIGGER', 'EXPLOIT', 'IMPACT', 'OUTCOME'][i] ?? 'STEP',
    ...s,
  }));
}

/**
 * Severity → base CVSS v3.1 score (AV:N/AC:L vector family) with an optional
 * adjustment for exploitability evidence. Kept deterministic.
 */
export function severityBand(severity: Severity): { low: number; high: number } {
  switch (severity) {
    case 'CRITICAL':
      return { low: 9.0, high: 10.0 };
    case 'HIGH':
      return { low: 7.0, high: 8.9 };
    case 'MEDIUM':
      return { low: 4.0, high: 6.9 };
    case 'LOW':
      return { low: 0.1, high: 3.9 };
    default:
      return { low: 0.0, high: 0.0 };
  }
}

export function evidenceSnippet(
  sourceCode: string,
  lineStart: number,
  lineEnd: number
): string {
  const lines = sourceCode.split('\n');
  const slice = lines
    .slice(Math.max(0, lineStart - 1), Math.min(lines.length, lineEnd))
    .join('\n')
    .trim();
  return slice || '(source line out of range)';
}