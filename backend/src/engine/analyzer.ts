import { v4 as uuidv4 } from 'uuid';
import {
  AuditReport,
  AuditSummary,
  CFGNode,
  DetectorContext,
  DetectorResult,
  FunctionInfo,
  Severity,
  StateVariableInfo,
  Vulnerability,
  VulnerabilityType,
} from '../types/index';
import { Parser } from './parser';
import { buildCFG } from './cfg';
import { detectGasOptimizations } from './gas';
import { generateSecureVersion } from './remediator';
import { analyzeBytecode } from './bytecode';
import { buildTaintAnalysis, TaintAnalysis } from './taint';
import {
  ReentrancyDetector,
} from '../detectors/reentrancy.detector';
import { OverflowDetector } from '../detectors/overflow.detector';
import { AccessControlDetector } from '../detectors/access-control.detector';
import { UncheckedCallsDetector } from '../detectors/unchecked-calls.detector';
import { TimestampDetector } from '../detectors/timestamp.detector';
import { FlashLoanDetector } from '../detectors/flash-loan.detector';
import { OracleManipulationDetector } from '../detectors/oracle-manipulation.detector';
import {
  FrontRunningDetector,
  DelegatecallDetector,
  UninitializedStorageDetector,
} from '../detectors/misc.detectors';

export type ProgressCallback = (
  stage: 'PARSING' | 'CFG_BUILD' | 'DETECTING' | 'REMEDIATING' | 'COMPLETE',
  progress: number,
  message: string,
  data?: unknown
) => void;

export interface AuditOptions {
  contractName: string;
  sourceCode: string;
  contractAddress?: string;
  network?: string;
  bytecode?: string;
  onProgress?: ProgressCallback;
}

const SEVERITY_WEIGHT: Record<Severity, number> = {
  CRITICAL: 10,
  HIGH: 6.5,
  MEDIUM: 4,
  LOW: 2,
  INFORMATIONAL: 1,
};

const RISK_WEIGHT: Record<Severity, number> = {
  CRITICAL: 50,
  HIGH: 30,
  MEDIUM: 15,
  LOW: 5,
  INFORMATIONAL: 1,
};

const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'];

export function summarizeVulnerabilities(vulns: Vulnerability[]): AuditSummary {
  const summary: AuditSummary = {
    critical: 0,
    high: 0,
    medium: 0,
    low: 0,
    informational: 0,
    total: vulns.length,
  };
  for (const v of vulns) {
    switch (v.severity) {
      case 'CRITICAL':
        summary.critical += 1;
        break;
      case 'HIGH':
        summary.high += 1;
        break;
      case 'MEDIUM':
        summary.medium += 1;
        break;
      case 'LOW':
        summary.low += 1;
        break;
      default:
        summary.informational += 1;
    }
  }
  return summary;
}

export function computeRiskScore(summary: AuditSummary): { score: number; label: string } {
  const total =
    summary.critical * RISK_WEIGHT.CRITICAL +
    summary.high * RISK_WEIGHT.HIGH +
    summary.medium * RISK_WEIGHT.MEDIUM +
    summary.low * RISK_WEIGHT.LOW +
    summary.informational * RISK_WEIGHT.INFORMATIONAL;

  const score = Math.min(100, Math.round(total));

  let label: string;
  if (summary.critical > 0 || summary.high > 0) label = 'CRITICAL';
  else if (summary.medium > 0) label = 'HIGH';
  else if (summary.low > 0) label = 'MEDIUM';
  else if (summary.informational > 0) label = 'LOW';
  else label = 'SAFE';

  return { score, label };
}

export function computeAuditScore(summary: AuditSummary): number {
  const penalty =
    summary.critical * RISK_WEIGHT.CRITICAL +
    summary.high * RISK_WEIGHT.HIGH +
    summary.medium * RISK_WEIGHT.MEDIUM +
    summary.low * RISK_WEIGHT.LOW +
    summary.informational * RISK_WEIGHT.INFORMATIONAL;
  return Math.max(0, Math.min(100, Math.round(100 - penalty)));
}

async function sleep(ms: number): Promise<void> {
  return new Promise<void>((r) => setTimeout(r, ms));
}

export class Analyzer {
  private options: AuditOptions;

  constructor(options: AuditOptions) {
    this.options = options;
  }

  async run(): Promise<AuditReport> {
    const { sourceCode, contractName, onProgress } = this.options;
    const startedAt = Date.now();
    const lines = sourceCode.split('\n');

    const emit = onProgress || (() => undefined);
    emit('PARSING', 5, 'Initializing parser...');

    // Phase 1: Parse.
    await sleep(30);
    const parser = new Parser(sourceCode);
    const ast = parser.parseAstSafe();
    if (!ast) {
      const detail = parser.getLastError();
      throw new Error(
        detail
          ? `Failed to parse Solidity source code: ${detail}`
          : 'Failed to parse Solidity source code. Check syntax and compiler version.'
      );
    }
    if (parser.getIsFallbackAst()) {
      emit('PARSING', 12, `Notice: Synthesized AST via resilient fallback parser (${parser.getLastError() ?? 'syntax notice'})`);
    }
    const functions: FunctionInfo[] = parser.extractFunctions(ast);
    const stateVariables: StateVariableInfo[] = parser.extractStateVariables(ast);
    const solidityVersion = parser.detectSolidityVersion(ast);
    emit('PARSING', 20, `AST parsed: ${functions.length} functions, ${stateVariables.length} state variables`, { functions: functions.length });

    // Build detector context.
    const context: DetectorContext = {
      sourceCode,
      lines,
      functions,
      stateVariables,
      solidityVersion,
      usesSafeMath: /using\s+SafeMath\s+for/.test(sourceCode),
      usesReentrancyGuard:
        /ReentrancyGuard|nonReentrant/.test(sourceCode),
      usesOwnable: /Ownable|onlyOwner/.test(sourceCode),
      usesAccessControl: /AccessControl|onlyRole/.test(sourceCode),
      ast,
    };

    emit('CFG_BUILD', 35, 'Resolving function call graph & control flow...');
    const rawVulnerabilities = await this.runDetectors(context, emit);
    emit('CFG_BUILD', 50, `Building Control Flow Graph (${functions.length} subgraphs)...`);

    const cfg: CFGNode[] = buildCFG(ast, rawVulnerabilities);
    emit('CFG_BUILD', 60, `CFG built: ${cfg.length} nodes`, { nodes: cfg.length });

    // Phase: Taint / Data-Flow Analysis.
    emit('DETECTING', 66, 'Running taint / data-flow analysis...');
    let taintResult: TaintAnalysis | undefined;
    try {
      taintResult = buildTaintAnalysis(sourceCode, ast, context);
      emit('DETECTING', 69, `Taint analysis complete: ${taintResult.sources.length} sources, ${taintResult.sinks.length} sinks, ${taintResult.edges.length} edges`);
    } catch (e) {
      emit('DETECTING', 69, `Taint analysis failed: ${e instanceof Error ? e.message : String(e)}`);
    }

    // Phase: Detection.
    emit('DETECTING', 70, 'Applying rule engine across '+ functions.length +' functions...');

    // Phase: Remediation.
    emit('REMEDIATING', 82, 'Generating secure rewrites and diffs...');
    const secureTemplate = generateSecureVersion(sourceCode, rawVulnerabilities);

    // Phase: finalize.
    const gasOptimizations = detectGasOptimizations(sourceCode, lines, (l) =>
      /view|pure|require\s*\(/.test(l)
    );

    emit('REMEDIATING', 92, `Gas analysis complete: ${gasOptimizations.length} optimizations found`);

    const summary = summarizeVulnerabilities(rawVulnerabilities);
    const risk = computeRiskScore(summary);
    const auditScore = computeAuditScore(summary);

    let bytecodeAnalysis;
    if (this.options.bytecode) {
      bytecodeAnalysis = analyzeBytecode(this.options.bytecode);
      emit('DETECTING', 78, `Bytecode analysis complete: ${bytecodeAnalysis.instructionCount} instructions, ${bytecodeAnalysis.findings.length} findings`);
    }

    await sleep(25);

    emit('COMPLETE', 100, 'Audit complete. Building report...', {
      vulnerabilities: summary.total,
      riskScore: risk.score,
    });

    return {
      reportId: uuidv4(),
      contractName,
      timestamp: new Date().toISOString(),
      scanDuration: Date.now() - startedAt,
      linesOfCode: lines.length,
      solcVersion: solidityVersion,
      overallRiskScore: risk.score,
      overallRiskLabel: risk.label,
      vulnerabilities: rawVulnerabilities,
      summary,
      cfg,
      ast: ast as unknown as object,
      gasOptimizations,
      auditScore,
      secureTemplate,
      ...(bytecodeAnalysis ? { bytecodeAnalysis } : {}),
      ...(taintResult
        ? {
            taintAnalysis: {
              sources: taintResult.sources,
              edges: taintResult.edges,
              sinks: taintResult.sinks,
              summary: taintResult.summary,
            },
          }
        : {}),
    };
  }

  private async runDetectors(
    context: DetectorContext,
    emit: ProgressCallback
  ): Promise<Vulnerability[]> {
    emit('DETECTING', 65, 'Running 10 security detectors...');

    const detectors = [
      new ReentrancyDetector(),
      new OverflowDetector(),
      new AccessControlDetector(),
      new UncheckedCallsDetector(),
      new TimestampDetector(),
      new FlashLoanDetector(),
      new OracleManipulationDetector(),
      new FrontRunningDetector(),
      new DelegatecallDetector(),
      new UninitializedStorageDetector(),
    ];

    const all: Vulnerability[] = [];
    const steps = detectors.length;

    for (let i = 0; i < detectors.length; i++) {
      const d = detectors[i];
      emit('DETECTING', 65 + Math.round(((i + 1) / steps) * 12), `Running ${d.name} detector...`);
      try {
        const res = d.detect(context);
        const vulns = res.map((r) => this.toVulnerability(r, i));
        all.push(...vulns);
      } catch (e) {
        // A detector failure should not abort the whole audit.
        const msg = e instanceof Error ? e.message : String(e);
        emit('DETECTING', 65, `${d.name} detector failed: ${msg}`);
      }
      await sleep(8);
    }

    // Sort by severity then location.
    return all.sort((a, b) => {
      const sevDiff =
        SEVERITY_ORDER.indexOf(b.severity) - SEVERITY_ORDER.indexOf(a.severity);
      if (sevDiff !== 0) return sevDiff;
      return a.lineStart - b.lineStart;
    });
  }

  private toVulnerability(
    r: DetectorResult,
    index: number
  ): Vulnerability {
    return {
      id: `${r.swcId}_${r.type}_${r.lineStart}_${index}`,
      type: r.type,
      severity: r.severity,
      title: r.title,
      description: r.description,
      confidence: r.confidence,
      evidence: r.evidence,
      attackPath: r.attackPath,
      lineStart: r.lineStart,
      lineEnd: r.lineEnd,
      columnStart: r.columnStart,
      columnEnd: r.columnEnd,
      codeSnippet: r.codeSnippet,
      recommendation: r.recommendation,
      remediatedCode: r.remediatedCode,
      references: r.references,
      swcId: r.swcId,
      cvssScore: r.cvssScore,
    };
  }
}

export async function runAudit(
  options: AuditOptions
): Promise<AuditReport> {
  const analyzer = new Analyzer(options);
  return analyzer.run();
}