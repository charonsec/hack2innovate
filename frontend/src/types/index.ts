export type Severity = 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'INFORMATIONAL';

export type VulnerabilityType =
  | 'REENTRANCY'
  | 'INTEGER_OVERFLOW'
  | 'INTEGER_UNDERFLOW'
  | 'UNCHECKED_RETURN'
  | 'ACCESS_CONTROL'
  | 'TIMESTAMP_DEPENDENCE'
  | 'FLASH_LOAN'
  | 'ORACLE_MANIPULATION'
  | 'FRONT_RUNNING'
  | 'SELF_DESTRUCT'
  | 'DELEGATECALL'
  | 'UNINITIALIZED_STORAGE';

export interface Vulnerability {
  id: string;
  type: VulnerabilityType;
  severity: Severity;
  title: string;
  description: string;
  lineStart: number;
  lineEnd: number;
  columnStart: number;
  columnEnd: number;
  codeSnippet: string;
  recommendation: string;
  remediatedCode: string;
  references: string[];
  swcId: string;
  cvssScore: number;
  confidence: number;
  evidence: string[];
  attackPath?: { label: string; description: string; nodeType?: string; line?: number }[];
}

export type CFGNodeType = 'ENTRY' | 'EXIT' | 'CONDITION' | 'STATEMENT' | 'CALL' | 'RETURN';

export interface CFGNode {
  id: string;
  label: string;
  type: CFGNodeType;
  lineNumber: number;
  children: string[];
  parents: string[];
  isVulnerable: boolean;
  vulnerabilityTypes: VulnerabilityType[];
}

export interface GasOptimization {
  line: number;
  description: string;
  estimatedSaving: string;
  code: string;
  optimizedCode: string;
}

export interface AuditSummary {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
  total: number;
}

export interface TaintSourceInfo {
  id: string;
  variable?: string;
  source: string;
  line: number;
  confidence: string;
  expression: string;
}

export interface TaintEdgeInfo {
  from: string;
  to: string;
  sink: string;
  line: number;
}

export interface TaintSinkInfo {
  sink: string;
  line: number;
  expression: string;
}

export interface TaintAnalysisReport {
  sources: TaintSourceInfo[];
  edges: TaintEdgeInfo[];
  sinks: TaintSinkInfo[];
  summary: string[];
}

export interface BytecodeOpInfo {
  pc: number;
  opcode: string;
  mnemonic: string;
  args: number[];
  isPush: boolean;
  isDangerous: boolean;
  danger?: string;
}

export interface BytecodeFindingInfo {
  opcode: string;
  pc: number;
  severity: string;
  title: string;
  description: string;
}

export interface BytecodeAnalysisInfo {
  valid: boolean;
  bytecodeLength: number;
  instructionCount: number;
  opcodes: BytecodeOpInfo[];
  findings: BytecodeFindingInfo[];
  hasDelegatecall: boolean;
  hasSelfdestruct: boolean;
  hasSstore: boolean;
  hasCallValue: boolean;
  error?: string;
  basicBlocks: { start: number; end: number; ops: string[]; summary: string }[];
}

export interface AuditReport {
  reportId: string;
  contractName: string;
  timestamp: string;
  scanDuration: number;
  linesOfCode: number;
  solcVersion: string;
  overallRiskScore: number;
  overallRiskLabel: string;
  vulnerabilities: Vulnerability[];
  summary: AuditSummary;
  cfg: CFGNode[];
  ast: object;
  gasOptimizations: GasOptimization[];
  auditScore: number;
  secureTemplate?: string;
  taintAnalysis?: TaintAnalysisReport;
  bytecodeAnalysis?: BytecodeAnalysisInfo;
}

export interface TemplateInfo {
  id: string;
  name: string;
  description: string;
  solidityVersion: string;
  sourceCode: string;
}

export interface ScanLog {
  id: string;
  timestamp: string;
  stage: string;
  message: string;
  progress: number;
  data?: unknown;
}

export type ScanStatus = 'idle' | 'scanning' | 'complete' | 'error';

export interface WSPayload {
  type?: string;
  reportId?: string;
  stage?: 'PARSING' | 'CFG_BUILD' | 'DETECTING' | 'REMEDIATING' | 'COMPLETE' | 'ERROR';
  progress?: number;
  message?: string;
  data?: unknown;
  timestamp?: string;
}

export interface DiffLine {
  prefix: '-' | '+' | ' ';
  text: string;
}

export const VULNERABILITY_TYPE_LABELS: Record<VulnerabilityType, string> = {
  REENTRANCY: 'Reentrancy',
  INTEGER_OVERFLOW: 'Integer Overflow',
  INTEGER_UNDERFLOW: 'Integer Underflow',
  UNCHECKED_RETURN: 'Unchecked Return',
  ACCESS_CONTROL: 'Access Control',
  TIMESTAMP_DEPENDENCE: 'Timestamp Dependence',
  FLASH_LOAN: 'Flash Loan',
  ORACLE_MANIPULATION: 'Oracle Manipulation',
  FRONT_RUNNING: 'Front Running',
  SELF_DESTRUCT: 'Self Destruct',
  DELEGATECALL: 'Delegatecall',
  UNINITIALIZED_STORAGE: 'Uninitialized Storage',
};