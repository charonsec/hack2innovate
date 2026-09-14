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

export interface AuditRequest {
  contractName: string;
  sourceCode: string;
  contractAddress?: string;
  network?: string;
}

export interface Vulnerability {
  id: string;
  type: VulnerabilityType;
  severity: Severity;
  title: string;
  description: string;
  confidence: number;
  evidence: string[];
  attackPath?: AttackPathStep[];
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
  bytecodeAnalysis?: BytecodeAnalysis;
  taintAnalysis?: TaintAnalysisReport;
}

export interface FunctionInfo {
  name: string;
  visibility: string;
  modifiers: string[];
  parameters: string[];
  returns: string[];
  hasExternalCall: boolean;
  hasStateChange: boolean;
  lineStart: number;
  lineEnd: number;
}

export interface StateVariableInfo {
  name: string;
  type: string;
  visibility: string;
  lineStart: number;
  lineEnd: number;
  isConstant: boolean;
  isImmutable: boolean;
}

export interface DetectorContext {
  sourceCode: string;
  lines: string[];
  functions: FunctionInfo[];
  stateVariables: StateVariableInfo[];
  solidityVersion: string;
  usesSafeMath: boolean;
  usesReentrancyGuard: boolean;
  usesOwnable: boolean;
  usesAccessControl: boolean;
  ast?: unknown;
}

export interface AttackPathStep {
  label: string;
  description: string;
  nodeType?: string;
  line?: number;
}

export interface DetectorResult {
  type: VulnerabilityType;
  severity: Severity;
  title: string;
  description: string;
  confidence: number;
  evidence: string[];
  attackPath?: AttackPathStep[];
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
}

export interface Detector {
  name: string;
  detect(context: DetectorContext): DetectorResult[];
}

export interface DetectorOutcome {
  confidence: number;
  evidence: string[];
  attackPath?: AttackPathStep[];
}

export interface WSMessage {
  stage: 'PARSING' | 'CFG_BUILD' | 'DETECTING' | 'REMEDIATING' | 'COMPLETE' | 'ERROR';
  progress: number;
  message: string;
  data?: unknown;
}

export interface TemplateInfo {
  id: string;
  name: string;
  description: string;
  solidityVersion: string;
  sourceCode: string;
}

export interface DemoInfo {
  id: string;
  name: string;
  category: 'vulnerable' | 'secure';
  vulnerabilityClasses: string[];
  sourceCode: string;
}

export interface DiffResult {
  originalCode: string;
  fixedCode: string;
  diff: string;
  addedImports: string[];
  addedModifiers: string[];
  changedFunctions: string[];
}

export interface BytecodeOp {
  pc: number;
  opcode: string;
  mnemonic: string;
  args: number[];
  isPush: boolean;
  isDangerous: boolean;
  danger?: string;
}

export interface BytecodeFinding {
  opcode: string;
  pc: number;
  severity: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW';
  title: string;
  description: string;
}

export interface BasicBlock {
  start: number;
  end: number;
  ops: string[];
  summary: string;
}

export interface BytecodeAnalysis {
  valid: boolean;
  bytecodeLength: number;
  error?: string;
  instructionCount: number;
  pushconstantCount: number;
  opcodes: BytecodeOp[];
  findings: BytecodeFinding[];
  hasDelegatecall: boolean;
  hasSelfdestruct: boolean;
  hasSstore: boolean;
  hasCallValue: boolean;
  basicBlocks: BasicBlock[];
}