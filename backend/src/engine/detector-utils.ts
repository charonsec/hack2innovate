import { DetectorContext, Severity, VulnerabilityType } from '../types/index';

export function getLine(lines: string[], lineNumber: number): string {
  const idx = lineNumber - 1;
  if (idx < 0 || idx >= lines.length) return '';
  return lines[idx].trim();
}

export function fullLine(lines: string[], lineNumber: number): string {
  const idx = lineNumber - 1;
  if (idx < 0 || idx >= lines.length) return '';
  return lines[idx];
}

export function snippet(lines: string[], start: number, end: number): string {
  const s = Math.max(1, start);
  const e = Math.min(lines.length, end);
  if (s > e) return '';
  return lines.slice(s - 1, e).join('\n');
}

export function isExternalCallToken(token: string): boolean {
  return ['call', 'delegatecall', 'transfer', 'send', 'staticcall'].includes(token);
}

export function severityToNumber(severity: Severity): number {
  switch (severity) {
    case 'CRITICAL':
      return 4;
    case 'HIGH':
      return 3;
    case 'MEDIUM':
      return 2;
    case 'LOW':
      return 1;
    default:
      return 0;
  }
}

const CVSS_WEIGHT: Record<Severity, number> = {
  CRITICAL: 9.5,
  HIGH: 7.8,
  MEDIUM: 5.4,
  LOW: 3.1,
  INFORMATIONAL: 1.0,
};

export function cvssFor(severity: Severity, adjustment = 0): number {
  const base = CVSS_WEIGHT[severity];
  return Math.max(0, Math.min(10, +(base + adjustment).toFixed(1)));
}

export function buildId(type: VulnerabilityType, line: number, index: number): string {
  return `${type}_${line}_${index}`;
}

export function containsFunctionName(
  context: DetectorContext,
  name: string
): boolean {
  return context.functions.some((f) => f.name === name);
}

export function findFunctionAt(
  context: DetectorContext,
  line: number
): { name: string; visibility: string; lineStart: number; lineEnd: number } | null {
  for (const f of context.functions) {
    if (line >= f.lineStart && line <= f.lineEnd) {
      return f;
    }
  }
  return null;
}

export function isSensitiveFunctionName(name: string): boolean {
  const lower = name.toLowerCase();
  const sensitive = [
    'mint',
    'burn',
    'setowner',
    'changeowner',
    'transferownership',
    'setfee',
    'setfees',
    'setoracle',
    'updateoracle',
    'setprice',
    'updateprice',
    'setrate',
    'setinterest',
    'setpremium',
    'fetchprice',
    'setadmin',
    'addadmin',
    'removeadmin',
    'pause',
    'unpause',
    'destruct',
    'kill',
    'initialize',
    'init',
    'renounce',
    'setimplementation',
    'upgrade',
    'setreserve',
    'setswap',
    'setmaxsupply',
    'setsupply',
    'transfertokens',
    'sweeptokens',
  ];
  return sensitive.some((s) => lower === s || lower.startsWith(s));
}

export function stripComments(line: string): string {
  const idx = line.indexOf('//');
  return idx >= 0 ? line.slice(0, idx) : line;
}

const OPENZEPPELIN_SAFEMATH_IMPORT = 'import "@openzeppelin/contracts/math/SafeMath.sol";';

export function hasSafeMath(context: DetectorContext): boolean {
  if (context.usesSafeMath) return true;
  // Direct import scan as a fallback.
  return (
    context.sourceCode.includes('SafeMath') &&
    context.sourceCode.includes('using SafeMath for')
  );
}

export function hasReentrancyGuard(context: DetectorContext): boolean {
  if (context.usesReentrancyGuard) return true;
  return context.sourceCode.includes('nonReentrant');
}

export function hasOwnable(context: DetectorContext): boolean {
  if (context.usesOwnable || context.usesAccessControl) return true;
  return (
    context.sourceCode.includes('Ownable') ||
    context.sourceCode.includes('onlyOwner') ||
    context.sourceCode.includes('AccessControl')
  );
}

export function safeMathSuggests(dataType: string): boolean {
  return /^(uint|int)(8|16|24|32|40|48|56|64|72|80|88|96|104|112|120|128|136|144|152|160|168|176|184|192|200|208|216|224|232|240|248|256)?$/.test(
    dataType
  );
}

export const OPENZEPPELIN_SAFEMATH_IMPORT_CONST = OPENZEPPELIN_SAFEMATH_IMPORT;

/** Unwraps NameValueExpression wrappers produced by .call{value: x}(...) syntax. */
export function unwrapCallee(node: unknown): AstNode | null {
  if (!isAstNode(node)) return null;
  if (node.type === 'NameValueExpression') {
    return unwrapCallee(node.expression);
  }
  return node;
}

export interface MemberCallInfo {
  memberName: string;
  base: AstNode | null;
}

/** Returns member-call info when the callee is X.member(...) — handles both
 *  plain MemberAccess and NameValueExpression-wrapped forms. */
export function memberCallInfo(callee: unknown): MemberCallInfo | null {
  const node = unwrapCallee(callee);
  if (!node || node.type !== 'MemberAccess') return null;
  return {
    memberName: (node.memberName as string) || '',
    base: (node.expression as AstNode) || null,
  };
}

export function isExternalCallMemberNode(node: unknown): boolean {
  const info = memberCallInfo(node);
  if (!info) return false;
  return ['call', 'delegatecall', 'staticcall', 'send', 'transfer'].includes(
    info.memberName
  );
}

export interface AstNode {
  type: string;
  loc?: {
    start: { line: number; column: number };
    end: { line: number; column: number };
  };
  [key: string]: unknown;
}

const SKIP_AST_KEYS = new Set(['loc', 'range', 'tokens', 'comments', 'parent']);

export function isAstNode(value: unknown): value is AstNode {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    typeof (value as { type?: unknown }).type === 'string'
  );
}

export function walkAst(node: unknown, visitor: (n: AstNode) => void): void {
  if (!isAstNode(node)) return;
  visitor(node);
  for (const key of Object.keys(node)) {
    if (SKIP_AST_KEYS.has(key)) continue;
    const value = node[key];
    if (Array.isArray(value)) {
      for (const item of value) {
        if (isAstNode(item)) walkAst(item, visitor);
      }
    } else if (isAstNode(value)) {
      walkAst(value, visitor);
    }
  }
}

export function findNodes(root: unknown, type: string): AstNode[] {
  const out: AstNode[] = [];
  walkAst(root, (n) => {
    if (n.type === type) out.push(n);
  });
  return out;
}

export function nodeLine(n: AstNode): number {
  return n && n.loc && n.loc.start ? n.loc.start.line : 0;
}

export function nodeEndLine(n: AstNode): number {
  return n && n.loc && n.loc.end ? n.loc.end.line : nodeLine(n);
}

export function deltaForSeverity(severity: Severity): string {
  switch (severity) {
    case 'CRITICAL':
      return '-high';
    case 'HIGH':
      return '-high';
    case 'MEDIUM':
      return '-medium';
    default:
      return '-low';
  }
}