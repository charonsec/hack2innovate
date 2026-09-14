import { parse } from '@solidity-parser/parser';
import {
  FunctionInfo,
  StateVariableInfo,
} from '../types/index';

interface NodeWithLoc {
  type: string;
  loc?: {
    start: { line: number; column: number };
    end: { line: number; column: number };
  };
  children?: Array<NodeWithLoc>;
  [key: string]: unknown;
}

const SKIP_KEYS = new Set(['loc', 'range', 'tokens', 'comments', 'parent']);
const SKIP_TYPES = new Set(['loc', 'range', 'token', 'comment']);

export type CallKind = 'internal' | 'external' | 'lowlevel' | 'delegatecall';

export interface CallGraphEdge {
  from: string;
  to: string;
  kind: CallKind;
  line: number;
}

function isNodeValue(value: unknown): value is NodeWithLoc {
  return (
    typeof value === 'object' &&
    value !== null &&
    !Array.isArray(value) &&
    typeof (value as { type?: unknown }).type === 'string'
  );
}

function walk(node: NodeWithLoc, visitor: (n: NodeWithLoc) => void): void {
  if (!node) return;
  visitor(node);
  for (const key of Object.keys(node)) {
    if (SKIP_KEYS.has(key)) continue;
    const value = node[key];
    if (Array.isArray(value)) {
      for (const item of value) {
        if (isNodeValue(item)) walk(item, visitor);
      }
    } else if (isNodeValue(value)) {
      walk(value, visitor);
    }
  }
}

function lineOf(node: NodeWithLoc): number {
  return node && node.loc && node.loc.start ? node.loc.start.line : 0;
}

function endLineOf(node: NodeWithLoc): number {
  return node && node.loc && node.loc.end ? node.loc.end.line : lineOf(node);
}

function columnOf(node: NodeWithLoc): number {
  return node && node.loc && node.loc.start ? node.loc.start.column : 0;
}

function endColumnOf(node: NodeWithLoc): number {
  return node && node.loc && node.loc.end ? node.loc.end.column : columnOf(node);
}

function findNodesAst(root: NodeWithLoc, type: string): NodeWithLoc[] {
  const out: NodeWithLoc[] = [];
  walk(root, (n) => {
    if (n.type === type) out.push(n);
  });
  return out;
}

function normalize(node: unknown): NodeWithLoc {
  return node as NodeWithLoc;
}

export class Parser {
  private sourceCode: string;

  constructor(sourceCode: string) {
    this.sourceCode = sourceCode;
  }

  parse(): NodeWithLoc {
    try {
      const ast = parse(this.sourceCode, {
        loc: true,
        range: true,
        tolerant: true,
        tokens: true,
      });
      return normalize(ast);
    } catch (e) {
      throw new Error(
        `Solidity parse error: ${e instanceof Error ? e.message : String(e)}`
      );
    }
  }

  parseAstSafe(): NodeWithLoc | null {
    try {
      return this.parse();
    } catch {
      return null;
    }
  }

  extractFunctions(astRoot: NodeWithLoc): FunctionInfo[] {
    const functions: FunctionInfo[] = [];
    const fnNodes = findNodesAst(astRoot, 'FunctionDefinition');
    for (const node of fnNodes) {
      const name = (node.name as string) || 'constructor';
      const visibility = (node.visibility as string) || 'default';
      const modifiers = Array.isArray(node.modifiers)
        ? (node.modifiers as Array<NodeWithLoc>).map((m) => {
            const mName = m.name;
            return typeof mName === 'object' && mName !== null
              ? ((mName as NodeWithLoc).name as string)
              : (mName as string);
          })
        : [];

      const paramList = node.parameters as NodeWithLoc | undefined;
      const parameters: string[] = [];
      if (paramList && Array.isArray(paramList.parameters)) {
        for (const p of paramList.parameters as Array<NodeWithLoc>) {
          const typeNode = (p as { typeName?: unknown }).typeName as NodeWithLoc | undefined;
          parameters.push(`${this.typeString(typeNode)} ${String(p.name || '')}`);
        }
      }

      const returnList = node.returnParameters as NodeWithLoc | undefined;
      const returns: string[] = [];
      if (returnList && Array.isArray(returnList.parameters)) {
        for (const p of returnList.parameters as Array<NodeWithLoc>) {
          const typeNode = (p as { typeName?: unknown }).typeName as NodeWithLoc | undefined;
          returns.push(`${this.typeString(typeNode)} ${String(p.name || '')}`);
        }
      }

      const body = node.body as NodeWithLoc | undefined;
      const bodyBlock = body && body.type === 'Block' ? body : undefined;

      functions.push({
        name,
        visibility,
        modifiers,
        parameters,
        returns,
        hasExternalCall: this.hasExternalCallInNode(node),
        hasStateChange: this.hasStateChangeInNode(node),
        lineStart: lineOf(node),
        lineEnd: endLineOf(node),
      });

      void bodyBlock;
    }
    return functions;
  }

  extractStateVariables(astRoot: NodeWithLoc): StateVariableInfo[] {
    const stateVars: StateVariableInfo[] = [];
    const decls = findNodesAst(astRoot, 'StateVariableDeclaration');
    for (const decl of decls) {
      const variables = decl.variables as Array<NodeWithLoc> | undefined;
      if (!variables) continue;
      for (const v of variables) {
        const typeNode = (v as { typeName?: unknown }).typeName as NodeWithLoc | undefined;
        stateVars.push({
          name: (v.name as string) || '',
          type: this.typeString(typeNode),
          visibility: (v.visibility as string) || 'internal',
          lineStart: lineOf(v),
          lineEnd: endLineOf(v),
          isConstant: Boolean(v.isConstant),
          isImmutable: Boolean(v.isImmutable),
        });
      }
    }
    return stateVars;
  }

  extractModifiers(astRoot: NodeWithLoc): { name: string; lineStart: number; hasBody: boolean }[] {
    const out: { name: string; lineStart: number; hasBody: boolean }[] = [];
    const mods = findNodesAst(astRoot, 'ModifierDefinition');
    for (const m of mods) {
      out.push({
        name: (m.name as string) || '',
        lineStart: lineOf(m),
        hasBody: Boolean(m.body),
      });
    }
    return out;
  }

  extractEvents(astRoot: NodeWithLoc): { name: string; lineStart: number }[] {
    const out: { name: string; lineStart: number }[] = [];
    const evts = findNodesAst(astRoot, 'EventDefinition');
    for (const e of evts) {
      out.push({ name: (e.name as string) || '', lineStart: lineOf(e) });
    }
    return out;
  }

  detectSolidityVersion(astRoot: NodeWithLoc): string {
    const pragmas = findNodesAst(astRoot, 'PragmaDirective');
    for (const p of pragmas) {
      if ((p.name as string) === 'solidity') {
        return (p.value as string) || 'unknown';
      }
    }
    return 'unknown';
  }

  /**
   * Resolve the callee of a FunctionCall node into a name and a call kind.
   * Handles plain Identifier callees (incl. `selfdestruct`/`suicide` builtins),
   * MemberAccess callees (this.foo(), token.transfer(), lib.foo()), and the
   * NameValueExpression wrapper used by the newer parser for call{value: x}().
   */
  private resolveCall(
    callee: NodeWithLoc | undefined
  ): { name: string; kind: CallKind } | null {
    if (!callee) return null;
    let expr = callee;
    // Newer parser wraps `addr.call{value: 1}()` as a NameValueExpression
    // inside FunctionCall.expression.
    if (expr.type === 'NameValueExpression') {
      const inner = expr.expression as NodeWithLoc | undefined;
      if (!inner) return null;
      expr = inner;
    }
    if (expr.type === 'Identifier') {
      const name = (expr.name as string) || '';
      if (name === 'selfdestruct' || name === 'suicide') {
        return { name, kind: 'lowlevel' };
      }
      return { name, kind: 'internal' };
    }
    if (expr.type === 'MemberAccess') {
      const member = (expr.memberName as string) || '';
      if (member === 'delegatecall') {
        return { name: member, kind: 'delegatecall' };
      }
      if (
        member === 'call' ||
        member === 'staticcall' ||
        member === 'send' ||
        member === 'transfer'
      ) {
        return { name: member, kind: 'lowlevel' };
      }
      return { name: member, kind: 'external' };
    }
    return null;
  }

  buildFunctionCallGraph(astRoot: NodeWithLoc): Map<string, string[]> {
    const graph = new Map<string, string[]>();
    const fnNodes = findNodesAst(astRoot, 'FunctionDefinition');
    for (const fn of fnNodes) {
      const name = (fn.name as string) || 'constructor';
      graph.set(name, []);
    }
    for (const fn of fnNodes) {
      const name = (fn.name as string) || 'constructor';
      const targets = new Set<string>();
      walk(fn, (n) => {
        if (n.type !== 'FunctionCall') return;
        const call = this.resolveCall(n.expression as NodeWithLoc | undefined);
        if (call) targets.add(call.name);
      });
      graph.set(name, Array.from(targets));
    }
    return graph;
  }

  /**
   * Build a typed edge list of every call site within each function, grouped by
   * `from` function, distinguishing internal vs external vs low-level vs
   * delegatecall. Powers the Call Graph tab in the UI.
   */
  buildCallGraphDetailed(astRoot: NodeWithLoc): CallGraphEdge[] {
    const edges: CallGraphEdge[] = [];
    const fnNodes = findNodesAst(astRoot, 'FunctionDefinition');
    for (const fn of fnNodes) {
      const from = (fn.name as string) || 'constructor';
      walk(fn, (n) => {
        if (n.type !== 'FunctionCall') return;
        const call = this.resolveCall(n.expression as NodeWithLoc | undefined);
        if (call) {
          edges.push({ from, to: call.name, kind: call.kind, line: lineOf(n) });
        }
      });
    }
    return edges;
  }

  getAstObject(): object {
    // Strip internal-only fields such as the raw text to keep the payload lean,
    // but keep everything structural so the frontend can render it.
    return this.parse() as unknown as object;
  }

  private hasExternalCallInNode(node: NodeWithLoc): boolean {
    let found = false;

    const isMemberCall = (n: NodeWithLoc): boolean => {
      let expr = n;
      // Unwrap NameValueExpression { value } syntax around .call{value:x}.
      if (expr.type === 'NameValueExpression' && expr.expression) {
        expr = expr.expression as NodeWithLoc;
      }
      return expr.type === 'MemberAccess';
    };

    walk(node, (n) => {
      if (found) return;
      if (n.type === 'FunctionCall') {
        const calleeObj = n.expression as NodeWithLoc | undefined;
        if (calleeObj && isMemberCall(calleeObj)) {
          let access = calleeObj;
          if (access.type === 'NameValueExpression') {
            access = access.expression as NodeWithLoc;
          }
          const member = access.memberName as string;
          if (['call', 'delegatecall', 'transfer', 'send', 'staticcall'].includes(member)) {
            found = true;
          } else if (['transfer', 'transferFrom', 'safeTransfer', 'safeTransferFrom'].includes(member)) {
            // Only count high-level interface member transfers.
            found = true;
          }
        }
      }
    });
    return found;
  }

  private hasStateChangeInNode(node: NodeWithLoc): boolean {
    let found = false;
    walk(node, (n) => {
      if (found) return;
      if (n.type === 'Assignment') {
        const op = n.operator as string;
        found = true;
        void op;
      }
      if (n.type === 'Assignment') {
        const op = n.operator as string;
        if (['+=', '-=', '*=', '/=', '**='].includes(op)) found = true;
      }
      if (n.type === 'VariableDeclarationStatement') {
        const initial = n.initialValue as NodeWithLoc | undefined;
        if (initial && initial.type === 'FunctionCall') {
          const callee = initial.expression as NodeWithLoc | undefined;
          if (
            callee &&
            callee.type === 'Identifier' &&
            ['transfer', 'send', 'call'].includes(callee.name as string)
          ) {
            found = true;
          }
        }
      }
      if (n.type === 'FunctionCall') {
        const callee = n.expression as NodeWithLoc | undefined;
        if (callee && callee.type === 'Identifier') {
          const calleeName = callee.name as string;
          if (
            calleeName.startsWith('_') &&
            !['_msgSender', '_transfer'].includes(calleeName)
          ) {
            // Heuristic: functions prefixed with _ are internal helpers that may write state.
            found = true;
          }
        }
      }
    });
    return found;
  }

  private typeString(typeNode: NodeWithLoc | undefined): string {
    if (!typeNode) return '';
    if (typeNode.type === 'ElementaryTypeName') {
      return (typeNode.name as string) || '';
    }
    if (typeNode.type === 'UserDefinedTypeName') {
      return (typeNode.namePath as string) || '';
    }
    if (typeNode.type === 'ArrayTypeName') {
      return `${this.typeString(typeNode.baseType as NodeWithLoc | undefined)}[]`;
    }
    if (typeNode.type === 'Mapping') {
      const keyType = this.typeString(typeNode.keyType as NodeWithLoc | undefined);
      const valueType = this.typeString(typeNode.valueType as NodeWithLoc | undefined);
      return `mapping(${keyType} => ${valueType})`;
    }
    if (typeNode.type === 'FunctionTypeName') {
      return 'function';
    }
    return (typeNode.name as string) || 'address';
  }
}

export function parseSolidity(sourceCode: string) {
  const p = new Parser(sourceCode);
  const ast = p.parse();
  return {
    ast,
    functions: p.extractFunctions(ast),
    stateVariables: p.extractStateVariables(ast),
    modifiers: p.extractModifiers(ast),
    events: p.extractEvents(ast),
    solidityVersion: p.detectSolidityVersion(ast),
    functionCallGraph: p.buildFunctionCallGraph(ast),
    callGraphDetailed: p.buildCallGraphDetailed(ast),
  };
}