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

export function sanitizeSourceCode(source: string): string {
  if (!source) return '';
  let s = source.replace(/^\uFEFF/, '');
  // Strip markdown code fences if wrapped in ```solidity ... ``` or ``` ... ```
  s = s.replace(/^```(?:solidity|sol)?\r?\n/i, '').replace(/\r?\n```\s*$/i, '');
  // Normalize line endings
  s = s.replace(/\r\n/g, '\n').replace(/\r/g, '\n');
  // Strip zero-width and invisible formatting characters
  s = s.replace(/[\u200B-\u200D\uFEFF]/g, '');
  return s;
}

export class Parser {
  private sourceCode: string;
  private rawSource: string;
  private lastError: string | null = null;
  private isFallbackAst = false;

  constructor(sourceCode: string) {
    this.rawSource = sourceCode;
    this.sourceCode = sanitizeSourceCode(sourceCode);
  }

  getLastError(): string | null {
    return this.lastError;
  }

  getIsFallbackAst(): boolean {
    return this.isFallbackAst;
  }

  parse(): NodeWithLoc {
    if (!this.sourceCode.trim()) {
      this.lastError = 'Solidity source code is empty or contains only whitespace.';
      throw new Error(this.lastError);
    }

    // Attempt 1: Standard tolerant parser
    try {
      const ast = parse(this.sourceCode, {
        loc: true,
        range: true,
        tolerant: true,
        tokens: true,
      });
      return normalize(ast);
    } catch (primaryErr) {
      const primaryMsg =
        primaryErr instanceof Error ? primaryErr.message : String(primaryErr);
      this.lastError = primaryMsg;

      // Attempt 2: Try building a resilient fallback AST from regex analysis
      try {
        const fallbackAst = this.buildFallbackAst();
        const extractedContracts = findNodesAst(fallbackAst, 'ContractDefinition');
        const extractedFns = findNodesAst(fallbackAst, 'FunctionDefinition');

        if (extractedContracts.length > 0 || extractedFns.length > 0) {
          this.isFallbackAst = true;
          console.warn(
            `[Parser] Primary parser failed (${primaryMsg}); recovered with fallback AST (${extractedContracts.length} contracts, ${extractedFns.length} functions).`
          );
          return fallbackAst;
        }
      } catch (fallbackErr) {
        console.warn('[Parser] Fallback AST construction error:', fallbackErr);
      }

      throw new Error(`Solidity parse error: ${primaryMsg}`);
    }
  }

  parseAstSafe(): NodeWithLoc | null {
    try {
      return this.parse();
    } catch (err) {
      if (!this.lastError && err instanceof Error) {
        this.lastError = err.message;
      }
      return null;
    }
  }

  private buildFallbackAst(): NodeWithLoc {
    const lines = this.sourceCode.split('\n');
    const children: NodeWithLoc[] = [];

    // 1. Pragma directive
    const pragmaMatch = this.sourceCode.match(/pragma\s+solidity\s+([^;]+);/);
    if (pragmaMatch) {
      children.push({
        type: 'PragmaDirective',
        name: 'solidity',
        value: pragmaMatch[1].trim(),
      });
    }

    // 2. Contracts / Interfaces / Libraries
    const contractRegex =
      /(?:abstract\s+)?(contract|interface|library)\s+([A-Za-z0-9_]+)(?:\s+is\s+([^{]+))?\s*\{/g;
    let match: RegExpExecArray | null;
    while ((match = contractRegex.exec(this.sourceCode)) !== null) {
      const kind = match[1];
      const name = match[2];
      const startLine = this.sourceCode.slice(0, match.index).split('\n').length;

      children.push({
        type: 'ContractDefinition',
        name,
        kind,
        subNodes: [],
        loc: {
          start: { line: startLine, column: 0 },
          end: { line: lines.length, column: 0 },
        },
      });
    }

    // 3. Functions
    const fnRegex =
      /function\s+([A-Za-z0-9_]*)\s*\(([^)]*)\)\s*([^{;]*)(?:\{|;)/g;
    while ((match = fnRegex.exec(this.sourceCode)) !== null) {
      const fnName = match[1] || 'fallback';
      const paramsStr = match[2];
      const modifiersStr = match[3];
      const startLine = this.sourceCode.slice(0, match.index).split('\n').length;

      let endLine = startLine;
      const bodyStartIdx = this.sourceCode.indexOf('{', match.index);
      if (bodyStartIdx !== -1 && bodyStartIdx - match.index < 250) {
        let depth = 1;
        let i = bodyStartIdx + 1;
        while (i < this.sourceCode.length && depth > 0) {
          if (this.sourceCode[i] === '{') depth++;
          else if (this.sourceCode[i] === '}') depth--;
          i++;
        }
        endLine = this.sourceCode.slice(0, i).split('\n').length;
      }

      const visibility =
        modifiersStr.match(/\b(public|external|internal|private)\b/)?.[1] ||
        'public';
      const modifiers = (
        modifiersStr.match(
          /\b(onlyOwner|onlyRole|nonReentrant|view|pure|payable|[A-Za-z0-9_]+)\b/g
        ) || []
      ).filter(
        (m) =>
          !['public', 'external', 'internal', 'private', 'returns', 'function'].includes(m)
      );

      const paramNodes: NodeWithLoc[] = paramsStr
        .split(',')
        .filter((p) => p.trim().length > 0)
        .map((p) => {
          const parts = p.trim().split(/\s+/);
          return {
            type: 'VariableDeclaration',
            typeName: { type: 'ElementaryTypeName', name: parts[0] || 'uint256' },
            name: parts[1] || '',
          };
        });

      children.push({
        type: 'FunctionDefinition',
        name: fnName,
        visibility,
        modifiers: modifiers.map((m) => ({ type: 'ModifierInvocation', name: m })),
        parameters: {
          type: 'ParameterList',
          parameters: paramNodes,
        },
        returnParameters: {
          type: 'ParameterList',
          parameters: [],
        },
        loc: {
          start: { line: startLine, column: 0 },
          end: { line: Math.max(startLine, endLine), column: 0 },
        },
        body: {
          type: 'Block',
          loc: {
            start: { line: startLine, column: 0 },
            end: { line: Math.max(startLine, endLine), column: 0 },
          },
        },
      });
    }

    // 4. State variables
    const stateVarRegex =
      /^\s*(mapping\s*\([^;]+\)|[A-Za-z0-9_\[\]]+)\s+(public|private|internal)?\s*([A-Za-z0-9_]+)\s*(?:=[^;]+)?;/gm;
    while ((match = stateVarRegex.exec(this.sourceCode)) !== null) {
      const typeName = match[1];
      const visibility = match[2] || 'internal';
      const varName = match[3];
      const line = this.sourceCode.slice(0, match.index).split('\n').length;

      children.push({
        type: 'StateVariableDeclaration',
        variables: [
          {
            type: 'VariableDeclaration',
            typeName: { type: 'ElementaryTypeName', name: typeName },
            name: varName,
            visibility,
            isConstant: false,
            isImmutable: false,
            loc: { start: { line, column: 0 }, end: { line, column: 0 } },
          },
        ],
        loc: { start: { line, column: 0 }, end: { line, column: 0 } },
      });
    }

    // 5. Modifiers
    const modRegex = /modifier\s+([A-Za-z0-9_]+)\s*(?:\([^)]*\))?\s*\{/g;
    while ((match = modRegex.exec(this.sourceCode)) !== null) {
      const modName = match[1];
      const line = this.sourceCode.slice(0, match.index).split('\n').length;
      children.push({
        type: 'ModifierDefinition',
        name: modName,
        body: true,
        loc: { start: { line, column: 0 }, end: { line, column: 0 } },
      });
    }

    return {
      type: 'SourceUnit',
      children,
    };
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