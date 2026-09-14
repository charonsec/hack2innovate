import { CFGNode, CFGNodeType, Vulnerability, VulnerabilityType } from '../types/index';
import { AstNode, findNodes, memberCallInfo, nodeEndLine, nodeLine, walkAst } from './detector-utils';

interface CFGBuildResult {
  nodes: CFGNode[];
}

/**
 * Builds an adjacency-list control-flow graph over the AST.
 * Every function becomes a subgraph: ENTRY -> statements -> EXIT.
 * if/while/for produce CONDITION nodes with branch edges (loop back-edges).
 * External calls produce CALL nodes; returns produce RETURN/EXIT nodes.
 * Nodes overlapping a reported vulnerability are flagged vulnerable.
 */
export function buildCFG(ast: unknown, vulnerabilities: Vulnerability[]): CFGNode[] {
  const builder = new CFGBuilder(ast, vulnerabilities);
  return builder.build();
}

class CFGBuilder {
  private nodes: CFGNode[] = [];
  private counter = 0;
  private readonly ast: unknown;
  private readonly vulns: Vulnerability[];

  constructor(ast: unknown, vulnerabilities: Vulnerability[]) {
    this.ast = ast;
    this.vulns = vulnerabilities;
  }

  build(): CFGNode[] {
    const fnNodes = findNodes(this.ast, 'FunctionDefinition');
    for (const fn of fnNodes) {
      this.buildFunction(fn);
    }
    if (this.nodes.length === 0) {
      // Fallback: contract-level nodes.
      const contracts = findNodes(this.ast, 'ContractDefinition');
      for (const c of contracts) {
        this.addNode('ENTRY', (c.name as string) || 'contract', nodeLine(c));
      }
    }
    return this.nodes;
  }

  private buildFunction(fn: AstNode): void {
    const name = (fn.name as string) || 'constructor';
    const startLine = nodeLine(fn);
    const endLine = nodeEndLine(fn);
    const entryId = this.addNode(
      'ENTRY',
      `fn: ${name}`,
      startLine
    );
    const body = fn.body as AstNode | undefined;
    if (!body) {
      const exit = this.addNode('EXIT', `${name} (decl)`, endLine);
      this.link(entryId, exit);
      return;
    }

    const { lastId } = this.buildBlock(body, entryId, `${name}`, startLine, endLine);

    const exit = this.addNode('EXIT', `${name} → exit`, endLine);
    this.link(lastId, exit);
  }

  private buildBlock(
    block: AstNode,
    entry: string,
    scope: string,
    startLine: number,
    endLine: number
  ): { lastId: string } {
    const statements = (block.statements as AstNode[]) || [];
    let current: string[] = [entry];

    for (const stmt of statements) {
      const { enterNodes, exitNodes } = this.buildStatement(stmt, current);
      current = exitNodes;
    }

    return { lastId: current.length ? current[current.length - 1] : entry };
  }

  private buildStatement(
    stmt: AstNode,
    inputs: string[]
  ): { enterNodes: string[]; exitNodes: string[] } {
    const type = stmt.type;
    const line = nodeLine(stmt);
    let exitBranches: string[] = [...inputs];

    switch (type) {
      case 'IfStatement': {
        const condId = this.addNode('CONDITION', `if ${this.conditionText(stmt)}`, line);
        this.linkAll(inputs, condId);
        const trueBody = stmt.trueBody as AstNode | undefined;
        const falseBody = stmt.falseBody as AstNode | undefined;
        const tails: string[] = [];

        if (trueBody) {
          const merged = { lastId: this.appendFrom(condId, trueBody) };
          tails.push(merged.lastId);
        } else {
          tails.push(condId);
        }

        if (falseBody) {
          const f = this.appendFrom(condId, falseBody);
          tails.push(f);
        } else {
          tails.push(condId);
        }
        exitBranches = Array.from(new Set(tails));
        break;
      }

      case 'WhileStatement':
      case 'DoWhileStatement': {
        const condId = this.addNode('CONDITION', `while ${this.conditionText(stmt)}`, line);
        this.linkAll(inputs, condId);
        const body = stmt.body as AstNode | undefined;
        let backTarget = condId;
        if (body) {
          const bodyEnd = this.appendFrom(condId, body);
          backTarget = bodyEnd; // back edge to condition
        }
        // Back edge: loop condition -> body end -> condition
        this.link(backTarget, condId);
        exitBranches = [condId];
        break;
      }

      case 'ForStatement': {
        const condId = this.addNode('CONDITION', `for-loop`, line);
        this.linkAll(inputs, condId);
        const body = stmt.body as AstNode | undefined;
        let loopEnd = backTarget(condId);
        if (body) {
          const be = this.appendFrom(condId, body);
          loopEnd = backTarget(be);
        }
        // Loop back edge modeled to the condition.
        this.link(loopEnd, condId);
        exitBranches = [condId];
        break;
      }

      case 'ReturnStatement': {
        const ret = this.addNode('RETURN', `return`, line);
        this.linkAll(inputs, ret);
        const exit = this.addNode('EXIT', `return → exit`, line);
        this.link(ret, exit);
        exitBranches = [exit];
        break;
      }

      case 'ExpressionStatement': {
        const expr = stmt.expression as AstNode | undefined;
        if (expr && expr.type === 'FunctionCall') {
          const callee = expr.expression as AstNode | undefined;
          const callInfo = memberCallInfo(callee);
          const isExternal =
            callInfo !== null &&
            ['call', 'delegatecall', 'transfer', 'send', 'staticcall'].includes(
              callInfo.memberName
            );
          const nodeType: CFGNodeType = isExternal ? 'CALL' : 'STATEMENT';
          const id = this.addNode(nodeType, this.expressionText(expr), line);
          this.linkAll(inputs, id);
          exitBranches = [id];
        } else {
          const id = this.addNode('STATEMENT', this.expressionText(expr || stmt), line);
          this.linkAll(inputs, id);
          exitBranches = [id];
        }
        break;
      }

      case 'VariableDeclarationStatement': {
        const id = this.addNode('STATEMENT', this.declarationText(stmt), line);
        this.linkAll(inputs, id);
        exitBranches = [id];
        break;
      }

      case 'Block': {
        const inner = this.buildBlock(stmt, inputs[0] || this.lastNodeId(), '', nodeLine(stmt), nodeEndLine(stmt));
        exitBranches = [inner.lastId];
        break;
      }

      case 'emit':
      case 'EmitStatement': {
        const id = this.addNode('STATEMENT', `emit ${this.expressionText(stmt)}`, line);
        this.linkAll(inputs, id);
        exitBranches = [id];
        break;
      }

      case 'BreakStatement':
      case 'ContinueStatement': {
        const id = this.addNode('STATEMENT', type, line);
        this.linkAll(inputs, id);
        exitBranches = [id];
        break;
      }

      case 'RevertStatement':
      case 'ThrowStatement': {
        const id = this.addNode('EXIT', `revert`, line);
        this.linkAll(inputs, id);
        exitBranches = [id];
        break;
      }

      default: {
        const id = this.addNode('STATEMENT', type, line);
        this.linkAll(inputs, id);
        exitBranches = [id];
      }
    }

    return { enterNodes: inputs, exitNodes: exitBranches };
  }

  private appendFrom(fromId: string, node: AstNode): string {
    if (node.type === 'Block') {
      const { lastId } = this.buildBlock(node, fromId, '', nodeLine(node), nodeEndLine(node));
      return lastId;
    }
    const { exitNodes } = this.buildStatement(node, [fromId]);
    return exitNodes[exitNodes.length - 1] || fromId;
  }

  private conditionText(node: AstNode): string {
    const cond = node.condition as AstNode | undefined;
    if (cond) return this.expressionText(cond).slice(0, 60);
    return '...';
  }

  private expressionText(expr: AstNode): string {
    if (!expr) return '';
    if (expr.type === 'Identifier') return (expr.name as string) || '';
    if (expr.type === 'MemberAccess') {
      const base = expr.expression as AstNode | undefined;
      return `${this.expressionText(base || ({} as AstNode))}.${expr.memberName}`;
    }
    if (expr.type === 'FunctionCall') {
      const callee = expr.expression as AstNode | undefined;
      return `${this.expressionText(callee || ({} as AstNode))}()`;
    }
    if (expr.type === 'BinaryOperation') {
      return `${this.expressionText((expr.left as AstNode) || ({} as AstNode))} ${expr.operator} ${this.expressionText((expr.right as AstNode) || ({} as AstNode))}`;
    }
    if (expr.type === 'Assignment') {
      return `${this.expressionText((expr.left as AstNode) || ({} as AstNode))} ${expr.operator} ${this.expressionText((expr.right as AstNode) || ({} as AstNode))}`;
    }
    if (expr.type === 'UnaryOperation') {
      return `${expr.operator}${this.expressionText((expr.subExpression as AstNode) || ({} as AstNode))}`;
    }
    if (expr.type === 'NumberLiteral') return `${expr.number}`;
    if (expr.type === 'BooleanLiteral') return `${expr.value}`;
    if (expr.type === 'StringLiteral') return `"${expr.value}"`;
    if (typeof (expr as { name?: unknown }).name === 'string') {
      const named = expr as unknown as { name: string };
      return named.name;
    }
    return expr.type || 'stmt';
  }

  private declarationText(stmt: AstNode): string {
    const rawVars = (stmt.variables as Array<AstNode | null> | undefined) ?? [];
    const vars = rawVars.filter((v): v is AstNode => v != null);
    if (vars.length) {
      const names = vars
        .map((v) => {
          const raw = v.name;
          return raw == null ? '?' : String(raw);
        })
        .join(', ');
      return `decl ${names}`;
    }
    return 'decl ...';
  }

  private addNode(type: CFGNodeType, label: string, line: number): string {
    const id = `n${this.counter++}`;
    const vulnHit = this.vulnerabilitiesForLine(type, label, line);
    this.nodes.push({
      id,
      label: String(label),
      type,
      lineNumber: line,
      children: [],
      parents: [],
      isVulnerable: vulnHit.length > 0,
      vulnerabilityTypes: vulnHit,
    });
    return id;
  }

  private vulnerabilitiesForLine(type: CFGNodeType, label: string, line: number): VulnerabilityType[] {
    if (type !== 'CALL' && type !== 'CONDITION' && type !== 'STATEMENT' && type !== 'ENTRY') {
      return [];
    }
    const types: VulnerabilityType[] = [];
    for (const v of this.vulns) {
      if (line >= v.lineStart && line <= v.lineEnd) {
        if (!types.includes(v.type)) types.push(v.type);
      }
    }
    // CALL nodes are vulnerable when they name a poisoned operation.
    if (type === 'CALL') {
      const lower = String(label).toLowerCase();
      if (/(call|transfer|send)/.test(lower)) {
        const forType = this.findVulnType(label, line);
        if (forType) types.push(forType);
      }
    }
    return types.length ? types : [];
  }

  private findVulnType(label: string, line: number): VulnerabilityType | null {
    for (const v of this.vulns) {
      if (line >= v.lineStart && line <= v.lineEnd) return v.type;
    }
    if (/(delegatecall)/i.test(label)) return 'DELEGATECALL';
    if (/(call|send|transfer)/i.test(label)) return 'REENTRANCY';
    return null;
  }

  private link(from: string, to: string): void {
    const fromNode = this.nodes.find((n) => n.id === from);
    const toNode = this.nodes.find((n) => n.id === to);
    if (!fromNode || !toNode) return;
    if (!fromNode.children.includes(to)) fromNode.children.push(to);
    if (!toNode.parents.includes(from)) toNode.parents.push(from);
  }

  private linkAll(from: string[], to: string): void {
    for (const f of from) this.link(f, to);
  }

  private lastNodeId(): string {
    return this.nodes.length ? this.nodes[this.nodes.length - 1].id : 'n0';
  }
}

function backTarget(condId: string): string {
  return condId;
}