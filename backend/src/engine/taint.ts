import { DetectorContext } from '../types/index';
import {
  AstNode,
  findNodes,
  nodeLine,
  walkAst,
  isAstNode,
} from './detector-utils';

// ─── Types ───────────────────────────────────────────────────────────────────

export type TaintSource =
  | 'msg.sender'
  | 'msg.value'
  | 'tx.origin'
  | 'block.timestamp'
  | 'block.number'
  | 'external_calldata'
  | 'external_call_return'
  | 'oracle'
  | 'amm_spot';

export interface TaintNode {
  id: string;
  variable?: string;
  source: TaintSource;
  line: number;
  confidence: 'high' | 'medium' | 'low';
  expression: string;
  originId?: string;
}

export interface TaintEdge {
  from: string;
  to: string;
  sink: string;
  line: number;
}

export interface TaintAnalysis {
  sources: TaintNode[];
  taintedVariables: Map<string, TaintNode[]>;
  edges: TaintEdge[];
  sinks: { sink: string; line: number; expression: string }[];
  summary: string[];
}

// ─── Source keywords ─────────────────────────────────────────────────────────

const SOURCE_KEYWORDS: Record<string, TaintSource> = {
  'msg.sender': 'msg.sender',
  'msg.value': 'msg.value',
  'tx.origin': 'tx.origin',
  'block.timestamp': 'block.timestamp',
  'block.number': 'block.number',
};

const ORACLE_PATTERNS = ['latestRoundData', 'getRoundData', 'latestAnswer', 'getAnswer', 'getPrice', 'peek', 'consult'];
const AMM_PATTERNS = ['getReserves', 'quote', 'getAmountOut', 'getAmountIn', 'swap', 'getPrice', 'price'];
const EXTERNAL_CALL_RETURN_PATTERNS = ['balanceOf', 'totalSupply', 'allowance'];

const ASSIGNMENT_OPS = new Set(['=', '+=', '-=', '*=', '/=', '**=']);
const ARITHMETIC_OPS = new Set(['+', '-', '*', '/', '**', '%']);

// ─── Helpers ─────────────────────────────────────────────────────────────────

function exprSnippet(node: AstNode, lines: string[]): string {
  const line = nodeLine(node);
  if (line > 0 && line <= lines.length) {
    return lines[line - 1].trim();
  }
  return node.type;
}

function isStateVariable(name: string, stateVars: { name: string }[]): boolean {
  return stateVars.some((sv) => sv.name === name);
}

/** Collect all Identifier names referenced inside a node. */
function collectIdentifiers(node: AstNode): string[] {
  const names: string[] = [];
  walkAst(node, (n) => {
    if (n.type === 'Identifier' && typeof n.name === 'string') {
      names.push(n.name);
    }
  });
  return names;
}

/**
 * Determine whether a node is an assignment-like statement.
 * Solidity parser represents `x = y`, `x += y` etc. as:
 *   - Assignment node (for `=`)
 *   - BinaryOperation node with op `+=`, `-=`, `*=`, `/=`, `**=`
 *     inside an ExpressionStatement
 *
 * Returns the "assignment node" (the BinaryOperation or Assignment) if it is one.
 */
function isAssignmentLike(node: AstNode): { target: AstNode; source: AstNode; op: string; line: number } | null {
  // Plain Assignment
  if (node.type === 'Assignment' && ASSIGNMENT_OPS.has(node.operator as string)) {
    if (isAstNode(node.left) && isAstNode(node.right)) {
      return {
        target: node.left as AstNode,
        source: node.right as AstNode,
        op: node.operator as string,
        line: nodeLine(node),
      };
    }
  }
  // BinaryOperation with assignment operator (+=, -=, etc.)
  if (node.type === 'BinaryOperation' && ASSIGNMENT_OPS.has(node.operator as string)) {
    if (isAstNode(node.left) && isAstNode(node.right)) {
      return {
        target: node.left as AstNode,
        source: node.right as AstNode,
        op: node.operator as string,
        line: nodeLine(node),
      };
    }
  }
  return null;
}

/** Resolve the left-hand side target name. */
function resolveTargetName(target: AstNode): string | null {
  if (target.type === 'VariableDeclaration' && typeof target.name === 'string') {
    return target.name;
  }
  if (target.type === 'Identifier' && typeof target.name === 'string') {
    return target.name;
  }
  if (target.type === 'IndexAccess' && isAstNode(target.base)) {
    return resolveTargetName(target.base as AstNode);
  }
  if (target.type === 'MemberAccess' && isAstNode(target.expression)) {
    return resolveTargetName(target.expression as AstNode);
  }
  return null;
}

/**
 * Walk a subtree with the option to skip source keywords that appear under an
 * IndexAccess *index* position. E.g. `balances[msg.sender]` — the value comes
 * from the mapping, not from `msg.sender`, so treat index keywords as non-sources.
 */
function walkSkippingIndexKeys(node: AstNode, visitor: (n: AstNode) => void): void {
  const visit = (n: AstNode): void => {
    visitor(n);
    if (n.type === 'IndexAccess') {
      // Descend into base only — skip the index expression.
      if (isAstNode(n.base)) visit(n.base as AstNode);
      return;
    }
    for (const key of Object.keys(n)) {
      if (['loc', 'range', 'tokens', 'comments', 'parent'].includes(key)) continue;
      const value = n[key];
      if (Array.isArray(value)) {
        for (const item of value) {
          if (isAstNode(item)) visit(item);
        }
      } else if (isAstNode(value)) {
        visit(value);
      }
    }
  };
  visit(node);
}

/** Detect whether an expression subtree contains a taint source keyword
 *  (ignoring source keywords used purely as mapping/slot index keys). */
function detectSourceInExpression(node: AstNode): TaintSource | null {
  let found: TaintSource | null = null;
  walkSkippingIndexKeys(node, (n) => {
    if (found) return;
    if (n.type === 'MemberAccess') {
      const obj = isAstNode(n.expression) ? (n.expression as AstNode) : null;
      const member = n.memberName as string;
      if (obj && obj.type === 'Identifier') {
        const key = `${obj.name}.${member}`;
        if (SOURCE_KEYWORDS[key]) {
          found = SOURCE_KEYWORDS[key];
        }
      }
    }
  });
  return found;
}

/** Check if a FunctionCall node calls an oracle/amm/external-return pattern. */
function detectExternalCallSource(callNode: AstNode): { kind: TaintSource; label: string } | null {
  if (!isAstNode(callNode.expression)) return null;
  const expr = callNode.expression as AstNode;
  let memberName = '';
  if (expr.type === 'MemberAccess') {
    memberName = (expr.memberName as string) || '';
  }
  if (ORACLE_PATTERNS.includes(memberName)) {
    return { kind: 'oracle', label: memberName };
  }
  if (AMM_PATTERNS.includes(memberName)) {
    return { kind: 'amm_spot', label: memberName };
  }
  if (EXTERNAL_CALL_RETURN_PATTERNS.includes(memberName)) {
    return { kind: 'external_call_return', label: memberName };
  }
  return null;
}

/** Unwrap an expression — if it's a NameValueExpression, return its inner expression. */
function unwrapNameValue(node: AstNode): AstNode {
  if (node.type === 'NameValueExpression' && isAstNode(node.expression)) {
    return node.expression as AstNode;
  }
  return node;
}

/** Resolve the callee member/identifier name of a FunctionCall node. */
function calleeName(callNode: AstNode): string {
  if (!isAstNode(callNode.expression)) return '';
  let expr = callNode.expression as AstNode;
  if (expr.type === 'NameValueExpression' && isAstNode(expr.expression)) {
    expr = expr.expression as AstNode;
  }
  if (expr.type === 'MemberAccess') {
    return (expr.memberName as string) || '';
  }
  if (expr.type === 'Identifier') {
    return (expr.name as string) || '';
  }
  return '';
}

// ─── Core Analysis ───────────────────────────────────────────────────────────

export function buildTaintAnalysis(
  _sourceCode: string,
  ast: unknown,
  context: DetectorContext
): TaintAnalysis {
  const lines = context.lines;
  const stateVars = context.stateVariables;
  const functions = context.functions;

  const sources: TaintNode[] = [];
  const taintedVariables = new Map<string, TaintNode[]>();
  const edges: TaintEdge[] = [];
  const sinks: { sink: string; line: number; expression: string }[] = [];
  const summary: string[] = [];

  let sourceCounter = 0;
  const makeId = () => `src_${++sourceCounter}`;

  // ── Phase 1: Identify taint sources per function ─────────────────────────

  const funcNodes = findNodes(ast, 'FunctionDefinition');

  for (const fnNode of funcNodes) {
    const fnName = (fnNode.name as string) || 'constructor';
    const fnLine = nodeLine(fnNode);
    const fnVisibility = (fnNode.visibility as string) || 'internal';
    const isExternalFn = fnVisibility === 'external' || fnVisibility === 'public';

    // 1a: Function parameters of external/public functions → external_calldata
    if (isExternalFn) {
      // Parser may return parameters as direct array or wrapped in a ParameterList node.
      let paramArray: AstNode[] | null = null;
      const raw = fnNode.parameters;
      if (Array.isArray(raw)) {
        paramArray = raw as AstNode[];
      } else if (isAstNode(raw)) {
        const wrapper = raw as AstNode;
        if (Array.isArray(wrapper.parameters)) {
          paramArray = wrapper.parameters as AstNode[];
        }
      }
      if (paramArray) {
        for (const param of paramArray) {
          const paramName = (param.name as string) || '';
          if (paramName) {
            const id = makeId();
            const src: TaintNode = {
              id,
              variable: paramName,
              source: 'external_calldata',
              line: fnLine,
              confidence: 'high',
              expression: `parameter ${paramName} of ${fnName}()`,
            };
            sources.push(src);
            const existing = taintedVariables.get(paramName) || [];
            existing.push(src);
            taintedVariables.set(paramName, existing);
          }
        }
      }
    }

    // 1b: Walk function body for source assignments
    const body = isAstNode(fnNode.body) ? (fnNode.body as AstNode) : null;
    if (!body) continue;

    // Collect all assignment-like statements:
    //   - VariableDeclarationStatement with initialValue
    //   - ExpressionStatement containing BinaryOperation with assignment op
    //   - ExpressionStatement containing Assignment
    const exprStmts = findNodes(body, 'ExpressionStatement');
    const varDecls = findNodes(body, 'VariableDeclarationStatement');

    for (const stmt of [...varDecls, ...exprStmts]) {
      const line = nodeLine(stmt);

      let assignmentNode: AstNode | null = null;
      let targetNode: AstNode | null = null;
      let sourceNode: AstNode | null = null;

      if (stmt.type === 'VariableDeclarationStatement') {
        // Extract target name and initialValue
        const declarations = stmt.variables as AstNode[] | undefined;
        if (Array.isArray(declarations) && declarations.length > 0) {
          targetNode = declarations[0];
        }
        if (isAstNode(stmt.initialValue)) {
          sourceNode = stmt.initialValue as AstNode;
        }
      } else if (stmt.type === 'ExpressionStatement' && isAstNode(stmt.expression)) {
        const expr = stmt.expression as AstNode;
        const assignment = isAssignmentLike(expr);
        if (assignment) {
          targetNode = assignment.target;
          sourceNode = assignment.source;
          assignmentNode = expr;
        }
      }

      if (!targetNode || !sourceNode) continue;

      const targetName = resolveTargetName(targetNode);
      if (!targetName) continue;

      // Check if the source expression contains a taint source keyword.
      // When the RHS is a call return (e.g. `(bool ok,) = addr.call(...)` or
      // `x = pool.getReserves()`), the callee is NOT data flowing into the
      // target — only the call return category applies (handled below). So skip
      // keyword detection for FunctionCall initialValues.
      const sourceKw =
        sourceNode.type === 'FunctionCall'
          ? null
          : detectSourceInExpression(sourceNode);
      if (sourceKw) {
        const id = makeId();
        const src: TaintNode = {
          id,
          variable: targetName,
          source: sourceKw,
          line,
          confidence: 'high',
          expression: exprSnippet(stmt, lines),
        };
        sources.push(src);
        const existing = taintedVariables.get(targetName) || [];
        // Avoid duplicate source entries for same variable+source+line
        const alreadyTracked = existing.some(
          (e) => e.source === sourceKw && e.line === line
        );
        if (!alreadyTracked) {
          existing.push(src);
          taintedVariables.set(targetName, existing);
        }
      }

      // Check for external call return sources (oracle, amm, balanceOf)
      if (sourceNode.type === 'FunctionCall') {
        const extSrc = detectExternalCallSource(sourceNode);
        if (extSrc) {
          const id = makeId();
          const src: TaintNode = {
            id,
            variable: targetName,
            source: extSrc.kind,
            line,
            confidence: 'medium',
            expression: `${extSrc.label}() at ${exprSnippet(stmt, lines)}`,
          };
          sources.push(src);
          const existing = taintedVariables.get(targetName) || [];
          const alreadyTracked = existing.some(
            (e) => e.source === extSrc.kind && e.line === line
          );
          if (!alreadyTracked) {
            existing.push(src);
            taintedVariables.set(targetName, existing);
          }
        }
      }
    }
  }

  // ── Phase 2: Propagation ──────────────────────────────────────────────────
  // If RHS of an assignment references tainted variables, LHS becomes tainted.
  // `propagatedPairs` dedupes on (target, originSourceId) so each SOURCE taint
  // is propagated to a given target exactly once. Using origin id (not the
  // expanding node id) prevents exponential growth on self-referential
  // assignments like `totalSupply = totalSupply + amount` — without it, each
  // fixed-point iteration re-propagates the target's own new taint nodes to
  // itself, doubling the taint list every round.
  const propagatedPairs = new Set<string>();
  let changed = true;
  let iterations = 0;
  const MAX_ITERATIONS = 6;

  while (changed && iterations < MAX_ITERATIONS) {
    changed = false;
    iterations++;

    for (const fnNode of funcNodes) {
      const body = isAstNode(fnNode.body) ? (fnNode.body as AstNode) : null;
      if (!body) continue;

      const exprStmts = findNodes(body, 'ExpressionStatement');
      const varDecls = findNodes(body, 'VariableDeclarationStatement');

      for (const stmt of [...varDecls, ...exprStmts]) {
        let targetNode: AstNode | null = null;
        let sourceNode: AstNode | null = null;

        if (stmt.type === 'VariableDeclarationStatement') {
          const declarations = stmt.variables as AstNode[] | undefined;
          if (Array.isArray(declarations) && declarations.length > 0) {
            targetNode = declarations[0];
          }
          if (isAstNode(stmt.initialValue)) {
            sourceNode = stmt.initialValue as AstNode;
          }
        } else if (stmt.type === 'ExpressionStatement' && isAstNode(stmt.expression)) {
          const expr = stmt.expression as AstNode;
          const assignment = isAssignmentLike(expr);
          if (assignment) {
            targetNode = assignment.target;
            sourceNode = assignment.source;
          }
        }

        if (!targetNode || !sourceNode) continue;
        const targetName = resolveTargetName(targetNode);
        if (!targetName) continue;

        // State-variable self-references: `stored = stored + x`. Propagate the
        // RHS taint origin ids into the target only once; skip the taint that
        // merely echoes the target's own name back at itself (handled by the
        // origin-id dedup below).
        const rhsIdents = collectIdentifiers(sourceNode);
        const taintedRhs = rhsIdents.filter((id) => taintedVariables.has(id) && id !== targetName);

        if (taintedRhs.length > 0) {
          const existing = taintedVariables.get(targetName) || [];
          for (const taintedIdent of taintedRhs) {
            const taintNodes = taintedVariables.get(taintedIdent) || [];
            for (const tn of taintNodes) {
              const originId = tn.originId ?? tn.id;
              const pairKey = `${targetName}|${originId}`;
              if (propagatedPairs.has(pairKey)) continue;
              propagatedPairs.add(pairKey);

              const id = makeId();
              const propagated: TaintNode = {
                id,
                variable: targetName,
                source: tn.source,
                line: nodeLine(stmt),
                confidence: 'medium',
                expression: `${tn.variable || tn.source} -> ${targetName}`,
                originId,
              };
              existing.push(propagated);
              edges.push({
                from: tn.id,
                to: propagated.id,
                sink: 'propagation',
                line: nodeLine(stmt),
              });
              changed = true;
            }
          }
          if (existing.length > 0) {
            taintedVariables.set(targetName, existing);
          }
        }

        // Even with no *other* tainted RHS identifiers, a direct source keyword
        // assignment (e.g. `x = msg.sender`) must taint once — already handled in
        // Phase 1. Self-only references add nothing.
      }
    }
  }

  // ── Phase 3: Detect sinks ─────────────────────────────────────────────────

  for (const fnNode of funcNodes) {
    const body = isAstNode(fnNode.body) ? (fnNode.body as AstNode) : null;
    if (!body) continue;

    const exprStmts = findNodes(body, 'ExpressionStatement');
    const varDecls = findNodes(body, 'VariableDeclarationStatement');

    for (const stmt of [...varDecls, ...exprStmts]) {
      const line = nodeLine(stmt);

      // ── 3a: State writes ─────────────────────────────────────────────────
      let targetNode: AstNode | null = null;
      let sourceNode: AstNode | null = null;

      if (stmt.type === 'VariableDeclarationStatement') {
        const declarations = stmt.variables as AstNode[] | undefined;
        if (Array.isArray(declarations) && declarations.length > 0) {
          targetNode = declarations[0];
        }
        if (isAstNode(stmt.initialValue)) {
          sourceNode = stmt.initialValue as AstNode;
        }
      } else if (stmt.type === 'ExpressionStatement' && isAstNode(stmt.expression)) {
        const expr = stmt.expression as AstNode;
        const assignment = isAssignmentLike(expr);
        if (assignment) {
          targetNode = assignment.target;
          sourceNode = assignment.source;
        }
      }

      if (targetNode) {
        const targetName = resolveTargetName(targetNode);
        if (targetName && isStateVariable(targetName, stateVars) && sourceNode) {
          // Tainted identifiers flowing into this assignment
          const allIdents = collectIdentifiers(sourceNode);
          const taintedFlow = allIdents.filter((id) => taintedVariables.has(id));
          for (const taintedIdent of taintedFlow) {
            const taintNodes = taintedVariables.get(taintedIdent) || [];
            for (const tn of taintNodes) {
              const sinkId = `sink_${++sourceCounter}`;
              edges.push({ from: tn.id, to: sinkId, sink: 'state_write', line });
              sinks.push({ sink: 'state_write', line, expression: exprSnippet(stmt, lines) });
              summary.push(
                `${tn.source} (via ${taintedIdent}) flows into ${targetName} (state_write) at line ${line}`
              );
            }
          }
          // Direct inline source keyword flowing into the state write
          if (taintedFlow.length === 0) {
            const directSource = detectSourceInExpression(sourceNode);
            if (directSource) {
              const inlineId = makeId();
              const inlineSrc: TaintNode = {
                id: inlineId,
                variable: directSource,
                source: directSource,
                line,
                confidence: 'high',
                expression: `${directSource} (inline) at ${exprSnippet(stmt, lines)}`,
              };
              sources.push(inlineSrc);
              const sinkId = `sink_${++sourceCounter}`;
              edges.push({ from: inlineId, to: sinkId, sink: 'state_write', line });
              sinks.push({ sink: 'state_write', line, expression: exprSnippet(stmt, lines) });
              summary.push(
                `${directSource} flows into ${targetName} (state_write) at line ${line}`
              );
            }
          }
        }
      }

      // ── 3b / 3d / 3e: Walk the statement for arithmetic, transfers,
      //     require/if access control, and price-related calls ──────────────
      const stmtExpr =
        stmt.type === 'ExpressionStatement'
          ? isAstNode(stmt.expression)
            ? (stmt.expression as AstNode)
            : null
          : stmt.type === 'VariableDeclarationStatement' && isAstNode(stmt.initialValue)
            ? (stmt.initialValue as AstNode)
            : null;

      if (!stmtExpr) continue;

      walkAst(stmtExpr, (n) => {
        // 3b: Arithmetic BinaryOperation (not assignment ops).
        //     If the op is */÷ and the tainted value is price-like (named
        //     `price`/`spot`/`rate` or sourced from an oracle/AMM), classify
        //     the sink as `price_calc` rather than plain `arithmetic`.
        if (
          n.type === 'BinaryOperation' &&
          ARITHMETIC_OPS.has(n.operator as string)
        ) {
          const operator = n.operator as string;
          const idents = collectIdentifiers(n);
          const taintedIdents = idents.filter((id) => taintedVariables.has(id));
          for (const taintedIdent of taintedIdents) {
            const taintNodes = taintedVariables.get(taintedIdent) || [];
            for (const tn of taintNodes) {
              const lowerVar = taintedIdent.toLowerCase();
              const isPriceSymbol =
                lowerVar.includes('price') ||
                lowerVar.includes('spot') ||
                lowerVar.includes('rate') ||
                lowerVar.includes('collateral') ||
                lowerVar.includes('_price');
              const isPriceSourced =
                tn.source === 'oracle' || tn.source === 'amm_spot';
              const sinkKind =
                (operator === '*' || operator === '/') &&
                (isPriceSymbol || isPriceSourced)
                  ? 'price_calc'
                  : 'arithmetic';
              const sinkId = `sink_${++sourceCounter}`;
              edges.push({ from: tn.id, to: sinkId, sink: sinkKind, line });
              sinks.push({ sink: sinkKind, line, expression: exprSnippet(stmt, lines) });
              summary.push(
                `${tn.source} (via ${taintedIdent}) used in ${sinkKind} at line ${line}`
              );
            }
          }
        }

        // 3c: require/assert access control with msg.sender / tx.origin
        if (
          n.type === 'FunctionCall' &&
          isAstNode(n.expression) &&
          (n.expression as AstNode).type === 'Identifier'
        ) {
          const name = ((n.expression as AstNode).name as string) || '';
          if (name === 'require' || name === 'assert') {
            const idents = collectIdentifiers(n);
            const hasSenderOrigin = idents.some(
              (id) => id === 'msg' || id === 'tx'
            );
            if (hasSenderOrigin) {
              const taintedInReq = idents.filter((id) => taintedVariables.has(id));
              for (const taintedIdent of taintedInReq) {
                const taintNodes = taintedVariables.get(taintedIdent) || [];
                for (const tn of taintNodes) {
                  const sinkId = `sink_${++sourceCounter}`;
                  edges.push({ from: tn.id, to: sinkId, sink: 'access_control', line });
                  sinks.push({ sink: 'access_control', line, expression: exprSnippet(n, lines) });
                  summary.push(
                    `${tn.source} (via ${taintedIdent}) used in access control check at line ${line}`
                  );
                }
              }
              // Direct msg.sender / tx.origin used in the require condition
              // (always flag this separately — it is the authentication basis)
              const directSource = detectSourceInExpression(n);
              if (directSource) {
                const inlineId = makeId();
                const inlineSrc: TaintNode = {
                  id: inlineId,
                  variable: directSource,
                  source: directSource,
                  line,
                  confidence: 'high',
                  expression: `${directSource} (inline) at ${exprSnippet(n, lines)}`,
                };
                sources.push(inlineSrc);
                const sinkId = `sink_${++sourceCounter}`;
                edges.push({ from: inlineId, to: sinkId, sink: 'access_control', line });
                sinks.push({ sink: 'access_control', line, expression: exprSnippet(n, lines) });
                summary.push(
                  `${directSource} used in access control check at line ${line}`
                );
              }
            }
          }
        }

        // 3d: Transfer amounts — .call{value: x}, .transfer(x), .send(x)
        if (n.type === 'FunctionCall' && isAstNode(n.expression)) {
          const calleeExpr = unwrapNameValue(n.expression as AstNode);
          const member = calleeExpr.type === 'MemberAccess'
            ? ((calleeExpr.memberName as string) || '')
            : '';
          if (['call', 'transfer', 'send'].includes(member)) {
            // Collect all argument expressions: positional args (n.arguments)
            // plus NameValueList values from a NameValueExpression callee
            // (e.g. msg.sender.call{value: bal}("")).
            const argExprs: AstNode[] = [];

            const collectFromList = (list: unknown) => {
              if (!Array.isArray(list)) return;
              for (const arg of list) {
                if (!isAstNode(arg)) continue;
                if (arg.type === 'NameValueList') {
                  const nvArgs = (arg.arguments as AstNode[]) || [];
                  const nvNames = (arg.names as string[]) || [];
                  for (let i = 0; i < nvArgs.length; i++) {
                    const nvArg = nvArgs[i];
                    const nvName = nvNames[i] || '';
                    if (nvName === 'value' || nvName === 'gas') {
                      argExprs.push(nvArg);
                    }
                  }
                } else {
                  argExprs.push(arg);
                }
              }
            };

            collectFromList(n.arguments);

            // The NameValueExpression wraps {value: x} in its own `.arguments`
            // when the parser splits positional vs name-value args.
            const inner = n.expression as AstNode;
            if (inner.type === 'NameValueExpression' && isAstNode(inner.arguments)) {
              collectFromList([inner.arguments as AstNode]);
            }

            for (const argExpr of argExprs) {
              const idents = collectIdentifiers(argExpr);
              const taintedIdents = idents.filter((id) => taintedVariables.has(id));
              for (const taintedIdent of taintedIdents) {
                const taintNodes = taintedVariables.get(taintedIdent) || [];
                for (const tn of taintNodes) {
                  const sinkId = `sink_${++sourceCounter}`;
                  edges.push({ from: tn.id, to: sinkId, sink: 'transfer_amount', line });
                  sinks.push({ sink: 'transfer_amount', line, expression: exprSnippet(n, lines) });
                  summary.push(
                    `${tn.source} (via ${taintedIdent}) used as transfer amount in .${member}() at line ${line}`
                  );
                }
              }
              if (taintedIdents.length === 0) {
                const directSource = detectSourceInExpression(argExpr);
                if (directSource) {
                  const inlineId = makeId();
                  const inlineSrc: TaintNode = {
                    id: inlineId,
                    variable: directSource,
                    source: directSource,
                    line,
                    confidence: 'high',
                    expression: `${directSource} (inline) at ${exprSnippet(n, lines)}`,
                  };
                  sources.push(inlineSrc);
                  const sinkId = `sink_${++sourceCounter}`;
                  edges.push({ from: inlineId, to: sinkId, sink: 'transfer_amount', line });
                  sinks.push({ sink: 'transfer_amount', line, expression: exprSnippet(n, lines) });
                  summary.push(
                    `${directSource} used as transfer amount in .${member}() at line ${line}`
                  );
                }
              }
            }
          }
        }

        // 3e: Price / collateral / liquidation — tainted values in price-like calls
        const pricePatterns = ['getamountout', 'quote', 'price', 'liquidat', 'collateral', 'oracle'];
        if (n.type === 'FunctionCall' && isAstNode(n.expression)) {
          const callee = calleeName(n);
          const lowerCallee = callee.toLowerCase();
          const isPriceLike = pricePatterns.some((p) => lowerCallee.includes(p));
          if (isPriceLike) {
            const sinkKind = lowerCallee.includes('liquidat')
              ? 'liquidation'
              : lowerCallee.includes('collateral')
                ? 'collateral'
                : 'price_calc';
            const args = (n.arguments as AstNode[]) || [];
            for (const arg of args) {
              if (arg.type === 'NameValueList') continue;
              const idents = collectIdentifiers(arg);
              const taintedIdents = idents.filter((id) => taintedVariables.has(id));
              for (const taintedIdent of taintedIdents) {
                const taintNodes = taintedVariables.get(taintedIdent) || [];
                for (const tn of taintNodes) {
                  const sinkId = `sink_${++sourceCounter}`;
                  edges.push({ from: tn.id, to: sinkId, sink: sinkKind, line });
                  sinks.push({ sink: sinkKind, line, expression: exprSnippet(n, lines) });
                  summary.push(
                    `${tn.source} (via ${taintedIdent}) used in ${sinkKind} call .${callee}() at line ${line}`
                  );
                }
              }
              if (taintedIdents.length === 0) {
                const directSource = detectSourceInExpression(arg);
                if (directSource) {
                  const inlineId = makeId();
                  const inlineSrc: TaintNode = {
                    id: inlineId,
                    variable: directSource,
                    source: directSource,
                    line,
                    confidence: 'high',
                    expression: `${directSource} (inline) at ${exprSnippet(n, lines)}`,
                  };
                  sources.push(inlineSrc);
                  const sinkId = `sink_${++sourceCounter}`;
                  edges.push({ from: inlineId, to: sinkId, sink: sinkKind, line });
                  sinks.push({ sink: sinkKind, line, expression: exprSnippet(n, lines) });
                  summary.push(
                    `${directSource} used in ${sinkKind} call .${callee}() at line ${line}`
                  );
                }
              }
            }
          }
        }
      });
    }
  }

  // ── Deduplicate edges ─────────────────────────────────────────────────────
  const seenEdges = new Set<string>();
  const uniqueEdges: TaintEdge[] = [];
  for (const e of edges) {
    const key = `${e.from}->${e.to}:${e.sink}:${e.line}`;
    if (!seenEdges.has(key)) {
      seenEdges.add(key);
      uniqueEdges.push(e);
    }
  }

  // ── Deduplicate sinks ─────────────────────────────────────────────────────
  const seenSinks = new Set<string>();
  const uniqueSinks = sinks.filter((s) => {
    const key = `${s.sink}:${s.line}`;
    if (seenSinks.has(key)) return false;
    seenSinks.add(key);
    return true;
  });

  return {
    sources,
    taintedVariables,
    edges: uniqueEdges,
    sinks: uniqueSinks,
    summary: [...new Set(summary)],
  };
}
