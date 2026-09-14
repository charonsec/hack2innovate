import {
  Detector,
  DetectorContext,
  DetectorResult,
  Severity,
  VulnerabilityType,
} from '../types/index';
import { computeConfidence, buildAttackPath, evidenceSnippet } from '../engine/confidence';
import {
  AstNode,
  buildId,
  cvssFor,
  findNodes,
  memberCallInfo,
  nodeLine,
  nodeEndLine,
  walkAst,
} from '../engine/detector-utils';

/**
 * DETECTOR 1 — Reentrancy (SWC-107)
 *
 * Pattern: [state read] -> [external call] -> [state write] in the same function.
 * Detected externally documented call members: .call(), .delegatecall(),
 * .transfer(), .send() as well as high-level interface calls where the return
 * value feeds a require/revert (indicating ETH/ERC transfer style calls).
 */

function resolveTargetName(node: AstNode | undefined): string {
  if (!node) return '';
  if (node.type === 'Identifier') return (node.name as string) || '';
  if (node.type === 'IndexAccess') {
    return resolveTargetName(node.base as AstNode);
  }
  if (node.type === 'MemberAccess') {
    const base = resolveTargetName(node.expression as AstNode);
    const member = (node.memberName as string) || '';
    return base ? `${base}.${member}` : member;
  }
  if (node.type === 'TupleExpression') {
    const comps = node.components as AstNode[];
    if (Array.isArray(comps) && comps.length > 0) {
      return resolveTargetName(comps[0]);
    }
  }
  return '';
}
export class ReentrancyDetector implements Detector {
  name = 'reentrancy';

  detect(context: DetectorContext): DetectorResult[] {
    const results: DetectorResult[] = [];
    if (!context.ast) return results;

    const fnNodes = findNodes(context.ast, 'FunctionDefinition');
    for (const fn of fnNodes) {
      const fnName = (fn.name as string) || 'constructor';
      const modifiers: string[] = Array.isArray(fn.modifiers)
        ? (fn.modifiers as AstNode[]).map((m) =>
            typeof m.name === 'object' && m.name !== null
              ? ((m.name as AstNode).name as string)
              : (m.name as string)
          )
        : [];

      if (modifiers.includes('nonReentrant')) continue;

      const body = fn.body as AstNode | undefined;
      if (!body) continue;

      // Collect ordered statements of interest.
      interface OrderedEvent {
        line: number;
        kind: 'EXT_CALL' | 'STATE_WRITE' | 'BALANCE_READ';
        targetState?: string;
      }
      const events: OrderedEvent[] = [];
      const deniedCalleeNames = new Set([
        'msg',
        'address',
        'bytes',
        'string',
        'require',
        'assert',
        'revert',
        '_msgSender',
      ]);

      walkAst(body, (n) => {
        if (n.type === 'FunctionCall') {
          const callee = n.expression as AstNode | undefined;
          const callInfo = memberCallInfo(callee);
          if (callInfo) {
            const member = callInfo.memberName;
            if (['call', 'delegatecall', 'staticcall', 'send', 'transfer'].includes(member)) {
              events.push({ line: nodeLine(n), kind: 'EXT_CALL' });
            }
            // High-level interface calls: IERC20(token).transfer(...)
            const base = callInfo.base;
            const baseName =
              base &&
              (base.type === 'Identifier')
                ? typeof base.name === 'string'
                  ? base.name
                  : ''
                : base && base.type === 'MemberAccess' && base.memberName === 'sender'
                  ? '_msgSender'
                  : '';
            if (
              !deniedCalleeNames.has(baseName) &&
              ['transfer', 'transferFrom', 'send', 'call', 'safeTransfer'].includes(member)
            ) {
              events.push({ line: nodeLine(n), kind: 'EXT_CALL' });
            }
          }
        }

        if (n.type === 'BinaryOperation') {
          const op = n.operator as string;
          if (['+=', '-=', '*=', '/='].includes(op)) {
            const left = n.left as AstNode | undefined;
            const target = resolveTargetName(left);
            if (target) {
              events.push({
                line: nodeLine(n),
                kind: 'STATE_WRITE',
                targetState: target,
              });
            }
          }
        }

        if (n.type === 'Assignment') {
          const left = n.left as AstNode | undefined;
          const target = resolveTargetName(left);
          if (target) {
            events.push({
              line: nodeLine(n),
              kind: 'STATE_WRITE',
              targetState: target,
            });
          }
        }

        if (n.type === 'MemberAccess' && (n.memberName as string) === 'balance') {
          const base = n.expression as AstNode | undefined;
          if (base && base.type === 'Identifier' && (base.name as string) !== 'msg') {
            events.push({ line: nodeLine(n), kind: 'BALANCE_READ' });
          }
        }
      });

      // Deduplicate ordered events by line+kind — the same external call can be
      // matched by both the low-level member branch and the high-level interface
      // branch, which would otherwise produce duplicate EXT_CALL entries.
      const seenEvents = new Set<string>();
      const uniqueEvents: OrderedEvent[] = [];
      for (const ev of events) {
        const key = `${ev.kind}:${ev.line}`;
        if (!seenEvents.has(key)) {
          seenEvents.add(key);
          uniqueEvents.push(ev);
        }
      }

      // CEI pattern check: find an EXT_CALL followed by a STATE_WRITE.
      let pendingCallLine = -1;
      let stateWriteAfter: OrderedEvent | null = null;
      for (const ev of uniqueEvents) {
        if (ev.kind === 'EXT_CALL') {
          pendingCallLine = ev.line;
        } else if (ev.kind === 'STATE_WRITE' && pendingCallLine !== -1) {
          if (ev.line > pendingCallLine) {
            stateWriteAfter = ev;
            break;
          }
        }
      }

      const hasGuard = context.usesReentrancyGuard;
      if (stateWriteAfter) {
        const startLine = nodeLine(fn);
        const endLine = nodeEndLine(fn);
        const codeSnippet = evidenceSnippet(context.sourceCode, startLine, endLine);
        const fixed = this.buildFixedCode(
          context,
          fnName,
          modifiers,
          startLine,
          endLine
        );

        const callSnippet = evidenceSnippet(
          context.sourceCode,
          pendingCallLine,
          pendingCallLine
        )
          .replace(/\s+/g, ' ')
          .slice(0, 80);

        const severity: Severity = hasGuard ? 'HIGH' : 'CRITICAL';
        const baseConfidence = hasGuard ? 60 : 90;

        const evidence: string[] = [
          `External call ${callSnippet} at line ${pendingCallLine} precedes state write at line ${stateWriteAfter.line}`,
          `Function ${fnName} is externally callable`,
        ];
        if (hasGuard) {
          evidence.push(
            `ReentrancyGuard is imported but the nonReentrant modifier is not applied to function ${fnName}`
          );
        } else {
          evidence.push('No ReentrancyGuard imported — contract has no reentrancy protection');
        }

        const attackPath = buildAttackPath([
          {
            label: 'Attacker calls function',
            description: `Externally callable function '${fnName}' at line ${startLine}`,
          },
          {
            label: 'Balance checked',
            description: 'Pre-condition / balance requirement passes',
          },
          {
            label: 'External call to attacker',
            description: `${callSnippet} — control transferred to attacker`,
          },
          {
            label: 'Attacker re-enters',
            description: `fallback() or receive() calls ${fnName}() again before state is updated at line ${stateWriteAfter.line}`,
          },
          {
            label: 'Balance reused',
            description: `State variable '${stateWriteAfter.targetState || 'storage'}' not yet updated → double execution`,
          },
          {
            label: 'Funds drained',
            description: 'Recursive re-entry drains contract state before it is committed',
          },
        ]);

        results.push({
          type: 'REENTRANCY' as VulnerabilityType,
          severity,
          title: `Reentrancy Attack in ${fnName}()`,
          description:
            'External call(s) are executed before internal state is updated. ' +
            'This violates the Checks-Effects-Interactions (CEI) pattern. An attacker ' +
            'can re-enter the same function recursively through a malicious fallback ' +
            'and drain the contract because balances are only subtracted after the call.',
          lineStart: pendingCallLine,
          lineEnd: endLine,
          columnStart: 0,
          columnEnd: 0,
          codeSnippet,
          recommendation:
            'Apply the Checks-Effects-Interactions pattern: update all state ' +
            'variables BEFORE making external calls. Additionally, add ' +
            'OpenZeppelin ReentrancyGuard and annotate the function with ' +
            'nonReentrant to block recursive re-entry.',
          remediatedCode: fixed,
          references: [
            'https://swcregistry.io/docs/SWC-107',
            'https://docs.soliditylang.org/en/latest/security-considerations.html#re-entrancy',
            'https://ethereum.org/en/developers/tutorials/secure-development-workflow/',
          ],
          swcId: 'SWC-107',
          cvssScore: cvssFor(severity),
          confidence: computeConfidence(baseConfidence, {
            lineMatchesEvidence: true,
            crossFunction: true,
            financialImpact: true,
          }),
          evidence,
          attackPath,
        });

        results.push({
          type: 'REENTRANCY',
          severity: hasGuard ? 'MEDIUM' : 'CRITICAL',
          title: 'Missing ReentrancyGuard on state-changing function',
          description:
            `${fnName}() performs an external interaction without a reentrancy ` +
            `guard, leaving the contract open to cross-function reentrancy attacks ` +
            `where a malicious contract re-enters alternate entry points.`,
          lineStart: startLine,
          lineEnd: endLine,
          columnStart: 0,
          columnEnd: 0,
          codeSnippet: evidenceSnippet(
            context.sourceCode,
            startLine,
            Math.min(startLine + 4, endLine)
          ),
          recommendation:
            'Import "@openzeppelin/contracts/security/ReentrancyGuard.sol", inherit ' +
            'ReentrancyGuard and add the nonReentrant modifier to every function that ' +
            'makes an external call.',
          remediatedCode: fixed,
          references: ['https://swcregistry.io/docs/SWC-107'],
          swcId: 'SWC-107',
          cvssScore: cvssFor(hasGuard ? 'MEDIUM' : 'CRITICAL'),
          confidence: computeConfidence(hasGuard ? 70 : 80, {
            lineMatchesEvidence: true,
          }),
          evidence: hasGuard
            ? [
                `ReentrancyGuard is imported but nonReentrant modifier not applied to function ${fnName}`,
                `Function ${fnName} performs external calls without guard protection`,
              ]
            : [
                'No ReentrancyGuard imported in contract',
                `Function ${fnName} performs external calls without any reentrancy protection`,
              ],
          attackPath,
        });
      }
    }

    return results;
  }

  private buildFixedCode(
    context: DetectorContext,
    fnName: string,
    modifiers: string[],
    startLine: number,
    endLine: number
  ): string {
    const lines = context.lines.slice(startLine - 1, endLine);
    const contractName = this.contractNameOf(context) || 'AuditedContract';

    const header: string[] = [
      'import "@openzeppelin/contracts/security/ReentrancyGuard.sol";',
      '',
      `contract ${contractName} is ReentrancyGuard {`,
    ];

    const out = lines.map((raw) => `    ${raw.replace(/\r$/, '')}`);
    const fixedBody = out.join('\n');

    // Apply the modifier to the vulnerable function signature.
    const sigRegex = /(\s*function\s+\w+\s*\([^)]*\))(\s*(?:public|external|internal|private))?/;
    const withGuard = fixedBody.replace(
      sigRegex,
      (_m, sig: string, vis: string) =>
        `${sig}${vis || ' public'} nonReentrant`
    );

    return [...header, '', withGuard, '}'].join('\n');
  }

  private contractNameOf(context: DetectorContext): string {
    const m = context.sourceCode.match(/contract\s+(\w+)/);
    return m ? m[1] : '';
  }
}