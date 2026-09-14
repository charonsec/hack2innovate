import {
  Detector,
  DetectorContext,
  DetectorResult,
  VulnerabilityType,
} from '../types/index';
import {
  AstNode,
  buildId,
  cvssFor,
  findNodes,
  memberCallInfo,
  nodeLine,
  nodeEndLine,
  snippet,
  walkAst,
} from '../engine/detector-utils';
import { computeConfidence, buildAttackPath, evidenceSnippet } from '../engine/confidence';

/**
 * DETECTOR 4 — Unchecked low-level call return values (SWC-104)
 *
 * Finds `.call`, `.delegatecall`, `.send` invocations whose boolean return
 * value is not consumed by a require/assert/if check, and high-level
 * interface token transfers whose bool return is ignored.
 */
export class UncheckedCallsDetector implements Detector {
  name = 'unchecked-calls';

  detect(context: DetectorContext): DetectorResult[] {
    const results: DetectorResult[] = [];
    if (!context.ast) return results;

    const callNodes = findNodes(context.ast, 'FunctionCall');
    for (const call of callNodes) {
      const callInfo = memberCallInfo(call.expression);
      if (!callInfo) continue;

      const member = callInfo.memberName;
      const lowLevel = ['call', 'delegatecall', 'staticcall', 'send'].includes(member);
      const highLevelTransfer =
        ['transfer', 'transferFrom', 'safeTransfer', 'safeTransferFrom'].includes(member) &&
        this.isInterfaceCall(callInfo.base);

      if (!lowLevel && !highLevelTransfer) continue;

      const line = nodeLine(call);
      const checkLine = this.findStatementAncestor(call);
      const statementRange = this.statementRange(context, checkLine);
      const usedInRequire = this.isChecked(context, checkLine);
      const wrappedInTryCatch = this.isWrappedInTryCatch(context, line);

      if (usedInRequire) continue;

      const callCode = this.lineSnippet(context, line);

      const sev = member === 'delegatecall' ? 'CRITICAL' : 'HIGH';
      const type: VulnerabilityType =
        member === 'delegatecall'
          ? 'DELEGATECALL'
          : 'UNCHECKED_RETURN';

      // Confidence based on call type
      let baseConfidence: number;
      if (member === 'call' || member === 'delegatecall' || member === 'staticcall') {
        baseConfidence = 90;
      } else if (member === 'send') {
        baseConfidence = 85;
      } else {
        // transfer/transferFrom — only flag if vault/accounting inconsistency plausible
        baseConfidence = 55;
      }

      const confidence = computeConfidence(baseConfidence, {
        handledException: wrappedInTryCatch,
      });

      const evidence: string[] = [
        evidenceSnippet(context.sourceCode, line, line),
        `Return value of ${member}() is not consumed by require/assert/if`,
      ];
      if (wrappedInTryCatch) {
        evidence.push('Call is wrapped in try/catch — return may be intentionally ignored');
      }
      if (member === 'transfer') {
        evidence.push('High-level transfer reverts on failure in modern Solidity; low confidence unless vault inconsistency is plausible');
      }

      results.push({
        type,
        severity: sev,
        title:
          type === 'DELEGATECALL'
            ? 'Unchecked delegatecall() return value'
            : `Unchecked return value from ${member}()`,
        description:
          member === 'delegatecall'
            ? 'delegatecall() executes code in the context of the current contract. ' +
              'If the return value is not checked, a failed call silently treats ' +
              'the operation as successful — corrupting storage or burning funds. ' +
              'Only call into trusted, verified code.'
            : `The return value of ${member}() is discarded. In the case of ` +
              'failure the caller continues executing with corrupted assumptions — ' +
              'ETH/send calls report failure as a false boolean, and token transfer ' +
              'functions that revert still consume the call.',
        confidence,
        evidence,
        attackPath: member === 'delegatecall'
          ? buildAttackPath([
              {
                label: 'Attacker supplies malicious contract address',
                description: 'The delegatecall target address is user-controlled or mutable',
              },
              {
                label: 'Malicious code executes in caller storage context',
                description: 'delegatecall runs the target\'s bytecode against the caller\'s storage slots',
              },
              {
                label: 'Return value ignored',
                description: 'Failed delegatecall is not detected; contract continues with corrupted state',
              },
              {
                label: 'Attacker drains funds or takes ownership',
                description: 'Overwritten storage slots grant asset access or admin control',
              },
            ])
          : buildAttackPath([
              {
                label: 'External call fails silently',
                description: `${member}() returns false/reverts but the return value is not checked`,
              },
              {
                label: 'Contract continues with stale state',
                description: 'Execution assumes the call succeeded; balances/allowances are stale',
              },
              {
                label: 'Attacker exploits stale assumptions',
                description: 'Subsequent logic uses the corrupted state to release funds or permissions',
              },
            ]),
        lineStart: line,
        lineEnd: line + 1,
        columnStart: 0,
        columnEnd: 0,
        codeSnippet: statementRange,
        recommendation:
          member === 'delegatecall'
            ? 'Validate the callee against a whitelist, add a reentrancy guard, ' +
              'check the return value, and test the target on a fork before release.'
            : `Capture the result and enforce it: ` +
              '`(bool ok, ) = addr.call{value: x}(""); require(ok, "call failed");` ' +
              'or `bool ok = token.transfer(to, amount); require(ok, "transfer failed");`.',
        remediatedCode: this.fixedCall(context, line, member),
        references: [
          'https://swcregistry.io/docs/SWC-104',
          'https://docs.soliditylang.org/en/latest/types.html#members-of-addresses',
          'https://ethereum.org/en/developers/tutorials/secure-development-workflow/',
        ],
        swcId: 'SWC-104',
        cvssScore: cvssFor(sev),
      });
    }

    // Deduplicate same-line findings (multiple calls on one line).
    const dedup = new Map<number, DetectorResult>();
    for (const r of results) {
      const existing = dedup.get(r.lineStart);
      if (!existing || existing.severity === 'CRITICAL') {
        dedup.set(r.lineStart, r);
      }
    }

    return Array.from(dedup.values());
  }

  private isInterfaceCall(base: AstNode | null): boolean {
    if (!base) return false;
    if (base.type === 'Identifier') {
      const name = (base.name as string) || '';
      return !['msg', 'address', 'this'].includes(name);
    }
    return true;
  }

  /**
   * Walks up the AST to find the enclosing statement node for a given call.
   * Falls back to the call's own line if no statement ancestor is found in the
   * AST (e.g. when the call is at the top level of a block).
   */
  private findStatementAncestor(call: AstNode): number {
    // Walk parent pointers to find the nearest Statement-type ancestor.
    let current: AstNode | undefined = call as AstNode;
    while (current) {
      if (
        current.type === 'IfStatement' ||
        current.type === 'ExpressionStatement' ||
        current.type === 'ReturnStatement' ||
        current.type === 'Block' ||
        current.type === 'ForStatement' ||
        current.type === 'WhileStatement'
      ) {
        return nodeLine(current);
      }
      current = current._parent as AstNode | undefined;
    }
    // Fallback: the call's own line.
    return nodeLine(call);
  }

  private statementRange(context: DetectorContext, line: number): string {
    return snippet(context.lines, Math.max(1, line - 1), line + 1);
  }

  private lineSnippet(context: DetectorContext, line: number): string {
    return snippet(context.lines, Math.max(1, line - 1), line + 1);
  }

  /**
   * Detects whether the call is wrapped in a try/catch block, which means the
   * developer intentionally handles the exception.
   */
  private isWrappedInTryCatch(context: DetectorContext, line: number): boolean {
    // Look backwards from the call line for a try statement
    for (let i = Math.max(0, line - 5); i < Math.min(context.lines.length, line); i++) {
      const ln = context.lines[i] || '';
      if (/\btry\s*\b/.test(ln)) return true;
    }
    return false;
  }

  private isChecked(context: DetectorContext, line: number): boolean {
    // Scan enclosing block (up to 12 lines around) for require/assert/if that
    // references the success boolean or the same variable.
    const start = Math.max(1, line - 12);
    const end = Math.min(context.lines.length, line + 12);
    const windowText = context.lines.slice(start - 1, end).join('\n');
    const stripped = windowText.replace(/\/\/.*$/gm, '');
    return (
      /require\s*\(\s*(success|ok|sent|ret|result)\b/.test(stripped) ||
      /require\s*\(\s*[^)]*,\s*["']/.test(stripped) ||
      /if\s*\(\s*!(success|ok|sent|ret|result)\s*\)\s*revert/.test(stripped) ||
      /if\s*\(\s*!(success|ok|sent|ret|result)\s*\)\s*\{?\s*revert/.test(stripped) ||
      /!\s*(success|ok|sent|ret|result)\b/.test(stripped) ||
      /assert\s*\(\s*(success|ok|sent|ret|result)\b/.test(stripped)
    );
  }

  private fixedCall(context: DetectorContext, line: number, member: string): string {
    const raw = (context.lines[line - 1] || '').replace(/\r$/, '');
    const indent = /^(\s*)/.exec(raw)?.[1] || '    ';
    const trimmed = raw.trim();
    if (member === 'delegatecall') {
      return `${indent}(bool success, bytes memory ret) = ${trimmed};\n${indent}require(success, "delegatecall failed");`;
    }
    if (member === 'send' || member === 'call' || member === 'staticcall') {
      return `${indent}(bool success, bytes memory data) = ${trimmed.replace(/^\s*\(bool[^=]*=\s*/, '')};\n${indent}require(success, "call failed");`;
    }
    return `${indent}bool ok = ${trimmed.replace(/^[^=]*=\s*/, '')};\n${indent}require(ok, "transfer failed");`;
  }
}
