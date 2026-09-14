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

      const checkLine = this.findStatementAncestor(call);
      const statementRange = this.statementRange(context, checkLine);
      const usedInRequire = this.isChecked(context, checkLine);

      if (usedInRequire) continue;

      const line = nodeLine(call);
      const callCode = this.lineSnippet(context, line);

      const sev = member === 'delegatecall' ? 'CRITICAL' : 'HIGH';
      const type: VulnerabilityType =
        member === 'delegatecall'
          ? 'DELEGATECALL'
          : 'UNCHECKED_RETURN';

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

  private findStatementAncestor(call: AstNode): number {
    return nodeLine(call);
  }

  private statementRange(context: DetectorContext, line: number): string {
    return snippet(context.lines, Math.max(1, line - 1), line + 1);
  }

  private lineSnippet(context: DetectorContext, line: number): string {
    return snippet(context.lines, Math.max(1, line - 1), line + 1);
  }

  private isChecked(context: DetectorContext, line: number): boolean {
    // Scan enclosing block (up to 12 lines around) for require/assert/if that
    // references the success boolean or the same variable.
    const start = Math.max(1, line - 12);
    const end = Math.min(context.lines.length, line + 12);
    const windowText = context.lines.slice(start - 1, end).join('\n');
    const stripped = windowText.replace(/\/\/.*$/gm, '');
    return (
      /require\s*\(\s*(success|ok|sent|ret)/.test(stripped) ||
      /require\s*\(\s*[^)]*,\s*["']/.test(stripped) ||
      /if\s*\(\s*!(success|ok|sent|ret)\s*\)\s*revert/.test(stripped) ||
      /assert\s*\(\s*(success|ok|sent|ret)/.test(stripped)
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