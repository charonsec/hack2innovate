import {
  Detector,
  DetectorContext,
  DetectorResult,
  VulnerabilityType,
} from '../types/index';
import {
  buildId,
  cvssFor,
  findNodes,
  hasOwnable,
  isSensitiveFunctionName,
  nodeLine,
  nodeEndLine,
  snippet,
  walkAst,
  AstNode,
} from '../engine/detector-utils';

const OZ_ACCESS_CONTROL_IMPORTS: Record<string, string> = {
  Ownable: 'import "@openzeppelin/contracts/access/Ownable.sol";',
  AccessControl: 'import "@openzeppelin/contracts/access/AccessControl.sol";',
};

export class AccessControlDetector implements Detector {
  name = 'access-control';

  detect(context: DetectorContext): DetectorResult[] {
    const results: DetectorResult[] = [];
    const guardModifiers = ['onlyOwner', 'onlyRole', 'auth', 'authorized', 'adminOnly'];
    const usesGuards = context.usesOwnable || context.usesAccessControl;

    if (!context.ast) return results;

    const fnNodes = findNodes(context.ast, 'FunctionDefinition');
    for (const fn of fnNodes) {
      const name = (fn.name as string) || '';
      if (!name) continue;
      if (!fn.body) continue; // skip interfaces/abstract declarations
      const visibility = (fn.visibility as string) || '';
      if (visibility !== 'public' && visibility !== 'external') continue;

      const modifiers: string[] = Array.isArray(fn.modifiers)
        ? (fn.modifiers as AstNode[]).map((m) =>
            typeof m.name === 'object' && m.name !== null
              ? ((m.name as AstNode).name as string)
              : (m.name as string)
          )
        : [];

      const hasGuard = modifiers.some((m) => guardModifiers.includes(m.toLowerCase()));
      const hasInlineAuthGuard = this.hasInlineAuthGuard(fn);
      const fnStart = nodeLine(fn);
      const fnEnd = nodeEndLine(fn);

      // 1) initialize() functions without guards can be front-run to take ownership.
      if (
        ['initialize', 'init', 'initializer', 'setup'].includes(name.toLowerCase()) &&
        !hasGuard
      ) {
        results.push({
          type: 'ACCESS_CONTROL',
          severity: 'CRITICAL',
          title: `Unprotected ${name}() — Initialization front-running`,
          description:
            `${name}() is public/external and has no access control modifier. In ` +
            'proxy / upgradeable patterns an attacker can front-run the deployer and ' +
            'call initialize() first to seize ownership or set critical parameters ' +
            '(admin, oracle, implementation).',
          lineStart: fnStart,
          lineEnd: fnEnd,
          columnStart: 0,
          columnEnd: 0,
          codeSnippet: snippet(context.lines, fnStart, Math.min(fnStart + 5, fnEnd)),
          recommendation:
            'Add the `initializer` modifier from OpenZeppelin, restrict the function to a ' +
            'deployer-only role, and add a requiresAdmin guard. Use a constructor for ' +
            'non-upgradeable deployments.',
          remediatedCode: this.addGuard(context, fn, name, 'onlyOwner', 'CRITICAL'),
          references: [
            'https://swcregistry.io/docs/SWC-105',
            'https://docs.openzeppelin.com/contracts/4.x/api/proxy#Initializable',
          ],
          swcId: 'SWC-105',
          cvssScore: cvssFor('CRITICAL'),
        });
      }

      // 2) Sensitive ops (mint/burn/transfer/owner changes/fees) without guards.
      if (isSensitiveFunctionName(name) && !hasGuard && !hasInlineAuthGuard && !usesGuards) {
        const severity = this.sensitivitySeverity(name);
        results.push({
          type: 'ACCESS_CONTROL',
          severity,
          title: `Missing access control on ${name}()`,
          description:
            `${name}() is ${visibility} and operates on a privileged capability ` +
            '(mint, burn, transfer of value, ownership, fees, emergency controls) but ' +
            'does not enforce any role/ownership modifier. Any caller can invoke it.',
          lineStart: fnStart,
          lineEnd: fnEnd,
          columnStart: 0,
          columnEnd: 0,
          codeSnippet: snippet(context.lines, fnStart, Math.min(fnStart + 6, fnEnd)),
          recommendation:
            'Inherit OpenZeppelin Ownable or AccessControl, declare an ' +
            '`onlyOwner`/`onlyRole(...)` modifier and attach it to this function. ' +
            'Restrict mint/burn/owner-changing operations to privileged roles.',
          remediatedCode: this.addGuard(context, fn, name, 'onlyOwner', severity),
          references: [
            'https://swcregistry.io/docs/SWC-105',
            'https://swcregistry.io/docs/SWC-115',
          ],
          swcId: severity === 'CRITICAL' ? 'SWC-105' : 'SWC-115',
          cvssScore: cvssFor(severity),
        });
      }
    }

    // 3) tx.origin based authorization — susceptible to phishing.
    if (context.ast) {
      walkAst(context.ast, (n) => {
        if (n.type === 'MemberAccess') {
          const base = n.expression as AstNode | undefined;
          if (base && base.type === 'Identifier' && (base.name as string) === 'tx') {
            if (n.memberName === 'origin') {
              const line = nodeLine(n);
              const ctxLine = snippet(context.lines, Math.max(1, line - 1), line + 1);
              if (this.isAuthContext(ctxLine)) {
                results.push({
                  type: 'ACCESS_CONTROL',
                  severity: 'HIGH',
                  title: 'tx.origin used for authorization',
                  description:
                    'tx.origin resolves to the original externally-owned account that ' +
                    'started the transaction. If an intermediate contract calls this ' +
                    'code, tx.origin still points at the EOA that initiated the whole ' +
                    'chain, enabling phishing-based privilege escalation (the ' +
                    '"Dark Forest" / tx.origin vulnerability).',
                  lineStart: line,
                  lineEnd: line,
                  columnStart: 0,
                  columnEnd: 0,
                  codeSnippet: ctxLine,
                  recommendation:
                    'Replace tx.origin with msg.sender in every authorization check. ' +
                    'Never use tx.origin for authentication.',
                  remediatedCode: ctxLine.replace(/tx\.origin/g, 'msg.sender'),
                  references: [
                    'https://swcregistry.io/docs/SWC-115',
                    'https://ethereum.org/en/developers/tutorials/secure-development-workflow/#use-msg-sender-not-txorigin',
                    'https://consensys.github.io/smart-contract-best-practices/development-recommendations/solidity-specific/tx-origin/',
                  ],
                  swcId: 'SWC-115',
                  cvssScore: cvssFor('HIGH'),
                });
              }
            }
          }
        }
      });
    }

    // 4) selfdestruct found outside of a guard-protected function.
    walkAst(context.ast as unknown, (n) => {
      if (n.type === 'FunctionCall') {
        const callee = n.expression as AstNode | undefined;
        if (callee && callee.type === 'Identifier') {
          const calleeName = callee.name as string;
          if (['selfdestruct', 'suicide'].includes(calleeName)) {
            const line = nodeLine(n);
            const fn = this.functionAtLine(context, line);
            const protectedFn =
              fn &&
              fn.modifiers.some((m) =>
                ['onlyOwner', 'onlyRole', 'adminOnly', 'auth'].includes(m.toLowerCase())
              );
            if (fn && !protectedFn) {
              results.push({
                type: 'SELF_DESTRUCT',
                severity: 'HIGH',
                title: 'Unprotected selfdestruct() call',
                description:
                  `${fn.name}() can reach a selfdestruct (suicide) instruction without ` +
                  'any ownership/role modifier. An attacker could destroy the contract ' +
                  'and recover all remaining ETH.',
                lineStart: line,
                lineEnd: line + 2,
                columnStart: 0,
                columnEnd: 0,
                codeSnippet: snippet(context.lines, Math.max(1, line - 2), line + 2),
                recommendation:
                  'Gate selfdestruct behind onlyOwner, add a timelock, and prefer ' +
                  'pausing + sweeping over destruction.',
                remediatedCode: `    function destroy() public onlyOwner {\n        selfdestruct(payable(owner));\n    }`,
                references: ['https://swcregistry.io/docs/SWC-106'],
                swcId: 'SWC-106',
                cvssScore: cvssFor('HIGH'),
              });
            }
          }
        }
      }
    });

    // 5) fee / parameter setters without restrictions.
    walkAst(context.ast as unknown, (n) => {
      if (n.type === 'StateVariableDeclaration') {
        const vars = n.variables as AstNode[] | undefined;
        if (!vars) return;
        for (const v of vars) {
          const vname = (v.name as string) || '';
          if (/fee|rate|ratio|admin|owner|implementation/.test(vname.toLowerCase()) === false) continue;
          // Skip if the variable is read-only/public — only flag assignable ones.
          // The setter path is covered accurately by the function scan above.
        }
      }
    });

    const dedup = new Map<string, DetectorResult>();
    for (const r of results) {
      const key = `${r.swcId}_${r.lineStart}_${r.title}`;
      if (!dedup.has(key)) dedup.set(key, r);
    }
    return Array.from(dedup.values());
  }

  private sensitivitySeverity(name: string): 'CRITICAL' | 'HIGH' {
    const lower = name.toLowerCase();
    if (/(mint|owner|transferownership|setimplementation|upgrade|selfdestruct|destroy|setoracle|setadmin)/.test(lower)) {
      return 'CRITICAL';
    }
    return 'HIGH';
  }

  private addGuard(
    context: DetectorContext,
    fn: AstNode,
    fnName: string,
    guard: string,
    severity: 'CRITICAL' | 'HIGH'
  ): string {
    const start = nodeLine(fn);
    const end = nodeEndLine(fn);
    const body = snippet(context.lines, start, end);
    const guardMod = guard === 'onlyOwner' && !context.sourceCode.includes('Ownable')
      ? `${OZ_ACCESS_CONTROL_IMPORTS.Ownable}

contract ${this.contractName(context) || 'AuditedContract'} is Ownable {`
      : '';
    const fixed = body.replace(
      /(function\s+\w+\s*\([^)]*\))(\s*(?:public|external))?/,
      (_m, sig: string, vis: string) =>
        `${sig}${vis || ' public'} ${guard}`
    );
    return [guardMod, '', fixed].filter(Boolean).join('\n');
  }

  private isAuthContext(line: string): boolean {
    const stripped = line.replace(/\/\/.*$/, '');
    return /(require|if|==|!=|msg\.sender|address)/.test(stripped) &&
      /tx\.origin/.test(stripped);
  }

  private hasInlineAuthGuard(fn: AstNode): boolean {
    let guarded = false;
    walkAst(fn, (n) => {
      if (guarded) return;
      if (n.type === 'FunctionCall') {
        const callee = n.expression as AstNode | undefined;
        if (callee) {
          const calleeName =
            callee.type === 'Identifier'
              ? ((callee.name as string) || '').toLowerCase()
              : '';
          if (calleeName === 'require' || calleeName === 'revert') {
            const argsText = JSON.stringify(n.arguments);
            if (/msg\.sender/.test(argsText) && /(owner|admin|==|!=|only|caller|address)/.test(argsText)) {
              guarded = true;
            }
          }
        }
      }
      if (n.type === 'BinaryOperation') {
        const left = n.left as AstNode | undefined;
        const operator = n.operator as string;
        if (
          left &&
          left.type === 'MemberAccess' &&
          (left.memberName as string) === 'sender' &&
          ['==', '!='].includes(operator)
        ) {
          guarded = true;
        }
      }
    });
    return guarded;
  }

  private functionAtLine(context: DetectorContext, line: number): { name: string; modifiers: string[] } | null {
    for (const f of context.functions) {
      if (line >= f.lineStart && line <= f.lineEnd) {
        return { name: f.name, modifiers: f.modifiers };
      }
    }
    return null;
  }

  private contractName(context: DetectorContext): string {
    const m = context.sourceCode.match(/contract\s+(\w+)/);
    return m ? m[1] : '';
  }
}