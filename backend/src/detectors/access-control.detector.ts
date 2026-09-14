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
import { computeConfidence, buildAttackPath, evidenceSnippet } from '../engine/confidence';

const OZ_ACCESS_CONTROL_IMPORTS: Record<string, string> = {
  Ownable: 'import "@openzeppelin/contracts/access/Ownable.sol";',
  AccessControl: 'import "@openzeppelin/contracts/access/AccessControl.sol";',
};

export class AccessControlDetector implements Detector {
  name = 'access-control';

  detect(context: DetectorContext): DetectorResult[] {
    const results: DetectorResult[] = [];
    const guardModifiers = ['onlyowner', 'onlyrole', 'auth', 'authorized', 'adminonly'];

    if (!context.ast) return results;

    const fnNodes = findNodes(context.ast, 'FunctionDefinition');

    let guardedFunctionCount = 0;
    for (const fn of fnNodes) {
      const mods: string[] = Array.isArray(fn.modifiers)
        ? (fn.modifiers as AstNode[]).map((m) =>
            typeof m.name === 'object' && m.name !== null
              ? ((m.name as AstNode).name as string)
              : (m.name as string)
          )
        : [];
      if (mods.some((m) => guardModifiers.includes(m.toLowerCase()))) {
        guardedFunctionCount++;
      }
    }
    const hasPartialGuard = guardedFunctionCount > 0;

    for (const fn of fnNodes) {
      const name = (fn.name as string) || '';
      if (!name) continue;
      if (!fn.body) continue;
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
      const fnBodySnippet = evidenceSnippet(context.sourceCode, fnStart, fnEnd);
      const ctxSnip = snippet(context.lines, fnStart, Math.min(fnStart + 5, fnEnd));

      // 1) initialize() functions without guards — front-running to seize ownership.
      if (
        ['initialize', 'init', 'initializer', 'setup'].includes(name.toLowerCase()) &&
        !hasGuard && !hasInlineAuthGuard
      ) {
        const confidence = computeConfidence(85, {
          lineMatchesEvidence: true,
          financialImpact: true,
        });
        results.push({
          type: 'ACCESS_CONTROL',
          severity: 'CRITICAL',
          title: `Unprotected ${name}() — Initialization front-running`,
          description:
            `${name}() is public/external and has no access control modifier. In ` +
            'proxy / upgradeable patterns an attacker can front-run the deployer and ' +
            'call initialize() first to seize ownership or set critical parameters ' +
            '(admin, oracle, implementation).',
          confidence,
          evidence: [fnBodySnippet],
          attackPath: buildAttackPath([
            {
              label: 'ENTRY',
              description: `Attacker calls ${name}() before the legitimate deployer`,
              line: fnStart,
            },
            {
              label: 'TRIGGER',
              description: `No auth modifier (onlyOwner / initializer) present on ${name}()`,
              line: fnStart,
            },
            {
              label: 'EXPLOIT',
              description: `Attacker-controlled values written to owner / admin / implementation slots`,
              line: fnStart,
            },
            {
              label: 'IMPACT',
              description: 'Attacker owns the contract, sets arbitrary parameters, drains funds',
              line: fnStart,
            },
          ]),
          lineStart: fnStart,
          lineEnd: fnEnd,
          columnStart: 0,
          columnEnd: 0,
          codeSnippet: ctxSnip,
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
      // FIX: only require hasGuard on the function itself — do NOT suppress when the
      // contract inherits Ownable/AccessControl. A sensitive function with no guard is
      // still vulnerable even if other functions ARE guarded.
      if (isSensitiveFunctionName(name) && !hasGuard && !hasInlineAuthGuard) {
        const severity = this.sensitivitySeverity(name);
        const financialImpact = /mint|withdraw|price|oracle|upgrade|fee/i.test(name);

        let base = 75;
        if (financialImpact) base += 10;
        const confidence = computeConfidence(base, {
          lineMatchesEvidence: true,
          financialImpact,
          crossFunction: hasPartialGuard,
        });

        results.push({
          type: 'ACCESS_CONTROL',
          severity,
          title: `Missing access control on ${name}()`,
          description:
            `${name}() is ${visibility} and operates on a privileged capability ` +
            '(mint, burn, transfer of value, ownership, fees, emergency controls) but ' +
            'does not enforce any role/ownership modifier. Any caller can invoke it.' +
            (hasPartialGuard
              ? ' Note: other functions in this contract DO have access control guards — ' +
                'this function was likely intended to be guarded but was missed.'
              : ''),
          confidence,
          evidence: [fnBodySnippet],
          attackPath: buildAttackPath([
            {
              label: 'ENTRY',
              description: `Attacker calls ${name}() externally`,
              line: fnStart,
            },
            {
              label: 'TRIGGER',
              description: `No onlyOwner / onlyRole modifier on ${name}()`,
              line: fnStart,
            },
            {
              label: 'EXPLOIT',
              description: `${name}() executes privileged state change — attacker controls parameters / mints tokens / withdraws funds`,
              line: fnStart,
            },
            {
              label: 'IMPACT',
              description:
                financialImpact
                  ? 'Financial loss — tokens minted, treasury drained, or protocol parameters set by attacker'
                  : 'Privilege escalation — attacker gains administrative capability',
              line: fnStart,
            },
          ]),
          lineStart: fnStart,
          lineEnd: fnEnd,
          columnStart: 0,
          columnEnd: 0,
          codeSnippet: ctxSnip,
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
                const evidence = evidenceSnippet(context.sourceCode, Math.max(1, line - 1), line + 1);
                const confidence = computeConfidence(88, {
                  lineMatchesEvidence: true,
                });
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
                  confidence,
                  evidence: [evidence],
                  attackPath: buildAttackPath([
                    {
                      label: 'ENTRY',
                      description: 'Victim EOA interacts with a malicious contract',
                      line,
                    },
                    {
                      label: 'TRIGGER',
                      description: 'Malicious contract forwards call to the vulnerable contract; tx.origin == victim EOA',
                      line,
                    },
                    {
                      label: 'EXPLOIT',
                      description: 'tx.origin == victim EOA passes the auth check — malicious contract executes privileged operation',
                      line,
                    },
                    {
                      label: 'IMPACT',
                      description: 'Attacker drains funds / changes ownership via victim\'s EOA identity',
                      line,
                    },
                  ]),
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
            if (!fn) return;
            const isProtected = fn.modifiers.some((m) =>
              ['onlyowner', 'onlyrole', 'adminonly', 'auth'].includes(m.toLowerCase())
            );
            const evidence = evidenceSnippet(context.sourceCode, Math.max(1, line - 2), line + 2);
            const confidence = computeConfidence(80, {
              guardPresent: isProtected,
              lineMatchesEvidence: true,
            });
            results.push({
              type: 'SELF_DESTRUCT',
              severity: isProtected ? 'MEDIUM' : 'HIGH',
              title: isProtected
                ? 'Protected selfdestruct() call'
                : 'Unprotected selfdestruct() call',
              description: isProtected
                ? `${fn.name}() contains a selfdestruct (suicide) instruction guarded by ` +
                  'an access-control modifier. While protected, selfdestruct is permanent ' +
                  'and should be avoided in production — prefer pausing + sweeping.'
                : `${fn.name}() can reach a selfdestruct (suicide) instruction without ` +
                  'any ownership/role modifier. An attacker could destroy the contract ' +
                  'and recover all remaining ETH.',
              confidence,
              evidence: [evidence],
              attackPath: isProtected
                ? undefined
                : buildAttackPath([
                    {
                      label: 'ENTRY',
                      description: `Attacker calls ${fn.name}() which reaches selfdestruct`,
                      line,
                    },
                    {
                      label: 'TRIGGER',
                      description: 'No onlyOwner modifier protects the selfdestruct path',
                      line,
                    },
                    {
                      label: 'EXPLOIT',
                      description: 'selfdestruct called — contract code and storage destroyed, ETH sent to attacker',
                      line,
                    },
                    {
                      label: 'IMPACT',
                      description: 'Contract permanently destroyed — all locked funds irrecoverable',
                      line,
                    },
                  ]),
              lineStart: line,
              lineEnd: line + 2,
              columnStart: 0,
              columnEnd: 0,
              codeSnippet: evidence,
              recommendation:
                'Gate selfdestruct behind onlyOwner, add a timelock, and prefer ' +
                'pausing + sweeping over destruction.',
              remediatedCode: `    function destroy() public onlyOwner {\n        selfdestruct(payable(owner));\n    }`,
              references: ['https://swcregistry.io/docs/SWC-106'],
              swcId: 'SWC-106',
              cvssScore: cvssFor(isProtected ? 'MEDIUM' : 'HIGH'),
            });
          }
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
