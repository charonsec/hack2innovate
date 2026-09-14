import {
  Detector,
  DetectorContext,
  DetectorResult,
  VulnerabilityType,
} from '../types/index';
import {
  buildId,
  cvssFor,
  deltaForSeverity,
  findNodes,
  nodeLine,
  snippet,
  walkAst,
  AstNode,
} from '../engine/detector-utils';
import { computeConfidence, buildAttackPath, evidenceSnippet } from '../engine/confidence';

const UINT_TYPES = [
  'uint', 'uint8', 'uint16', 'uint24', 'uint32', 'uint40', 'uint48', 'uint56',
  'uint64', 'uint72', 'uint80', 'uint88', 'uint96', 'uint104', 'uint112', 'uint120',
  'uint128', 'uint136', 'uint144', 'uint152', 'uint160', 'uint168', 'uint176', 'uint184',
  'uint192', 'uint200', 'uint208', 'uint216', 'uint224', 'uint232', 'uint240', 'uint248',
  'uint256',
];

const INT_TYPES = [
  'int', 'int8', 'int16', 'int24', 'int32', 'int40', 'int48', 'int56', 'int64',
  'int72', 'int80', 'int88', 'int96', 'int104', 'int112', 'int120', 'int128',
  'int136', 'int144', 'int152', 'int160', 'int168', 'int176', 'int184', 'int192',
  'int200', 'int208', 'int216', 'int224', 'int232', 'int240', 'int248', 'int256',
];

function parseVersionMajor(pragma: string): number {
  const m = pragma.match(/(\d+)\.(\d+)\.(\d+)/);
  if (!m) return 0;
  return parseInt(m[1], 10);
}

export class OverflowDetector implements Detector {
  name = 'overflow';

  detect(context: DetectorContext): DetectorResult[] {
    const results: DetectorResult[] = [];

    // Explicit unchecked blocks always warrant analysis regardless of version.
    const uncheckedBlocks = context.sourceCode.match(
      /unchecked\s*\{[\s\S]*?\}/g
    );
    if (uncheckedBlocks && uncheckedBlocks.length) {
      let searchOffset = 0;
      for (const block of uncheckedBlocks) {
        // Find the line of THIS specific unchecked block, not always the first one.
        const matchIdx = context.sourceCode.indexOf(block, searchOffset);
        if (matchIdx < 0) continue;
        searchOffset = matchIdx + block.length;

        const lineNo =
          context.sourceCode.substring(0, matchIdx).split('\n').length;
        if (lineNo <= 0) continue;
        const hasArithmetic = /[+*/-]/.test(block.replace(/[=;{}]/g, ''));
        if (hasArithmetic) {
          const financialImpact = this.hasFinancialImpact(context, lineNo);
          const confidence = computeConfidence(85, { financialImpact });
          const evidence: string[] = [
            evidenceSnippet(context.sourceCode, lineNo, lineNo),
          ];
          if (financialImpact) {
            evidence.push('Function modifies balance/price state variables');
          }
          results.push({
            type: 'INTEGER_OVERFLOW',
            severity: 'HIGH',
            title: 'Unchecked arithmetic block',
            description:
              'The `unchecked` block disables Solidity\'s built-in overflow ' +
              'and underflow checks on every arithmetic operation inside it. If the ' +
              'inputs exceed the type bounds the value silently wraps, enabling ' +
              'price / balance manipulation.',
            confidence,
            evidence,
            attackPath: buildAttackPath([
              {
                label: 'Attacker provides extreme input',
                description: 'Supply a value that pushes arithmetic past uint256 bounds',
              },
              {
                label: 'Unchecked arithmetic wraps silently',
                description: 'The unchecked block suppresses the Solidity 0.8 overflow revert',
              },
              {
                label: 'Wrapped value stored in state',
                description: 'The corrupted result is written to a balance or price slot',
              },
              {
                label: 'Attacker extracts value',
                description: 'Use the manipulated state to withdraw or borrow excess funds',
              },
            ]),
            lineStart: lineNo,
            lineEnd: lineNo,
            columnStart: 0,
            columnEnd: 0,
            codeSnippet: block,
            recommendation:
              'Remove the unchecked block, or if computational gas savings are ' +
              'required, prove the inputs cannot exceed bounds and document the ' +
              'invariant. Wrap external-facing operations with explicit bounds checks.',
            remediatedCode: block.replace(
              'unchecked',
              '// SAFE: explicit bounds checks applied before each operation\n        checked'
            ),
            references: [
              'https://docs.soliditylang.org/en/v0.8.17/units-and-global-variables.html#checked-or-unchecked-arithmetic',
              'https://swcregistry.io/docs/SWC-101',
            ],
            swcId: 'SWC-101',
            cvssScore: cvssFor('HIGH'),
          });
        }
      }
    }

    // solc >= 0.8.0 has built-in overflow protection outside unchecked blocks.
    // Arithmetic in >=0.8.0 outside unchecked{} is SAFE — skip it.

    // Only analyze <0.8.0 contracts without SafeMath for implicit arithmetic.
    const preEight = this.isPre080(context.solidityVersion);
    if (preEight && !context.usesSafeMath && !context.sourceCode.includes('using SafeMath for')) {
      const arithmeticNodes = this.collectArithmetic(context);
      const seen = new Set<number>();
      for (const node of arithmeticNodes) {
        const line = nodeLine(node);
        if (seen.has(line)) continue;
        seen.add(line);

        const rawOp = (node.operator as string) || '';
        const operator = rawOp.replace(/=$/, ''); // normalize += -> +
        const typeDetected = this.detectOperandType(context, node, operator);
        if (!UINT_TYPES.includes(typeDetected) && !INT_TYPES.includes(typeDetected)) {
          continue;
        }

        const inferredTypes = !UINT_TYPES.includes(typeDetected) && !INT_TYPES.includes(typeDetected);
        const financialImpact = this.hasFinancialImpact(context, line);
        const sev = operator === '+' && UINT_TYPES.includes(typeDetected)
          ? 'HIGH'
          : 'MEDIUM';
        const vulnType =
          operator === '-'
            ? ('INTEGER_UNDERFLOW' as VulnerabilityType)
            : ('INTEGER_OVERFLOW' as VulnerabilityType);

        const surrounding = snippet(context.lines, Math.max(1, line - 1), line + 1);
        const confidence = computeConfidence(70, { inferredTypes, financialImpact });
        const evidence: string[] = [
          evidenceSnippet(context.sourceCode, line, line),
          `Operator '${operator}' applied to ${typeDetected} without SafeMath (solc ${context.solidityVersion})`,
        ];
        if (financialImpact) {
          evidence.push('Function modifies balance/price state variables');
        }

        results.push({
          type: vulnType,
          severity: sev,
          title:
            vulnType === 'INTEGER_UNDERFLOW'
              ? 'Potential Integer Underflow'
              : 'Potential Integer Overflow',
          description:
            `Arithmetic operation '${operator}' is applied to ${typeDetected} values ` +
            `without SafeMath while the contract targets Solidity ${context.solidityVersion}. ` +
            'Solc < 0.8.0 silently wraps overflowing arithmetic on uint/int types, letting ' +
            'an attacker drive balances, allowances, and totals to unintended values.',
          confidence,
          evidence,
          attackPath: buildAttackPath([
            {
              label: 'Contract compiled with solc < 0.8.0',
              description: `Target version ${context.solidityVersion} has no built-in overflow checks`,
            },
            {
              label: 'Arithmetic without SafeMath',
              description: `The '${operator}' operator on ${typeDetected} silently wraps on overflow`,
            },
            {
              label: 'Attacker triggers overflow',
              description: 'Craft calldata that pushes the arithmetic past the type boundary',
            },
            {
              label: 'Corrupted value persisted',
              description: 'The wrapped result is written to storage, corrupting balances or totals',
            },
          ]),
          lineStart: line,
          lineEnd: line,
          columnStart: 0,
          columnEnd: 0,
          codeSnippet: surrounding,
          recommendation:
            'Upgrade to Solidity ^0.8.0 which reverts on overflow by default, or ' +
            'import OpenZeppelin SafeMath and replace every `+ - * /` with ' +
            '`.add() .sub() .mul() .div()`.',
          remediatedCode: this.safeMathVersion(context, line, operator),
          references: ['https://swcregistry.io/docs/SWC-101'],
          swcId: 'SWC-101',
          cvssScore: cvssFor(sev),
        });
      }
    }

    // Deduplicate unchecked-blocks that overlap with state variable initializers.
    return results;
  }

  private isPre080(version: string): boolean {
    const m = version.match(/(\d+)\.(\d+)\.(\d+)/);
    if (!m) return false;
    const [major, minor] = [parseInt(m[1], 10), parseInt(m[2], 10)];
    return major < 0 || (major === 0 && minor < 8);
  }

  private hasFinancialImpact(context: DetectorContext, line: number): boolean {
    const financialNames = /balance|price|total|amount|reserve|supply|debt|collateral|treasury|fee/i;
    // Scan enclosing function for state variable writes involving financial names.
    const start = Math.max(0, line - 40);
    const end = Math.min(context.lines.length, line + 10);
    const window = context.lines.slice(start, end).join('\n');
    return (
      financialNames.test(window) &&
      /=\s*[a-zA-Z]|balanceOf|totalSupply|price|reserve/.test(window)
    );
  }

  private collectArithmetic(context: DetectorContext): AstNode[] {
    const out: AstNode[] = [];
    if (context.ast) {
      walkAst(context.ast, (n) => {
        if (n.type === 'BinaryOperation') {
          const op = n.operator as string;
          if (['+', '-', '*', '**'].includes(op)) {
            out.push(n);
          }
        }
        if (n.type === 'Assignment') {
          const op = n.operator as string;
          if (
            ['+=', '-=', '*=', '/=', '**='].includes(op) ||
            op === '='
          ) {
            // Only += style compound assignments mutate; plain `=` with
            // arithmetic RHS is handled through BinaryOperation capture.
            if (op !== '=') out.push(n);
          }
        }
        if (n.type === 'UnaryOperation') {
          const op = n.operator as string;
          if (['++', '--'].includes(op)) {
            out.push(n);
          }
        }
      });
    } else {
      // Fallback line-level scanning when AST walk is unavailable.
      const lines = context.lines;
      lines.forEach((ln, i) => {
        if (/[+\-*/]{1,2}=|(\b)[+\-*/]{1}(\b)/.test(ln) && !ln.trim().startsWith('//')) {
          out.push({ type: 'BinaryOperation', operator: '+', loc: { start: { line: i + 1, column: 0 } } } as unknown as AstNode);
        }
      });
    }
    return out;
  }

  private detectOperandType(context: DetectorContext, node: AstNode, operator: string): string {
    // Unary ++/-- operate on subExpression; compound assignments on left.
    const targetNode =
      node.type === 'UnaryOperation'
        ? (node.subExpression as AstNode | undefined)
        : (node.left as AstNode | undefined);
    if (targetNode && targetNode.type === 'Identifier') {
      const name = targetNode.name as string;
      for (const sv of context.stateVariables) {
        if (sv.name === name) return sv.type;
      }
      // Search function local declarations in the same function.
      const m = context.sourceCode.match(
        new RegExp(`(uint256|uint|int256|int)\\s+${name}\\s*=`)
      );
      if (m) return m[1];
    }
    return operator === '-' ? 'uint256' : 'uint256';
  }

  private safeMathVersion(context: DetectorContext, line: number, op: string): string {
    const m = context.lines[line - 1] || '';
    const trimmed = m.trim();
    const fnMap: Record<string, string> = { '+': 'add', '-': 'sub', '*': 'mul', '**': 'pow' };
    const fn = fnMap[op] || 'add';
    const replaced = trimmed.replace(
      /([a-zA-Z_][a-zA-Z0-9_]*)\s*([+\-*]+)\s*([a-zA-Z_][a-zA-Z0-9_]*)/,
      (_, a: string, _op: string, b: string) => `${a}.${fn}(${b})`
    );
    return `    uint256 x = ${replaced};`;
  }
}
