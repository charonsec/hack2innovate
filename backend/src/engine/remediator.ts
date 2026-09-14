import { DiffResult, Vulnerability } from '../types/index';

/**
 * Generates unified-diff text between an original and a remediated source.
 * The diff is rendered client-side: lines prefixed with '-' are removals,
 * '+' are additions and ' ' is context.
 */
export function generateDiff(
  originalCode: string,
  vulnerability: Vulnerability
): DiffResult {
  const fixedCode =
    vulnerability.remediatedCode.length > 0
      ? vulnerability.remediatedCode
      : originalCode;

  return {
    originalCode,
    fixedCode,
    diff: buildUnifiedDiff(originalCode, fixedCode, vulnerability.lineStart),
    addedImports: extractImports(fixedCode, originalCode),
    addedModifiers: extractModifiers(fixedCode, originalCode),
    changedFunctions: functionNamesTouched(fixedCode, originalCode),
  };
}

/**
 * Produces a complete rewritten secure contract with every finding applied.
 */
export function generateSecureVersion(
  sourceCode: string,
  vulnerabilities: Vulnerability[]
): string {
  let version = sourceCode;
  const seen = new Set<string>();

  const sorted = [...vulnerabilities].sort(
    (a, b) => a.lineStart - b.lineStart
  );

  for (const vuln of sorted) {
    if (seen.has(vuln.type)) continue;

    if (vuln.remediatedCode && vuln.remediatedCode.includes('import ')) {
      const importLine = vuln.remediatedCode.match(/import\s+[^;]+;\s*/)?.[0];
      if (importLine && !version.includes(importLine.trim().replace(/;\s*import/, ';'))) {
        // Only prepend the import if its target module is not already imported.
        const module = importLine.match(/"([^"]+)"/)?.[1];
        if (module && !version.includes(module)) {
          version = version.replace(
            /(\/\/ SPDX-License-Identifier:[^\n]*\n|pragma solidity[^\n]*\n)/,
            `$1${importLine}\n`
          );
        }
      }
    }

    // Replace the vulnerable line-range with the remediated snippet when the
    // remediated code looks like a function-level rewrite.
    if (
      vuln.remediatedCode &&
      vuln.remediatedCode.includes('contract ') &&
      vuln.remediatedCode.includes('function ')
    ) {
      // Keep the original contract name when possible.
      const contractName = version.match(/contract\s+(\w+)/)?.[1];
      if (contractName) {
        const inline = vuln.remediatedCode
          .replace(/import\s+[^;]+;\s*\n*/g, '')
          .replace(/contract\s+\w+\s*(?:is\s+ReentrancyGuard)?\s*\{/, '')
          .replace(/\}\s*$/, '');
        version = applyInlineRewrite(version, vuln, inline);
      }
    } else if (vuln.remediatedCode) {
      // Token-level remediation (e.g. tx.origin -> msg.sender).
      const originalFragment = vuln.codeSnippet;
      if (originalFragment && vuln.remediatedCode !== originalFragment) {
        const replaced = smartReplace(version, originalFragment, vuln.remediatedCode);
        if (replaced) version = replaced;
      }
    }
    seen.add(vuln.type);
  }

  version = ensureNoEmptyTrailing(version);
  return version.trimEnd() + '\n';
}

function applyInlineRewrite(
  source: string,
  vuln: Vulnerability,
  rewrittenBlock: string
): string {
  const lines = source.split('\n');
  const start = Math.max(1, vuln.lineStart - 1);
  const end = Math.min(lines.length, vuln.lineEnd + 1);
  const blockLines = lines.slice(start - 1, end);

  // Replace only if the vulnerable block is a self-contained function chunk.
  if (
    blockLines.some((l) => l.includes('function ')) ||
    blockLines.some((l) => l.includes('{'))
  ) {
    const before = lines.slice(0, start - 1).join('\n');
    const after = lines.slice(end).join('\n');
    return [before, indentBlock(rewrittenBlock.trim()), after].join('\n');
  }
  return source;
}

function smartReplace(source: string, search: string, replace: string): string | null {
  const idx = source.indexOf(search.trim());
  if (idx === -1) return null;
  return source.slice(0, idx) + replace + source.slice(idx + search.trim().length);
}

function extractImports(fixed: string, original: string): string[] {
  const oImports = new Set(original.match(/import\s+[^;]+;/g) || []);
  return (fixed.match(/import\s+[^;]+;/g) || []).filter((i) => !oImports.has(i));
}

function extractModifiers(fixed: string, original: string): string[] {
  const mods = new Set<string>();
  for (const m of fixed.match(/(?:public|external)\s+(nonReentrant|onlyOwner|onlyRole\s*\([^)]*\))\b/g) || []) {
    mods.add(m.split(/\s+/).slice(1).join(' '));
  }
  return Array.from(mods);
}

function functionNamesTouched(fixed: string, original: string): string[] {
  const oFuncs = new Set(original.match(/function\s+(\w+)/g) || []);
  return (fixed.match(/function\s+(\w+)/g) || []).filter((f) => !oFuncs.has(f));
}

function indentBlock(block: string): string {
  return block
    .split('\n')
    .map((l) => (l.trim().length ? `    ${l}` : l))
    .join('\n');
}

function ensureNoEmptyTrailing(code: string): string {
  while (code.endsWith('\n\n')) {
    code = code.slice(0, -1);
  }
  return code;
}

/** Line-based unified diff (LCS-free, Myers-free heuristic that is adequate for
 *  code-block replacement display). */
function buildUnifiedDiff(
  original: string,
  fixed: string,
  contextStartLine: number
): string {
  const a = original.split('\n');
  const b = fixed.split('\n');
  const out: string[] = [];
  const max = Math.max(a.length, b.length);
  let hunkStart = -1;
  let hunk: { prefix: string; text: string }[] = [];

  const flush = () => {
    if (hunk.length === 0) return;
    out.push(`@@ -${hunkStart},${hunk.length} @@`);
    for (const line of hunk) out.push(`${line.prefix}${line.text}`);
    out.push('');
    hunk = [];
  };

  for (let i = 0; i < max; i++) {
    const aLine = i < a.length ? a[i] : undefined;
    const bLine = i < b.length ? b[i] : undefined;
    const nearFinding = Math.abs(i + 1 - contextStartLine) <= 14;

    if (aLine === bLine && aLine !== undefined && bLine !== undefined) {
      if (nearFinding) {
        if (hunkStart === -1) hunkStart = i + 1;
        hunk.push({ prefix: ' ', text: aLine });
        if (hunk.length >= 40) flush();
      } else {
        flush();
        if (out.length < 2000) out.push(` ${aLine}`);
      }
    } else {
      if (hunkStart === -1) hunkStart = i + 1;
      if (aLine !== undefined) hunk.push({ prefix: '-', text: aLine });
      if (bLine !== undefined) hunk.push({ prefix: '+', text: bLine });
      if (hunk.length >= 60) flush();
    }
  }
  flush();

  return out.join('\n');
}

/** Convenience function the frontend uses to colorize a DiffResult. */
export function parseDiff(diffText: string): Array<{ prefix: '-' | '+' | ' '; text: string }> {
  const lines = diffText.split('\n').filter((l) => l.trim().length > 0);
  return lines
    .filter((l) => l.startsWith('-') || l.startsWith('+') || l.startsWith(' '))
    .map((l) => ({
      prefix: l.charCodeAt(0) === 45 ? '-' : l.charCodeAt(0) === 43 ? '+' : ' ',
      text: l.slice(1),
    }));
}