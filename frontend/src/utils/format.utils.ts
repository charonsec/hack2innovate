export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB'];
  const i = Math.max(0, Math.floor(Math.log(bytes) / Math.log(1024)));
  return `${(bytes / Math.pow(1024, i)).toFixed(1)} ${units[i]}`;
}

export function formatFileSize(bytes: number): string {
  return formatBytes(bytes);
}

export function formatDuration(ms: number): string {
  if (ms < 1000) return `${ms}ms`;
  const s = ms / 1000;
  if (s < 60) return `${s.toFixed(1)}s`;
  const m = Math.floor(s / 60);
  const rem = Math.round(s - m * 60);
  return `${m}m ${rem}s`;
}

export function formatDate(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    hour: '2-digit',
    minute: '2-digit',
  });
}

export function formatTime(isoOrMs: string | number): string {
  const d = new Date(isoOrMs);
  if (Number.isNaN(d.getTime())) return '';
  return d.toLocaleTimeString('en-US', {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  });
}

export function truncate(text: string, max = 160): string {
  if (text.length <= max) return text;
  return `${text.slice(0, max)}…`;
}

export function capitalize(text: string): string {
  return text.charAt(0).toUpperCase() + text.slice(1);
}

export function pluralize(count: number, word: string): string {
  return `${count} ${word}${count === 1 ? '' : 's'}`;
}

export function slugify(text: string): string {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '');
}

export function downloadText(filename: string, content: string, mime = 'text/plain'): void {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
}

export function toVulnerabilityLabel(type: string): string {
  const formatted = type.split('_').join(' ').toLowerCase();
  return formatted.replace(/\b\w/g, (char) => char.toUpperCase());
}

export function cx(...parts: Array<string | false | null | undefined>): string {
  return parts.filter(Boolean).join(' ');
}

export interface DiffLine {
  type: 'add' | 'remove' | 'context';
  content: string;
  lineNumber: number | null;
}

export function getLineType(line: string, origLines: Set<string>, addLines: Set<string>): DiffLine['type'] {
  if (addLines.has(line)) return 'add';
  if (origLines.has(line)) return 'remove';
  return 'context';
}

/**
 * LCS (longest common subsequence) on two arrays of lines using a classic
 * dynamic-programming table. Returns the common subsequence of exact lines
 * (indentation preserved) shared between `a` and `b`.
 */
function lcsLines(a: string[], b: string[]): string[] {
  const n = a.length;
  const m = b.length;
  const width = m + 1;
  const dp = new Uint32Array((n + 1) * width);
  for (let i = n - 1; i >= 0; i--) {
    const row = i * width;
    const nextRow = row + width;
    for (let j = m - 1; j >= 0; j--) {
      dp[row + j] =
        a[i] === b[j]
          ? dp[nextRow + j + 1] + 1
          : Math.max(dp[nextRow + j], dp[row + j + 1]);
    }
  }
  const lcs: string[] = [];
  let i = 0;
  let j = 0;
  while (i < n && j < m) {
    if (a[i] === b[j]) {
      lcs.push(a[i]);
      i++;
      j++;
    } else if (dp[(i + 1) * width + j] >= dp[i * width + j + 1]) {
      i++;
    } else {
      j++;
    }
  }
  return lcs;
}

export function computeDiff(original: string, remediated: string): DiffLine[] {
  const origLines = original.split('\n');
  const remLines = remediated.split('\n');

  // Trim the identical prefix and suffix so the DP only runs over the
  // actually-changed region.
  let prefixLen = 0;
  const commonMin = Math.min(origLines.length, remLines.length);
  while (
    prefixLen < commonMin &&
    origLines[prefixLen] === remLines[prefixLen]
  ) {
    prefixLen++;
  }

  let origEnd = origLines.length;
  let remEnd = remLines.length;
  while (
    origEnd > prefixLen &&
    remEnd > prefixLen &&
    origLines[origEnd - 1] === remLines[remEnd - 1]
  ) {
    origEnd--;
    remEnd--;
  }

  const result: DiffLine[] = [];

  for (let k = 0; k < prefixLen; k++) {
    result.push({ type: 'context', content: origLines[k], lineNumber: k + 1 });
  }

  const midOrig = origLines.slice(prefixLen, origEnd);
  const midRem = remLines.slice(prefixLen, remEnd);
  const lcs = lcsLines(midOrig, midRem);

  let i = 0;
  let j = 0;
  for (const line of lcs) {
    while (i < midOrig.length && midOrig[i] !== line) {
      result.push({
        type: 'remove',
        content: midOrig[i],
        lineNumber: prefixLen + i + 1,
      });
      i++;
    }
    while (j < midRem.length && midRem[j] !== line) {
      result.push({ type: 'add', content: midRem[j], lineNumber: null });
      j++;
    }
    result.push({ type: 'context', content: line, lineNumber: prefixLen + i + 1 });
    i++;
    j++;
  }
  while (i < midOrig.length) {
    result.push({
      type: 'remove',
      content: midOrig[i],
      lineNumber: prefixLen + i + 1,
    });
    i++;
  }
  while (j < midRem.length) {
    result.push({ type: 'add', content: midRem[j], lineNumber: null });
    j++;
  }

  for (let k = origEnd; k < origLines.length; k++) {
    result.push({ type: 'context', content: origLines[k], lineNumber: k + 1 });
  }

  return result;
}

export function getSeverityLabel(severity: string): string {
  switch (severity) {
    case 'CRITICAL': return 'Critical';
    case 'HIGH': return 'High';
    case 'MEDIUM': return 'Medium';
    case 'LOW': return 'Low';
    case 'INFORMATIONAL': return 'Info';
    default: return severity;
  }
}