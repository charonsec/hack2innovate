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

export function computeDiff(original: string, remediated: string): DiffLine[] {
  const origLines = original.split('\n');
  const remedLines = remediated.split('\n');

  const origSet = new Set(origLines.map((l) => l.trim()));
  const addSet = new Set(remedLines.map((l) => l.trim()));

  const maxLen = Math.max(origLines.length, remedLines.length);
  const result: DiffLine[] = [];

  let origIdx = 0;
  let remIdx = 0;

  while (origIdx < origLines.length || remIdx < remedLines.length) {
    const oLine = origIdx < origLines.length ? origLines[origIdx] : undefined;
    const rLine = remIdx < remedLines.length ? remedLines[remIdx] : undefined;

    if (oLine !== undefined && rLine !== undefined && oLine === rLine) {
      result.push({ type: 'context', content: oLine, lineNumber: origIdx + 1 });
      origIdx++;
      remIdx++;
    } else if (rLine !== undefined && !origSet.has(rLine.trim())) {
      result.push({ type: 'add', content: rLine, lineNumber: null });
      remIdx++;
    } else if (oLine !== undefined && !addSet.has(oLine.trim())) {
      result.push({ type: 'remove', content: oLine, lineNumber: origIdx + 1 });
      origIdx++;
    } else {
      if (oLine !== undefined) {
        result.push({ type: 'remove', content: oLine, lineNumber: origIdx + 1 });
        origIdx++;
      }
      if (rLine !== undefined) {
        result.push({ type: 'add', content: rLine, lineNumber: null });
        remIdx++;
      }
    }
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