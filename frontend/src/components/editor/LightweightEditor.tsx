import {
  forwardRef,
  useEffect,
  useImperativeHandle,
  useMemo,
  useRef,
  useState,
  UIEvent,
  KeyboardEvent,
} from 'react';
import { Vulnerability } from '@/types';
import { SolidityEditorHandle } from './SolidityEditor';

interface LightweightEditorProps {
  value: string;
  onChange?: (value: string) => void;
  readOnly?: boolean;
  height?: number | string;
  vulnerabilities?: Vulnerability[];
  onLineClick?: (vulnerability: Vulnerability | null) => void;
  focusedLine?: number | null;
}

// Simple Solidity syntax highlighter using regex tokenization
function highlightSolidity(code: string): string {
  const escapeHtml = (str: string) =>
    str
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;');

  const lines = code.split('\n');

  return lines
    .map((line) => {
      let escaped = escapeHtml(line);

      // Comments: // ...
      if (escaped.includes('//')) {
        const commentIdx = escaped.indexOf('//');
        const before = escaped.substring(0, commentIdx);
        const comment = escaped.substring(commentIdx);
        return `${tokenizeLine(before)}<span class="text-[#6B7280] italic">${comment}</span>`;
      }

      return tokenizeLine(escaped);
    })
    .join('\n');
}

function tokenizeLine(line: string): string {
  const keywords = [
    'pragma', 'solidity', 'contract', 'library', 'interface', 'using', 'for',
    'function', 'mapping', 'struct', 'enum', 'event', 'modifier', 'error',
    'revert', 'public', 'private', 'internal', 'external', 'view', 'pure',
    'payable', 'returns', 'return', 'require', 'assert', 'emit', 'memory',
    'storage', 'calldata', 'if', 'else', 'while', 'do', 'break', 'continue',
    'new', 'delete', 'this', 'selfdestruct', 'immutable', 'constant',
    'unchecked', 'try', 'catch', 'is', 'address', 'bytes'
  ];

  const types = [
    'uint256', 'uint128', 'uint64', 'uint32', 'uint16', 'uint8', 'uint',
    'int256', 'int128', 'int64', 'int32', 'int16', 'int8', 'int',
    'bool', 'string', 'bytes32', 'bytes4'
  ];

  // Strings — stashed in an array and referenced by index placeholders that
  // cannot collide with real code content.
  const strings: string[] = [];
  line = line.replace(/(["'])(?:(?=(\\?))\2.)*?\1/g, (match) => {
    strings.push(match);
    return `\u0000${strings.length - 1}\u0000`;
  });

  // Numbers
  line = line.replace(/\b(0x[0-9a-fA-F]+|\d+)\b/g, '<span class="text-[#8B5CF6]">$1</span>');

  // Types
  for (const t of types) {
    const reg = new RegExp(`\\b(${t})\\b`, 'g');
    line = line.replace(reg, '<span class="text-[#0EA5E9] font-medium">$1</span>');
  }

  // Keywords
  for (const kw of keywords) {
    const reg = new RegExp(`\\b(${kw})\\b`, 'g');
    line = line.replace(reg, '<span class="text-[#00FF88] font-semibold">$1</span>');
  }

  // Restore strings
  line = line.replace(/\u0000(\d+)\u0000/g, (_, index) => {
    return `<span class="text-[#FDE047]">${strings[Number(index)] ?? ''}</span>`;
  });

  return line;
}

export const LightweightEditor = forwardRef<SolidityEditorHandle, LightweightEditorProps>(
  (
    {
      value,
      onChange,
      readOnly = false,
      height = 500,
      vulnerabilities = [],
      onLineClick,
      focusedLine,
    },
    ref
  ) => {
    const textareaRef = useRef<HTMLTextAreaElement>(null);
    const preRef = useRef<HTMLPreElement>(null);
    const lineNumbersRef = useRef<HTMLDivElement>(null);
    const [cursorLine, setCursorLine] = useState<number>(1);
    const [activeVulns, setActiveVulns] = useState<Vulnerability[]>(vulnerabilities);

    useEffect(() => {
      setActiveVulns(vulnerabilities);
    }, [vulnerabilities]);

    const lines = useMemo(() => value.split('\n'), [value]);
    const lineCount = lines.length;

    // Map each line number to any vulnerability on that line
    const vulnLineMap = useMemo(() => {
      const map = new Map<number, Vulnerability>();
      for (const v of activeVulns) {
        const start = Math.max(1, v.lineStart);
        const end = Math.max(start, v.lineEnd);
        for (let i = start; i <= end; i++) {
          if (!map.has(i)) {
            map.set(i, v);
          }
        }
      }
      return map;
    }, [activeVulns]);

    useImperativeHandle(ref, () => ({
      revealLine: (line: number) => {
        if (!textareaRef.current) return;
        const lineHeight = 24; // 1.5rem
        const targetScroll = Math.max(0, (line - 3) * lineHeight);
        textareaRef.current.scrollTop = targetScroll;
        if (lineNumbersRef.current) lineNumbersRef.current.scrollTop = targetScroll;
        if (preRef.current) preRef.current.scrollTop = targetScroll;
      },
      getEditor: () => ({
        revealLineInCenter: (line: number) => {
          if (!textareaRef.current) return;
          const lineHeight = 24;
          const offset = textareaRef.current.clientHeight / 2;
          const targetScroll = Math.max(0, line * lineHeight - offset);
          textareaRef.current.scrollTop = targetScroll;
        },
        focus: () => {
          textareaRef.current?.focus();
        },
      }),
      setDecorationsFor: (vulns: Vulnerability[]) => {
        setActiveVulns(vulns);
      },
    }));

    useEffect(() => {
      if (!focusedLine || !textareaRef.current) return;
      const lineHeight = 24;
      const offset = textareaRef.current.clientHeight / 2;
      const targetScroll = Math.max(0, focusedLine * lineHeight - offset);
      textareaRef.current.scrollTop = targetScroll;
      if (lineNumbersRef.current) lineNumbersRef.current.scrollTop = targetScroll;
      if (preRef.current) preRef.current.scrollTop = targetScroll;
    }, [focusedLine]);

    const handleScroll = (e: UIEvent<HTMLTextAreaElement>) => {
      const scrollTop = e.currentTarget.scrollTop;
      const scrollLeft = e.currentTarget.scrollLeft;

      if (lineNumbersRef.current) {
        lineNumbersRef.current.scrollTop = scrollTop;
      }
      if (preRef.current) {
        preRef.current.scrollTop = scrollTop;
        preRef.current.scrollLeft = scrollLeft;
      }
    };

    const updateCursorLine = (textarea: HTMLTextAreaElement) => {
      const pos = textarea.selectionStart;
      const textBefore = textarea.value.substring(0, pos);
      const currentLine = textBefore.split('\n').length;
      setCursorLine(currentLine);

      const vuln = vulnLineMap.get(currentLine) ?? null;
      onLineClick?.(vuln);
    };

    const handleKeyDown = (e: KeyboardEvent<HTMLTextAreaElement>) => {
      if (readOnly) return;

      const textarea = textareaRef.current;
      if (!textarea) return;

      // Tab key -> 4 spaces
      if (e.key === 'Tab') {
        e.preventDefault();
        const start = textarea.selectionStart;
        const end = textarea.selectionEnd;
        const spaces = '    ';

        const nextVal = value.substring(0, start) + spaces + value.substring(end);
        onChange?.(nextVal);

        requestAnimationFrame(() => {
          textarea.selectionStart = textarea.selectionEnd = start + 4;
          updateCursorLine(textarea);
        });
      }

      // Enter key -> auto indent
      if (e.key === 'Enter') {
        const start = textarea.selectionStart;
        const lineStart = value.lastIndexOf('\n', start - 1) + 1;
        const currentLineText = value.substring(lineStart, start);
        const match = currentLineText.match(/^(\s+)/);
        const indent = match ? match[1] : '';

        if (indent) {
          e.preventDefault();
          const extra = currentLineText.trim().endsWith('{') ? '    ' : '';
          const nextVal = value.substring(0, start) + '\n' + indent + extra + value.substring(textarea.selectionEnd);
          onChange?.(nextVal);

          requestAnimationFrame(() => {
            const newPos = start + 1 + indent.length + extra.length;
            textarea.selectionStart = textarea.selectionEnd = newPos;
            updateCursorLine(textarea);
          });
        }
      }
    };

    const highlightedCode = useMemo(() => highlightSolidity(value), [value]);

    const formattedHeight = typeof height === 'number' ? `${height}px` : height;

    return (
      <div
        className="relative flex overflow-hidden rounded-xl border border-[#2A2D35] bg-[#0D0F13] font-mono text-[13px] leading-6 select-none"
        style={{ height: formattedHeight }}
      >
        {/* Line Numbers Gutter */}
        <div
          ref={lineNumbersRef}
          className="w-14 shrink-0 overflow-hidden border-r border-[#2A2D35] bg-[#0A0B0D] py-3 text-right select-none"
        >
          {Array.from({ length: lineCount }, (_, i) => {
            const lineNum = i + 1;
            const vuln = vulnLineMap.get(lineNum);
            const isCursor = lineNum === cursorLine;
            const isFocused = lineNum === focusedLine;

            let severityColor = '';
            if (vuln) {
              const sev = vuln.severity.toLowerCase();
              if (sev === 'critical') severityColor = 'bg-[#EF4444]/20 text-[#EF4444] font-bold';
              else if (sev === 'high') severityColor = 'bg-[#F97316]/20 text-[#F97316] font-bold';
              else if (sev === 'medium') severityColor = 'bg-[#F59E0B]/20 text-[#F59E0B] font-bold';
              else severityColor = 'bg-[#00FF88]/20 text-[#00FF88] font-bold';
            }

            return (
              <div
                key={lineNum}
                onClick={() => {
                  const v = vulnLineMap.get(lineNum) ?? null;
                  onLineClick?.(v);
                  if (textareaRef.current) {
                    textareaRef.current.focus();
                  }
                }}
                className={`h-6 cursor-pointer px-2 transition-colors ${
                  severityColor ||
                  (isFocused
                    ? 'bg-[#00FF88]/20 text-[#00FF88] font-semibold'
                    : isCursor
                    ? 'text-[#00FF88] font-medium'
                    : 'text-[#4B5563] hover:text-[#94A3B8]')
                }`}
                title={vuln ? `[${vuln.severity}] ${vuln.title}` : `Line ${lineNum}`}
              >
                {vuln ? (
                  <span className="mr-1 text-[9px]">●</span>
                ) : null}
                {lineNum}
              </div>
            );
          })}
        </div>

        {/* Code View Area */}
        <div className="relative flex-1 overflow-hidden select-text">
          {/* Syntax Highlighted Underlay */}
          <pre
            ref={preRef}
            aria-hidden="true"
            className="pointer-events-none absolute inset-0 m-0 overflow-hidden py-3 px-4 font-mono text-[13px] leading-6 whitespace-pre text-[#F1F5F9]"
            dangerouslySetInnerHTML={{ __html: highlightedCode + '\n' }}
          />

          {/* Vulnerability Highlight Strips */}
          <div className="pointer-events-none absolute inset-0 py-3">
            {Array.from({ length: lineCount }, (_, i) => {
              const lineNum = i + 1;
              const vuln = vulnLineMap.get(lineNum);
              const isFocused = lineNum === focusedLine;

              if (!vuln && !isFocused) {
                return <div key={lineNum} className="h-6" />;
              }

              let bgClass = 'bg-[#00FF88]/10';
              if (vuln) {
                const s = vuln.severity.toLowerCase();
                if (s === 'critical') bgClass = 'bg-red-500/15 border-l-2 border-red-500';
                else if (s === 'high') bgClass = 'bg-orange-500/15 border-l-2 border-orange-500';
                else if (s === 'medium') bgClass = 'bg-amber-500/15 border-l-2 border-amber-500';
                else bgClass = 'bg-emerald-500/15 border-l-2 border-emerald-500';
              }

              return (
                <div
                  key={lineNum}
                  className={`h-6 ${bgClass} transition-colors`}
                />
              );
            })}
          </div>

          {/* Editable Textarea Overlay */}
          <textarea
            ref={textareaRef}
            value={value}
            readOnly={readOnly}
            onChange={(e) => {
              onChange?.(e.target.value);
              updateCursorLine(e.target);
            }}
            onSelect={(e) => updateCursorLine(e.currentTarget)}
            onClick={(e) => updateCursorLine(e.currentTarget)}
            onKeyUp={(e) => updateCursorLine(e.currentTarget)}
            onKeyDown={handleKeyDown}
            onScroll={handleScroll}
            spellCheck={false}
            autoCapitalize="off"
            autoComplete="off"
            autoCorrect="off"
            className="absolute inset-0 h-full w-full resize-none border-0 bg-transparent py-3 px-4 font-mono text-[13px] leading-6 text-transparent caret-[#00FF88] outline-none selection:bg-[#00FF88]/30 whitespace-pre overflow-auto"
            style={{
              tabSize: 4,
            }}
          />
        </div>
      </div>
    );
  }
);

LightweightEditor.displayName = 'LightweightEditor';
