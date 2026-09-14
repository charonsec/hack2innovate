import { forwardRef, useEffect, useImperativeHandle, useRef } from 'react';
import Editor, { BeforeMount, OnMount } from '@monaco-editor/react';
import type * as Monaco from 'monaco-editor';
import { Vulnerability } from '@/types';

export interface SolidityEditorHandle {
  revealLine: (line: number) => void;
  getEditor: () => {
    revealLineInCenter: (line: number) => void;
    focus: () => void;
  } | null;
  setDecorationsFor: (vulnerabilities: Vulnerability[]) => void;
}

interface SolidityEditorProps {
  value: string;
  onChange?: (value: string) => void;
  readOnly?: boolean;
  height?: number | string;
  vulnerabilities?: Vulnerability[];
  onLineClick?: (vulnerability: Vulnerability | null) => void;
  focusedLine?: number | null;
}

interface DecorationTriplet {
  range: Monaco.Range;
  options: Monaco.editor.IModelDecorationOptions;
}

let themeRegistered = false;

// Monarch tokenizer + theme. Accepts the Monaco instance owned by @monaco-editor/react
// so all editors (including the CDN-loaded copy) get the same registration.
export function registerSolidityLanguage(monaco: typeof Monaco): void {
  const id = 'solidity';
  const exists = monaco.languages.getLanguages().some((l) => l.id === id);
  if (!exists) {
    monaco.languages.register({ id, extensions: ['.sol'], aliases: ['Solidity'] });
    monaco.languages.setMonarchTokensProvider(id, {
      keywords: [
        'pragma', 'contract', 'library', 'interface', 'using', 'for', 'function',
        'mapping', 'struct', 'enum', 'event', 'modifier', 'error', 'revert',
        'public', 'private', 'internal', 'external', 'view', 'pure', 'payable',
        'returns', 'return', 'require', 'assert', 'emit', 'memory', 'storage',
        'calldata', 'if', 'else', 'while', 'do', 'break', 'continue',
        'new', 'delete', 'this', 'selfdestruct', 'immutable', 'constant',
        'unchecked', 'try', 'catch', 'is', 'address', 'bytes',
      ],
      typeKeywords: [
        'uint', 'uint8', 'uint16', 'uint24', 'uint32', 'uint40', 'uint48', 'uint56',
        'uint64', 'uint72', 'uint80', 'uint88', 'uint96', 'uint104', 'uint112',
        'uint120', 'uint128', 'uint136', 'uint144', 'uint152', 'uint160', 'uint168',
        'uint176', 'uint184', 'uint192', 'uint200', 'uint208', 'uint216', 'uint224',
        'uint232', 'uint240', 'uint248', 'uint256',
        'int', 'int8', 'int16', 'int32', 'int64', 'int128', 'int256',
        'bool', 'string', 'bytes4', 'bytes32', 'var', 'fixed', 'ufixed',
      ],
      tokenizer: {
        root: [
          [/\/\/.*$/, 'comment'],
          [/\/\*/, 'comment', '@comment'],
          [/[{}()[\]]/, '@brackets'],
          [/\d+/, 'number'],
          [/[a-zA-Z_$][\w$]*/, {
            cases: {
              '@keywords': 'keyword',
              '@typeKeywords': 'type',
              '@default': 'identifier',
            },
          }],
          [/"[^"]*"/, 'string'],
          [/'.*'/, 'string'],
          [/[=><+\-*/%!&|^~?:;,.]+/, 'delimiter'],
        ],
        comment: [
          [/[^*/]+/, 'comment'],
          [/\*\//, 'comment', '@pop'],
          [/[*\/]/, 'comment'],
        ],
      },
    });
  }

  const themeExists = themeRegistered;
  if (!themeExists) {
    themeRegistered = true;
    monaco.editor.defineTheme('hexaudit-dark', {
      base: 'vs-dark',
      inherit: true,
      rules: [
        { token: 'keyword', foreground: '00FF88', fontStyle: 'bold' },
        { token: 'type', foreground: '0EA5E9' },
        { token: 'comment', foreground: '6B7280', fontStyle: 'italic' },
        { token: 'string', foreground: 'FDE047' },
        { token: 'number', foreground: '8B5CF6' },
        { token: 'delimiter', foreground: '94A3B8' },
        { token: 'identifier', foreground: 'F1F5F9' },
      ],
      colors: {
        'editor.background': '#0D0F13',
        'editor.foreground': '#F1F5F9',
        'editor.lineHighlightBackground': '#1A1D25',
        'editorLineNumber.foreground': '#4B5563',
        'editorLineNumber.activeForeground': '#00FF88',
        'editorCursor.foreground': '#00FF88',
        'editorIndentGuide.background': '#2A2D35',
        'editorWidget.background': '#111318',
        'editorWidget.border': '#2A2D35',
        'minimap.background': '#0A0B0D',
        'scrollbarSlider.background': '#2A2D3580',
      },
    });
  }
}

export const SolidityEditor = forwardRef<SolidityEditorHandle, SolidityEditorProps>(
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
    const editorRef = useRef<Monaco.editor.IStandaloneCodeEditor | null>(null);
    const decorationRef = useRef<Monaco.editor.IEditorDecorationsCollection | null>(null);
    const monacoRef = useRef<typeof Monaco | null>(null);

    const buildDecorations = (
      monaco: typeof Monaco,
      editor: Monaco.editor.IStandaloneCodeEditor,
      vulns: Vulnerability[]
    ): DecorationTriplet[] => {
      const model = editor.getModel();
      if (!model || vulns.length === 0) return [];

      const decorations: DecorationTriplet[] = [];
      for (const v of vulns) {
        const startLine = Math.max(1, v.lineStart);
        const endLine = Math.max(startLine, v.lineEnd);
        decorations.push({
          range: new monaco.Range(
            startLine,
            1,
            endLine,
            model.getLineMaxColumn(endLine)
          ),
          options: {
            isWholeLine: true,
            className: `vuln-line vuln-${v.severity.toLowerCase()}`,
            glyphMarginClassName: `vuln-glyph vuln-glyph-${v.severity.toLowerCase()}`,
            hoverMessage: {
              value: `**${v.severity} · ${v.swcId}** — ${v.title}\n\n${v.description}`,
            },
            linesDecorationsClassName: `vuln-gutter vuln-gutter-${v.severity.toLowerCase()}`,
          },
        });
      }
      return decorations;
    };

    useImperativeHandle(ref, () => ({
      revealLine: (line: number) => {
        const editor = editorRef.current;
        if (!editor) return;
        editor.revealLineInCenter(line);
        editor.setPosition({ lineNumber: line, column: 1 });
        editor.focus();
      },
      getEditor: () => editorRef.current,
      setDecorationsFor: (vulns: Vulnerability[]) => {
        const editor = editorRef.current;
        const monaco = monacoRef.current;
        if (!editor || !decorationRef.current || !monaco) return;
        decorationRef.current.clear();
        decorationRef.current.set(buildDecorations(monaco, editor, vulns));
      },
    }));

    const handleBeforeMount: BeforeMount = (monaco) => {
      registerSolidityLanguage(monaco);
    };

    const handleMount: OnMount = (editor, monaco) => {
      editorRef.current = editor;
      monacoRef.current = monaco;
      decorationRef.current = monaco.editor.createDecorationsCollection(editor);

      monaco.editor.setTheme('hexaudit-dark');

      editor.onDidChangeCursorPosition((e) => {
        const line = e.position.lineNumber;
        const vuln = vulnerabilities.find(
          (v) => line >= v.lineStart && line <= Math.max(v.lineStart, v.lineEnd)
        );
        onLineClick?.(vuln ?? null);
      });

      if (vulnerabilities.length > 0) {
        const collection =
          decorationRef.current ??
          (decorationRef.current = monaco.editor.createDecorationsCollection(editor));
        collection.set(buildDecorations(monaco, editor, vulnerabilities));
      }
    };

    useEffect(() => {
      if (!focusedLine || !editorRef.current) return;
      editorRef.current.revealLineInCenter(focusedLine);
    }, [focusedLine]);

    return (
      <div className="relative overflow-hidden rounded-xl border border-[#2A2D35] bg-[#0D0F13]">
        <Editor
          height={height}
          defaultLanguage="solidity"
          language="solidity"
          theme="hexaudit-dark"
          value={value}
          beforeMount={handleBeforeMount}
          onChange={(next) => onChange?.(next ?? '')}
          onMount={handleMount}
          options={{
            readOnly,
            minimap: { enabled: true, renderCharacters: false, maxColumn: 80 },
            fontSize: 13,
            fontFamily: 'JetBrains Mono, monospace',
            lineNumbers: 'on',
            glyphMargin: true,
            folding: true,
            automaticLayout: true,
            scrollBeyondLastLine: false,
            renderLineHighlight: 'all',
            padding: { top: 12, bottom: 12 },
            suggestOnTriggerCharacters: true,
            tabSize: 4,
            wordWrap: 'off',
            hideCursorInOverviewRuler: true,
            overviewRulerBorder: false,
            scrollbar: {
              verticalScrollbarSize: 10,
              horizontalScrollbarSize: 10,
            },
            smoothScrolling: true,
            cursorBlinking: 'smooth',
          }}
        />
      </div>
    );
  }
);
SolidityEditor.displayName = 'SolidityEditor';