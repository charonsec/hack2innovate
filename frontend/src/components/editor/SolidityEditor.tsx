import {
  forwardRef,
  useEffect,
  useImperativeHandle,
  useRef,
  useState,
} from 'react';
import Editor, { BeforeMount, OnMount, loader } from '@monaco-editor/react';
import type * as Monaco from 'monaco-editor';
import { Code2, Zap, AlertCircle } from 'lucide-react';
import { Vulnerability } from '@/types';
import { LightweightEditor } from './LightweightEditor';
import MonacoWorker from '@/monaco-worker?worker';

// Provide the local web worker to avoid 404s when Monaco spawns editorWorkerService
if (typeof self !== 'undefined') {
  self.MonacoEnvironment = {
    getWorker: () => new MonacoWorker(),
  };
}

// Bundle Monaco locally (separate chunk) instead of fetching it from a CDN at
// runtime — a blocked/slow CDN used to leave the editor stuck on "Loading…".
let monacoConfigPromise: Promise<void> | null = null;
function configureBundledMonaco(): Promise<void> {
  if (!monacoConfigPromise) {
    monacoConfigPromise = import('monaco-editor')
      .then((monaco) => loader.config({ monaco: monaco as unknown as typeof Monaco }))
      .catch((err) => {
        console.warn('[SolidityEditor] Failed to load bundled Monaco:', err);
      });
  }
  return monacoConfigPromise;
}
configureBundledMonaco();

const MONACO_FALLBACK_TIMEOUT_MS = 8000;

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
  showModeToggle?: boolean;
}

interface DecorationTriplet {
  range: Monaco.Range;
  options: Monaco.editor.IModelDecorationOptions;
}

interface SafeDecorationCollection {
  set: (decorations: DecorationTriplet[]) => void;
  clear: () => void;
}

function initDecorationCollection(
  editor: Monaco.editor.IStandaloneCodeEditor
): SafeDecorationCollection {
  if (typeof editor.createDecorationsCollection === 'function') {
    const col = editor.createDecorationsCollection();
    return {
      set: (decs) => col.set(decs),
      clear: () => col.clear(),
    };
  }
  // Fallback to deltaDecorations if createDecorationsCollection is not available
  let oldIds: string[] = [];
  return {
    set: (decs) => {
      try {
        oldIds = editor.deltaDecorations(oldIds, decs);
      } catch (err) {
        console.warn('[SolidityEditor] deltaDecorations error:', err);
      }
    },
    clear: () => {
      try {
        oldIds = editor.deltaDecorations(oldIds, []);
      } catch (err) {
        console.warn('[SolidityEditor] deltaDecorations clear error:', err);
      }
    },
  };
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
      showModeToggle = true,
    },
    ref
  ) => {
    const editorRef = useRef<Monaco.editor.IStandaloneCodeEditor | null>(null);
    const decorationRef = useRef<SafeDecorationCollection | null>(null);
    const monacoRef = useRef<typeof Monaco | null>(null);
    const lightweightRef = useRef<SolidityEditorHandle | null>(null);

    const [mode, setMode] = useState<'monaco' | 'lightweight'>('monaco');
    const [monacoFailed, setMonacoFailed] = useState<boolean>(false);
    // The Editor must not mount before loader.config() resolves, otherwise
    // @monaco-editor/react races ahead with its default CDN configuration.
    const [monacoBundled, setMonacoBundled] = useState(false);

    useEffect(() => {
      let alive = true;
      configureBundledMonaco().then(() => {
        if (alive) setMonacoBundled(true);
      });
      return () => {
        alive = false;
      };
    }, []);

    // If Monaco never mounts (slow/failed loader), fall back to the lightweight
    // editor automatically instead of showing "Loading…" forever.
    useEffect(() => {
      if (mode !== 'monaco' || monacoFailed) return;
      const timer = setTimeout(() => {
        if (!editorRef.current) {
          console.warn('[SolidityEditor] Monaco did not mount in time — switching to Lightweight editor');
          setMonacoFailed(true);
          setMode('lightweight');
        }
      }, MONACO_FALLBACK_TIMEOUT_MS);
      return () => clearTimeout(timer);
    }, [mode, monacoFailed]);

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
        if (mode === 'lightweight' || monacoFailed) {
          lightweightRef.current?.revealLine(line);
          return;
        }
        const editor = editorRef.current;
        if (!editor) {
          lightweightRef.current?.revealLine(line);
          return;
        }
        try {
          editor.revealLineInCenter(line);
          editor.setPosition({ lineNumber: line, column: 1 });
          editor.focus();
        } catch {
          lightweightRef.current?.revealLine(line);
        }
      },
      getEditor: () => {
        if (mode === 'lightweight' || monacoFailed) {
          return lightweightRef.current?.getEditor() ?? null;
        }
        const editor = editorRef.current;
        if (!editor) return lightweightRef.current?.getEditor() ?? null;
        return {
          revealLineInCenter: (line: number) => editor.revealLineInCenter(line),
          focus: () => editor.focus(),
        };
      },
      setDecorationsFor: (vulns: Vulnerability[]) => {
        if (mode === 'lightweight' || monacoFailed) {
          lightweightRef.current?.setDecorationsFor(vulns);
          return;
        }
        const editor = editorRef.current;
        const monaco = monacoRef.current;
        if (!editor || !monaco) {
          lightweightRef.current?.setDecorationsFor(vulns);
          return;
        }
        try {
          if (!decorationRef.current) {
            decorationRef.current = initDecorationCollection(editor);
          }
          decorationRef.current.clear();
          decorationRef.current.set(buildDecorations(monaco, editor, vulns));
        } catch (err) {
          console.warn('[SolidityEditor] Failed to set decorations:', err);
        }
      },
    }));

    const handleBeforeMount: BeforeMount = (monaco) => {
      try {
        registerSolidityLanguage(monaco);
      } catch (err) {
        console.warn('[SolidityEditor] registerSolidityLanguage error:', err);
      }
    };

    const handleMount: OnMount = (editor, monaco) => {
      try {
        editorRef.current = editor;
        monacoRef.current = monaco;

        // Correct API: call createDecorationsCollection on the editor instance, with fallback
        decorationRef.current = initDecorationCollection(editor);

        try {
          monaco.editor.setTheme('hexaudit-dark');
        } catch {
          // ignore theme fallback
        }

        editor.onDidChangeCursorPosition((e) => {
          const line = e.position.lineNumber;
          const vuln = vulnerabilities.find(
            (v) => line >= v.lineStart && line <= Math.max(v.lineStart, v.lineEnd)
          );
          onLineClick?.(vuln ?? null);
        });

        if (vulnerabilities.length > 0) {
          decorationRef.current.set(buildDecorations(monaco, editor, vulnerabilities));
        }
      } catch (err) {
        console.error('[SolidityEditor] Monaco onMount failed, falling back to LightweightEditor:', err);
        setMonacoFailed(true);
        setMode('lightweight');
      }
    };

    useEffect(() => {
      if (!focusedLine) return;
      if (mode === 'lightweight' || monacoFailed) {
        lightweightRef.current?.revealLine(focusedLine);
      } else if (editorRef.current) {
        try {
          editorRef.current.revealLineInCenter(focusedLine);
        } catch {
          // ignore
        }
      }
    }, [focusedLine, mode, monacoFailed]);

    const formattedHeight = typeof height === 'number' ? `${height}px` : height;
    const isPercentHeight = typeof height === 'string' && height.includes('%');

    const monacoOptions: Monaco.editor.IStandaloneEditorConstructionOptions = {
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
    };

    const monacoEditor = monacoBundled ? (
      <Editor
        height={formattedHeight}
        defaultLanguage="solidity"
        language="solidity"
        theme="hexaudit-dark"
        value={value}
        beforeMount={handleBeforeMount}
        onChange={(next) => onChange?.(next ?? '')}
        onMount={handleMount}
        options={monacoOptions}
      />
    ) : (
      <div className="flex h-full items-center justify-center text-xs text-textSecondary">
        loading editor…
      </div>
    );

    return (
      <div className="group relative flex h-full min-h-0 flex-col overflow-hidden rounded-xl border border-[#2A2D35] bg-[#0D0F13]">
        {/* Editor Toolbar Header */}
        {showModeToggle && (
          <div className="flex h-9 shrink-0 items-center justify-between border-b border-[#2A2D35]/80 bg-[#111318] px-3 text-xs">
            <div className="flex items-center gap-2 text-textSecondary">
              <span className="font-mono font-medium text-textPrimary">Solidity</span>
              <span className="text-[10px] text-textSecondary/60">0.8.x</span>
              {monacoFailed && (
                <span className="flex items-center gap-1 rounded bg-amber-500/15 px-1.5 py-0.5 text-[10px] text-amber-400">
                  <AlertCircle size={10} />
                  Monaco unavailable — using Lightweight editor
                </span>
              )}
            </div>

            <div className="flex items-center gap-1">
              <button
                type="button"
                onClick={() => setMode('monaco')}
                disabled={monacoFailed}
                className={`flex items-center gap-1.5 rounded px-2 py-0.5 text-[11px] font-medium transition-all ${
                  mode === 'monaco' && !monacoFailed
                    ? 'bg-[#00FF88]/15 text-[#00FF88] border border-[#00FF88]/30 shadow-sm'
                    : 'text-textSecondary hover:text-textPrimary hover:bg-surface/50 disabled:opacity-40 disabled:cursor-not-allowed'
                }`}
                title="Monaco IDE: full syntax highlighting, minimap, rich diagnostics"
              >
                <Code2 size={12} />
                Monaco IDE
              </button>

              <button
                type="button"
                onClick={() => setMode('lightweight')}
                className={`flex items-center gap-1.5 rounded px-2 py-0.5 text-[11px] font-medium transition-all ${
                  mode === 'lightweight' || monacoFailed
                    ? 'bg-[#00FF88]/15 text-[#00FF88] border border-[#00FF88]/30 shadow-sm'
                    : 'text-textSecondary hover:text-textPrimary hover:bg-surface/50'
                }`}
                title="Lightweight editor: zero-dependency, instant load, fast typing"
              >
                <Zap size={12} />
                Lightweight
              </button>
            </div>
          </div>
        )}

        {/* Editor Body — the wrapper must have a definite height for Monaco's
            percentage height to resolve (fixes the collapsed 5px editor). */}
        {mode === 'monaco' && !monacoFailed ? (
          <div className="relative min-h-0 flex-1">
            {isPercentHeight ? (
              <div className="absolute inset-0">{monacoEditor}</div>
            ) : (
              monacoEditor
            )}
          </div>
        ) : (
          <LightweightEditor
            ref={lightweightRef}
            value={value}
            onChange={onChange}
            readOnly={readOnly}
            height={height}
            vulnerabilities={vulnerabilities}
            onLineClick={onLineClick}
            focusedLine={focusedLine}
          />
        )}
      </div>
    );
  }
);

SolidityEditor.displayName = 'SolidityEditor';