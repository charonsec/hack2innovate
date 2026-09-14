import { useCallback, useEffect, useRef, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import { motion } from 'framer-motion';
import {
  UploadCloud,
  FileCode2,
  Play,
  ShieldCheck,
  ListChecks,
  Zap,
  GitBranch,
  Cpu,
  ShieldAlert,
  Droplets,
  Timer,
  Lock,
  FileWarning,
  LineChart,
  Link2,
  Flame,
  AlertCircle,
} from 'lucide-react';
import { SolidityEditor } from '@/components/editor/SolidityEditor';
import { useAuditStore } from '@/store/auditStore';
import { useAudit } from '@/hooks/useAudit';
import { Button } from '@/components/ui/button';
import { Card, CardContent, CardHeader, CardTitle } from '@/components/ui/card';
import { Input, Label } from '@/components/ui/input';
import { ErrorBoundary } from '@/components/ui/ErrorBoundary';
import { cx, formatFileSize } from '@/utils/format.utils';

const API_URL = '/api';

interface DemoInfo {
  id: string;
  name: string;
  category: 'vulnerable' | 'secure';
  vulnerabilityClasses: string[];
  sourceCode: string;
}

const VULN_TABLE = [
  {
    icon: AlertCircle,
    name: 'Reentrancy',
    swc: 'SWC-107',
    desc: 'External calls before state updates enable recursive drain.',
  },
  {
    icon: AlertCircle,
    name: 'Integer Overflow',
    swc: 'SWC-101',
    desc: 'Arithmetic silently wraps beyond type bounds.',
  },
  {
    icon: Lock,
    name: 'Access Control',
    swc: 'SWC-105',
    desc: 'Sensitive functions callable by any address.',
  },
  {
    icon: FileWarning,
    name: 'Unchecked Return',
    swc: 'SWC-104',
    desc: 'Ignored low-level call results hide failures.',
  },
  {
    icon: Timer,
    name: 'Timestamp Dependence',
    swc: 'SWC-116',
    desc: 'block.timestamp used for fairness or randomness.',
  },
  {
    icon: Droplets,
    name: 'Flash Loan',
    swc: 'N/A',
    desc: 'Unprotected single-transaction borrow surfaces.',
  },
  {
    icon: LineChart,
    name: 'Oracle Manipulation',
    swc: 'SWC-113',
    desc: 'Pricing from manipulable spot sources.',
  },
  {
    icon: ShieldAlert,
    name: 'Front Running',
    swc: 'SWC-114',
    desc: 'No deadline or slippage protection.',
  },
  {
    icon: Link2,
    name: 'Delegatecall',
    swc: 'SWC-112',
    desc: 'Untrusted delegatecall rewrites caller storage.',
  },
  {
    icon: Flame,
    name: 'Self Destruct',
    swc: 'SWC-106',
    desc: 'Destruction reachable by unprivileged callers.',
  },
] as const;

export function HomePage() {
  const navigate = useNavigate();
  const { sourceCode, contractName, setSourceCode, setContractName, setUploadFile, uploadFileName, uploadFileSize } =
    useAuditStore();
  const { startAudit } = useAudit();
  const errorMessage = useAuditStore((s) => s.errorMessage);

  const fileInputRef = useRef<HTMLInputElement>(null);
  const [dragOver, setDragOver] = useState(false);
  const [demos, setDemos] = useState<DemoInfo[]>([]);
  const [selectedDemo, setSelectedDemo] = useState('');

  useEffect(() => {
    fetch(`${API_URL}/demos`)
      .then((r) => (r.ok ? r.json() : []))
      .then((data: DemoInfo[]) => setDemos(data))
      .catch(() => {});
  }, []);

  const handleDemoSelect = useCallback(
    (demoId: string) => {
      setSelectedDemo(demoId);
      const demo = demos.find((d) => d.id === demoId);
      if (demo) {
        setSourceCode(demo.sourceCode);
        setContractName(demo.name);
        setUploadFile(null, null);
      }
    },
    [demos, setSourceCode, setContractName, setUploadFile]
  );

  const handleFiles = useCallback(
    (files: FileList | null) => {
      const file = files?.[0];
      if (!file) return;
      if (!file.name.toLowerCase().endsWith('.sol')) {
        useAuditStore.setState({ errorMessage: 'Please upload a .sol file' });
        return;
      }
      const reader = new FileReader();
      reader.onload = () => {
        let text = String(reader.result ?? '');
        // Strip UTF-8 BOM and markdown code fences if present
        text = text.replace(/^\uFEFF/, '');
        text = text.replace(/^```(?:solidity|sol)?\r?\n/i, '').replace(/\r?\n```\s*$/i, '');
        setSourceCode(text);
        setContractName(file.name.replace(/\.sol$/i, ''));
        setUploadFile(file.name, file.size);
      };
      reader.readAsText(file);
    },
    [setSourceCode, setContractName, setUploadFile]
  );

  const handleAudit = async () => {
    if (sourceCode.trim().length === 0) {
      useAuditStore.setState({ errorMessage: 'Paste a Solidity contract or drop a .sol file.' });
      return;
    }
    try {
      await startAudit({ contractName, sourceCode });
      navigate('/report');
    } catch {
      // error surfaced via store
    }
  };

  return (
    <div className="animate-fade-in space-y-10">
      <div className="space-y-6">
        <div className="space-y-4">
          <motion.div
            initial={{ opacity: 0, y: -6 }}
            animate={{ opacity: 1, y: 0 }}
            className="flex items-center gap-2"
          >
            <ShieldCheck size={18} className="text-[#00FF88]" />
            <span className="font-mono text-sm tracking-widest text-[#00FF88]">
              HEXAUDIT · SMART CONTRACT SECURITY LAB
            </span>
          </motion.div>
          <motion.h1
            initial={{ opacity: 0, y: 10 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.4 }}
            className="text-4xl font-bold text-textPrimary sm:text-5xl"
          >
            Audit Solidity code
            <br />
            <span className="bg-gradient-main bg-clip-text font-mono text-transparent">
              before the exploit does.
            </span>
          </motion.h1>
          <p className="max-w-2xl text-base leading-relaxed text-textSecondary">
            HexAudit parses your contract into an abstract syntax tree and control-flow graph,
            then runs ten detection families that map to SWC identifiers. Every finding includes
            severity, CVSS score, line-level context, and a remediated patch.
          </p>
        </div>

        <Card className="overflow-hidden border-[#00FF88]/30">
          <CardContent className="p-4">
            <div className="flex flex-col gap-4">
              <div className="flex flex-col gap-4 sm:flex-row">
                <div className="flex-1">
                  <Label htmlFor="contract-name">Contract name</Label>
                  <Input
                    id="contract-name"
                    value={contractName}
                    onChange={(e) => setContractName(e.target.value)}
                    placeholder="MyToken"
                    className="mt-1.5 font-mono"
                  />
                </div>
              </div>

              {demos.length > 0 && (
                <div className="space-y-1.5">
                  <Label htmlFor="demo-select" className="text-xs text-textSecondary">
                    Quick demo
                  </Label>
                  <select
                    id="demo-select"
                    value={selectedDemo}
                    onChange={(e) => handleDemoSelect(e.target.value)}
                    className="w-full rounded-md border border-[#2A2D35] bg-surface px-3 py-2 font-mono text-sm text-textPrimary outline-none focus:border-[#00FF88]/60"
                  >
                    <option value="">Load demo contract...</option>
                    <optgroup label="Vulnerable">
                      {demos
                        .filter((d) => d.category === 'vulnerable')
                        .map((d) => (
                          <option key={d.id} value={d.id}>
                            {d.name} — {d.vulnerabilityClasses.join(', ')}
                          </option>
                        ))}
                    </optgroup>
                    <optgroup label="Secure">
                      {demos
                        .filter((d) => d.category === 'secure')
                        .map((d) => (
                          <option key={d.id} value={d.id}>
                            {d.name}
                          </option>
                        ))}
                    </optgroup>
                  </select>
                  <p className="text-[11px] text-textSecondary/60">
                    One-click demo: load a vulnerable contract, then click Run Security Audit.
                  </p>
                </div>
              )}

              <div className="flex flex-col items-start justify-between gap-3 rounded-lg border border-dashed border-[#2A2D35] bg-surface p-4 sm:flex-row sm:items-center"
                onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
                onDragLeave={() => setDragOver(false)}
                onDrop={(e) => { e.preventDefault(); setDragOver(false); handleFiles(e.dataTransfer.files); }}
              >
                <div className="flex items-center gap-2 text-sm text-textSecondary">
                  <UploadCloud size={16} className={cx(dragOver ? 'text-[#00FF88]' : 'text-textSecondary/50')} />
                  {uploadFileName ? (
                    <span className="font-mono text-textPrimary">
                      {uploadFileName}{' '}
                      <span className="text-textSecondary">
                        ({uploadFileSize != null ? formatFileSize(uploadFileSize) : 'unknown'})
                      </span>
                    </span>
                  ) : (
                    <span>Drop a .sol file here, or select one</span>
                  )}
                </div>
                <div className="flex gap-2">
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".sol,text/x-solidity"
                    className="hidden"
                    onChange={(e) => handleFiles(e.target.files)}
                  />
                  <Button variant="outline" size="sm" onClick={() => fileInputRef.current?.click()}>
                    <FileCode2 size={14} />
                    Browse
                  </Button>
                </div>
              </div>

              <div className="overflow-hidden rounded-xl">
                <ErrorBoundary
                  fallbackTitle="Editor failed to load"
                  fallbackMessage="The code editor could not initialize. You can still paste code using the text area below."
                >
                  <SolidityEditor
                    value={sourceCode}
                    onChange={setSourceCode}
                    height={360}
                  />
                </ErrorBoundary>
              </div>

              <div className="flex flex-wrap items-center justify-between gap-3">
                <div className="flex items-center gap-2 text-xs text-textSecondary">
                  <span className="font-mono">{(sourceCode.match(/\n/g) ?? []).length + 1} lines</span>·
                  <span className="font-mono">{(sourceCode.length / 1024).toFixed(1)} KB</span>
                </div>
                <Button size="lg" onClick={handleAudit}>
                  <Play size={16} className="fill-black" />
                  Run Security Audit
                </Button>
              </div>
            </div>
          </CardContent>
        </Card>

        {errorMessage && (
          <div className="flex items-center gap-2 rounded-lg border border-critical/30 bg-critical/5 px-4 py-3 text-sm text-critical">
            <AlertCircle size={16} />
            <span>{errorMessage}</span>
            <button
              onClick={() => useAuditStore.setState({ errorMessage: null })}
              className="ml-auto text-xs opacity-60 hover:opacity-100"
            >
              Dismiss
            </button>
          </div>
        )}

        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          <FeatureCard
            icon={ListChecks}
            title="10 Detection Families"
            desc="Reentrancy, overflow, access control, unchecked calls, timestamp, flash-loan, oracle, front-running, delegatecall, selfdestruct."
          />
          <FeatureCard
            icon={GitBranch}
            title="AST + CFG Analysis"
            desc="Both structural parse trees and control-flow reasoning feed every detector."
          />
          <FeatureCard
            icon={Cpu}
            title="SWC-Classified"
            desc="Each issue maps to its SWC identifier with CVSS v3.1 scoring."
          />
          <FeatureCard
            icon={Zap}
            title="Auto Remediation"
            desc="Remediated patches and a fully hardened secure template for every contract."
          />
        </div>

        <div>
          <h2 className="mb-4 font-mono text-lg font-semibold text-textPrimary">
            Detection Coverage
          </h2>
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-5">
            {VULN_TABLE.map((v) => {
              const Icon = v.icon;
              return (
                <div
                  key={v.name}
                  className="group rounded-lg border border-[#2A2D35] bg-surface p-4 transition-colors hover:border-[#00FF88]/40"
                >
                  <div className="flex items-center gap-2">
                    <Icon size={15} className="text-[#0EA5E9]" />
                    <span className="text-sm font-medium text-textPrimary">{v.name}</span>
                  </div>
                  <p className="mt-1 font-mono text-[11px] text-[#00FF88]">{v.swc}</p>
                  <p className="mt-1.5 text-xs leading-relaxed text-textSecondary">{v.desc}</p>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </div>
  );
}

function FeatureCard({
  icon: Icon,
  title,
  desc,
}: {
  icon: typeof ShieldCheck;
  title: string;
  desc: string;
}) {
  return (
    <Card className="transition-transform hover:translate-y-[-2px]">
      <CardHeader>
        <div className="mb-2 flex h-10 w-10 items-center justify-center rounded-lg border border-[#00FF88]/30 bg-[#00FF88]/10">
          <Icon size={18} className="text-[#00FF88]" />
        </div>
        <CardTitle className="text-sm">{title}</CardTitle>
      </CardHeader>
      <CardContent>
        <p className="text-xs leading-relaxed text-textSecondary">{desc}</p>
      </CardContent>
    </Card>
  );
}