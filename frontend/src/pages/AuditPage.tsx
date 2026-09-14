import { useCallback, useRef } from 'react';
import { useNavigate } from 'react-router-dom';
import { Play, Loader2, ArrowRight, FileCode2 } from 'lucide-react';
import { useAuditStore } from '@/store/auditStore';
import { useAudit } from '@/hooks/useAudit';
import { useWebSocket } from '@/hooks/useWebSocket';
import { SolidityEditor, SolidityEditorHandle } from '@/components/editor/SolidityEditor';
import { ScanConsole } from '@/components/audit/ScanConsole';
import { FindingsList } from '@/components/audit/FindingsList';
import { Button } from '@/components/ui/button';
import { ErrorBoundary } from '@/components/ui/ErrorBoundary';
import { motion, AnimatePresence } from 'framer-motion';

export function AuditPage() {
  const navigate = useNavigate();
  const {
    sourceCode,
    contractName,
    setSourceCode,
    scanStatus,
    report,
    setReport,
    setScanStatus,
    selectVulnerability,
    selectedVulnerability,
  } = useAuditStore();

  const { startAudit, handleWSEvent } = useAudit();
  useWebSocket({ enabled: scanStatus === 'scanning', onMessage: handleWSEvent });

  const editorRef = useRef<SolidityEditorHandle>(null);

  const handleAudit = useCallback(async () => {
    if (scanStatus === 'scanning') return;
    setScanStatus('scanning');
    setReport(null);
    selectVulnerability(null);

    await startAudit({ contractName, sourceCode });
  }, [scanStatus, setScanStatus, setReport, selectVulnerability, startAudit, contractName, sourceCode]);

  const handleVulnSelect = (vuln: Parameters<typeof selectVulnerability>[0]) => {
    selectVulnerability(vuln);
    if (vuln && editorRef.current) {
      editorRef.current.revealLine(vuln.lineStart);
    }
  };

  return (
    <div className="animate-fade-in space-y-5">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-lg border border-[#00FF88]/30 bg-[#00FF88]/10">
            <FileCode2 size={18} className="text-[#00FF88]" />
          </div>
          <div>
            <h1 className="font-mono text-lg font-bold text-textPrimary">{contractName}</h1>
            <p className="font-mono text-xs text-textSecondary">
              {scanStatus === 'complete' && report
                ? `scan complete · ${report.summary.total} findings`
                : scanStatus === 'scanning'
                  ? 'scanning…'
                  : 'ready'}
            </p>
          </div>
        </div>

        <AnimatePresence>
          {scanStatus !== 'scanning' && (
            <motion.div
              initial={{ opacity: 0, scale: 0.95 }}
              animate={{ opacity: 1, scale: 1 }}
              exit={{ opacity: 0 }}
              className="flex items-center gap-2"
            >
              {scanStatus === 'complete' && report && (
                <Button variant="outline" size="lg" onClick={() => navigate('/report')}>
                  Full Report <ArrowRight size={16} />
                </Button>
              )}
              <Button size="lg" onClick={handleAudit} variant={scanStatus === 'complete' ? 'ghost' : 'default'}>
                {scanStatus === 'error' ? (
                  <>
                    <ArrowRight size={16} /> Retry Scan
                  </>
                ) : (
                  <>
                    <Play size={16} className="fill-black" />
                    {scanStatus === 'complete' ? 'Rescan' : 'Start Scan'}
                  </>
                )}
              </Button>
            </motion.div>
          )}
          {scanStatus === 'scanning' && (
            <motion.div
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
            >
              <Button size="lg" variant="secondary" disabled>
                <Loader2 size={16} className="animate-spin" />
                Scanning…
              </Button>
            </motion.div>
          )}
        </AnimatePresence>
      </div>

      <div className="grid h-[calc(100vh-220px)] min-h-[480px] gap-5 lg:grid-cols-2">
        <div className="flex min-w-0 flex-col gap-3">
          <div className="flex items-center justify-between">
            <span className="px-1 font-mono text-xs uppercase tracking-widest text-textSecondary">
              source
            </span>
            <span className="px-1 font-mono text-xs text-textSecondary">
              {(sourceCode.match(/\n/g) ?? []).length + 1} lines
            </span>
          </div>
          <div className="min-h-0 flex-1">
            <ErrorBoundary
              fallbackTitle="Editor failed to load"
              fallbackMessage="The code editor could not initialize."
            >
              <SolidityEditor
                ref={editorRef}
                value={sourceCode}
                onChange={setSourceCode}
                readOnly={scanStatus === 'scanning'}
                height="100%"
                focusedLine={selectedVulnerability?.lineStart ?? null}
                vulnerabilities={report?.vulnerabilities ?? []}
              />
            </ErrorBoundary>
          </div>
        </div>

        <div className="flex min-h-0 flex-col gap-3">
          <span className="px-1 font-mono text-xs uppercase tracking-widest text-textSecondary">
            scan engine
          </span>
          <div className="min-h-[220px]">
            <ScanConsole />
          </div>

          {report && scanStatus === 'complete' && (
            <div className="flex-1 overflow-hidden rounded-xl border border-[#2A2D35] bg-[#0D0F13] p-4">
              <FindingsList
                vulnerabilities={report.vulnerabilities}
                selectedId={selectedVulnerability?.id ?? null}
                onSelect={handleVulnSelect}
              />
            </div>
          )}
        </div>
      </div>
    </div>
  );
}