import { useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Terminal, CheckCircle2, XCircle, Activity } from 'lucide-react';
import { useAuditStore } from '@/store/auditStore';
import { cx, formatTime } from '@/utils/format.utils';
import { ScanStatus } from '@/types';

function StatusBadge({ status, progress }: { status: ScanStatus; progress: number }) {
  if (status === 'scanning') {
    return (
      <span className="flex items-center gap-1.5 text-xs font-mono text-[#0EA5E9]">
        <Activity size={12} className="animate-pulse" />
        {progress}%
      </span>
    );
  }
  if (status === 'complete') {
    return (
      <span className="flex items-center gap-1.5 text-xs font-mono text-[#00FF88]">
        <CheckCircle2 size={12} />
        complete
      </span>
    );
  }
  if (status === 'error') {
    return (
      <span className="flex items-center gap-1.5 text-xs font-mono text-critical">
        <XCircle size={12} />
        error
      </span>
    );
  }
  return (
    <span className="flex items-center gap-1.5 text-xs font-mono text-textSecondary">
      <span className="h-1.5 w-1.5 rounded-full bg-textSecondary" />
      idle
    </span>
  );
}

const STAGE_TEXT: Record<string, string> = {
  PARSING: 'Parsing source & building AST…',
  EVALUATION: 'Walking state mutations…',
  CFG: 'Building control-flow graph…',
  ANALYSIS: 'Running detection rules…',
  REMEDIATION: 'Generating remediation…',
  GAS: 'Optimizing gas & scoring…',
  COMPLETE: 'Audit complete',
};

export function ScanConsole() {
  const logs = useAuditStore((s) => s.scanLogs);
  const status = useAuditStore((s) => s.scanStatus);
  const progress = useAuditStore((s) => s.scanProgress);
  const containerRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (containerRef.current) {
      containerRef.current.scrollTop = containerRef.current.scrollHeight;
    }
  }, [logs.length]);

  const lastStage = logs.length > 0 ? logs[logs.length - 1].stage : status === 'complete' ? 'COMPLETE' : '';

  return (
    <div className="flex h-full flex-col overflow-hidden rounded-xl border border-[#2A2D35] bg-[#0A0B0D]">
      <div className="flex items-center justify-between border-b border-[#2A2D35] px-4 py-2.5">
        <div className="flex items-center gap-2">
          <Terminal size={14} className="text-[#00FF88]" />
          <span className="font-mono text-xs text-textSecondary">hex-scan · live console</span>
        </div>
        <div className="flex items-center gap-2">
          <StatusBadge status={status} progress={progress} />
        </div>
      </div>

      <div ref={containerRef} className="flex-1 overflow-y-auto px-4 py-3 font-mono text-xs leading-relaxed">
        <AnimatePresence initial={false}>
          {logs.map((log) => (
            <motion.div
              key={log.id}
              initial={{ opacity: 0, y: 6 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.15 }}
              className="flex gap-3"
            >
              <span className="shrink-0 text-textSecondary/50">
                {formatTime(log.timestamp)}
              </span>
              <span className="shrink-0 w-24 text-[#0EA5E9]">{log.stage}</span>
              <span className="text-textPrimary/90">{log.message}</span>
              <span
                className={cx(
                  'ml-auto shrink-0 font-mono',
                  log.progress === 100 ? 'text-[#00FF88]' : 'text-textSecondary/60'
                )}
              >
                {log.progress}%
              </span>
            </motion.div>
          ))}
        </AnimatePresence>

        {status === 'scanning' && lastStage && STAGE_TEXT[lastStage] && (
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            className="flex gap-3 text-textSecondary"
          >
            <span className="shrink-0 text-textSecondary/50">—:—:—</span>
            <span className="shrink-0 w-24 text-[#0EA5E9]">{lastStage}</span>
            <span className="flex items-center gap-1.5">
              <span className="animate-pulse">▊▊▊▊▊</span>
              {STAGE_TEXT[lastStage]}
            </span>
            <span className="ml-auto">{progress}%</span>
          </motion.div>
        )}

        {logs.length === 0 && (
          <p className="text-textSecondary/50">
            system ready. input source and run <span className="text-[#00FF88]">audit</span> to begin…
          </p>
        )}
      </div>

      <div className="h-1 bg-surface2">
        <motion.div
          className="h-full bg-gradient-main shadow-glow"
          animate={{ width: `${Math.min(100, Math.max(0, progress))}%` }}
          transition={{ duration: 0.3 }}
        />
      </div>
    </div>
  );
}