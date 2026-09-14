import { useCallback } from 'react';
import { useAuditStore } from '@/store/auditStore';
import { AuditReport } from '@/types';
import { WSPayload } from '@/types';

const API_URL = '/api';

export interface StartAuditInput {
  contractName: string;
  sourceCode: string;
  contractAddress?: string;
  network?: string;
}

export function useAudit() {
  const {
    setScanStatus,
    updateProgress,
    addLog,
    setReport,
    setError,
    contractName,
  } = useAuditStore();

  const startAudit = useCallback(
    async (input: StartAuditInput): Promise<AuditReport> => {
      setScanStatus('scanning');
      setError(null);
      updateProgress(2, 'Initiating audit request...', 'PARSING');

      try {
        const res = await fetch(`${API_URL}/audit`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            contractName: input.contractName || contractName,
            sourceCode: input.sourceCode,
            contractAddress: input.contractAddress,
            network: input.network,
          }),
        });

        if (!res.ok) {
          const err = await res.json().catch(() => ({ error: res.statusText }));
          throw new Error(err.error ?? `HTTP ${res.status}`);
        }

        const report = (await res.json()) as AuditReport;
        setReport(report);
        setScanStatus('complete');
        updateProgress(100, 'Audit complete.', 'COMPLETE');
        return report;
      } catch (e) {
        const msg = e instanceof Error ? e.message : 'Unknown audit error';
        setError(msg);
        setScanStatus('error');
        throw e;
      }
    },
    [contractName, setError, setReport, setScanStatus, updateProgress]
  );

  const handleWSEvent = useCallback(
    (payload: WSPayload) => {
      if (payload.stage && payload.progress != null) {
        updateProgress(
          payload.progress,
          payload.message ?? '',
          payload.stage,
          payload.data
        );
      } else if (payload.type === 'connected') {
        addLog({ stage: 'WS', message: payload.message ?? 'connected', progress: 0 });
      }
    },
    [addLog, updateProgress]
  );

  const fetchReport = useCallback(
    async (reportId: string): Promise<AuditReport | null> => {
      try {
        const res = await fetch(`${API_URL}/report/${reportId}`);
        if (!res.ok) return null;
        const report = (await res.json()) as AuditReport;
        setReport(report);
        setScanStatus('complete');
        return report;
      } catch {
        return null;
      }
    },
    [setReport, setScanStatus]
  );

  const fetchTemplates = useCallback(async () => {
    const res = await fetch(`${API_URL}/templates`);
    if (!res.ok) throw new Error('Failed to load templates');
    return (await res.json()) as Array<{
      id: string;
      name: string;
      description: string;
      solidityVersion: string;
      sourceCode: string;
    }>;
  }, []);

  return {
    startAudit,
    handleWSEvent,
    fetchReport,
    fetchTemplates,
  };
}