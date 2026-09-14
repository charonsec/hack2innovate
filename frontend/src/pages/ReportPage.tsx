import { Link, useParams } from 'react-router-dom';
import { FileSearch, ArrowLeft } from 'lucide-react';
import { AuditReport as AuditReportView } from '@/components/report/AuditReport';
import { useAuditStore } from '@/store/auditStore';
import { useAudit } from '@/hooks/useAudit';
import { useEffect, useState } from 'react';
import { Button } from '@/components/ui/button';
import { AuditReport } from '@/types';

export function ReportPage() {
  const { reportId } = useParams<{ reportId: string }>();
  const report = useAuditStore((s) => s.report);
  const scanStatus = useAuditStore((s) => s.scanStatus);
  const setReport = useAuditStore((s) => s.setReport);
  const setScanStatus = useAuditStore((s) => s.setScanStatus);
  const { fetchReport } = useAudit();

  const [loading, setLoading] = useState(false);
  const [notFound, setNotFound] = useState(false);

  useEffect(() => {
    if (reportId && !report) {
      setLoading(true);
      fetchReport(reportId)
        .then((remote) => {
          if (!remote) setNotFound(true);
        })
        .finally(() => setLoading(false));
    }
  }, [reportId, report, fetchReport]);

  useEffect(() => {
    if (!report) return;
    setReport(report);
    setScanStatus('complete');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  if (loading) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 py-40">
        <div className="h-8 w-8 animate-spin rounded-full border-2 border-[#00FF88] border-t-transparent" />
        <p className="text-sm text-textSecondary">Loading report…</p>
      </div>
    );
  }

  const active = (report ?? null) as AuditReport | null;

  if (!active) {
    return (
      <div className="flex flex-col items-center justify-center gap-4 py-40 text-center">
        <div className="flex h-16 w-16 items-center justify-center rounded-2xl border border-[#2A2D35] bg-surface">
          <FileSearch size={28} className="text-textSecondary" />
        </div>
        <div>
          <h1 className="text-lg font-semibold text-textPrimary">No report in memory</h1>
          <p className="mt-1 max-w-sm text-sm text-textSecondary">
            {notFound
              ? `Report ${reportId ?? ''} was not found on the server. Run a new audit to generate one.`
              : 'Run a security audit first, then return here to view the full report.'}
          </p>
        </div>
        <Link to="/">
          <Button>
            <ArrowLeft size={15} />
            Run an Audit
          </Button>
        </Link>
      </div>
    );
  }

  return <AuditReportView report={active} />;
}