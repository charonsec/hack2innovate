import { motion } from 'framer-motion';
import { FileCode2, Clock, Ruler, Cpu, ShieldAlert } from 'lucide-react';
import { AuditReport } from '@/types';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent } from '@/components/ui/card';
import { severityColorHex, riskLabelColor } from '@/utils/severity.utils';
import { formatDate, formatDuration } from '@/utils/format.utils';

export interface ReportHeaderProps {
  report: AuditReport;
}

export function ReportHeader({ report }: ReportHeaderProps) {
  const riskColor = severityColorHex(report.overallRiskLabel as never) ?? riskLabelColor(report.overallRiskLabel);

  return (
    <Card className="overflow-hidden">
      <div className="relative border-b border-[#2A2D35] bg-gradient-to-br from-[#10141A] via-[#0D0F13] to-[#0A0B0D] px-6 py-6">
        <div className="absolute inset-x-0 top-0 h-1 bg-gradient-main" />
        <div
          className="absolute -right-8 -top-8 h-40 w-40 rounded-full opacity-20 blur-3xl"
          style={{ background: riskColor }}
        />
        <div className="flex flex-col gap-6 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <div className="flex items-center gap-2">
              <FileCode2 size={18} className="text-[#00FF88]" />
              <span className="font-mono text-xs uppercase tracking-widest text-textSecondary">
                Audit Report
              </span>
            </div>
            <motion.h1
              initial={{ opacity: 0, y: 8 }}
              animate={{ opacity: 1, y: 0 }}
              className="mt-3 font-mono text-2xl font-bold text-textPrimary"
            >
              {report.contractName}
              <span className="ml-2 text-lg text-textSecondary">.sol</span>
            </motion.h1>
            <p className="mt-1 font-mono text-xs text-textSecondary">{report.reportId}</p>

            <div className="mt-4 flex flex-wrap items-center gap-x-5 gap-y-2 text-sm text-textSecondary">
              <span className="flex items-center gap-1.5">
                <Clock size={14} /> {formatDate(report.timestamp)}
              </span>
              <span className="flex items-center gap-1.5">
                <Ruler size={14} /> {report.linesOfCode} LOC
              </span>
              <span className="flex items-center gap-1.5">
                <Cpu size={14} /> {report.solcVersion}
              </span>
              <span className="flex items-center gap-1.5">
                <ShieldAlert size={14} /> {formatDuration(report.scanDuration)} scan
              </span>
            </div>
          </div>

          <RiskGauge score={report.overallRiskScore} label={report.overallRiskLabel} />

          <div className="flex flex-col items-center gap-2 lg:items-end">
            <div className="flex flex-wrap gap-2">
              <Badge variant="success">{report.summary.total} total</Badge>
              {report.summary.critical > 0 && <Badge variant="critical">{report.summary.critical} critical</Badge>}
              {report.summary.high > 0 && <Badge variant="high">{report.summary.high} high</Badge>}
              {report.summary.medium > 0 && <Badge variant="medium">{report.summary.medium} medium</Badge>}
              {report.summary.low > 0 && <Badge variant="low">{report.summary.low} low</Badge>}
              {report.summary.informational > 0 && <Badge variant="info">{report.summary.informational} info</Badge>}
            </div>
            <div className="mt-1 text-center">
              <span className="font-mono text-xs text-textSecondary">contract health</span>
              <div className="font-mono text-xl font-bold" style={{ color: riskColor }}>
                {report.auditScore.toFixed(1)}/100
              </div>
            </div>
          </div>
        </div>
      </div>
    </Card>
  );
}

export function RiskGauge({ score, label }: { score: number; label: string }) {
  const color = riskLabelColor(label);
  const radius = 52;
  const circumference = 2 * Math.PI * radius;
  const pct = Math.min(100, Math.max(0, score));
  const offset = circumference - (pct / 100) * circumference;

  return (
    <div className="flex items-center gap-4">
      <div className="relative h-32 w-32">
        <svg viewBox="0 0 120 120" className="h-full w-full -rotate-90">
          <circle
            cx="60"
            cy="60"
            r={radius}
            fill="none"
            stroke="#1A1D25"
            strokeWidth="10"
          />
          <motion.circle
            cx="60"
            cy="60"
            r={radius}
            fill="none"
            stroke={color}
            strokeWidth="10"
            strokeLinecap="round"
            strokeDasharray={circumference}
            initial={{ strokeDashoffset: circumference }}
            animate={{ strokeDashoffset: offset }}
            transition={{ duration: 1.4, ease: 'easeOut' }}
            style={{ filter: `drop-shadow(0 0 8px ${color})` }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className="font-mono text-xl font-bold" style={{ color }}>
            {Math.round(pct)}
          </span>
          <span className="font-mono text-[9px] uppercase tracking-widest text-textSecondary">
            risk score
          </span>
        </div>
      </div>
      <div>
        <div className="font-mono text-lg font-bold" style={{ color }}>
          {label}
        </div>
        <div className="text-xs text-textSecondary">overall risk</div>
      </div>
    </div>
  );
}