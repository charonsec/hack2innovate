import { AuditReport } from '@/types';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { SeverityPieChart } from '@/components/graphs/severityCharts';
import { buildKeyFindingsParagraph } from '@/utils/severity.utils';
import { CYBER_SECURITY_LEVELS, getSecurityLevel } from '@/utils/severity.utils';

export interface ExecutiveSummaryProps {
  report: AuditReport;
}

export function ExecutiveSummary({ report }: ExecutiveSummaryProps) {
  const level = getSecurityLevel(report.auditScore);

  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader>
          <CardTitle>Executive Summary</CardTitle>
          <CardDescription>
            High-level assessment of {report.contractName} for protocol operators and
            governance reviewers.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <p className="text-sm leading-relaxed text-textPrimary/90">
            {buildKeyFindingsParagraph(report.vulnerabilities)}
          </p>

          <div className="mt-5 flex items-center gap-3 rounded-lg border border-[#2A2D35] bg-surface p-4">
            <div className="flex h-12 w-12 items-center justify-center rounded-lg border border-[#00FF88]/40 bg-[#00FF88]/10">
              <span className="font-mono text-2xl font-bold text-[#00FF88]">{level.icon}</span>
            </div>
            <div>
              <p className="font-mono text-sm font-bold text-textPrimary">
                {level.label}
              </p>
              <p className="text-xs text-textSecondary">{level.description}</p>
            </div>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle>Severity Distribution</CardTitle>
          <CardDescription>
            Findings grouped by severity with CVSS-aligned color treatment.
          </CardDescription>
        </CardHeader>
        <CardContent>
          <SeverityPieChart vulnerabilities={report.vulnerabilities} />
        </CardContent>
      </Card>
    </div>
  );
}

export const CYBER_LEVELS = CYBER_SECURITY_LEVELS;