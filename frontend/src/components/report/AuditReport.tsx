import { useCallback } from 'react';
import {
  FileText,
  ListChecks,
  GitBranch,
  Fuel,
  ShieldAlert,
  Wrench,
  LayoutDashboard,
  PieChart,
  Flag,
} from 'lucide-react';
import type { AuditReport as AuditReportType } from '@/types';
import { Tabs, TabsList, TabsTrigger, TabsContent } from '@/components/ui/tabs';
import { useAuditStore } from '@/store/auditStore';
import { ReportHeader } from '@/components/report/ReportHeader';
import { ExecutiveSummary } from '@/components/report/ExecutiveSummary';
import { SeverityBadge } from '@/components/audit/SeverityBadge';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { FindingsList } from '@/components/audit/FindingsList';
import { CFGGraph } from '@/components/graphs/CFGGraph';
import { SeverityPieChart, VulnBarChart } from '@/components/graphs/severityCharts';
import { DiffViewer } from '@/components/editor/DiffViewer';
import { SolidityEditor } from '@/components/editor/SolidityEditor';
import { PDFExporter } from '@/components/report/PDFExporter';
import VulnerabilityDetail from '@/components/audit/VulnerabilityDetail';

export interface AuditReportProps {
  report: AuditReportType;
}

interface TabDef {
  id: string;
  label: string;
  icon: typeof FileText;
}

const TABS: TabDef[] = [
  { id: 'overview', label: 'Overview', icon: FileText },
  { id: 'summary', label: 'Executive Summary', icon: LayoutDashboard },
  { id: 'findings', label: 'Findings', icon: ListChecks },
  { id: 'analysis', label: 'AST Analysis', icon: PieChart },
  { id: 'cfg', label: 'Control Flow', icon: GitBranch },
  { id: 'gas', label: 'Gas', icon: Fuel },
  { id: 'risks', label: 'Risk Ratings', icon: ShieldAlert },
  { id: 'remediation', label: 'Remediation', icon: Wrench },
  { id: 'closing', label: 'Closing', icon: Flag },
];

function countAstNodes(node: unknown, acc: Map<string, number>): void {
  if (node == null || typeof node !== 'object') return;
  const obj = node as Record<string, unknown>;
  const type = obj.type as string;
  if (type) {
    acc.set(type, (acc.get(type) ?? 0) + 1);
  }
  for (const value of Object.values(obj)) {
    if (Array.isArray(value)) {
      for (const item of value) {
        if (item && typeof item === 'object') countAstNodes(item, acc);
      }
    } else if (value && typeof value === 'object') {
      countAstNodes(value, acc);
    }
  }
}

function astStats(ast: object | undefined): { total: number; types: Array<[string, number]> } {
  const acc = new Map<string, number>();
  countAstNodes(ast ?? {}, acc);
  const types = [...acc.entries()].sort((a, b) => b[1] - a[1]).slice(0, 12);
  const total = [...acc.values()].reduce((sum, v) => sum + v, 0);
  return { total, types };
}

export function AuditReport({ report }: AuditReportProps) {
  const activeTab = useAuditStore((s) => s.activeTab);
  const setActiveTab = useAuditStore((s) => s.setActiveTab);
  const selectedVulnerability = useAuditStore((s) => s.selectedVulnerability);
  const selectVulnerability = useAuditStore((s) => s.selectVulnerability);
  const originalSourceCode = useAuditStore((s) => s.sourceCode);

  const ast = astStats(report.ast);

  const handleSelectVuln = useCallback(
    (vuln: Parameters<typeof selectVulnerability>[0]) => {
      selectVulnerability(vuln);
    },
    [selectVulnerability]
  );

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4">
        <Tabs defaultValue={activeTab} value={activeTab} onValueChange={setActiveTab}>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <TabsList className="h-auto flex-wrap gap-1">
              {TABS.map((tab) => {
                const Icon = tab.icon;
                return (
                  <TabsTrigger key={tab.id} value={tab.id} className="gap-1.5">
                    <Icon size={13} />
                    {tab.label}
                  </TabsTrigger>
                );
              })}
            </TabsList>
            <PDFExporter report={report} />
          </div>

          <TabsContent value="overview">
            <ReportHeader report={report} />
          </TabsContent>

          <TabsContent value="summary">
            <ExecutiveSummary report={report} />
          </TabsContent>

          <TabsContent value="findings" className="mt-4">
            <div className="grid gap-4 lg:grid-cols-[1fr_1.4fr]">
              <div>
                <Card className="mb-2">
                  <CardHeader>
                    <CardTitle>Vulnerability List</CardTitle>
                    <CardDescription>
                      {report.summary.total} finding
                      {report.summary.total === 1 ? '' : 's'} across{' '}
                      {report.vulnerabilities.length && new Set(report.vulnerabilities.map((v) => v.type)).size}{' '}
                      classes
                    </CardDescription>
                  </CardHeader>
                </Card>
                <FindingsList
                  vulnerabilities={report.vulnerabilities}
                  selectedId={selectedVulnerability?.id ?? null}
                  onSelect={handleSelectVuln}
                />
              </div>

              {selectedVulnerability ? (
                <VulnerabilityDetail vulnerability={selectedVulnerability} />
              ) : (
                <Card className="flex min-h-[360px] items-center justify-center border-dashed">
                  <div className="max-w-sm text-center">
                    <ListChecks size={36} className="mx-auto text-textSecondary/40" />
                    <p className="mt-3 text-sm font-medium text-textPrimary">
                      Select a finding to view details
                    </p>
                    <p className="mt-1 text-xs text-textSecondary">
                      Each finding includes the vulnerable snippet, severity, CVSS score, SWC reference, and a
                      remediation patch.
                    </p>
                  </div>
                </Card>
              )}
            </div>
          </TabsContent>

          <TabsContent value="analysis" className="mt-4">
            <div className="grid gap-4 lg:grid-cols-3">
              <Card className="lg:col-span-2">
                <CardHeader>
                  <CardTitle>Abstract Syntax Tree</CardTitle>
                  <CardDescription>
                    {ast.total.toLocaleString()} AST nodes parsed with the Solidity parser 0.16.x grammar.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="flex flex-wrap gap-2">
                    {ast.types.map(([type, count]) => (
                      <div
                        key={type}
                        className="flex items-center gap-2 rounded-lg border border-[#2A2D35] bg-surface px-3 py-2"
                      >
                        <Badge variant="outline" className="font-mono">
                          {type}
                        </Badge>
                        <span className="font-mono text-sm text-[#00FF88]">{count}</span>
                      </div>
                    ))}
                    {ast.types.length === 0 && (
                      <p className="text-sm text-textSecondary">AST data not available.</p>
                    )}
                  </div>
                </CardContent>
              </Card>

              <Card>
                <CardHeader>
                  <CardTitle>Contract Statistics</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3 text-sm">
                  <StatRow label="Lines of code" value={String(report.linesOfCode)} />
                  <StatRow label="Functions" value={String(countFunctions(report.ast))} />
                  <StatRow label="State variables" value={String(countStateVars(report.ast))} />
                  <StatRow label="CFG nodes" value={String(report.cfg.length)} />
                  <StatRow label="Solc version" value={report.solcVersion} />
                  <StatRow label="Scan duration" value={`${report.scanDuration}ms`} />
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="cfg" className="mt-4">
            <Card>
              <CardHeader className="flex-row items-center justify-between space-y-0">
                <div>
                  <CardTitle>Control Flow Graph</CardTitle>
                  <CardDescription>
                    {report.cfg.length} nodes — red nodes are vulnerable; click to jump to the source line.
                  </CardDescription>
                </div>
              </CardHeader>
              <CardContent>
                <CFGGraph
                  nodes={report.cfg}
                  vulnerableLines={report.vulnerabilities.map((v) => v.lineStart)}
                />
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="gas" className="mt-4">
            <Card>
              <CardHeader>
                <CardTitle>Gas Optimizations</CardTitle>
                <CardDescription>
                  {report.gasOptimizations.length} optimization
                  {report.gasOptimizations.length === 1 ? '' : 's'} identified for cost-sensitive paths.
                </CardDescription>
              </CardHeader>
              <CardContent>
                {report.gasOptimizations.length === 0 ? (
                  <p className="text-sm text-textSecondary">
                    No gas optimizations were suggested for this contract.
                  </p>
                ) : (
                  <div className="space-y-3">
                    {report.gasOptimizations.map((g) => (
                      <div
                        key={`${g.line}-${g.description}`}
                        className="rounded-lg border border-[#2A2D35] bg-surface p-4"
                      >
                        <div className="flex flex-wrap items-center justify-between gap-2">
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className="font-mono">
                              L{g.line}
                            </Badge>
                            <span className="text-sm font-medium text-textPrimary">
                              {g.description}
                            </span>
                          </div>
                          {g.estimatedSaving && (
                            <Badge variant="default">{g.estimatedSaving}</Badge>
                          )}
                        </div>
                        <div className="mt-3 grid gap-2 font-mono text-[12px] sm:grid-cols-2">
                          <pre className="overflow-x-auto rounded-md border border-critical/30 bg-[#0A0B0D] p-3 text-[#F87171]">
                            {g.code}
                          </pre>
                          <pre className="overflow-x-auto rounded-md border border-[#00FF88]/30 bg-[#0A0B0D] p-3 text-[#4ADE80]">
                            {g.optimizedCode}
                          </pre>
                        </div>
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="risks" className="mt-4">
            <div className="grid gap-4 lg:grid-cols-2">
              <Card>
                <CardHeader>
                  <CardTitle>Severity Breakdown</CardTitle>
                </CardHeader>
                <CardContent>
                  <SeverityPieChart vulnerabilities={report.vulnerabilities} />
                </CardContent>
              </Card>
              <Card>
                <CardHeader>
                  <CardTitle>Vulnerability Classes</CardTitle>
                </CardHeader>
                <CardContent>
                  <VulnBarChart vulnerabilities={report.vulnerabilities} />
                </CardContent>
              </Card>
              <Card className="lg:col-span-2">
                <CardHeader>
                  <CardTitle>Risk Matrix</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="overflow-x-auto">
                    <table className="w-full text-left text-sm">
                      <thead>
                        <tr className="border-b border-[#2A2D35] text-xs uppercase tracking-wider text-textSecondary">
                          <th className="py-2 pr-4 font-medium">ID</th>
                          <th className="py-2 pr-4 font-medium">Title</th>
                          <th className="py-2 pr-4 font-medium">Severity</th>
                          <th className="py-2 pr-4 font-medium">CVSS</th>
                          <th className="py-2 pr-4 font-medium">SWC</th>
                          <th className="py-2 pr-4 font-medium">Lines</th>
                        </tr>
                      </thead>
                      <tbody>
                        {report.vulnerabilities.map((v) => (
                          <tr
                            key={v.id}
                            className="border-b border-[#2A2D35]/50 transition-colors hover:bg-surface"
                          >
                            <td className="py-2.5 pr-4 font-mono text-xs text-textSecondary">
                              {v.id}
                            </td>
                            <td className="py-2.5 pr-4 font-medium text-textPrimary">
                              {v.title}
                            </td>
                            <td className="py-2.5 pr-4">
                              <SeverityBadge severity={v.severity} withLabel />
                            </td>
                            <td className="py-2.5 pr-4 font-mono text-xs text-textSecondary">
                              {v.cvssScore.toFixed(1)}
                            </td>
                            <td className="py-2.5 pr-4 font-mono text-xs text-textSecondary">
                              {v.swcId}
                            </td>
                            <td className="py-2.5 pr-4 font-mono text-xs text-textSecondary">
                              L{v.lineStart}–{v.lineEnd}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </CardContent>
              </Card>
            </div>
          </TabsContent>

          <TabsContent value="remediation" className="mt-4">
            <div className="space-y-6">
              <DiffViewer
                original={originalSourceCode}
                remediated={report.secureTemplate ?? ''}
              />

              {report.secureTemplate ? (
                <Card>
                  <CardHeader>
                    <CardTitle>Hardened Template</CardTitle>
                    <CardDescription>
                      The fully remediated contract (with Check-Effects-Interactions, guards,
                      ERC20 safe math, and protected privileged functions).
                    </CardDescription>
                  </CardHeader>
                  <CardContent>
                    <SolidityEditor
                      value={report.secureTemplate}
                      readOnly
                      height={480}
                    />
                  </CardContent>
                </Card>
              ) : (
                <Card>
                  <CardContent className="p-6 text-sm text-textSecondary">
                    No secure template was generated for this report.
                  </CardContent>
                </Card>
              )}
            </div>
          </TabsContent>

          <TabsContent value="closing" className="mt-4">
            <Card className="bg-gradient-to-br from-[#0D0F13] to-[#0A0B0D]">
              <CardContent className="p-8">
                <h3 className="font-mono text-xl font-bold text-textPrimary">
                  Closing Statement
                </h3>
                <p className="mt-4 max-w-3xl text-sm leading-relaxed text-textPrimary/85">
                  HexAudit performed a static, non-interactive audit of{' '}
                  <span className="font-mono text-[#00FF88]">{report.contractName}</span> using
                  AST-derived analysis and control-flow reasoning. A total of{' '}
                  <span className="text-textPrimary">{report.summary.total}</span> issues were
                  identified ({report.summary.critical} critical, {report.summary.high} high,{' '}
                  {report.summary.medium} medium, {report.summary.low} low,{' '}
                  {report.summary.informational} informational).
                </p>
                <p className="mt-3 max-w-3xl text-sm leading-relaxed text-textPrimary/85">
                  {report.vulnerabilities.length > 0
                    ? 'All critical and high-severity findings should be remediated and re-audited before mainnet. Deploying with known critical issues risks irrecoverable fund loss.'
                    : 'No critical or high-severity findings were identified. The contract may proceed to independent review and formal verification before deployment.'}
                </p>

                <div className="mt-8 grid gap-3 sm:grid-cols-3">
                  <div className="rounded-lg border border-[#2A2D35] bg-surface p-4 text-center">
                    <p className="font-mono text-2xl font-bold text-textPrimary">
                      {report.auditScore.toFixed(1)}
                    </p>
                    <p className="text-xs text-textSecondary">Audit Score / 100</p>
                  </div>
                  <div className="rounded-lg border border-[#2A2D35] bg-surface p-4 text-center">
                    <p className="font-mono text-2xl font-bold text-textPrimary">
                      {report.linesOfCode}
                    </p>
                    <p className="text-xs text-textSecondary">Lines Analyzed</p>
                  </div>
                  <div className="rounded-lg border border-[#2A2D35] bg-surface p-4 text-center">
                    <p className="font-mono text-2xl font-bold text-textPrimary">
                      {report.cfg.length}
                    </p>
                    <p className="text-xs text-textSecondary">CFG Nodes Traversed</p>
                  </div>
                </div>

                <div className="mt-8 flex flex-col gap-2 border-t border-[#2A2D35] pt-6 text-xs text-textSecondary">
                  <span>Report ID: {report.reportId}</span>
                  <span>
                    Generated: {new Date(report.timestamp).toISOString()} · Engine hexstrike v1.0
                  </span>
                  <span className="text-textSecondary/70">
                    HexAudit does not substitute for human review or formal verification.
                  </span>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}

function StatRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between border-b border-[#2A2D35]/60 pb-2 last:border-0">
      <span className="text-textSecondary">{label}</span>
      <span className="font-mono text-textPrimary">{value}</span>
    </div>
  );
}

function countFunctions(ast: object | undefined): number {
  let count = 0;
  const walk = (node: unknown): void => {
    if (node == null || typeof node !== 'object') return;
    const obj = node as Record<string, unknown>;
    if ((obj.type as string) === 'FunctionDefinition') count += 1;
    for (const value of Object.values(obj)) {
      if (Array.isArray(value)) {
        for (const item of value) {
          if (item && typeof item === 'object') walk(item);
        }
      } else if (value && typeof value === 'object') walk(value);
    }
  };
  walk(ast ?? {});
  return count;
}

function countStateVars(ast: object | undefined): number {
  let count = 0;
  const walk = (node: unknown): void => {
    if (node == null || typeof node !== 'object') return;
    const obj = node as Record<string, unknown>;
    if ((obj.type as string) === 'StateVariableDeclaration') count += 1;
    for (const value of Object.values(obj)) {
      if (Array.isArray(value)) {
        for (const item of value) {
          if (item && typeof item === 'object') walk(item);
        }
      } else if (value && typeof value === 'object') walk(value);
    }
  };
  walk(ast ?? {});
  return count;
}