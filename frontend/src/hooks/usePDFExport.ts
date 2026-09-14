import { useCallback, useState } from 'react';
import jsPDF from 'jspdf';
import { AuditReport } from '@/types';
import { formatDate, formatDuration, downloadText } from '@/utils/format.utils';

interface PDFExportState {
  exporting: boolean;
  progress: number;
}

const SEVERITY_RGB: Record<string, [number, number, number]> = {
  CRITICAL: [239, 68, 68],
  HIGH: [249, 115, 22],
  MEDIUM: [234, 179, 8],
  LOW: [59, 130, 246],
  INFORMATIONAL: [107, 114, 128],
};

export function usePDFExport(report: AuditReport | null) {
  const [state, setState] = useState<PDFExportState>({ exporting: false, progress: 0 });

  const setProgress = (progress: number) => setState({ exporting: true, progress });

  const exportPDF = useCallback(async () => {
    if (!report) return;
    setState({ exporting: true, progress: 5 });

    try {
      // eslint-disable-next-line new-cap
      const pdf = new jsPDF({ orientation: 'portrait', unit: 'pt', format: 'a4' });
      const pageWidth = pdf.internal.pageSize.getWidth();
      const pageHeight = pdf.internal.pageSize.getHeight();
      const margin = 44;
      const contentWidth = pageWidth - margin * 2;

      let y = 0;

      const newPage = () => {
        pdf.addPage();
        pdf.setFillColor(10, 11, 13);
        pdf.rect(0, 0, pageWidth, pageHeight, 'F');
        pdf.setFillColor(0, 255, 136);
        pdf.rect(0, 0, pageWidth, 6, 'F');
        y = margin;
      };

      pdf.setFillColor(10, 11, 13);
      pdf.rect(0, 0, pageWidth, pageHeight, 'F');
      pdf.setFillColor(0, 255, 136);
      pdf.rect(0, 0, pageWidth, 6, 'F');

      // Header
      pdf.setTextColor(0, 255, 136);
      pdf.setFont('helvetica', 'bold');
      pdf.setFontSize(24);
      pdf.text('Smart Contract Security Audit', margin, margin + 24);
      y = margin + 34;

      pdf.setFontSize(12);
      pdf.setFont('helvetica', 'bold');
      pdf.setTextColor(0, 255, 136);
      pdf.text(`Contract: ${report.contractName}`, margin, y + 24);

      pdf.setFont('helvetica', 'normal');
      pdf.setFontSize(10);
      pdf.setTextColor(148, 163, 184);
      pdf.text(`Report ID: ${report.reportId}`, margin, y + 40);
      pdf.text(`Audited: ${formatDate(report.timestamp)}`, margin, y + 54);
      pdf.text(`Duration: ${formatDuration(report.scanDuration)}`, margin, y + 68);
      pdf.text(`Lines of Code: ${report.linesOfCode}`, margin, y + 82);
      pdf.text(`Compiler: ${report.solcVersion}`, margin, y + 96);
      pdf.setTextColor(0, 255, 136);
      pdf.text(
        `Risk: ${report.overallRiskLabel} (${report.overallRiskScore.toFixed(1)}/100) — Audit Score: ${report.auditScore.toFixed(1)}/100`,
        margin,
        y + 116
      );
      y += 140;

      // Summary box
      pdf.setFillColor(26, 29, 37);
      pdf.roundedRect(margin, y, contentWidth, 96, 6, 6, 'F');
      pdf.setFont('helvetica', 'bold');
      pdf.setFontSize(11);
      pdf.setTextColor(0, 255, 136);
      pdf.text('EXECUTIVE SUMMARY', margin + 14, y + 20);

      const rows: Array<[string, number]> = [
        ['Total Issues', report.summary.total],
        ['Critical', report.summary.critical],
        ['High', report.summary.high],
        ['Medium', report.summary.medium],
        ['Low', report.summary.low],
        ['Informational', report.summary.informational],
      ];
      pdf.setFont('helvetica', 'normal');
      pdf.setFontSize(10);
      rows.forEach(([label, value], i) => {
        const rowY = y + 38 + i * 17;
        pdf.setTextColor(241, 245, 249);
        pdf.text(label, margin + 14, rowY);
        pdf.setTextColor(0, 255, 136);
        pdf.text(String(value), margin + contentWidth - 24, rowY);
      });
      y += 120;

      setProgress(25);

      // Findings
      pdf.setFont('helvetica', 'bold');
      pdf.setFontSize(13);
      pdf.setTextColor(0, 255, 136);
      pdf.text('FINDINGS', margin, y + 10);
      y += 32;

      pdf.setFont('helvetica', 'normal');
      for (const vuln of report.vulnerabilities) {
        const minHeight = 84;
        if (y + minHeight > pageHeight - margin) {
          newPage();
          pdf.setFont('helvetica', 'bold');
          pdf.setFontSize(13);
          pdf.setTextColor(0, 255, 136);
          pdf.text('FINDINGS (cont.)', margin, y + 10);
          y += 26;
        }

        const rgb = SEVERITY_RGB[vuln.severity] ?? [107, 114, 128];
        pdf.setFillColor(rgb[0], rgb[1], rgb[2]);
        pdf.roundedRect(margin, y, 6, 58, 2, 2, 'F');

        pdf.setFont('helvetica', 'bold');
        pdf.setFontSize(10.5);
        pdf.setTextColor(rgb[0], rgb[1], rgb[2]);
        pdf.text(
          `[${vuln.severity}] ${vuln.swcId} — ${vuln.title}`,
          margin + 16,
          y + 18
        );

        pdf.setFont('helvetica', 'normal');
        pdf.setFontSize(9);
        pdf.setTextColor(241, 245, 249);
        const confText = `Confidence: ${Math.round(vuln.confidence)}%`;
        const desc = pdf.splitTextToSize(
          `Lines ${vuln.lineStart}-${vuln.lineEnd} (CVSS ${vuln.cvssScore.toFixed(1)}) — ${vuln.description}`,
          contentWidth - 32
        );
        pdf.text(desc.slice(0, 12), margin + 16, y + 34);

        pdf.setTextColor(148, 163, 184);
        pdf.text(confText, margin + 16, y + 34 + Math.min(desc.length, 12) * 11 + 4);

        let findingY = y + 34 + Math.min(desc.length, 12) * 11 + 16;

        if (vuln.evidence && vuln.evidence.length > 0) {
          pdf.setTextColor(148, 163, 184);
          const eviItems = vuln.evidence.slice(0, 3);
          for (const item of eviItems) {
            const eviLines = pdf.splitTextToSize(`• ${item}`, contentWidth - 48);
            for (const line of eviLines.slice(0, 2)) {
              if (findingY > pageHeight - margin) { newPage(); }
              pdf.text(line as string, margin + 22, findingY);
              findingY += 11;
            }
            findingY += 2;
          }
        }

        y = Math.max(y + 86, findingY + 6);
      }

      setProgress(55);

      // Gas optimizations
      if (report.gasOptimizations.length > 0) {
        if (y + 40 > pageHeight - margin) {
          newPage();
          pdf.setFont('helvetica', 'bold');
          pdf.setFontSize(13);
          pdf.setTextColor(0, 255, 136);
          pdf.text('GAS OPTIMIZATIONS', margin, y + 10);
          y += 26;
        } else {
          pdf.setFont('helvetica', 'bold');
          pdf.setFontSize(13);
          pdf.setTextColor(0, 255, 136);
          pdf.text('GAS OPTIMIZATIONS', margin, y + 10);
          y += 26;
        }

        pdf.setFont('helvetica', 'normal');
        pdf.setFontSize(9);
        for (const g of report.gasOptimizations) {
          if (y + 36 > pageHeight - margin) newPage();
          pdf.setTextColor(148, 163, 184);
          pdf.text(`L${g.line}`, margin, y + 6);
          pdf.setTextColor(241, 245, 249);
          const lines = pdf.splitTextToSize(
            `${g.description} ${g.estimatedSaving ? `(est. ${g.estimatedSaving})` : ''}`,
            contentWidth - 48
          );
          pdf.text(lines.slice(0, 4), margin + 36, y + 6);
          y += Math.min(lines.length, 4) * 12 + 14;
        }
        y += 20;
      }

      setProgress(75);

      // Remediation summary
      if (report.vulnerabilities.length > 0) {
        if (y + 60 > pageHeight - margin) newPage();
        pdf.setFont('helvetica', 'bold');
        pdf.setFontSize(13);
        pdf.setTextColor(0, 255, 136);
        pdf.text('RECOMMENDED REMEDIATION', margin, y + 10);
        y += 28;

        pdf.setFont('helvetica', 'normal');
        pdf.setFontSize(9.5);
        const remediationNotes: string[] = [];
        for (const vuln of report.vulnerabilities) {
          remediationNotes.push(`[${vuln.swcId}] ${vuln.title}: ${vuln.recommendation}`);
        }
        const lines = pdf.splitTextToSize(remediationNotes.join('\n'), contentWidth);
        for (const line of lines) {
          if (y + 14 > pageHeight - margin) newPage();
          pdf.setTextColor(226, 232, 240);
          pdf.text(line as string, margin, y);
          y += 15;
        }
      }
      y += 24;

      setProgress(88);

      // Signature block
      if (y + 90 > pageHeight - margin) newPage();
      pdf.setTextColor(0, 255, 136);
      pdf.setFont('helvetica', 'bold');
      pdf.setFontSize(11);
      pdf.text('About this audit', margin, y + 8);
      pdf.setFont('helvetica', 'normal');
      pdf.setFontSize(9);
      pdf.setTextColor(148, 163, 184);
      pdf.text(
        'HexAudit applies static analysis across AST and control-flow graphs with ten detector rules (-d solc AST parsing, reentrancy, overflow, access control, unchecked calls, timestamp dependence, flash-loan economics, oracle manipulation, delegatecall, selfdestruct). Results assist human review but do not constitute a guarantee of security. Deploy only after independent formal verification.',
        margin,
        y + 24,
        { maxWidth: contentWidth }
      );

      y += 80;
      pdf.setTextColor(0, 255, 136);
      pdf.text('HexAudit Security Team', margin, y);
      pdf.text('hexaudit-security · hexstrike engine v1.0', margin, y + 16);

      setProgress(94);

      pdf.setPage(1);
      const pages = pdf.getNumberOfPages();
      for (let i = 1; i <= pages; i++) {
        pdf.setPage(i);
        pdf.setFontSize(8);
        pdf.setTextColor(148, 163, 184);
        pdf.text(
          `HexAudit — ${report.reportId} — page ${i} of ${pages}`,
          margin,
          pageHeight - 18
        );
      }

      pdf.save(`${report.contractName}_audit_report.pdf`);
      setState({ exporting: true, progress: 100 });
      setState({ exporting: false, progress: 100 });
    } catch (e) {
      console.error('[PDF Export]', e);
      setState({ exporting: false, progress: 0 });
      throw e;
    }
  }, [report]);

  const exportSecureContract = useCallback(() => {
    if (!report) return;
    if (report.secureTemplate) {
      downloadText(`${report.contractName}_secure.sol`, report.secureTemplate, 'text/plain');
    }
  }, [report]);

  return {
    exporting: state.exporting,
    progress: state.progress,
    exportPDF,
    exportSecureContract,
  };
}