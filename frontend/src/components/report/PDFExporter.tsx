import { FileDown, FileCode2 } from 'lucide-react';
import { AuditReport } from '@/types';
import { usePDFExport } from '@/hooks/usePDFExport';
import { Button } from '@/components/ui/button';

export interface PDFExporterProps {
  report: AuditReport;
}

export function PDFExporter({ report }: PDFExporterProps) {
  const { exporting, progress, exportPDF, exportSecureContract } =
    usePDFExport(report);

  return (
    <div className="flex flex-wrap items-center gap-2">
      <Button
        variant="default"
        size="sm"
        onClick={() => exportPDF()}
        disabled={exporting}
      >
        <FileDown size={14} />
        {exporting ? `Exporting… ${progress}%` : 'Export PDF'}
      </Button>
      <Button
        variant="outline"
        size="sm"
        onClick={exportSecureContract}
        disabled={!report.secureTemplate}
      >
        <FileCode2 size={14} />
        Secure Contract
      </Button>
    </div>
  );
}