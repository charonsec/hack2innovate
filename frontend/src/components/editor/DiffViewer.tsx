import { useMemo, useState } from 'react';
import { ChevronDown, ChevronUp, Download } from 'lucide-react';
import { Card, CardContent } from '@/components/ui/card';
import { Badge } from '@/components/ui/badge';
import { Button } from '@/components/ui/button';
import { cx, downloadText, computeDiff } from '@/utils/format.utils';
import { useAuditStore } from '@/store/auditStore';

interface DiffViewerProps {
  original: string;
  remediated: string;
  prependContractName?: string;
}

export function DiffViewer({ original, remediated }: DiffViewerProps) {
  const contractName = useAuditStore((s) => s.contractName);
  const [collapsed, setCollapsed] = useState(false);

  const diff = useMemo(
    () => computeDiff(original, remediated),
    [original, remediated]
  );

  const addedLines = diff.filter((l) => l.type === 'add').length;
  const removedLines = diff.filter((l) => l.type === 'remove').length;

  const handleDownload = () => {
    downloadText(`${contractName}_remediated.sol`, remediated, 'text/plain');
  };

  return (
    <Card className="overflow-hidden">
      <CardContent className="p-0">
        <div className="flex items-center justify-between border-b border-[#2A2D35] bg-surface px-4 py-3">
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={() => setCollapsed((c) => !c)}
              className="flex items-center gap-2 text-sm font-medium text-textSecondary hover:text-textPrimary"
            >
              {collapsed ? <ChevronUp size={16} /> : <ChevronDown size={16} />}
              Remediated Contract
            </button>
            <Badge variant="success" className="ml-2">
              +{addedLines} −{removedLines}
            </Badge>
          </div>
          <Button variant="outline" size="sm" onClick={handleDownload}>
            <Download size={14} />
            Download .sol
          </Button>
        </div>

        {!collapsed && (
          <div className="max-h-[560px] overflow-auto">
            <table className="w-full border-collapse font-mono text-[13px] leading-6">
              <tbody>
                {diff.map((line, idx) => (
                  <tr
                    key={idx}
                    className={cx(
                      line.type === 'add' && 'bg-[#00FF88]/[0.06]',
                      line.type === 'remove' && 'bg-critical/[0.06]'
                    )}
                  >
                    <td
                      className={cx(
                        'w-2 select-none border-r border-[#2A2D35] px-2 text-center',
                        line.type === 'add'
                          ? 'text-[#00FF88]'
                          : line.type === 'remove'
                            ? 'text-critical'
                            : 'text-textSecondary/50'
                      )}
                    >
                      {line.type === 'add' ? '+' : line.type === 'remove' ? '−' : ''}
                    </td>
                    <td className="w-16 select-none border-r border-[#2A2D35] px-3 text-right text-textSecondary/60">
                      {line.lineNumber ?? ''}
                    </td>
                    <td
                      className={cx(
                        'whitespace-pre px-4',
                        line.type === 'add'
                          ? 'text-[#4ADE80]'
                          : line.type === 'remove'
                            ? 'text-[#F87171]'
                            : 'text-textPrimary/85'
                      )}
                    >
                      {line.content || ' '}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </CardContent>
    </Card>
  );
}