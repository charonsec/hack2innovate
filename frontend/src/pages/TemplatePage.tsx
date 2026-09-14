import { useCallback, useEffect, useState } from 'react';
import { FileCheck2, Loader2, Copy, Check, ArrowRight } from 'lucide-react';
import { TemplateInfo } from '@/types';
import { useAudit } from '@/hooks/useAudit';
import { useAuditStore } from '@/store/auditStore';
import { SolidityEditor } from '@/components/editor/SolidityEditor';
import { Button } from '@/components/ui/button';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from '@/components/ui/card';
import { cx } from '@/utils/format.utils';

export function TemplatePage() {
  const { fetchTemplates } = useAudit();
  const setSourceCode = useAuditStore((s) => s.setSourceCode);
  const setContractName = useAuditStore((s) => s.setContractName);

  const [templates, setTemplates] = useState<TemplateInfo[]>([]);
  const [activeId, setActiveId] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [copied, setCopied] = useState(false);

  useEffect(() => {
    let cancelled = false;
    fetchTemplates()
      .then((list) => {
        if (cancelled) return;
        setTemplates(list);
        if (list.length > 0) setActiveId(list[0].id);
      })
      .catch((e) => {
        if (!cancelled) setError(e instanceof Error ? e.message : 'Failed to load templates');
      })
      .finally(() => {
        if (!cancelled) setLoading(false);
      });
    return () => {
      cancelled = true;
    };
  }, [fetchTemplates]);

  const active = templates.find((t) => t.id === activeId) ?? null;

  const handleCopy = useCallback(async () => {
    if (!active) return;
    try {
      await navigator.clipboard.writeText(active.sourceCode);
      setCopied(true);
      setTimeout(() => setCopied(false), 1800);
    } catch {
      // clipboard unavailable
    }
  }, [active]);

  const handleUseForAudit = useCallback(() => {
    if (!active) return;
    setSourceCode(active.sourceCode);
    setContractName(active.id);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  }, [active, setSourceCode, setContractName]);

  if (loading) {
    return (
      <div className="flex items-center justify-center gap-3 py-40 text-textSecondary">
        <Loader2 size={20} className="animate-spin text-[#00FF88]" />
        Loading templates…
      </div>
    );
  }

  if (error) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 py-40 text-center">
        <FileCheck2 size={32} className="text-textSecondary" />
        <p className="text-sm text-textSecondary">{error}</p>
        <p className="text-xs text-textSecondary/60">
          Ensure the backend API is running on port 3001.
        </p>
      </div>
    );
  }

  return (
    <div className="animate-fade-in space-y-6">
      <div>
        <div className="flex items-center gap-2">
          <FileCheck2 size={18} className="text-[#00FF88]" />
          <span className="font-mono text-sm tracking-widest text-[#00FF88]">
            HARDENED CONTRACT TEMPLATES
          </span>
        </div>
        <h1 className="mt-2 text-3xl font-bold text-textPrimary">
          Production-grade Solidity references
        </h1>
        <p className="mt-2 max-w-2xl text-sm text-textSecondary">
          These templates pass every HexAudit detector. Each one applies checks-effects-interactions,
          explicit access control, safe math, and authenticated privileged operations.
        </p>
      </div>

      <div className="grid gap-5 lg:grid-cols-[280px_1fr]">
        <div className="space-y-2">
          {templates.map((t) => (
            <button
              key={t.id}
              type="button"
              onClick={() => setActiveId(t.id)}
              className={cx(
                'w-full rounded-lg border p-3 text-left transition-colors',
                activeId === t.id
                  ? 'border-[#00FF88]/60 bg-[#00FF88]/[0.06]'
                  : 'border-[#2A2D35] bg-surface hover:border-[#3A3F4B]'
              )}
            >
              <div className="flex items-center justify-between">
                <span className="font-mono text-sm font-medium text-textPrimary">{t.name}</span>
                <Badge variant="outline" className="font-mono text-[10px]">
                  {t.solidityVersion}
                </Badge>
              </div>
              <p className="mt-1 line-clamp-2 text-xs leading-relaxed text-textSecondary">
                {t.description}
              </p>
            </button>
          ))}
        </div>

        {active ? (
          <Card className="overflow-hidden">
            <CardHeader className="flex flex-row flex-wrap items-start justify-between gap-3 border-b border-[#2A2D35]">
              <div>
                <CardTitle className="font-mono">{active.name}</CardTitle>
                <CardDescription className="mt-1">{active.description}</CardDescription>
              </div>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={handleCopy}>
                  {copied ? <Check size={14} className="text-[#00FF88]" /> : <Copy size={14} />}
                  {copied ? 'Copied' : 'Copy'}
                </Button>
                <Button size="sm" onClick={handleUseForAudit}>
                  Use for audit <ArrowRight size={14} />
                </Button>
              </div>
            </CardHeader>
            <CardContent className="p-0">
              <SolidityEditor value={active.sourceCode} readOnly height={560} />
            </CardContent>
          </Card>
        ) : (
          <Card>
            <CardContent className="p-10 text-sm text-textSecondary">
              Select a template on the left.
            </CardContent>
          </Card>
        )}
      </div>
    </div>
  );
}