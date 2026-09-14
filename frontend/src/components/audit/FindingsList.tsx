import { useMemo, useState } from 'react';
import { AnimatePresence, motion } from 'framer-motion';
import { Search, ShieldCheck, Frown } from 'lucide-react';
import { Vulnerability, Severity } from '@/types';
import { VulnerabilityCard } from '@/components/audit/VulnerabilityCard';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { cx } from '@/utils/format.utils';
import { SEVERITY_ORDER } from '@/utils/severity.utils';

export interface FindingsListProps {
  vulnerabilities: Vulnerability[];
  selectedId: string | null;
  onSelect: (vuln: Vulnerability | null) => void;
  compact?: boolean;
}

export function FindingsList({
  vulnerabilities,
  selectedId,
  onSelect,
  compact = false,
}: FindingsListProps) {
  const [query, setQuery] = useState('');
  const [filter, setFilter] = useState<'ALL' | Severity>('ALL');

  const counts = useMemo(() => {
    const c: Record<string, number> = { ALL: vulnerabilities.length };
    for (const sev of SEVERITY_ORDER) {
      c[sev] = vulnerabilities.filter((v) => v.severity === sev).length;
    }
    return c;
  }, [vulnerabilities]);

  const filtered = useMemo(() => {
    return vulnerabilities.filter((v) => {
      const matchesQuery =
        !query ||
        v.title.toLowerCase().includes(query.toLowerCase()) ||
        v.swcId.toLowerCase().includes(query.toLowerCase());
      const matchesFilter = filter === 'ALL' || v.severity === filter;
      return matchesQuery && matchesFilter;
    });
  }, [vulnerabilities, query, filter]);

  if (vulnerabilities.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center gap-3 rounded-xl border border-dashed border-[#2A2D35] p-10 text-center">
        <ShieldCheck size={40} className="text-[#00FF88]" />
        <div>
          <p className="text-sm font-medium text-textPrimary">No vulnerabilities found</p>
          <p className="mt-1 text-xs text-textSecondary">
            The contract passed all detection rules in this pass.
          </p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-3">
      {!compact && (
        <div className="flex flex-col gap-2 sm:flex-row sm:items-center">
          <div className="relative flex-1">
            <Search
              size={14}
              className="absolute left-3 top-1/2 -translate-y-1/2 text-textSecondary/60"
            />
            <Input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Filter findings…"
              className="pl-9"
            />
          </div>
          <div className="flex gap-1">
            {(['ALL', ...SEVERITY_ORDER] as Array<'ALL' | Severity>).map((sev) => (
              <Button
                key={sev}
                variant={filter === sev ? 'default' : 'ghost'}
                size="sm"
                onClick={() => setFilter(sev)}
                className={cx(
                  filter !== sev && 'border border-[#2A2D35]',
                  sev !== 'ALL' && filter === sev && '',
                  filter === sev && sev === 'CRITICAL' && 'bg-critical text-white'
                )}
              >
                {sev === 'ALL' ? 'All' : sev.slice(0, 3).toUpperCase()}
                <span className="opacity-60">{counts[sev]}</span>
              </Button>
            ))}
          </div>
        </div>
      )}

      <div className="flex items-center justify-between px-1">
        <span className="text-xs text-textSecondary">
          {filtered.length} of {vulnerabilities.length} finding
          {vulnerabilities.length === 1 ? '' : 's'}
        </span>
      </div>

      {filtered.length === 0 ? (
        <div className="flex flex-col items-center gap-2 rounded-lg border border-dashed border-[#2A2D35] p-8 text-center">
          <Frown size={28} className="text-textSecondary/50" />
          <p className="text-sm text-textSecondary">No findings match the current filter.</p>
        </div>
      ) : (
        <div className={cx('flex flex-col gap-2', !compact && 'max-h-[520px] overflow-auto pr-1')}>
          <AnimatePresence initial={false}>
            {filtered.map((vuln) => (
              <motion.div
                key={vuln.id}
                layout
                initial={{ opacity: 0, y: 8 }}
                animate={{ opacity: 1, y: 0 }}
                exit={{ opacity: 0, scale: 0.98 }}
                transition={{ duration: 0.15 }}
              >
                <VulnerabilityCard
                  vulnerability={vuln}
                  selected={selectedId === vuln.id}
                  onSelect={(v) => onSelect(vuln.id === selectedId ? null : v)}
                />
              </motion.div>
            ))}
          </AnimatePresence>
        </div>
      )}
    </div>
  );
}