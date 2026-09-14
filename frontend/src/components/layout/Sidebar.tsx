import { Link, useLocation } from 'react-router-dom';
import {
  LayoutGrid,
  FileCheck2,
  ShieldAlert,
  Cpu,
} from 'lucide-react';
import { useAuditStore } from '@/store/auditStore';
import { cx } from '@/utils/format.utils';

const LINKS = [
  { to: '/', label: 'Start Audit', icon: LayoutGrid },
  { to: '/templates', label: 'Secure Templates', icon: FileCheck2 },
];

export function Sidebar() {
  const location = useLocation();
  const report = useAuditStore((s) => s.report);
  const scanStatus = useAuditStore((s) => s.scanStatus);

  const hasReport = report && scanStatus === 'complete';

  return (
    <aside className="hidden w-56 shrink-0 flex-col border-r border-[#2A2D35] bg-[#0D0F13] lg:flex">
      <nav className="flex flex-1 flex-col gap-1 p-4">
        {LINKS.map((link) => {
          const active = location.pathname === link.to;
          const Icon = link.icon;
          return (
            <Link
              key={link.to}
              to={link.to}
              className={cx(
                'flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors',
                active
                  ? 'bg-[#00FF88]/10 text-[#00FF88] border border-[#00FF88]/30'
                  : 'text-textSecondary hover:bg-surface hover:text-textPrimary'
              )}
            >
              <Icon size={16} />
              {link.label}
            </Link>
          );
        })}

        {hasReport ? (
          <Link
            to="/report"
            className={cx(
              'flex items-center gap-3 rounded-lg px-3 py-2.5 text-sm font-medium transition-colors',
              location.pathname === '/report'
                ? 'bg-[#0EA5E9]/10 text-[#0EA5E9] border border-[#0EA5E9]/30'
                : 'text-textSecondary hover:bg-surface hover:text-textPrimary'
            )}
          >
            <ShieldAlert size={16} />
            Audit Report
            <span className="ml-auto rounded-full bg-[#00FF88]/15 px-2 py-0.5 font-mono text-[10px] text-[#00FF88]">
              {report.summary.total}
            </span>
          </Link>
        ) : null}
      </nav>

      <div className="border-t border-[#2A2D35] p-4">
        <div className="rounded-lg border border-[#2A2D35] bg-surface p-3">
          <div className="flex items-center gap-2 text-xs text-textSecondary">
            <Cpu size={14} className="text-[#0EA5E9]" />
            <span className="font-mono">detection-engine v1.0</span>
          </div>
          <p className="mt-1.5 text-[11px] leading-relaxed text-textSecondary/70">
            10 detectors · AST + CFG · SWC mapping · auto-remediation
          </p>
        </div>
        <p className="mt-3 text-center text-[10px] text-textSecondary/50">
          © {new Date().getFullYear()} HexAudit Security
        </p>
      </div>
    </aside>
  );
}

export const SidebarSpacer = () => <div className="hidden lg:block w-56 shrink-0" />;