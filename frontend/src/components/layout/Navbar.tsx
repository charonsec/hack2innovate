import { Link, useLocation } from 'react-router-dom';
import { motion } from 'framer-motion';
import { ShieldCheck, FileText, LayoutGrid } from 'lucide-react';
import { cx } from '@/utils/format.utils';

const NAV_ITEMS = [
  { to: '/', label: 'Audit', icon: LayoutGrid },
  { to: '/templates', label: 'Templates', icon: FileText },
];

export function Navbar() {
  const location = useLocation();

  return (
    <motion.header
      initial={{ y: -32, opacity: 0 }}
      animate={{ y: 0, opacity: 1 }}
      transition={{ duration: 0.5, ease: 'easeOut' }}
      className="sticky top-0 z-50 border-b border-[#2A2D35] bg-[#0A0B0D]/90 backdrop-blur-md"
    >
      <div className="mx-auto flex h-16 max-w-7xl items-center justify-between px-4 sm:px-6">
        <Link to="/" className="flex items-center gap-3">
          <div className="relative flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-main shadow-glow">
            <ShieldCheck size={20} className="text-black" strokeWidth={2.5} />
          </div>
          <div className="leading-tight">
            <span className="font-mono text-lg font-bold text-textPrimary">
              Hex<span className="text-[#00FF88]">Audit</span>
            </span>
            <span className="block text-[10px] uppercase tracking-widest text-textSecondary">
              Smart Contract Auditor
            </span>
          </div>
        </Link>

        <nav className="flex items-center gap-1 rounded-lg border border-[#2A2D35] bg-surface p-1">
          {NAV_ITEMS.map((item) => {
            const active = location.pathname === item.to;
            const Icon = item.icon;
            return (
              <Link
                key={item.to}
                to={item.to}
                className={cx(
                  'flex items-center gap-2 rounded-md px-3 py-1.5 text-sm font-medium transition-colors',
                  active
                    ? 'bg-[#00FF88] text-black shadow-glow'
                    : 'text-textSecondary hover:bg-surface2 hover:text-textPrimary'
                )}
              >
                <Icon size={15} />
                {item.label}
              </Link>
            );
          })}
        </nav>

        <div className="hidden items-center gap-2 sm:flex">
          <span className="flex items-center gap-1.5 rounded-full border border-[#00FF88]/30 bg-[#00FF88]/10 px-3 py-1 text-xs font-mono text-[#00FF88]">
            <span className="h-1.5 w-1.5 animate-pulse rounded-full bg-[#00FF88]" />
            ENGINE READY
          </span>
        </div>
      </div>
    </motion.header>
  );
}