import * as React from 'react';
import { cx } from '@/utils/format.utils';

type BadgeVariant = 'default' | 'critical' | 'high' | 'medium' | 'low' | 'info' | 'success' | 'outline';

const variantClasses: Record<BadgeVariant, string> = {
  default: 'bg-[#00FF88]/15 text-[#00FF88] border-[#00FF88]/40',
  critical: 'bg-critical/15 text-[#FCA5A5] border-critical/40',
  high: 'bg-high/15 text-[#FDBA74] border-high/40',
  medium: 'bg-medium/15 text-[#FDE047] border-medium/40',
  low: 'bg-low/15 text-[#93C5FD] border-low/40',
  info: 'bg-info/15 text-[#9CA3AF] border-info/40',
  success: 'bg-[#00FF88]/15 text-[#00FF88] border-[#00FF88]/40',
  outline: 'bg-transparent border-[#2A2D35] text-textSecondary',
};

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement> {
  variant?: BadgeVariant;
}

export const Badge = React.forwardRef<HTMLSpanElement, BadgeProps>(
  ({ className, variant = 'default', ...props }, ref) => (
    <span
      ref={ref}
      className={cx(
        'inline-flex items-center rounded-full border px-2.5 py-0.5 text-xs font-medium font-mono',
        variantClasses[variant],
        className
      )}
      {...props}
    />
  )
);
Badge.displayName = 'Badge';