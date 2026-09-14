import * as React from 'react';
import { cx } from '@/utils/format.utils';

export const Input = React.forwardRef<HTMLInputElement, React.InputHTMLAttributes<HTMLInputElement>>(
  ({ className, ...props }, ref) => (
    <input
      ref={ref}
      className={cx(
        'flex h-10 w-full rounded-lg border border-[#2A2D35] bg-surface2 px-3 py-2 text-sm text-textPrimary placeholder:text-textSecondary/60 outline-none transition-colors focus:border-[#00FF88]/70 focus:ring-1 focus:ring-[#00FF88]/50 disabled:cursor-not-allowed disabled:opacity-50',
        className
      )}
      {...props}
    />
  )
);
Input.displayName = 'Input';

export const Textarea = React.forwardRef<HTMLTextAreaElement, React.TextareaHTMLAttributes<HTMLTextAreaElement>>(
  ({ className, ...props }, ref) => (
    <textarea
      ref={ref}
      className={cx(
        'flex min-h-[80px] w-full rounded-lg border border-[#2A2D35] bg-surface2 px-3 py-2 text-sm text-textPrimary placeholder:text-textSecondary/60 outline-none transition-colors focus:border-[#00FF88]/70 focus:ring-1 focus:ring-[#00FF88]/50 disabled:cursor-not-allowed disabled:opacity-50',
        className
      )}
      {...props}
    />
  )
);
Textarea.displayName = 'Textarea';

export const Label = React.forwardRef<HTMLLabelElement, React.LabelHTMLAttributes<HTMLLabelElement>>(
  ({ className, ...props }, ref) => (
    <label
      ref={ref}
      className={cx('text-sm font-medium leading-none text-textSecondary', className)}
      {...props}
    />
  )
);
Label.displayName = 'Label';

export const Progress = React.forwardRef<HTMLDivElement, React.HTMLAttributes<HTMLDivElement> & { value?: number }>(
  ({ className, value = 0, ...props }, ref) => (
    <div
      ref={ref}
      className={cx('relative h-2 w-full overflow-hidden rounded-full bg-surface2', className)}
      {...props}
    >
      <div
        className="h-full rounded-full bg-gradient-main transition-all duration-300 ease-out"
        style={{ width: `${Math.min(100, Math.max(0, value))}%` }}
      />
    </div>
  )
);
Progress.displayName = 'Progress';