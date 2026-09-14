import * as React from 'react';
import { cx } from '@/utils/format.utils';

type ButtonVariant = 'default' | 'outline' | 'ghost' | 'destructive' | 'gradient' | 'secondary';
type ButtonSize = 'default' | 'sm' | 'lg' | 'icon';

const variantClasses: Record<ButtonVariant, string> = {
  default:
    'bg-[#00FF88] text-black hover:brightness-110 shadow-glow',
  gradient:
    'bg-gradient-main text-black font-semibold hover:brightness-110 shadow-glow',
  outline:
    'border border-[#2A2D35] bg-transparent text-textPrimary hover:bg-surface2',
  ghost: 'bg-transparent text-textSecondary hover:bg-surface2 hover:text-textPrimary',
  destructive: 'bg-critical/20 text-[#FCA5A5] border border-critical/40 hover:bg-critical/30',
  secondary: 'bg-surface2 text-textPrimary hover:bg-[#242833]',
};

const sizeClasses: Record<ButtonSize, string> = {
  default: 'h-10 px-5 py-2 text-sm',
  sm: 'h-8 px-3 text-xs',
  lg: 'h-12 px-8 text-base',
  icon: 'h-9 w-9',
};

export interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
}

export const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  ({ className, variant = 'default', size = 'default', ...props }, ref) => {
    return (
      <button
        ref={ref}
        className={cx(
          'inline-flex items-center justify-center gap-2 rounded-lg font-medium transition-all duration-200 disabled:pointer-events-none disabled:opacity-50 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-[#00FF88]/60 active:scale-[0.98]',
          variantClasses[variant],
          sizeClasses[size],
          className
        )}
        {...props}
      />
    );
  }
);
Button.displayName = 'Button';

export { Button as buttonVariants };