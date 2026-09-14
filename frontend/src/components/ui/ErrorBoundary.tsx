import React, { Component, ErrorInfo, ReactNode } from 'react';
import { AlertTriangle, RefreshCcw } from 'lucide-react';
import { Button } from '@/components/ui/button';

interface Props {
  children: ReactNode;
  fallbackTitle?: string;
  fallbackMessage?: string;
}

interface State {
  hasError: boolean;
  error: Error | null;
}

export class ErrorBoundary extends Component<Props, State> {
  constructor(props: Props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error: Error): State {
    return { hasError: true, error };
  }

  componentDidCatch(error: Error, errorInfo: ErrorInfo): void {
    console.error('[ErrorBoundary]', error, errorInfo);
  }

  handleReset = (): void => {
    this.setState({ hasError: false, error: null });
  };

  render(): ReactNode {
    if (this.state.hasError) {
      return (
        <div className="flex min-h-[200px] flex-col items-center justify-center gap-4 rounded-xl border border-critical/30 bg-critical/5 p-8 text-center">
          <AlertTriangle size={32} className="text-critical" />
          <div>
            <h3 className="text-base font-semibold text-textPrimary">
              {this.props.fallbackTitle ?? 'Something went wrong'}
            </h3>
            <p className="mt-1 max-w-md text-sm text-textSecondary">
              {this.props.fallbackMessage ?? 'An error occurred while rendering this section.'}
            </p>
            {this.state.error && (
              <pre className="mt-3 max-w-lg overflow-auto rounded-lg border border-[#2A2D35] bg-surface p-3 text-left font-mono text-xs text-critical">
                {this.state.error.message}
              </pre>
            )}
          </div>
          <Button variant="outline" size="sm" onClick={this.handleReset}>
            <RefreshCcw size={14} />
            Try again
          </Button>
        </div>
      );
    }

    return this.props.children;
  }
}