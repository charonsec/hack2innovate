import { Severity } from '@/types';
import { Badge } from '@/components/ui/badge';

const SEVERITY_BADGE_VARIANT: Record<Severity, 'critical' | 'high' | 'medium' | 'low' | 'info'> = {
  CRITICAL: 'critical',
  HIGH: 'high',
  MEDIUM: 'medium',
  LOW: 'low',
  INFORMATIONAL: 'info',
};

export interface SeverityBadgeProps {
  severity: Severity;
  withLabel?: boolean;
  className?: string;
}

export function SeverityBadge({ severity, withLabel = true }: SeverityBadgeProps) {
  return (
    <Badge variant={SEVERITY_BADGE_VARIANT[severity]}>
      {withLabel ? severity : severity.slice(0, 3).toUpperCase()}
    </Badge>
  );
}