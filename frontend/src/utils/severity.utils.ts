import { Severity, Vulnerability, VulnerabilityType } from '@/types';

export const SEVERITY_COLORS: Record<Severity, { hex: string; bg: string; text: string; border: string; glow: string }> = {
  CRITICAL: {
    hex: '#EF4444',
    bg: 'rgba(239,68,68,0.12)',
    text: '#FCA5A5',
    border: 'rgba(239,68,68,0.5)',
    glow: '0 0 12px rgba(239,68,68,0.4)',
  },
  HIGH: {
    hex: '#F97316',
    bg: 'rgba(249,115,22,0.12)',
    text: '#FDBA74',
    border: 'rgba(249,115,22,0.5)',
    glow: '0 0 12px rgba(249,115,22,0.35)',
  },
  MEDIUM: {
    hex: '#EAB308',
    bg: 'rgba(234,179,8,0.12)',
    text: '#FDE047',
    border: 'rgba(234,179,8,0.5)',
    glow: '0 0 12px rgba(234,179,8,0.35)',
  },
  LOW: {
    hex: '#3B82F6',
    bg: 'rgba(59,130,246,0.12)',
    text: '#93C5FD',
    border: 'rgba(59,130,246,0.5)',
    glow: '0 0 12px rgba(59,130,246,0.3)',
  },
  INFORMATIONAL: {
    hex: '#6B7280',
    bg: 'rgba(107,114,128,0.12)',
    text: '#9CA3AF',
    border: 'rgba(107,114,128,0.5)',
    glow: '0 0 12px rgba(107,114,128,0.25)',
  },
};

export const SEVERITY_ORDER: Severity[] = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL'];

export function severityRank(severity: Severity): number {
  return SEVERITY_ORDER.indexOf(severity);
}

export function severityColorHex(severity: Severity): string {
  return SEVERITY_COLORS[severity].hex;
}

export function riskLabelColor(label: string): string {
  const upper = label.toUpperCase();
  switch (upper) {
    case 'CRITICAL':
      return '#EF4444';
    case 'HIGH':
      return '#F97316';
    case 'MEDIUM':
      return '#EAB308';
    case 'LOW':
      return '#3B82F6';
    default:
      return '#00FF88';
  }
}

export function summaryLabel(summary: {
  critical: number;
  high: number;
  medium: number;
  low: number;
  informational: number;
  total: number;
}): string {
  if (summary.critical > 0) return 'CRITICAL';
  if (summary.high > 0) return 'HIGH';
  if (summary.medium > 0) return 'MEDIUM';
  if (summary.low > 0) return 'LOW';
  if (summary.informational > 0) return 'LOW';
  return 'SAFE';
}

export function vulnerabilityTypeDescription(type: VulnerabilityType): string {
  const map: Record<VulnerabilityType, string> = {
    REENTRANCY: 'External call made before state updates — recursive drain of funds.',
    INTEGER_OVERFLOW: 'Arithmetic exceeds type bounds and silently wraps.',
    INTEGER_UNDERFLOW: 'Arithmetic drops below zero and wraps to a huge value.',
    UNCHECKED_RETURN: 'Low-level call return value ignored — silent failures.',
    ACCESS_CONTROL: 'Sensitive operations callable by any address.',
    TIMESTAMP_DEPENDENCE: 'block.timestamp used in fairness / randomness logic.',
    FLASH_LOAN: 'Single-transaction borrow surface without guards or spot-price risk.',
    ORACLE_MANIPULATION: 'Pricing from manipulable single-block spot sources.',
    FRONT_RUNNING: 'No deadline/slippage protection; mempool-seizable intent.',
    SELF_DESTRUCT: 'Contract destruction reachable by unprivileged callers.',
    DELEGATECALL: 'Untrusted delegatecall can rewrite caller storage.',
    UNINITIALIZED_STORAGE: 'Storage pointers bound to the zero slot.',
  };
  return map[type] ?? 'Unknown vulnerability class.';
}

export function buildKeyFindingsParagraph(
  vulnerabilities: Vulnerability[]
): string {
  if (vulnerabilities.length === 0) {
    return 'No security issues were identified during the audit. The contract follows the ' +
      'Checks-Effects-Interactions pattern, applies access control on privileged operations, ' +
      'and does not rely on single-block pricing. We recommend a formal verification pass ' +
      'before mainnet deployment as a final hardening step.';
  }

  const criticals = vulnerabilities.filter((v) => v.severity === 'CRITICAL');
  const highs = vulnerabilities.filter((v) => v.severity === 'HIGH');
  const top = [...criticals, ...highs];

  const parts: string[] = [];
  if (criticals.length > 0) {
    parts.push(
      `The contract contains ${criticals.length} critical finding${criticals.length > 1 ? 's' : ''}: ` +
        criticals.map((c) => `${c.title} (${c.swcId})`).join('; ') +
        '. These require immediate remediation before any deployment or additional TVL.'
    );
  }
  if (highs.length > 0) {
    parts.push(
      `${highs.length} high severity issue${highs.length > 1 ? 's' : ''} were identified, ` +
        `including ${highs[0].title} (${highs[0].swcId}).`
    );
  }
  if (mediaCount(vulnerabilities) > 0) {
    parts.push(
      `The audit also flagged ${mediaCount(vulnerabilities)} medium-severity concern${mediaCount(vulnerabilities) > 1 ? 's' : ''} ` +
        'related to protocol economics and oracle usage that should be addressed with hardened integrations.'
    );
  }
  if (top.length === 0) {
    parts.push(
      'No critical or high-severity issues were identified. Remaining findings are informational ' +
        'and engineering-level improvements.'
    );
  }
  return parts.join(' ');
}

function mediaCount(vulns: Vulnerability[]): number {
  return vulns.filter((v) => v.severity === 'MEDIUM').length;
}

export interface SecurityLevel {
  icon: string;
  label: string;
  description: string;
  min: number;
  max: number;
  color: string;
}

export const CYBER_SECURITY_LEVELS: SecurityLevel[] = [
  {
    icon: '✕',
    label: 'CRITICAL',
    description: 'Immediate action required — funds are at direct risk of loss or theft.',
    min: 0,
    max: 19.9,
    color: '#EF4444',
  },
  {
    icon: '!',
    label: 'HIGH RISK',
    description: 'High-priority remediation needed before adding further value or users.',
    min: 20,
    max: 39.9,
    color: '#F97316',
  },
  {
    icon: 'Δ',
    label: 'ELEVATED RISK',
    description: 'Not deployable as-is; medium-severity issues must be resolved.',
    min: 40,
    max: 59.9,
    color: '#EAB308',
  },
  {
    icon: '–',
    label: 'MODERATE',
    description: 'Generally sound but hardening and polish still recommended.',
    min: 60,
    max: 79.9,
    color: '#3B82F6',
  },
  {
    icon: '✓',
    label: 'LOW RISK',
    description: 'Minor issues only; safe to proceed with normal review cycles.',
    min: 80,
    max: 100,
    color: '#00FF88',
  },
];

export function getSecurityLevel(auditScore: number): SecurityLevel {
  return (
    CYBER_SECURITY_LEVELS.find((l) => auditScore >= l.min && auditScore <= l.max) ??
    CYBER_SECURITY_LEVELS[0]
  );
}