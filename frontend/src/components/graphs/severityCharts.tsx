import { useMemo } from 'react';
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  Legend,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
} from 'recharts';
import { Severity, Vulnerability } from '@/types';
import { SEVERITY_COLORS, SEVERITY_ORDER } from '@/utils/severity.utils';

const SEVERITY_LABELS: Record<Severity, string> = {
  CRITICAL: 'Critical',
  HIGH: 'High',
  MEDIUM: 'Medium',
  LOW: 'Low',
  INFORMATIONAL: 'Info',
};

export interface SeverityPieChartProps {
  vulnerabilities: Vulnerability[];
  height?: number;
}

export function SeverityPieChart({ vulnerabilities, height = 280 }: SeverityPieChartProps) {
  const data = useMemo(
    () =>
      SEVERITY_ORDER.map((sev) => ({
        name: SEVERITY_LABELS[sev],
        value: vulnerabilities.filter((v) => v.severity === sev).length,
        color: SEVERITY_COLORS[sev].hex,
      })).filter((d) => d.value > 0),
    [vulnerabilities]
  );

  if (data.length === 0) {
    return (
      <div className="flex h-[280px] items-center justify-center text-sm text-textSecondary">
        No findings to chart.
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={height}>
      <PieChart>
        <Pie
          data={data}
          cx="50%"
          cy="50%"
          innerRadius={60}
          outerRadius={95}
          paddingAngle={3}
          dataKey="value"
          stroke="#0A0B0D"
          strokeWidth={2}
        >
          {data.map((entry) => (
            <Cell key={entry.name} fill={entry.color} />
          ))}
        </Pie>
        <Tooltip
          contentStyle={{
            background: '#111318',
            border: '1px solid #2A2D35',
            borderRadius: 8,
            color: '#F1F5F9',
            fontFamily: 'JetBrains Mono, monospace',
            fontSize: 12,
          }}
          formatter={(value: number | string) => [`${value} finding${Number(value) === 1 ? '' : 's'}`, '']}
        />
        <Legend
          formatter={(value: string) => (
            <span style={{ color: '#9CA3AF', fontSize: 12 }}>{value}</span>
          )}
          iconType="circle"
        />
      </PieChart>
    </ResponsiveContainer>
  );
}

export interface VulnBarChartProps {
  vulnerabilities: Vulnerability[];
  height?: number;
}

export function VulnBarChart({ vulnerabilities, height = 260 }: VulnBarChartProps) {
  const data = useMemo(() => {
    const grouped = new Map<string, { count: number; severity: Severity }>();
    for (const v of vulnerabilities) {
      const cur = grouped.get(v.type) ?? { count: 0, severity: v.severity };
      cur.count += 1;
      if (SEVERITY_ORDER.indexOf(v.severity) < SEVERITY_ORDER.indexOf(cur.severity)) {
        cur.severity = v.severity;
      }
      grouped.set(v.type, cur);
    }
    return [...grouped.entries()]
      .map(([type, val]) => ({
        name: type.replace(/_/g, ' ').toLowerCase(),
        findings: val.count,
        color: SEVERITY_COLORS[val.severity].hex,
      }))
      .sort((a, b) => b.findings - a.findings);
  }, [vulnerabilities]);

  if (data.length === 0) {
    return (
      <div className="flex h-[260px] items-center justify-center text-sm text-textSecondary">
        No vulnerability classes to chart.
      </div>
    );
  }

  return (
    <ResponsiveContainer width="100%" height={height}>
      <BarChart data={data} layout="vertical" margin={{ left: 8, right: 16, top: 8, bottom: 8 }}>
        <CartesianGrid stroke="#2A2D35" strokeDasharray="3 3" horizontal={false} />
        <XAxis
          type="number"
          allowDecimals={false}
          tick={{ fill: '#6B7280', fontSize: 11 }}
          axisLine={{ stroke: '#2A2D35' }}
          tickLine={false}
        />
        <YAxis
          type="category"
          dataKey="name"
          width={110}
          tick={{ fill: '#9CA3AF', fontSize: 11, fontFamily: 'monospace' }}
          axisLine={false}
          tickLine={false}
        />
        <Tooltip
          contentStyle={{
            background: '#111318',
            border: '1px solid #2A2D35',
            borderRadius: 8,
            color: '#F1F5F9',
            fontFamily: 'JetBrains Mono, monospace',
            fontSize: 12,
          }}
          cursor={{ fill: 'rgba(0,255,136,0.05)' }}
        />
        <Bar dataKey="findings" radius={[0, 6, 6, 0]} barSize={18}>
          {data.map((entry) => (
            <Cell key={entry.name} fill={entry.color} />
          ))}
        </Bar>
      </BarChart>
    </ResponsiveContainer>
  );
}