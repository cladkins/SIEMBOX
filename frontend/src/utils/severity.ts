/**
 * The shared 4-tier criticality vocabulary (alert severity, vulnerability
 * criticality, SOC triage risk, Digital Risk findings), so colour coding stays
 * the same on every panel. These colours are reserved for severity.
 */
export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low'] as const;
export type SeverityLevel = (typeof SEVERITY_ORDER)[number];

export const SEVERITY_LABELS: Record<SeverityLevel, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
};

export const SEVERITY_COLORS: Record<string, string> = {
  critical: '#f56c6c',
  high: '#e6a23c',
  medium: '#409eff',
  low: '#67c23a',
};
