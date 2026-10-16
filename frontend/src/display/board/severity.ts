/**
 * Severity on the wall (BIG-DISPLAY.md §5.1): never colour alone, always a
 * word, a shape and the fixed order ◆ Critical, ▲ High, ● Medium, ▼ Low. The
 * colours are the app's own (utils/severity.ts), so the wall and the app agree.
 */
import { SEVERITY_COLORS, SEVERITY_LABELS } from '../../utils/severity.ts';
import type { Category, Sev } from '../types.ts';

export const SEV_ORDER: readonly Sev[] = ['critical', 'high', 'medium', 'low'];

export const SEV_SHAPE: Record<Sev, string> = { critical: '◆', high: '▲', medium: '●', low: '▼' };

export const SEV_LABEL: Record<Sev, string> = SEVERITY_LABELS;

export const SEV_COLOR: Record<Sev, string> = {
  critical: SEVERITY_COLORS.critical,
  high: SEVERITY_COLORS.high,
  medium: SEVERITY_COLORS.medium,
  low: SEVERITY_COLORS.low,
};

/** Fixed wording for alerts SIEMBox's own monitors raise (the server sends a label for rule alerts). */
export const CATEGORY_LABEL: Record<Category, string> = {
  rule: 'Detection rule',
  sign_in: 'Sign-in protection',
  leaked_credentials: 'Leaked credentials',
  domain_monitoring: 'Domain monitoring',
  endpoint: 'Endpoint detection',
  other: 'Other',
};
