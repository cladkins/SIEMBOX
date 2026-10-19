/**
 * What each panel key is called on the wall, and which attribution a view
 * that shows it must print (BIG-DISPLAY.md §5.3). Pure.
 */
import type { Attribution } from '../types.ts';

/** 'recent_alerts:high' -> ['recent_alerts', 'high']; 'ingest' -> ['ingest', null]. */
export function splitKey(key: string): [string, string | null] {
  const i = key.indexOf(':');
  return i < 0 ? [key, null] : [key.slice(0, i), key.slice(i + 1)];
}

const WINDOW_DAYS: Record<string, string> = { '1': '24 h', '7': '7 days', '30': '30 days' };

export function panelTitle(key: string): string {
  const [kind, param] = splitKey(key);
  switch (kind) {
    case 'open_alerts':
      return 'Open alerts';
    case 'alert_pulse':
      return 'Alerts, last 24 h';
    case 'recent_alerts':
      return param === 'critical'
        ? 'Recent critical'
        : param === 'medium'
          ? 'Recent medium and above'
          : 'Recent high & critical';
    case 'top_rules':
      return param === '1' ? 'Top detections, 1 h' : 'Top detections, 24 h';
    case 'ingest':
      return 'Log ingestion';
    case 'sources':
      return `Sources (silent > ${param ?? '15'} m)`;
    case 'shippers':
      return 'Shippers';
    case 'endpoints':
      return 'Endpoints';
    case 'threat_map':
      return `Alert origins, ${WINDOW_DAYS[param ?? '1'] ?? '24 h'}`;
    case 'top_sources':
      return 'Top alerting addresses, 24 h';
    case 'digital_risk':
      return 'Digital risk';
    case 'vulnerabilities':
      return 'Vulnerabilities';
    default:
      return kind;
  }
}

/** The attributions a view's panels require, in the order the snapshot lists them. */
export function viewAttributions(panelKeys: readonly string[], available: readonly Attribution[]): Attribution[] {
  const kinds = new Set(panelKeys.map((key) => splitKey(key)[0]));
  return available.filter((a) =>
    a === 'dbip' ? kinds.has('threat_map') || kinds.has('top_sources') : kinds.has('digital_risk')
  );
}

export const ATTRIBUTION_TEXT: Record<Attribution, string> = {
  dbip: 'IP Geolocation by DB-IP (db-ip.com)',
  hibp: 'Breach data: Have I Been Pwned (CC BY 4.0)',
};
