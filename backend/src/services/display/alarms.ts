/**
 * The alarm strip (docs/architecture/BIG-DISPLAY.md §5.6) and the attribution
 * list (§5.3), derived from the panels a snapshot carries. Pure.
 *
 * Alarms come only from panels in some view of the display, never from a
 * forbidden one. Critical first, then in the order below; at most 4. Their
 * text is fixed wording and numbers only.
 */
import type { Alarm, AlarmKey, Attribution, Endpoints, Ingest, OpenAlerts, PanelEnvelope, Shippers, Sources } from './types';

export const MAX_ALARMS = 4;

const ORDER: AlarmKey[] = [
  'new_critical',
  'ingest_stalled',
  'udp_drops',
  'ingest_slow',
  'sources_silent',
  'shippers_offline',
  'endpoints_offline',
  'data_delayed',
];

/** Fixed wording: a symbol, then capitals, digits and spaces. */
export const ALARM_TEXT = /^[◆✕▲] [A-Z0-9 ()]{1,40}$/;

const plural = (n: number, one: string, many: string) => `${n} ${n === 1 ? one : many}`;

/** "18 MIN", "3 H", "2 D". */
export function durationText(ms: number): string {
  const minutes = Math.max(0, Math.floor(ms / 60_000));
  if (minutes < 120) return `${minutes} MIN`;
  const hours = Math.floor(minutes / 60);
  return hours < 48 ? `${hours} H` : `${Math.floor(hours / 24)} D`;
}

const idOf = (key: string) => key.split(':')[0];

export function deriveAlarms(panels: Record<string, PanelEnvelope>, at: number): Alarm[] {
  const alarms: Alarm[] = [];
  const add = (key: AlarmKey, level: Alarm['level'], text: string, panel: string) => {
    if (!alarms.some((a) => a.key === key)) alarms.push({ key, level, text, panel });
  };
  for (const [key, envelope] of Object.entries(panels)) {
    if (envelope.state !== 'ok' && envelope.state !== 'stale') continue;
    switch (idOf(key)) {
      case 'open_alerts': {
        const n = (envelope.data as OpenAlerts).by_severity.critical.untouched;
        if (n > 0) add('new_critical', 'critical', `◆ ${n} NEW CRITICAL`, key);
        break;
      }
      case 'ingest': {
        const ingest = envelope.data as Ingest;
        if (ingest.state === 'stalled' && ingest.last_log_at) {
          add('ingest_stalled', 'critical', `✕ NO LOGS FOR ${durationText(at - new Date(ingest.last_log_at).getTime())}`, key);
        }
        if ((ingest.udp_dropped_15m ?? 0) > 0) add('udp_drops', 'warning', '▲ DROPPING LOGS (UDP)', key);
        if (ingest.state === 'slow') add('ingest_slow', 'warning', '▲ LOG RATE LOW', key);
        break;
      }
      case 'sources': {
        const n = (envelope.data as Sources).silent;
        const current = alarms.find((a) => a.key === 'sources_silent');
        // Two sources panels with different thresholds: the larger count wins.
        if (n > 0 && current && Number(current.text.split(' ')[1]) < n) alarms.splice(alarms.indexOf(current), 1);
        if (n > 0) add('sources_silent', 'warning', `▲ ${plural(n, 'SOURCE', 'SOURCES')} SILENT`, key);
        break;
      }
      case 'shippers': {
        const n = (envelope.data as Shippers).offline;
        if (n > 0) add('shippers_offline', 'warning', `▲ ${plural(n, 'SHIPPER', 'SHIPPERS')} OFFLINE`, key);
        break;
      }
      case 'endpoints': {
        const n = (envelope.data as Endpoints).offline;
        if (n > 0) add('endpoints_offline', 'warning', `▲ ${plural(n, 'ENDPOINT', 'ENDPOINTS')} OFFLINE`, key);
        break;
      }
    }
  }
  const delayed = Object.entries(panels).find(([, e]) => e.state === 'stale' || e.state === 'unavailable');
  if (delayed) add('data_delayed', 'warning', '▲ SOME DATA DELAYED', delayed[0]);
  const rank = (a: Alarm) => (a.level === 'critical' ? 0 : 100) + ORDER.indexOf(a.key);
  return alarms.sort((a, b) => rank(a) - rank(b)).slice(0, MAX_ALARMS);
}

/** CC BY 4.0 credits for what the display shows: DB-IP for the map and source addresses, HIBP for Digital Risk. */
export function deriveAttributions(panels: Record<string, PanelEnvelope>): Attribution[] {
  const shown = Object.entries(panels)
    .filter(([, e]) => e.state !== 'forbidden')
    .map(([key]) => idOf(key));
  const out: Attribution[] = [];
  if (shown.includes('threat_map') || shown.includes('top_sources')) out.push('dbip');
  if (shown.includes('digital_risk')) out.push('hibp');
  return out;
}
