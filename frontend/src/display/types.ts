/**
 * The snapshot a screen renders: a copy of backend/src/services/display/types.ts
 * (docs/architecture/BIG-DISPLAY.md §7.6). Keep the two in step. Every string
 * in panel data is an enum, an ISO timestamp or a label the server's privacy
 * check allowed; the board renders them as text only (no v-html).
 */
export type Sev = 'critical' | 'high' | 'medium' | 'low';
export type Privacy = 'operations' | 'public';

export const SEVERITIES: readonly Sev[] = ['critical', 'high', 'medium', 'low'];

/** What raised an alert: a detection rule, or one of SIEMBox's own monitors. */
export type Category = 'rule' | 'sign_in' | 'leaked_credentials' | 'domain_monitoring' | 'endpoint' | 'other';

export interface OpenAlerts {
  total: number;
  by_severity: Record<Sev, { open: number; untouched: number; oldest_at: string | null }>;
}

export interface AlertPulse {
  total_24h: number;
  prev_24h: number;
  last_hour: number;
  by_severity_24h: Record<Sev, number>;
  /** 24, oldest first; the last is the current, partial hour. */
  hourly: Array<{ total: number; critical: number }>;
}

export interface RecentAlerts {
  min_severity: Sev;
  more: boolean;
  /** At most 6, newest first. */
  items: Array<{ severity: Sev; status: 'new' | 'investigating'; category: Category; label: string; at: string }>;
}

export interface TopRules {
  window_hours: 1 | 24;
  total: number;
  /** At most 6. */
  items: Array<{ category: Category; label: string; worst_severity: Sev; count: number }>;
}

export type IngestState = 'flowing' | 'slow' | 'stalled' | 'idle';

export interface Ingest {
  state: IngestState;
  last_log_at: string | null;
  stall_minutes: number;
  /** The last complete minute. */
  logs_last_minute: number | null;
  /** 60, oldest first; the last is the current, partial minute. Null without the rollup. */
  per_minute: number[] | null;
  rate_15m_per_minute: number | null;
  /** The 24 h median per minute. */
  baseline_per_minute: number | null;
  /** 24, oldest first. */
  hourly: Array<{ total: number; unparsed: number }>;
  parsed_pct_24h: number | null;
  udp_dropped_15m: number | null;
  /** The oldest minute the rollup holds. */
  rollup_since: string | null;
}

/**
 * silent: a steady source that stopped. quiet: a low-volume or bursty source
 * between writes (never alarmed). unknown: it might have logged into the
 * counter's overflow row meanwhile, so its silence can't be told.
 */
export type SourceState = 'silent' | 'active' | 'quiet' | 'unknown';

export interface Sources {
  silent_after_minutes: number;
  active: number;
  silent: number;
  quiet: number;
  unknown: number;
  unknown_shippers: number;
  /** Set while the rollup holds less than 24 h: "Collecting since …". */
  since: string | null;
  more_active: number;
  /** At most 8; [] in public mode. */
  rows: Array<{
    kind: 'shipper' | 'poller' | 'direct';
    label: string | null;
    state: SourceState;
    logs_per_minute: number;
    last_seen_at: string;
    silent_minutes: number | null;
  }>;
}

export interface Shippers {
  total: number;
  online: number;
  offline: number;
  pending: number;
  error: number;
  unknown_shippers_24h: number | null;
  /** At most 6, longest offline first; [] in public mode. */
  offline_list: Array<{ name: string; last_seen_at: string | null }>;
}

export interface Endpoints {
  total: number;
  online: number;
  offline: number;
  detections_24h: number;
  /** At most 6. */
  offline_list: Array<{ hostname: string | null; last_seen_at: string | null }>;
}

export interface ThreatMap {
  window_days: 1 | 7 | 30;
  located: number;
  total_in_window: number;
  /** At most 50; ISO 3166 alpha-2 codes only (names come from the client). */
  countries: Array<{ code: string; count: number }>;
}

export interface TopSources {
  /** At most 6. */
  items: Array<{ ip: string; country_code: string | null; alerts: number; worst_severity: Sev; last_at: string }>;
}

export interface DigitalRisk {
  configured: boolean;
  open_total: number;
  open_by_severity: Record<Sev, number>;
  new_7d: number;
  accounts_to_reset: number;
  impersonation_open: number;
}

export interface Vulnerabilities {
  scanned: boolean;
  open_by_severity: Record<Sev, number>;
  affected_assets: number;
}

export type PanelData =
  | OpenAlerts
  | AlertPulse
  | RecentAlerts
  | TopRules
  | Ingest
  | Sources
  | Shippers
  | Endpoints
  | ThreatMap
  | TopSources
  | DigitalRisk
  | Vulnerabilities;

export type PanelEnvelope =
  | { state: 'ok'; as_of: string; data: PanelData }
  | { state: 'stale'; as_of: string; reason: 'busy' | 'error'; data: PanelData }
  | { state: 'unavailable'; reason: 'busy' | 'error' }
  | { state: 'not_configured'; message: string }
  | { state: 'forbidden' };

export type AlarmKey =
  | 'new_critical'
  | 'ingest_stalled'
  | 'udp_drops'
  | 'ingest_slow'
  | 'sources_silent'
  | 'shippers_offline'
  | 'endpoints_offline'
  | 'data_delayed';

export interface Alarm {
  key: AlarmKey;
  level: 'critical' | 'warning';
  text: string;
  /** The panel key it came from (for data_delayed, the first panel that is delayed). */
  panel: string;
}

export type Attribution = 'dbip' | 'hibp';

export interface DisplayBlock {
  name: string;
  config_version: number;
  privacy: Privacy;
  refresh_seconds: number;
  rotation: { enabled: boolean; seconds: number };
  timezone: string | null;
  clock: boolean;
  burn_in_shift: boolean;
  /** Panel keys. */
  views: Array<{ title: string; panels: string[] }>;
}

export interface DisplaySnapshot {
  /** When it was assembled (ISO). */
  generated_at: string;
  /** For the screen's clock offset. */
  server_time: string;
  /** The backend's version: a screen reloads itself when it changes. */
  app_version: string;
  display: DisplayBlock;
  /** At most 4, critical first. */
  alarms: Alarm[];
  attributions: Attribution[];
  /** One per distinct panel key in the views. */
  panels: Record<string, PanelEnvelope>;
}

/** The refusal codes a screen acts on (backend/src/middleware/displayAuth.ts). */
export type RefusalCode =
  | 'DISPLAY_TOKEN_REQUIRED'
  | 'DISPLAY_LINK_INVALID'
  | 'DISPLAY_LINK_REVOKED'
  | 'DISPLAY_LINK_EXPIRED'
  | 'DISPLAY_LINK_PAUSED'
  | 'DISPLAY_NETWORK_NOT_ALLOWED';
