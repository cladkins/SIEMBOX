// Shared types for the Log Discovery feature (scope -> discovery -> matcher -> ranker -> onboarder).
// See spec: fingerprints/*.yaml are community-extensible signal definitions; a
// runtime source is what one scan observed about one host.

export interface PortSignal {
  port: number;
  weight: number;
}

export interface HttpSignal {
  path: string;
  expect?: string;
  weight: number;
}

export interface MdnsSignal {
  service: string;
  weight: number;
}

export interface SsdpSignal {
  st?: string;
  server_contains?: string;
  weight: number;
}

export interface TlsSignal {
  subject_cn?: string;
  weight: number;
}

export interface MacOuiSignal {
  oui: string;
  weight: number;
}

export interface FingerprintSignals {
  ports: PortSignal[];
  http: HttpSignal[];
  mdns: MdnsSignal[];
  ssdp: SsdpSignal[];
  tls: TlsSignal[];
  mac_oui: MacOuiSignal[];
}

export interface LogAccessMethod {
  method: 'syslog_push' | 'file' | 'api_pull' | string;
  target_port?: number;
  format?: string;
  auth?: string;
  path?: string;
  endpoint?: string;
}

export interface FingerprintCredentials {
  required: boolean;
  optional: Array<{ type: string; unlocks?: string[] }>;
}

export interface FingerprintEntry {
  id: string;
  name: string;
  category: string;
  security_value: number;
  signals: FingerprintSignals;
  confidence_floor: number;
  attack_data_sources: string[];
  log_access: LogAccessMethod[];
  onboard_template: string;
  credentials: FingerprintCredentials;
}

// What a scan observed about one host, before matching.
export interface HttpProbeResult {
  port: number;
  path: string;
  status: number | null;
  body: string;
  headers: Record<string, string>;
}

export interface TlsProbeResult {
  port: number;
  subject_cn?: string;
  san?: string[];
}

export interface BannerResult {
  port: number;
  banner: string;
}

export interface DiscoveredSignals {
  ip: string;
  mac?: string;
  hostname?: string;
  open_ports: number[];
  http_responses: HttpProbeResult[];
  tls_subjects: TlsProbeResult[];
  banners: BannerResult[];
  mdns_services: string[];
  ssdp_services: Array<{ st?: string; server?: string }>;
  discovery_methods: string[]; // arp | mdns | ssdp | dhcp_lease | active_probe
}

export interface FingerprintMatch {
  fingerprint: FingerprintEntry;
  weight: number;
  confidence: number; // weight capped to [0, 100]
  is_guess: boolean; // confidence below the fingerprint's confidence_floor
  matched_signals: string[]; // human-readable list, e.g. "port 443", "http /admin/"
}

export type SourceStatus = 'candidate' | 'confirmed' | 'onboarded' | 'ignored';

/** Bulk poller status for the sources table — never includes the credential itself. */
export interface RuntimeSourcePollerStatus {
  configured: boolean;
  enabled: boolean;
  last_status: 'ok' | 'error' | null;
  last_polled_at: string | null;
  last_error: string | null;
}

export interface RuntimeSource {
  id: number;
  ip: string;
  mac: string | null;
  hostname: string | null;
  open_ports: number[];
  matched_fingerprint_id: string | null;
  confidence: number;
  is_guess: boolean;
  security_value: number | null;
  status: SourceStatus;
  selected_log_access: LogAccessMethod | null;
  evidence: Record<string, unknown>;
  poller?: RuntimeSourcePollerStatus;
}

export interface RankedSource extends RuntimeSource {
  reason: string;
}

export interface RankedResult {
  top: RankedSource[];
  advanced: RankedSource[];
}
