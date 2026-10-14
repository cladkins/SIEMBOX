import apiClient from './api';

export type DiscoverySourceStatus = 'candidate' | 'confirmed' | 'onboarded' | 'ignored';
export type DiscoveryScanMode = 'passive' | 'active' | 'full';
export type DiscoveryScanStatus = 'queued' | 'running' | 'completed' | 'failed';

/** A log shipper as returned by GET /api/shippers (only the fields the picker needs). */
export interface ShipperSummary {
  id: number;
  name: string;
  status: 'pending' | 'online' | 'offline' | 'error';
  hostname?: string | null;
}

export interface LogAccessMethod {
  method: string;
  target_port?: number;
  format?: string;
  auth?: string;
  path?: string;
  endpoint?: string;
}

export interface FingerprintEntry {
  id: string;
  name: string;
  category: string;
  security_value: number;
  confidence_floor: number;
  attack_data_sources: string[];
  log_access: LogAccessMethod[];
  credentials: { required: boolean; optional: Array<{ type: string; unlocks?: string[] }> };
}

export interface RankedSourcePollerStatus {
  configured: boolean;
  enabled: boolean;
  last_status: 'ok' | 'error' | null;
  last_polled_at: string | null;
  last_error: string | null;
  /** The URL being polled (scheme, host, port, path; never a credential or query string). */
  effective_url?: string | null;
}

/**
 * How SIEMBox reaches an API-polled source (GET .../poller `target`). Only a
 * manually added source's address can change; port/tls/endpoint are editable
 * for every source. Never includes a credential.
 */
export interface PollTargetView {
  fingerprint_id: string;
  manual: boolean;
  ip_address: string;
  /** What polling uses now: the stored setting where there is one, else the default. */
  port: number;
  tls: boolean;
  effective_url: string;
  /** The stored settings; for a scan-discovered source, null where the default applies. */
  overrides: { port: number | null; tls: boolean | null; endpoint: string | null };
  defaults: { port: number; tls: boolean; endpoint: string };
}

/** Body for PATCH /log-discovery/sources/:id. Absent = unchanged; null = back to the default. */
export interface SourceTargetChanges {
  /** Manually added sources only. */
  ip_address?: string;
  port?: number | null;
  tls?: boolean | null;
  /** A path such as /api/hassio/core/logs; null (or '') = the fingerprint's endpoint. */
  endpoint?: string | null;
  /**
   * Required with an ip_address change when the source has a saved token: the
   * server never sends a saved token to a new address, so the token comes
   * again and is swapped in the same update as the move.
   */
  credential?: { secret: string; username?: string };
  /**
   * The source's address as it was loaded: the change only applies while the
   * source still has it (409 otherwise, e.g. when another admin moved it while
   * the dialog was open).
   */
  expected_ip_address?: string;
}

export interface SourceTargetUpdateResult {
  source: { id: number; ip_address: string };
  poller: PollerStatus;
  target: PollTargetView | null;
}

export interface RankedSource {
  id: number;
  ip: string;
  mac: string | null;
  hostname: string | null;
  open_ports: number[];
  matched_fingerprint_id: string | null;
  confidence: number;
  is_guess: boolean;
  security_value: number | null;
  status: DiscoverySourceStatus;
  selected_log_access: LogAccessMethod | null;
  evidence: Record<string, unknown>;
  reason: string;
  poller?: RankedSourcePollerStatus;
}

export interface RankedSources {
  top: RankedSource[];
  advanced: RankedSource[];
}

export interface DiscoveryScan {
  id: number;
  mode: DiscoveryScanMode;
  cidrs: string[];
  status: DiscoveryScanStatus;
  started_at: string;
  completed_at: string | null;
  error_message: string | null;
  results_summary: {
    hosts_seen: number;
    hosts_matched: number;
    /** Hosts that couldn't be matched or saved; the rest of the scan still completed. Absent on older scans. */
    hosts_failed?: number;
    /** The first few of those failures. */
    host_errors?: Array<{ ip: string; error: string }>;
  } | null;
  /** Shipper the scan ran on (null/absent = ran on the SIEMBox backend). */
  assigned_shipper_id?: number | null;
  assigned_shipper_name?: string | null;
}

export interface ScopePreview {
  cidrs: string[];
  vlan_warning: string | null;
  rejected_cidrs: string[];
  /** The host's real detected LAN CIDR, offered as a one-click suggestion. Only ever non-null under the opt-in host-networking mode — see DEPLOYMENT.md's "Log Discovery and Network Visibility" section. */
  detected_lan_cidr: string | null;
}

export interface TriggerScanResponse {
  scan_id: number;
  cidrs: string[];
  vlan_warning: string | null;
  rejected_cidrs: string[];
}

export interface OnboardPreview {
  instructions: string;
  log_access: LogAccessMethod;
}

export interface PollerStatus {
  configured: boolean;
  fingerprint_id?: string;
  credential_username?: string | null;
  enabled?: boolean;
  poll_interval_minutes?: number;
  last_polled_at?: string | null;
  last_status?: 'ok' | 'error' | null;
  last_error?: string | null;
  last_event_count?: number | null;
  /** How the source is reached; null when it has no API pull method. Only from GET .../poller. */
  target?: PollTargetView | null;
}

/** For calls whose caller shows the error itself (see api.ts's skipErrorToast). */
export interface QuietOption {
  quiet?: boolean;
}

export interface SaveCredentialOptions extends QuietOption {
  /**
   * The source's address the token is entered for (as shown to the admin): the
   * server only saves the token while the source still has it, and answers 409
   * otherwise, so a token typed for one address never reaches another.
   */
  expectedIpAddress?: string;
}

export interface PollNowResult {
  ok: boolean;
  count: number;
  error?: string;
}

/** Body for POST /log-discovery/sources/manual. port/scheme are persisted in the source's evidence server-side. */
export interface ManualSourcePayload {
  ip_address: string;
  hostname?: string;
  /** A pollable device-type id (from getPollableFingerprintIds). */
  fingerprint_id: string;
  port: number;
  tls: boolean;
}

class LogDiscoveryServiceClient {
  async getScope(manualCidrs: string[] = []): Promise<ScopePreview> {
    const params = manualCidrs.length > 0 ? `?manual_cidrs=${encodeURIComponent(manualCidrs.join(','))}` : '';
    const response = await apiClient.get(`/log-discovery/scope${params}`);
    return response.data;
  }

  /** The persisted standing scan-scope CIDRs (server-side, shared across admins/devices). */
  async getScopeCidrs(): Promise<string[]> {
    const response = await apiClient.get('/log-discovery/scope/cidrs');
    return response.data.cidrs;
  }

  /** Replace the persisted scan scope. Returns the accepted set plus any CIDRs the server rejected (invalid or larger than /22). */
  async saveScopeCidrs(cidrs: string[]): Promise<{ cidrs: string[]; rejected: string[] }> {
    const response = await apiClient.put('/log-discovery/scope/cidrs', { cidrs });
    return response.data;
  }

  async getFingerprints(): Promise<FingerprintEntry[]> {
    const response = await apiClient.get('/log-discovery/fingerprints');
    return response.data;
  }

  async triggerScan(
    mode: DiscoveryScanMode,
    manualCidrs: string[] = [],
    assignedShipperId?: number | null
  ): Promise<TriggerScanResponse> {
    const body: Record<string, unknown> = { mode, manual_cidrs: manualCidrs };
    if (assignedShipperId != null) body.assignedShipperId = assignedShipperId;
    const response = await apiClient.post('/log-discovery/scans', body);
    return response.data;
  }

  /** List log shippers (for the "Run from" discovery-scan picker). */
  async getShippers(): Promise<ShipperSummary[]> {
    const response = await apiClient.get('/shippers');
    return response.data;
  }

  async getScans(): Promise<DiscoveryScan[]> {
    const response = await apiClient.get('/log-discovery/scans');
    return response.data;
  }

  async getScan(id: number): Promise<DiscoveryScan> {
    const response = await apiClient.get(`/log-discovery/scans/${id}`);
    return response.data;
  }

  async cancelScan(id: number): Promise<{ cancelled: boolean; scan: DiscoveryScan }> {
    const response = await apiClient.post(`/log-discovery/scans/${id}/cancel`);
    return response.data;
  }

  async getSources(): Promise<RankedSources> {
    const response = await apiClient.get('/log-discovery/sources');
    return response.data;
  }

  async confirmSource(id: number): Promise<RankedSource> {
    const response = await apiClient.post(`/log-discovery/sources/${id}/confirm`);
    return response.data;
  }

  async ignoreSource(id: number): Promise<RankedSource> {
    const response = await apiClient.post(`/log-discovery/sources/${id}/ignore`);
    return response.data;
  }

  async previewOnboard(id: number, methodIndex = 0): Promise<OnboardPreview> {
    const response = await apiClient.post(`/log-discovery/sources/${id}/onboard/preview`, { method_index: methodIndex });
    return response.data;
  }

  async confirmOnboard(id: number, methodIndex = 0): Promise<{ source: RankedSource; instructions: string }> {
    const response = await apiClient.post(`/log-discovery/sources/${id}/onboard/confirm`, {
      method_index: methodIndex,
      confirm: true,
    });
    return response.data;
  }

  /** Fingerprint ids with a real poll adapter — so the UI doesn't hardcode which of the 10 bundled fingerprints support it. */
  async getPollableFingerprintIds(): Promise<string[]> {
    const response = await apiClient.get('/log-discovery/poller/supported-fingerprints');
    return response.data;
  }

  async getPollerStatus(id: number): Promise<PollerStatus> {
    const response = await apiClient.get(`/log-discovery/sources/${id}/poller`);
    return response.data;
  }

  async savePollerCredential(id: number, secret: string, username?: string, opts: SaveCredentialOptions = {}): Promise<PollerStatus> {
    const response = await apiClient.post(
      `/log-discovery/sources/${id}/poller/credential`,
      { secret, username, expected_ip_address: opts.expectedIpAddress },
      { skipErrorToast: opts.quiet }
    );
    return response.data;
  }

  async revokePollerCredential(id: number): Promise<{ cleared: boolean }> {
    const response = await apiClient.delete(`/log-discovery/sources/${id}/poller/credential`);
    return response.data;
  }

  async setPolling(id: number, changes: { enabled?: boolean; poll_interval_minutes?: number }): Promise<PollerStatus> {
    const response = await apiClient.patch(`/log-discovery/sources/${id}/poller`, changes);
    return response.data;
  }

  /**
   * Poll once now. Can take a while: each request to the source may wait up to
   * 15 s, and Home Assistant may try both of its log endpoints, so this allows
   * more than the client's 10 s default before giving up.
   */
  async runPollNow(id: number, opts: QuietOption = {}): Promise<PollNowResult> {
    const response = await apiClient.post(`/log-discovery/sources/${id}/poller/run-now`, undefined, {
      timeout: 90_000,
      skipErrorToast: opts.quiet,
    });
    return response.data;
  }

  /**
   * Change how SIEMBox reaches an API-polled source (admin only): port, HTTPS,
   * endpoint path, and for a manually added source its address. Leaves the saved
   * token alone. The caller shows validation errors itself.
   */
  async updateSourceTarget(id: number, changes: SourceTargetChanges): Promise<SourceTargetUpdateResult> {
    const response = await apiClient.patch(`/log-discovery/sources/${id}`, changes, { skipErrorToast: true });
    return response.data;
  }

  /**
   * Manually add an api_pull source for a device the admin already knows about,
   * without a scan. Returns the created discovery_sources row (we need its id to
   * then reuse savePollerCredential/setPolling/runPollNow). port/tls are stored
   * server-side in the source's evidence.
   */
  async createManualSource(payload: ManualSourcePayload): Promise<{ id: number; ip_address: string }> {
    const response = await apiClient.post('/log-discovery/sources/manual', payload);
    return response.data;
  }

  /** Delete a manually added source (403 from the server for a scan-discovered one). */
  async deleteSource(id: number): Promise<{ deleted: boolean }> {
    const response = await apiClient.delete(`/log-discovery/sources/${id}`);
    return response.data;
  }
}

export default new LogDiscoveryServiceClient();
