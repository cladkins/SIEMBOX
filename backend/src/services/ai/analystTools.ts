/**
 * Read-only "tools" the AI Security Analyst may call. Each tool maps to an
 * existing service/model function (called directly, never over HTTP). The model
 * only ever picks a tool NAME and supplies args that are validated + clamped here
 * — model output is never turned into SQL/URLs/shell. Results are shaped to a
 * small field whitelist so the LLM never receives unbounded rows.
 *
 * Everything here is strictly read-only: there are no create/update/delete
 * executors, which is what makes the v1 analyst safe by construction.
 */
import { isIP } from 'net';
import { AlertModel } from '../../models/Alert';
import { ParsedLogModel } from '../../models/ParsedLog';
import { EdrAgentModel } from '../../models/EdrAgent';
import { AssetRepository } from '../assets/assetRepository';
import { AutoDiscoveryService } from '../assets/autoDiscoveryService';
import { VulnerabilityProcessor } from '../scanner/vulnerabilityProcessor';
import { FeedService } from '../threatintel/feedService';
import { ReputationService } from '../threatintel/reputationService';

export type Role = 'admin' | 'analyst' | 'viewer' | 'operator';

export interface ToolContext {
  userRole: Role;
}

export interface AnalystTool {
  name: string;
  description: string;
  /** Human-readable arg spec rendered into the system prompt. */
  args: string;
  /** When set, only this role (or admin) sees and can call the tool. */
  minRole?: Role;
  run: (args: Record<string, any>, ctx: ToolContext) => Promise<any>;
}

// ---- arg coercion helpers (never trust the model's values) -------------------

function clampInt(v: any, min: number, max: number, def: number): number {
  const n = Math.floor(Number(v));
  if (!Number.isFinite(n)) return def;
  return Math.min(max, Math.max(min, n));
}
function enumArg(v: any, allowed: readonly string[]): string | undefined {
  const s = String(v ?? '').toLowerCase();
  return allowed.includes(s) ? s : undefined;
}
function str(v: any, maxLen = 64): string | undefined {
  if (typeof v !== 'string') return undefined;
  const s = v.trim();
  return s ? s.slice(0, maxLen) : undefined;
}
function sinceHoursToDate(hours: number): Date {
  return new Date(Date.now() - hours * 3600 * 1000);
}
function pick<T extends Record<string, any>>(o: T | null | undefined, keys: string[]): any {
  if (!o) return o;
  const out: Record<string, any> = {};
  for (const k of keys) if (o[k] !== undefined) out[k] = o[k];
  return out;
}
function clip(s: any, n = 400): any {
  if (typeof s !== 'string') return s;
  return s.length > n ? s.slice(0, n) + '…' : s;
}

const SEVERITIES = ['low', 'medium', 'high', 'critical'] as const;
const ALERT_STATUSES = ['new', 'investigating', 'closed', 'false_positive'] as const;
const VULN_STATUSES = ['open', 'patched', 'false_positive', 'accepted'] as const;
const ASSET_STATUSES = ['active', 'inactive', 'offline'] as const;
const ASSET_TYPES = ['server', 'workstation', 'network', 'iot', 'mobile', 'endpoint', 'unknown'] as const;

// ---- the registry -----------------------------------------------------------

const ALL_TOOLS: AnalystTool[] = [
  {
    name: 'get_system_overview',
    description: 'High-level posture: alert, vulnerability, and asset summary counts. Start here for "what should I look at" questions.',
    args: 'none',
    run: async () => {
      const [alerts, vulnerabilities, assets] = await Promise.all([
        AlertModel.getStatistics(),
        VulnerabilityProcessor.getVulnerabilityStats(),
        AutoDiscoveryService.getStatistics(),
      ]);
      return { alerts, vulnerabilities, assets };
    },
  },
  {
    name: 'get_alert_stats',
    description: 'Counts of alerts by status (new/investigating/closed) and severity.',
    args: 'none',
    run: async () => AlertModel.getStatistics(),
  },
  {
    name: 'list_alerts',
    description: 'List recent alerts, newest first, optionally filtered. Use to triage current detections.',
    args: 'severity?(low|medium|high|critical), status?(new|investigating|closed|false_positive), limit?(1-25, default 10), sinceHours?(1-168)',
    run: async (a) => {
      const severity = enumArg(a.severity, SEVERITIES);
      const status = enumArg(a.status, ALERT_STATUSES);
      const limit = clampInt(a.limit, 1, 25, 10);
      const sinceHours = a.sinceHours !== undefined ? clampInt(a.sinceHours, 1, 168, 24) : undefined;
      const startTime = sinceHours ? sinceHoursToDate(sinceHours) : undefined;
      const { alerts, total } = await AlertModel.findAll({ severity, status, limit, startTime });
      return {
        total,
        alerts: (alerts || []).map((al: any) => ({
          id: al.id,
          severity: al.severity,
          status: al.status,
          title: al.title,
          created_at: al.created_at,
          source_ip: al.matched_data?.source_ip,
          country: al.matched_data?.country_name,
        })),
      };
    },
  },
  {
    name: 'get_alert',
    description: 'Full detail for one alert by id (title, description, matched data, status).',
    args: 'id(number, required)',
    run: async (a) => {
      const id = clampInt(a.id, 1, Number.MAX_SAFE_INTEGER, 0);
      if (!id) return { error: 'id is required' };
      const al: any = await AlertModel.findById(id);
      if (!al) return { error: `alert ${id} not found` };
      return {
        id: al.id,
        severity: al.severity,
        status: al.status,
        title: al.title,
        description: clip(al.description, 800),
        created_at: al.created_at,
        matched_data: al.matched_data,
      };
    },
  },
  {
    name: 'alerts_by_country',
    description: 'Alert counts grouped by source country over the last N days (incl. foreign-login counts).',
    args: 'days?(1-365, default 30), limit?(1-25, default 10)',
    run: async (a) => {
      const days = clampInt(a.days, 1, 365, 30);
      const limit = clampInt(a.limit, 1, 25, 10);
      return { rows: await AlertModel.getCountByCountry(days, limit) };
    },
  },
  {
    name: 'get_vulnerability_stats',
    description: 'Vulnerability posture: open/patched counts by severity, affected assets, unique CVEs.',
    args: 'none',
    run: async () => VulnerabilityProcessor.getVulnerabilityStats(),
  },
  {
    name: 'get_asset_vulnerabilities',
    description: 'Vulnerabilities for a specific asset id (CVE, severity, CVSS, status).',
    args: 'assetId(number, required), status?(open|patched|false_positive|accepted), severity?(low|medium|high|critical), limit?(1-25, default 10)',
    run: async (a) => {
      const assetId = clampInt(a.assetId, 1, Number.MAX_SAFE_INTEGER, 0);
      if (!assetId) return { error: 'assetId is required' };
      const rows = await VulnerabilityProcessor.getAssetVulnerabilities(assetId, {
        status: enumArg(a.status, VULN_STATUSES),
        severity: enumArg(a.severity, SEVERITIES),
        limit: clampInt(a.limit, 1, 25, 10),
      });
      return {
        asset_id: assetId,
        vulnerabilities: (rows || []).map((v: any) => ({
          cve_id: v.cve_id,
          title: clip(v.title, 160),
          severity: v.severity,
          cvss_score: v.cvss_score,
          status: v.status,
        })),
      };
    },
  },
  {
    name: 'list_assets',
    description: 'List discovered assets, optionally filtered. Use to find hosts by name/IP or by criticality.',
    args: 'status?(active|inactive|offline), criticality?(low|medium|high|critical), asset_type?(server|workstation|network|iot|mobile|endpoint|unknown), search?(IP or hostname), limit?(1-25, default 10)',
    run: async (a) => {
      const { assets, total } = await AssetRepository.getAll({
        status: enumArg(a.status, ASSET_STATUSES) as any,
        criticality: enumArg(a.criticality, SEVERITIES) as any,
        asset_type: enumArg(a.asset_type, ASSET_TYPES) as any,
        search: str(a.search),
        limit: clampInt(a.limit, 1, 25, 10),
      });
      return {
        total,
        assets: (assets || []).map((as: any) => ({
          id: as.id,
          hostname: as.hostname,
          ip_address: as.ip_address,
          asset_type: as.asset_type,
          criticality: as.criticality,
          status: as.status,
          last_seen: as.last_seen,
        })),
      };
    },
  },
  {
    name: 'get_asset',
    description: 'Full detail for one asset by id, incl. open ports/services.',
    args: 'id(number, required)',
    run: async (a) => {
      const id = clampInt(a.id, 1, Number.MAX_SAFE_INTEGER, 0);
      if (!id) return { error: 'id is required' };
      const as: any = await AssetRepository.getById(id);
      if (!as) return { error: `asset ${id} not found` };
      return {
        ...pick(as, [
          'id',
          'ip_address',
          'hostname',
          'os_type',
          'os_version',
          'asset_type',
          'criticality',
          'status',
          'first_seen',
          'last_seen',
        ]),
        services: (as.services || [])
          .slice(0, 25)
          .map((s: any) => ({ port: s.port, protocol: s.protocol, service_name: s.service_name, state: s.state })),
      };
    },
  },
  {
    name: 'get_asset_stats',
    description: 'Asset discovery summary: counts by discovery method, active/offline, recently seen.',
    args: 'none',
    run: async () => AutoDiscoveryService.getStatistics(),
  },
  {
    name: 'lookup_ip',
    description: 'Threat-intel verdict for an IP: which blocklist feeds flag it + reputation provider scores.',
    args: 'ip(IPv4/IPv6, required)',
    run: async (a) => {
      const ip = str(a.ip, 64);
      if (!ip || !isIP(ip)) return { error: 'a valid ip is required' };
      const [feeds, reputation] = await Promise.all([
        FeedService.lookupIp(ip),
        ReputationService.lookupIp(ip),
      ]);
      return {
        ip,
        feeds,
        reputation: (reputation || []).map((r: any) =>
          pick(r, ['provider', 'label', 'ok', 'score', 'classification', 'summary'])
        ),
      };
    },
  },
  {
    name: 'search_logs',
    description: 'Search recent PARSED logs (expensive — always bounded). Use to investigate an IP or event type.',
    args: 'sinceHours(1-72, REQUIRED), sourceIp?(IP), eventType?, appName?, search?(text), limit?(1-20, default 10)',
    run: async (a) => {
      const sinceHours = clampInt(a.sinceHours, 1, 72, 24);
      const sourceIp = str(a.sourceIp, 64);
      if (sourceIp && !isIP(sourceIp)) return { error: 'sourceIp must be a valid IP' };
      const { logs, total } = await ParsedLogModel.findAll({
        sourceIp,
        eventType: str(a.eventType),
        appName: str(a.appName),
        search: str(a.search),
        startTime: sinceHoursToDate(sinceHours),
        limit: clampInt(a.limit, 1, 20, 10),
      });
      return {
        total,
        logs: (logs || []).map((l: any) => ({
          id: l.id,
          timestamp: l.timestamp,
          source_ip: l.source_ip,
          event_type: l.event_type,
          app_name: l.app_name,
          parsed_data: clip(JSON.stringify(l.parsed_data ?? {}), 500),
        })),
      };
    },
  },
  {
    name: 'list_edr_agents',
    description: 'List EDR endpoint agents with status, open vuln counts, and recent detections. (Admin only.)',
    args: 'none',
    minRole: 'admin',
    run: async () => {
      const rows = await EdrAgentModel.listWithStats();
      return {
        agents: (rows || []).map((g: any) => ({
          agent_id: g.agent_id,
          hostname: g.hostname,
          os: g.os,
          status: g.live_status || g.status,
          last_seen: g.last_seen,
          open_vulns: g.open_vulns,
          recent_detections: g.recent_detections,
        })),
      };
    },
  },
];

/** Tools visible to a given role (admin sees everything; minRole gates the rest). */
export function getToolsForRole(role: Role): AnalystTool[] {
  return ALL_TOOLS.filter((t) => !t.minRole || role === 'admin' || role === t.minRole);
}

/** Find a role-permitted tool by name (returns undefined if missing or not allowed). */
export function findToolForRole(name: string, role: Role): AnalystTool | undefined {
  return getToolsForRole(role).find((t) => t.name === name);
}
