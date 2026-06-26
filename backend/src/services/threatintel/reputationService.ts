/**
 * On-demand IP reputation via bring-your-own-key providers (Phase 4).
 *
 * Unlike the blocklist feeds, these results are not bulk-ingested or persisted —
 * they're fetched live when an operator looks up an IP, then cached briefly in
 * memory to avoid hammering rate-limited APIs. Provider API keys are stored
 * encrypted in system_settings (same scheme as the AI builder key).
 */

import { isIP } from 'net';
import { query } from '../../config/database';
import { logger } from '../../utils/logger';
import { CredentialEncryption } from '../credentials/credentialEncryption';

const LOOKUP_TIMEOUT_MS = 12_000;
const CACHE_TTL_MS = 10 * 60 * 1000;

export type ProviderName = 'abuseipdb' | 'otx';

interface ProviderDef {
  name: ProviderName;
  label: string;
  docsUrl: string;
  signupUrl: string;
  lookup: (ip: string, key: string) => Promise<ReputationResult>;
}

export interface ReputationResult {
  provider: ProviderName;
  label: string;
  ok: boolean;
  summary?: string; // short human-readable verdict
  score?: number | null; // 0-100 risk where the provider exposes one
  classification?: string | null; // e.g. 'malicious' | 'benign' | 'unknown'
  link?: string | null; // provider page for this IP
  details?: Record<string, any>;
  error?: string;
}

// Defence-in-depth IP hygiene, applied INLINE in each provider's lookup. The
// primary SSRF barrier is structural: the request host is a constant baked into
// the URL object (see fetchJson), so the IP only ever lands in the path/query and
// cannot redirect the request. On top of that, isIP() at the entry point and this
// regexp guard reject any malformed value before it reaches a provider URL.
const SAFE_IP_RE = /^[0-9A-Fa-f:.]{2,45}$/;

// Takes a URL object (never a string) so the request destination is the constant
// host baked into the URL at construction; only path/query carry the IP. Passing
// the structured URL keeps the host provably non-user-controlled at the fetch sink.
async function fetchJson(url: URL, headers: Record<string, string>): Promise<{ status: number; body: any }> {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), LOOKUP_TIMEOUT_MS);
  try {
    const res = await fetch(url, { signal: ctrl.signal, headers: { Accept: 'application/json', ...headers } });
    let body: any = null;
    try {
      body = await res.json();
    } catch {
      /* leave body null */
    }
    return { status: res.status, body };
  } finally {
    clearTimeout(timer);
  }
}

const PROVIDERS: Record<ProviderName, ProviderDef> = {
  abuseipdb: {
    name: 'abuseipdb',
    label: 'AbuseIPDB',
    docsUrl: 'https://docs.abuseipdb.com/',
    signupUrl: 'https://www.abuseipdb.com/register',
    async lookup(ip, key) {
      if (!SAFE_IP_RE.test(ip)) throw new Error('Invalid IP for reputation lookup');
      // Constant host via the URL API; the IP only lands in a query parameter, so
      // it cannot influence the request destination (closes the SSRF path).
      const u = new URL('https://api.abuseipdb.com/api/v2/check');
      u.searchParams.set('ipAddress', ip);
      u.searchParams.set('maxAgeInDays', '90');
      const { status, body } = await fetchJson(u, { Key: key });
      if (status === 401 || status === 403) {
        return { provider: 'abuseipdb', label: 'AbuseIPDB', ok: false, error: 'Invalid API key' };
      }
      if (status < 200 || status >= 300 || !body?.data) {
        return { provider: 'abuseipdb', label: 'AbuseIPDB', ok: false, error: body?.errors?.[0]?.detail || `HTTP ${status}` };
      }
      const d = body.data;
      const score = typeof d.abuseConfidenceScore === 'number' ? d.abuseConfidenceScore : null;
      return {
        provider: 'abuseipdb',
        label: 'AbuseIPDB',
        ok: true,
        score,
        classification: score == null ? 'unknown' : score >= 75 ? 'malicious' : score >= 25 ? 'suspicious' : 'benign',
        summary: `Abuse confidence ${score ?? '?'}% · ${d.totalReports ?? 0} reports`,
        link: `https://www.abuseipdb.com/check/${encodeURIComponent(ip)}`,
        details: {
          totalReports: d.totalReports,
          countryCode: d.countryCode,
          usageType: d.usageType,
          isp: d.isp,
          domain: d.domain,
          isWhitelisted: d.isWhitelisted,
          lastReportedAt: d.lastReportedAt,
        },
      };
    },
  },
  otx: {
    name: 'otx',
    label: 'AlienVault OTX',
    docsUrl: 'https://otx.alienvault.com/api',
    signupUrl: 'https://otx.alienvault.com/',
    async lookup(ip, key) {
      if (!SAFE_IP_RE.test(ip)) throw new Error('Invalid IP for reputation lookup');
      // Constant host + path prefix; the IP-type segment is derived from isIP() (not
      // user input) and the encoded IP is appended to the path only, so the request
      // host stays provably constant at the sink (closes the SSRF path).
      const section = isIP(ip) === 6 ? 'IPv6' : 'IPv4';
      const u = new URL('https://otx.alienvault.com/api/v1/indicators/');
      u.pathname += `${section}/${encodeURIComponent(ip)}/general`;
      const { status, body } = await fetchJson(u, { 'X-OTX-API-KEY': key });
      if (status === 401 || status === 403) {
        return { provider: 'otx', label: 'AlienVault OTX', ok: false, error: 'Invalid API key' };
      }
      if (status < 200 || status >= 300 || !body) {
        return { provider: 'otx', label: 'AlienVault OTX', ok: false, error: body?.error || body?.detail || `HTTP ${status}` };
      }
      // OTX's free "general" endpoint has no 0-100 score; the actionable signal is
      // how many community "pulses" (threat reports) reference the IP. A non-empty
      // `validation` marks known-good infrastructure (whitelisted).
      const pulseCount = Number(body?.pulse_info?.count) || 0;
      const whitelisted = Array.isArray(body?.validation) && body.validation.length > 0;
      const latestPulse = body?.pulse_info?.pulses?.[0]?.name;
      const classification = whitelisted
        ? 'benign'
        : pulseCount >= 5 ? 'malicious' : pulseCount >= 1 ? 'suspicious' : 'benign';
      return {
        provider: 'otx',
        label: 'AlienVault OTX',
        ok: true,
        score: whitelisted ? 0 : Math.min(100, pulseCount * 20),
        classification,
        summary: pulseCount > 0
          ? `In ${pulseCount} OTX pulse${pulseCount === 1 ? '' : 's'}${latestPulse ? ` · ${latestPulse}` : ''}`
          : whitelisted ? 'Whitelisted in OTX' : 'Not referenced in OTX pulses',
        link: `https://otx.alienvault.com/indicator/ip/${encodeURIComponent(ip)}`,
        details: {
          pulseCount,
          country: body?.country_name,
          asn: body?.asn,
          city: body?.city,
          validation: body?.validation,
          latestPulse,
        },
      };
    },
  },
};

const cache = new Map<string, { expires: number; value: ReputationResult }>();

async function getSetting(key: string): Promise<string | undefined> {
  const r = await query('SELECT value FROM system_settings WHERE key = $1', [key]);
  return r.rows[0]?.value;
}
async function setSetting(key: string, value: string): Promise<void> {
  await query(
    `INSERT INTO system_settings (key, value) VALUES ($1, $2)
     ON CONFLICT (key) DO UPDATE SET value = $2, updated_at = NOW()`,
    [key, value]
  );
}

function keyKey(name: ProviderName) {
  return `ti_${name}_key`;
}
function enabledKey(name: ProviderName) {
  return `ti_${name}_enabled`;
}

async function getProviderKey(name: ProviderName): Promise<string | undefined> {
  const stored = await getSetting(keyKey(name));
  if (!stored) return undefined;
  try {
    const { encrypted, iv, authTag } = JSON.parse(stored);
    return CredentialEncryption.decrypt(encrypted, iv, authTag);
  } catch (e) {
    logger.warn(`[ThreatIntel] stored ${name} key could not be decrypted`, {
      error: e instanceof Error ? e.message : String(e),
    });
    return undefined;
  }
}

export class ReputationService {
  /** Public provider list for the UI — never exposes the key itself. */
  static async getProvidersPublic(): Promise<
    Array<{ name: ProviderName; label: string; docsUrl: string; signupUrl: string; configured: boolean; enabled: boolean }>
  > {
    const out = [];
    for (const def of Object.values(PROVIDERS)) {
      const configured = !!(await getSetting(keyKey(def.name)));
      const enabled = (await getSetting(enabledKey(def.name))) === 'true';
      out.push({ name: def.name, label: def.label, docsUrl: def.docsUrl, signupUrl: def.signupUrl, configured, enabled });
    }
    return out;
  }

  /** Save a provider's key (encrypted; '' clears it) and/or its enabled flag. */
  static async saveProvider(
    name: ProviderName,
    input: { apiKey?: string | null; enabled?: boolean }
  ): Promise<void> {
    if (!PROVIDERS[name]) throw new Error('Unknown provider');
    if (input.apiKey === null || input.apiKey === '') {
      await setSetting(keyKey(name), '');
    } else if (typeof input.apiKey === 'string') {
      const enc = CredentialEncryption.encrypt(input.apiKey); // throws if CREDENTIAL_ENCRYPTION_KEY unset
      await setSetting(keyKey(name), JSON.stringify(enc));
    }
    if (typeof input.enabled === 'boolean') {
      await setSetting(enabledKey(name), input.enabled ? 'true' : 'false');
    }
  }

  /** Look an IP up against every enabled + configured provider (cached briefly). */
  static async lookupIp(ip: string): Promise<ReputationResult[]> {
    if (!isIP(ip)) return [];
    const results: ReputationResult[] = [];
    for (const def of Object.values(PROVIDERS)) {
      if ((await getSetting(enabledKey(def.name))) !== 'true') continue;
      const key = await getProviderKey(def.name);
      if (!key) continue;

      const cacheKey = `${def.name}:${ip}`;
      const hit = cache.get(cacheKey);
      if (hit && hit.expires > Date.now()) {
        results.push(hit.value);
        continue;
      }
      try {
        const value = await def.lookup(ip, key);
        cache.set(cacheKey, { expires: Date.now() + CACHE_TTL_MS, value });
        results.push(value);
      } catch (err: any) {
        const msg = err?.name === 'AbortError' ? 'Lookup timed out' : err?.message || 'Lookup failed';
        results.push({ provider: def.name, label: def.label, ok: false, error: msg });
      }
    }
    return results;
  }
}
