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

export type ProviderName = 'abuseipdb' | 'greynoise';

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

async function fetchJson(url: string, headers: Record<string, string>): Promise<{ status: number; body: any }> {
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
      const url = `https://api.abuseipdb.com/api/v2/check?ipAddress=${encodeURIComponent(ip)}&maxAgeInDays=90`;
      const { status, body } = await fetchJson(url, { Key: key });
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
  greynoise: {
    name: 'greynoise',
    label: 'GreyNoise',
    docsUrl: 'https://docs.greynoise.io/',
    signupUrl: 'https://www.greynoise.io/viz/signup',
    async lookup(ip, key) {
      const url = `https://api.greynoise.io/v3/community/${encodeURIComponent(ip)}`;
      const { status, body } = await fetchJson(url, { key });
      if (status === 401 || status === 403) {
        return { provider: 'greynoise', label: 'GreyNoise', ok: false, error: 'Invalid API key' };
      }
      // 404 from the community endpoint = "IP not observed", a valid benign answer.
      if (status === 404) {
        return {
          provider: 'greynoise',
          label: 'GreyNoise',
          ok: true,
          classification: 'unknown',
          summary: body?.message || 'Not observed by GreyNoise',
          link: `https://viz.greynoise.io/ip/${encodeURIComponent(ip)}`,
          details: { noise: false, riot: false },
        };
      }
      if (status < 200 || status >= 300 || !body) {
        return { provider: 'greynoise', label: 'GreyNoise', ok: false, error: body?.message || `HTTP ${status}` };
      }
      return {
        provider: 'greynoise',
        label: 'GreyNoise',
        ok: true,
        classification: body.classification || 'unknown',
        summary: `${body.classification || 'unknown'}${body.name && body.name !== 'unknown' ? ` · ${body.name}` : ''}${body.noise ? ' · internet noise' : ''}`,
        link: body.link || `https://viz.greynoise.io/ip/${encodeURIComponent(ip)}`,
        details: { noise: body.noise, riot: body.riot, name: body.name, lastSeen: body.last_seen },
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
