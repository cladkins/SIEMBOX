import * as fs from 'fs';
import { Reader, CountryResponse } from 'mmdb-lib';
import { logger } from '../../utils/logger';

/**
 * Offline GeoIP country enrichment backed by the DB-IP IP-to-Country Lite MMDB
 * (CC BY 4.0 — attribution required; see docs/geoip.md).
 *
 * Singleton, fail-open: if the MMDB file is missing or unreadable, ONE warning
 * is logged at init and every lookup returns null, so the pipeline keeps working
 * with no geo fields rather than erroring.
 *
 * The reader is pure-JS (mmdb-lib, no native deps). DB-IP lite records look like
 * { country: { iso_code: "US", names: { en: "United States" } }, continent: {...} }.
 */

export interface GeoLookup {
  country_code: string;
  country_name: string;
}

const DEFAULT_DB_PATH = '/app/data/dbip-country-lite.mmdb';

class GeoIpService {
  private reader: Reader<CountryResponse> | null = null;
  private homeCountries: Set<string> = new Set();
  private loaded = false;

  constructor() {
    this.loadHomeCountries();
    this.load();
  }

  /** Parse GEOIP_HOME_COUNTRIES (comma-separated ISO-2, e.g. "US,CA") into a set. */
  private loadHomeCountries(): void {
    const raw = process.env.GEOIP_HOME_COUNTRIES || '';
    this.homeCountries = new Set(
      raw
        .split(',')
        .map((c) => c.trim().toUpperCase())
        .filter((c) => c.length > 0)
    );
  }

  /** Load the MMDB into memory. Logs exactly one warning and no-ops on failure. */
  private load(): void {
    const dbPath = process.env.GEOIP_DB_PATH || DEFAULT_DB_PATH;
    try {
      if (!fs.existsSync(dbPath)) {
        logger.warn(
          `GeoIP: database not found at ${dbPath} — geo enrichment disabled (lookups return null). ` +
            `Run backend/scripts/update-geoip.sh to download the DB-IP lite MMDB.`
        );
        this.reader = null;
        this.loaded = false;
        return;
      }
      const buffer = fs.readFileSync(dbPath);
      this.reader = new Reader<CountryResponse>(buffer);
      this.loaded = true;
      logger.info(`GeoIP: loaded country database from ${dbPath}`, {
        homeCountries: Array.from(this.homeCountries),
      });
    } catch (error) {
      logger.warn(`GeoIP: failed to load database from ${dbPath} — geo enrichment disabled`, {
        error: error instanceof Error ? error.message : String(error),
      });
      this.reader = null;
      this.loaded = false;
    }
  }

  /** True once a database has been successfully loaded. */
  isReady(): boolean {
    return this.loaded && this.reader !== null;
  }

  /**
   * Look up a public IP's country. Returns null for private/reserved/loopback/
   * link-local/invalid IPs, on miss, or when no DB is loaded.
   */
  lookup(ip: string | undefined | null): GeoLookup | null {
    if (!this.reader) return null;
    const normalized = this.normalizeIp(ip);
    if (normalized === null) return null;
    try {
      const rec = this.reader.get(normalized);
      const iso = rec?.country?.iso_code;
      if (!iso) return null;
      return {
        country_code: iso,
        country_name: rec?.country?.names?.en || iso,
      };
    } catch {
      return null;
    }
  }

  /** A country is foreign when it is set and not in the home-country list. */
  isForeign(countryCode: string | undefined | null): boolean {
    if (!countryCode) return false;
    if (this.homeCountries.size === 0) return false; // no home list -> nothing is "foreign"
    return !this.homeCountries.has(String(countryCode).toUpperCase());
  }

  /** Re-read the home-country env and reload the MMDB (e.g. after a monthly update). */
  reload(): void {
    this.loadHomeCountries();
    this.load();
  }

  /**
   * Validate + normalize an IP for lookup. Returns the lookup string, or null if
   * the address is private/reserved/loopback/link-local/CGNAT/invalid (mmdb-lib
   * does NOT validate input, so we must guard here).
   */
  private normalizeIp(ip: string | undefined | null): string | null {
    if (!ip || typeof ip !== 'string') return null;
    const s = ip.trim();
    if (s === '') return null;

    // IPv4-mapped IPv6 -> treat as the embedded IPv4 (::ffff:1.2.3.4)
    const mapped = s.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i);
    const candidate = mapped ? mapped[1] : s;

    const v4 = candidate.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
    if (v4) {
      const o = v4.slice(1).map((n) => parseInt(n, 10));
      if (o.some((n) => n > 255)) return null; // invalid octet
      const [a, b] = o;
      if (a === 0) return null; // 0.0.0.0/8
      if (a === 10) return null; // RFC1918
      if (a === 127) return null; // loopback
      if (a === 169 && b === 254) return null; // link-local
      if (a === 172 && b >= 16 && b <= 31) return null; // RFC1918
      if (a === 192 && b === 168) return null; // RFC1918
      if (a === 100 && b >= 64 && b <= 127) return null; // CGNAT 100.64/10
      if (a >= 224) return null; // multicast/reserved
      return candidate;
    }

    // IPv6
    if (s.includes(':')) {
      const low = s.toLowerCase();
      if (low === '::1' || low === '::') return null; // loopback/unspecified
      if (low.startsWith('fe80:')) return null; // link-local
      if (low.startsWith('fc') || low.startsWith('fd')) return null; // ULA fc00::/7
      return s;
    }

    return null; // not a recognizable IP literal
  }
}

export const geoipService = new GeoIpService();
