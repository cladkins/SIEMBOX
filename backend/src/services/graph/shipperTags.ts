/**
 * Which shipper a raw_logs.shipper_id tag belongs to. A tag is the first 8 hex
 * characters of md5 or sha256 of a shipper's key, or of its HTTP push key's
 * hash (see services/shippers/unknownSources.ts, which computes them the same
 * way); a tag no shipper matches is a ghost shipper, shown as a shipper_tag
 * node (intentional: a revoked shipper keeps sending with its cached config).
 *
 * The map is computed in SQL and cached for 60 s. The prefixes never leave the
 * server: callers get only "this tag is shipper N".
 */
import type { Query } from './budget';

export const SHIPPER_TAG_TTL_MS = 60_000;

/**
 * $1 none. The api_key ~ hex test runs before decode() (CASE), so one
 * malformed key can't abort the query (issue #17).
 */
export const SHIPPER_TAGS_SQL = `
  SELECT id,
         CASE WHEN api_key ~ '^([0-9a-fA-F]{2})+$'
              THEN lower(substring(md5(decode(api_key, 'hex')), 1, 8)) END AS md5_tag,
         CASE WHEN api_key ~ '^([0-9a-fA-F]{2})+$'
              THEN lower(substring(encode(sha256(decode(api_key, 'hex')), 'hex'), 1, 8)) END AS sha256_tag,
         lower(substring(http_push_key_hash, 1, 8)) AS push_tag
    FROM log_shippers`;

interface TagRow {
  id: number;
  md5_tag: string | null;
  sha256_tag: string | null;
  push_tag: string | null;
}

export interface ShipperTagMap {
  /** The shipper id a tag belongs to, using `q` to refresh the map when it is stale. */
  lookup(q: Query, tags: string[]): Promise<Map<string, number>>;
  invalidate(): void;
}

export function createShipperTagMap(now: () => number = () => Date.now(), ttlMs = SHIPPER_TAG_TTL_MS): ShipperTagMap {
  let cached: { at: number; map: Map<string, number> } | null = null;

  // A stale map is reloaded on the caller's own connection, inside its own
  // budget: never shared in flight, so one request's timeout or rollback can't
  // fail another's. (log_shippers holds tens of rows: a reload is cheap.)
  async function load(q: Query): Promise<Map<string, number>> {
    if (cached && now() - cached.at < ttlMs) return cached.map;
    const rows = await q<TagRow>(SHIPPER_TAGS_SQL);
    const map = new Map<string, number>();
    for (const row of rows) {
      for (const tag of [row.md5_tag, row.sha256_tag, row.push_tag]) {
        if (tag && /^[0-9a-f]{8}$/.test(tag) && !map.has(tag)) map.set(tag, Number(row.id));
      }
    }
    cached = { at: now(), map };
    return map;
  }

  return {
    async lookup(q, tags) {
      const map = await load(q);
      const out = new Map<string, number>();
      for (const tag of tags) {
        const id = map.get(tag);
        if (id !== undefined) out.set(tag, id);
      }
      return out;
    },
    invalidate() {
      cached = null;
    },
  };
}

export const shipperTags = createShipperTagMap();
