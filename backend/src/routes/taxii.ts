/**
 * TAXII 2.1 server (read-only) for Threat Hunting.
 *
 *   GET /api/taxii2/                                             discovery
 *   GET /api/taxii2/hunts/                                       API root
 *   GET /api/taxii2/hunts/collections/                           collections
 *   GET /api/taxii2/hunts/collections/{id}/                      one collection
 *   GET /api/taxii2/hunts/collections/{id}/objects/              objects (envelope)
 *   GET /api/taxii2/hunts/collections/{id}/objects/{object-id}/  one object
 *   GET /api/taxii2/hunts/collections/{id}/objects/{object-id}/versions/
 *   GET /api/taxii2/hunts/collections/{id}/manifest/             manifest
 *
 * One collection, "SIEMBox Threat Hunts", holds every hunt's STIX objects
 * (services/hunting/stix.ts). Filters: added_after, limit, next, match[id],
 * match[type], match[version], match[spec_version]. Each object has one
 * version (its current `modified`); a hunt's objects are dated by when the
 * hunt last changed, so `added_after` returns hunts that changed since the
 * client's last poll.
 *
 * Login: a TAXII token or a user session (middleware/taxiiAuth.ts).
 */
import { Request, Response, Router } from 'express';
import { collectionObjects, CollectionObject } from '../services/hunting/huntService';
import { siemboxIdentity, STIX_MEDIA_TYPE, stableUuid } from '../services/hunting/stix';

const router = Router();

export const TAXII_MEDIA_TYPE = 'application/taxii+json;version=2.1';
export const HUNTS_COLLECTION_ID = stableUuid('siembox-threat-hunts');
const DEFAULT_LIMIT = 100;
const MAX_LIMIT = 1000;
const IDENTITY_ADDED = new Date('2026-01-01T00:00:00.000Z');

function send(res: Response, status: number, body: unknown, headers: Record<string, string> = {}): void {
  res.status(status).set(headers).type(TAXII_MEDIA_TYPE).send(JSON.stringify(body));
}

function taxiiError(res: Response, status: number, title: string, description?: string): void {
  send(res, status, { title, ...(description ? { description } : {}), http_status: String(status) });
}

function baseUrl(req: Request): string {
  return `${req.protocol}://${req.get('host')}${req.baseUrl}`;
}

function collectionInfo() {
  return {
    id: HUNTS_COLLECTION_ID,
    title: 'SIEMBox Threat Hunts',
    description:
      'Every threat hunt in this SIEMBox: the source report, its indicators, hypotheses (notes), ATT&CK techniques, and sightings of what the hunt found in the logs.',
    alias: 'threat-hunts',
    can_read: true,
    can_write: false,
    media_types: [STIX_MEDIA_TYPE],
  };
}

function list(raw: unknown): string[] {
  if (raw === undefined || raw === null) return [];
  const values = Array.isArray(raw) ? raw : [raw];
  return values.flatMap((v) => String(v).split(',')).map((v) => v.trim()).filter(Boolean);
}

interface Filtered {
  items: CollectionObject[];
  error?: string;
}

/** Apply the TAXII filters (all but paging) to the collection. */
async function filtered(req: Request, opts: { objectId?: string } = {}): Promise<Filtered> {
  const all: CollectionObject[] = [{ object: siemboxIdentity(), dateAdded: IDENTITY_ADDED }, ...(await collectionObjects())];
  let items = all;

  const addedAfter = req.query.added_after;
  if (addedAfter !== undefined) {
    const t = new Date(String(addedAfter));
    if (Number.isNaN(t.getTime())) return { items: [], error: 'added_after must be an RFC 3339 timestamp' };
    items = items.filter((i) => i.dateAdded > t);
  }
  const match = (req.query.match ?? {}) as Record<string, unknown>;
  const ids = opts.objectId ? [opts.objectId] : list(match.id);
  if (ids.length) items = items.filter((i) => ids.includes(i.object.id));
  const types = list(match.type);
  if (types.length) items = items.filter((i) => types.includes(i.object.type));
  const specs = list(match.spec_version);
  if (specs.length && !specs.includes('2.1')) items = [];
  const versions = list(match.version);
  const exact = versions.filter((v) => !['first', 'last', 'all'].includes(v));
  if (exact.length) {
    items = items.filter((i) =>
      exact.some((v) => {
        const want = new Date(v).getTime();
        const have = new Date(String(i.object.modified ?? i.object.created ?? '')).getTime();
        return !Number.isNaN(want) && want === have;
      })
    );
  }
  return { items };
}

/** limit + next paging; `next` is an opaque offset. */
function page(req: Request, items: CollectionObject[]): { slice: CollectionObject[]; more: boolean; next?: string; error?: string } {
  const limitRaw = req.query.limit;
  let limit = DEFAULT_LIMIT;
  if (limitRaw !== undefined) {
    limit = parseInt(String(limitRaw), 10);
    if (Number.isNaN(limit) || limit < 1) return { slice: [], more: false, error: 'limit must be a positive integer' };
    limit = Math.min(limit, MAX_LIMIT);
  }
  let offset = 0;
  if (req.query.next !== undefined) {
    offset = parseInt(String(req.query.next), 10);
    if (Number.isNaN(offset) || offset < 0) return { slice: [], more: false, error: 'next is not a value this server issued' };
  }
  const slice = items.slice(offset, offset + limit);
  const more = offset + limit < items.length;
  return { slice, more, ...(more ? { next: String(offset + limit) } : {}) };
}

function dateHeaders(slice: CollectionObject[]): Record<string, string> {
  if (!slice.length) return {};
  return {
    'X-TAXII-Date-Added-First': slice[0].dateAdded.toISOString(),
    'X-TAXII-Date-Added-Last': slice[slice.length - 1].dateAdded.toISOString(),
  };
}

function requireCollection(req: Request, res: Response): boolean {
  if (req.params.collectionId === HUNTS_COLLECTION_ID || req.params.collectionId === 'threat-hunts') return true;
  taxiiError(res, 404, 'Collection not found', `This API root has one collection: ${HUNTS_COLLECTION_ID}`);
  return false;
}

router.get('/', (req: Request, res: Response) => {
  send(res, 200, {
    title: 'SIEMBox TAXII 2.1',
    description: 'Threat hunts from SIEMBox as STIX 2.1.',
    contact: 'Your SIEMBox administrator',
    default: `${baseUrl(req)}/hunts/`,
    api_roots: [`${baseUrl(req)}/hunts/`],
  });
});

router.get('/hunts', (_req: Request, res: Response) => {
  send(res, 200, {
    title: 'SIEMBox Threat Hunting',
    description: 'Threat hunts: indicators, hypotheses and sightings.',
    versions: [TAXII_MEDIA_TYPE],
    max_content_length: 10 * 1024 * 1024,
  });
});

router.get('/hunts/collections', (_req: Request, res: Response) => {
  send(res, 200, { collections: [collectionInfo()] });
});

router.get('/hunts/collections/:collectionId', (req: Request, res: Response) => {
  if (!requireCollection(req, res)) return;
  send(res, 200, collectionInfo());
});

router.get('/hunts/collections/:collectionId/objects', async (req: Request, res: Response) => {
  if (!requireCollection(req, res)) return;
  const { items, error } = await filtered(req);
  if (error) return taxiiError(res, 400, 'Bad filter', error);
  const p = page(req, items);
  if (p.error) return taxiiError(res, 400, 'Bad paging parameter', p.error);
  send(
    res,
    200,
    { more: p.more, ...(p.next ? { next: p.next } : {}), objects: p.slice.map((i) => i.object) },
    dateHeaders(p.slice)
  );
});

router.get('/hunts/collections/:collectionId/objects/:objectId', async (req: Request, res: Response) => {
  if (!requireCollection(req, res)) return;
  const { items, error } = await filtered(req, { objectId: String(req.params.objectId) });
  if (error) return taxiiError(res, 400, 'Bad filter', error);
  if (!items.length) return taxiiError(res, 404, 'Object not found');
  send(res, 200, { more: false, objects: items.map((i) => i.object) }, dateHeaders(items));
});

router.get('/hunts/collections/:collectionId/objects/:objectId/versions', async (req: Request, res: Response) => {
  if (!requireCollection(req, res)) return;
  const { items, error } = await filtered(req, { objectId: String(req.params.objectId) });
  if (error) return taxiiError(res, 400, 'Bad filter', error);
  if (!items.length) return taxiiError(res, 404, 'Object not found');
  send(
    res,
    200,
    { more: false, versions: items.map((i) => String(i.object.modified ?? i.object.created)) },
    dateHeaders(items)
  );
});

router.get('/hunts/collections/:collectionId/manifest', async (req: Request, res: Response) => {
  if (!requireCollection(req, res)) return;
  const { items, error } = await filtered(req);
  if (error) return taxiiError(res, 400, 'Bad filter', error);
  const p = page(req, items);
  if (p.error) return taxiiError(res, 400, 'Bad paging parameter', p.error);
  send(
    res,
    200,
    {
      more: p.more,
      ...(p.next ? { next: p.next } : {}),
      objects: p.slice.map((i) => ({
        id: i.object.id,
        date_added: i.dateAdded.toISOString(),
        version: String(i.object.modified ?? i.object.created),
        media_type: STIX_MEDIA_TYPE,
      })),
    },
    dateHeaders(p.slice)
  );
});

export default router;
