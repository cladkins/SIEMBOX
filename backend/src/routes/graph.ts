/**
 * Context Graph (read-only, every role; services/graph/visibility.ts decides
 * what each role's graph holds). Mounted behind `authenticate` in app.ts.
 *
 *   GET /search?q=                       what a typed string could mean
 *   GET /neighborhood?entity=type:key    an entity and what is linked to it
 *   GET /relation?entity=&rel=           one relation of it, paged and searchable
 *
 * Answers: 200 (partial results and unknown entities included), 400
 * GRAPH_BAD_ENTITY / GRAPH_BAD_PARAM, 404 GRAPH_NOT_AVAILABLE, 503 GRAPH_BUSY
 * with Retry-After. Never 401 for bad input. The graph's own refusals are
 * answered here, not thrown to errorHandler, so they log nothing.
 */
import { Router, type Request, type Response } from 'express';
import { badParam, GRAPH_BUSY_RETRY_AFTER_SECONDS, GraphBusyError, GraphError } from '../services/graph/errors';
import { parseEntity } from '../services/graph/entityKey';
import { hasUnsafeChars } from '../services/graph/labels';
import { getNeighborhood, getRelation, type Caller } from '../services/graph/neighborhood';
import { knownRel } from '../services/graph/relations';
import type { SortKey } from '../services/graph/resolvers/common';
import { search } from '../services/graph/search';
import { graphDeps } from '../services/graph/service';
import { ORIGINS, type Origin } from '../services/graph/types';
import { resolveWindow } from '../services/graph/window';

const router = Router();

/** A query parameter given at most once, as a string (repeats and qs objects are a 400). */
function single(req: Request, name: string): string | undefined {
  const value = req.query[name];
  if (value === undefined) return undefined;
  if (typeof value !== 'string') throw badParam(`${name} may be given once, as plain text`);
  return value;
}

function intParam(req: Request, name: string, min: number, max: number, fallback: number): number {
  const raw = single(req, name);
  if (raw === undefined || raw === '') return fallback;
  if (!/^\d{1,6}$/.test(raw)) throw badParam(`${name} must be a whole number from ${min} to ${max}`);
  const n = Number(raw);
  if (n < min || n > max) throw badParam(`${name} must be a whole number from ${min} to ${max}`);
  return n;
}

function oneOf<T extends string>(req: Request, name: string, allowed: readonly T[]): T | undefined {
  const raw = single(req, name);
  if (raw === undefined || raw === '') return undefined;
  if (!(allowed as readonly string[]).includes(raw)) throw badParam(`${name} must be one of ${allowed.join(', ')}`);
  return raw as T;
}

function includeParam(req: Request): Origin[] | undefined {
  const raw = single(req, 'include');
  if (raw === undefined) return undefined;
  const parts = raw.split(',').map((part) => part.trim()).filter(Boolean);
  // `include=` (empty) is the default, not "nothing".
  if (parts.length === 0) return undefined;
  for (const part of parts) {
    if (!(ORIGINS as readonly string[]).includes(part)) throw badParam(`include lists origins: ${ORIGINS.join(', ')}`);
  }
  return [...new Set(parts as Origin[])];
}

function caller(req: Request): Caller {
  return { id: req.user!.id, role: req.user!.role };
}

function windowOf(req: Request) {
  return resolveWindow({ window: single(req, 'window'), around: single(req, 'around') }, graphDeps.now());
}

/** Answer the graph's own errors; anything else goes on to errorHandler. */
async function answer(res: Response, work: () => Promise<unknown>): Promise<void> {
  try {
    res.json(await work());
  } catch (err) {
    if (err instanceof GraphError) {
      res.status(err.statusCode).json({ status: 'error', statusCode: err.statusCode, code: err.code, message: err.message });
      return;
    }
    if (err instanceof GraphBusyError) {
      res
        .status(503)
        .set('Retry-After', String(GRAPH_BUSY_RETRY_AFTER_SECONDS))
        .json({ status: 'error', statusCode: 503, code: err.code, message: err.message, retryAfter: GRAPH_BUSY_RETRY_AFTER_SECONDS });
      return;
    }
    throw err;
  }
}

router.get('/search', (req: Request, res: Response) => answer(res, () => search(graphDeps, caller(req), single(req, 'q'))));

router.get('/neighborhood', (req: Request, res: Response) =>
  answer(res, () =>
    getNeighborhood(graphDeps, caller(req), {
      center: parseEntity(single(req, 'entity')),
      window: windowOf(req),
      limit: intParam(req, 'limit', 1, 25, 5),
      include: includeParam(req),
      vulnStatus: oneOf(req, 'vuln_status', ['open', 'all'] as const) ?? 'open',
    })
  )
);

router.get('/relation', (req: Request, res: Response) =>
  answer(res, () => {
    const rel = single(req, 'rel');
    if (!rel || !knownRel(rel)) throw badParam('rel must name a relation (see GET /api/graph/neighborhood groups[].rel)');
    const q = single(req, 'q');
    if (q !== undefined && q.length > 100) throw badParam('q must be at most 100 characters');
    // As /search refuses them: a NUL would reach the ILIKE parameter and fail the statement.
    if (q !== undefined && hasUnsafeChars(q)) throw badParam('q may not contain control or bidi characters');
    return getRelation(graphDeps, caller(req), {
      center: parseEntity(single(req, 'entity')),
      rel,
      window: windowOf(req),
      limit: intParam(req, 'limit', 1, 50, 50),
      offset: intParam(req, 'offset', 0, 1000, 0),
      q: q?.trim() ? q.trim().toLowerCase() : undefined,
      sort: oneOf<SortKey>(req, 'sort', ['count', 'last_seen', 'first_seen']),
      order: oneOf(req, 'order', ['desc', 'asc'] as const),
      vulnStatus: oneOf(req, 'vuln_status', ['open', 'all'] as const) ?? 'open',
    });
  })
);

export default router;
