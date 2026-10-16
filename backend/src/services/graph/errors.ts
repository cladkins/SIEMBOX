/**
 * The Context Graph's own refusals. routes/graph.ts answers them directly
 * (never through errorHandler, so they write no "API Error" line or
 * application_errors row), in the usual envelope plus a `code`:
 *
 *   400 GRAPH_BAD_ENTITY     the entity isn't `type:key` with a valid key
 *   400 GRAPH_BAD_PARAM      any other parameter is out of range
 *   404 GRAPH_NOT_AVAILABLE  the relation (or centre type) isn't one this role may expand
 *   503 GRAPH_BUSY           no slot within a second, no database connection, or every source timed out
 *
 * A graph route never answers 401 for bad input: 401 means only that the
 * session is missing or expired (middleware/auth.ts).
 */

export type GraphErrorCode = 'GRAPH_BAD_ENTITY' | 'GRAPH_BAD_PARAM' | 'GRAPH_NOT_AVAILABLE';

export class GraphError extends Error {
  readonly statusCode: 400 | 404;
  readonly code: GraphErrorCode;

  constructor(code: GraphErrorCode, message: string) {
    super(message);
    this.name = 'GraphError';
    this.code = code;
    this.statusCode = code === 'GRAPH_NOT_AVAILABLE' ? 404 : 400;
  }
}

export const badEntity = (message: string) => new GraphError('GRAPH_BAD_ENTITY', message);
export const badParam = (message: string) => new GraphError('GRAPH_BAD_PARAM', message);
export const notAvailable = (message: string) => new GraphError('GRAPH_NOT_AVAILABLE', message);

/** How long a busy caller is told to wait, in seconds (the Retry-After header). */
export const GRAPH_BUSY_RETRY_AFTER_SECONDS = 2;

export class GraphBusyError extends Error {
  readonly code = 'GRAPH_BUSY';

  constructor(message = 'The Context Graph is busy. Try again in a few seconds.') {
    super(message);
    this.name = 'GraphBusyError';
  }
}
