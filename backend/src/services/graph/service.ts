/**
 * The process-wide Context Graph: the main pool (never the ingest pool), and
 * the shared semaphore and cache. routes/graph.ts uses this instance; tests
 * build their own GraphDeps.
 */
import { getClient } from '../../config/database';
import type { QueryClient } from '../shippers/snapshotCache';
import { graphCache, graphSemaphore } from './limits';
import type { GraphDeps } from './neighborhood';

export const graphDeps: GraphDeps = {
  acquire: getClient as unknown as () => Promise<QueryClient>,
  semaphore: graphSemaphore,
  cache: graphCache,
  now: () => Date.now(),
};
