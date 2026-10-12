// Poll orchestration for API-pull Log Discovery sources. Mirrors
// FeedService.refreshFeed's shape exactly (services/threatintel/feedService.ts):
// never throws, always records status, so one bad source never stops the
// batch. Driven on a schedule by jobs/discoveryApiPoller.ts.
import { logger } from '../../../utils/logger';
import { ErrorLogService } from '../../errors/errorLogService';
import { DiscoverySourceModel } from '../../../models/DiscoverySource';
import { DiscoverySourcePoller, DiscoverySourcePollerModel } from '../../../models/DiscoverySourcePoller';
import { RawLogModel } from '../../../models/RawLog';
import { runInIngestContext } from '../../../config/database';
import { ParserEngine } from '../../parser/parserEngine';
import { getFingerprintById } from '../fingerprintLoader';
import { getAdapter } from './registry';
import { buildPollTarget } from './pollTarget';
import { PollError, describeConnectFailure } from './pollError';

export interface PollOutcome {
  ok: boolean;
  count: number;
  error?: string;
}

/** Poll one source. Never throws — always records last_status/last_error/last_polled_at via recordResult. */
export async function pollOneSource(row: DiscoverySourcePoller): Promise<PollOutcome> {
  const sourceId = row.discovery_source_id;
  try {
    const source = await DiscoverySourceModel.findById(sourceId);
    if (!source) {
      const error = 'Discovery source no longer exists';
      await DiscoverySourcePollerModel.recordResult(sourceId, { ok: false, count: 0, error });
      return { ok: false, count: 0, error };
    }

    const fingerprint = getFingerprintById(row.fingerprint_id);
    const logAccess = fingerprint?.log_access.find((la) => la.method === 'api_pull');
    const adapter = getAdapter(row.fingerprint_id);
    if (!fingerprint || !logAccess || !adapter) {
      const error = !fingerprint
        ? `Fingerprint "${row.fingerprint_id}" is no longer in the library`
        : !logAccess
          ? 'Fingerprint no longer declares an api_pull method'
          : 'No poller adapter registered for this fingerprint';
      await DiscoverySourcePollerModel.recordResult(sourceId, { ok: false, count: 0, error });
      return { ok: false, count: 0, error };
    }

    const credential = DiscoverySourcePollerModel.decryptCredential(row);
    // Port/scheme/endpoint overrides: a manual source's from its evidence, a
    // scan-discovered source's from poll_overrides (see pollTarget.ts). Without
    // any, these stay undefined and each adapter keeps its default derivation.
    const target = buildPollTarget(source, logAccess);

    let result;
    try {
      result = await adapter.fetchEvents(target, credential, row.poll_cursor);
    } catch (err) {
      // A request that never got an HTTP answer (refused, unreachable, timed
      // out, TLS mismatch) is reported with the URL it tried, so a wrong port or
      // HTTPS switch is obvious. Only fetch errors: an ECONNREFUSED from the
      // database while storing events below must not read as the source's.
      const connectFailure = err instanceof PollError ? null : describeConnectFailure(err, adapter.describeUrl(target, row.poll_cursor));
      if (!connectFailure) throw err;
      throw new PollError(connectFailure, {
        human: `Couldn't connect to the ${fingerprint.name} source`,
        resolution: "Check the source's address, port and HTTPS setting (Log Discovery, Edit) and that it is online",
        category: 'network',
      });
    }

    // Storing and parsing the pulled events is ingestion, so it runs on the ingest
    // pool (with connection retry) like syslog and HTTP push; the source/cursor
    // bookkeeping around it stays on the main pool. A failure here aborts the
    // poll WITHOUT advancing the cursor, so the next run re-fetches and dedupes.
    const count = await runInIngestContext(async () => {
      let stored = 0;
      for (const evt of result.events) {
        const created = await RawLogModel.create({
          timestamp: evt.timestamp ?? new Date(),
          raw_message: evt.message,
          source_ip: source.ip_address,
          hostname: source.hostname,
          app_name: fingerprint.id,
          discovery_source_id: source.id,
          ingest_event_id: evt.eventId,
        });
        if (!created) continue; // deduped by (discovery_source_id, ingest_event_id)
        await ParserEngine.getInstance().processLog(created);
        stored++;
      }
      return stored;
    });

    await DiscoverySourcePollerModel.recordResult(sourceId, { ok: true, count, cursor: result.nextCursor });
    return { ok: true, count };
  } catch (err: any) {
    // A PollError (from an adapter, or a connection failure above) already says
    // what to do; anything else keeps its own message.
    const msg = (err?.name === 'AbortError' ? 'Fetch timed out' : err?.message || 'Poll failed').slice(0, 500);
    await DiscoverySourcePollerModel.recordResult(sourceId, { ok: false, count: 0, error: msg }).catch(() => {});
    // Explicit translation: this is an outbound HTTP call to a discovery source, not
    // the app's own Postgres connection -- without this, ERROR_TRANSLATIONS'
    // substring scan mislabels any ECONNREFUSED/ETIMEDOUT here as a database error
    // ("Check PostgreSQL is running") on the dashboard, which is actively wrong.
    ErrorLogService.logBackgroundError('discovery-api-poller', msg, {
      dedupeKey: `poll-${sourceId}`,
      translation:
        err instanceof PollError
          ? { human: err.human, category: err.category, severity: 'warning', resolution: err.resolution }
          : {
              human: `Couldn't reach ${row.fingerprint_id} source for polling`,
              category: 'network',
              severity: 'warning',
              resolution:
                "Check the source is online and reachable at its address, port and scheme (Log Discovery, Edit), and that the saved credential is still valid",
            },
    });
    logger.warn(`[DiscoveryApiPoller] source ${sourceId} (${row.fingerprint_id}) poll failed: ${msg}`);
    return { ok: false, count: 0, error: msg };
  }
}

export async function pollDueSources(): Promise<{ polled: number }> {
  const due = await DiscoverySourcePollerModel.findDue();
  for (const row of due) {
    await pollOneSource(row);
  }
  return { polled: due.length };
}
