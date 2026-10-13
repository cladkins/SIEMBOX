// Poll orchestration for API-pull Log Discovery sources. Mirrors
// FeedService.refreshFeed's shape exactly (services/threatintel/feedService.ts):
// never throws, always records status, so one bad source never stops the
// batch. Driven on a schedule by jobs/discoveryApiPoller.ts.
import { logger } from '../../../utils/logger';
import { ErrorLogService } from '../../errors/errorLogService';
import { DiscoverySourcePollerModel } from '../../../models/DiscoverySourcePoller';
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

export interface PollOneOptions {
  /** Skip the source (null) when its polling has been turned off: the scheduled cycle. run-now polls regardless. */
  onlyEnabled?: boolean;
}

/**
 * Poll one source. Its credential, cursor and poll target are read together,
 * in one statement, when the poll starts (findPollSnapshot) -- never taken from
 * a row read earlier, so the token and the address always come from the same
 * committed state (an address change swaps both in one update). Null when the
 * source has no poller (or, with onlyEnabled, polling is off). Otherwise never
 * throws: always records last_status/last_error/last_polled_at via recordResult.
 */
export async function pollOneSource(sourceId: number, opts: PollOneOptions = {}): Promise<PollOutcome | null> {
  let fingerprintId = 'API-polled';
  try {
    const snapshot = await DiscoverySourcePollerModel.findPollSnapshot(sourceId);
    if (!snapshot || (opts.onlyEnabled && !snapshot.poller.enabled)) return null;
    const { poller: row, source, version } = snapshot;
    fingerprintId = row.fingerprint_id;

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

    // startedFrom: an edit that reset the cursor (a new address or endpoint)
    // while this poll ran keeps its reset; this poll's cursor belongs to the old
    // target. Other changes made meanwhile (the interval, polling on/off, a new
    // token for the same address) don't stop this cursor from being written.
    await DiscoverySourcePollerModel.recordResult(sourceId, { ok: true, count, cursor: result.nextCursor, startedFrom: version });
    if (result.warning) reportPollWarning(sourceId, fingerprint.name, result.warning);
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
              human: `Couldn't reach ${fingerprintId} source for polling`,
              category: 'network',
              severity: 'warning',
              resolution:
                "Check the source is online and reachable at its address, port and scheme (Log Discovery, Edit), and that the saved credential is still valid",
            },
    });
    logger.warn(`[DiscoveryApiPoller] source ${sourceId} (${fingerprintId}) poll failed: ${msg}`);
    return { ok: false, count: 0, error: msg };
  }
}

/**
 * A poll that worked but could not collect everything (e.g. more new lines than
 * one answer holds): a warning on the dashboard's error log, so it isn't silent.
 */
function reportPollWarning(sourceId: number, sourceName: string, warning: string): void {
  logger.warn(`[DiscoveryApiPoller] source ${sourceId}: ${warning}`);
  ErrorLogService.logBackgroundError('discovery-api-poller', warning.slice(0, 500), {
    dedupeKey: `poll-warning-${sourceId}`,
    translation: {
      human: `Some ${sourceName} log lines may not have been collected`,
      category: 'configuration',
      severity: 'warning',
      resolution: "Shorten the source's poll interval (Log Discovery or Log Shippers, API-Polled Sources) so fewer lines arrive between polls",
    },
  });
}

export async function pollDueSources(): Promise<{ polled: number }> {
  let polled = 0;
  for (const sourceId of await DiscoverySourcePollerModel.findDueIds()) {
    // Read when its turn comes: a source moved, revoked or turned off since the
    // cycle started is polled as it is now (or skipped), not as it was.
    if (await pollOneSource(sourceId, { onlyEnabled: true })) polled++;
  }
  return { polled };
}
