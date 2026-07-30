// Poll orchestration for API-pull Log Discovery sources. Mirrors
// FeedService.refreshFeed's shape exactly (services/threatintel/feedService.ts):
// never throws, always records status, so one bad source never stops the
// batch. Driven on a schedule by jobs/discoveryApiPoller.ts.
import { logger } from '../../../utils/logger';
import { ErrorLogService } from '../../errors/errorLogService';
import { DiscoverySourceModel } from '../../../models/DiscoverySource';
import { DiscoverySourcePoller, DiscoverySourcePollerModel } from '../../../models/DiscoverySourcePoller';
import { RawLogModel } from '../../../models/RawLog';
import { ParserEngine } from '../../parser/parserEngine';
import { getFingerprintById } from '../fingerprintLoader';
import { getAdapter } from './registry';
import { PollTarget } from './types';

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
    const target: PollTarget = {
      sourceId: source.id,
      ip: source.ip_address,
      openPorts: source.open_ports || [],
      evidence: source.evidence || {},
      logAccess,
    };

    const result = await adapter.fetchEvents(target, credential, row.poll_cursor);

    let count = 0;
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
      count++;
    }

    await DiscoverySourcePollerModel.recordResult(sourceId, { ok: true, count, cursor: result.nextCursor });
    return { ok: true, count };
  } catch (err: any) {
    const msg = (err?.name === 'AbortError' ? 'Fetch timed out' : err?.message || 'Poll failed').slice(0, 500);
    await DiscoverySourcePollerModel.recordResult(sourceId, { ok: false, count: 0, error: msg }).catch(() => {});
    // Explicit translation: this is an outbound HTTP call to a discovery source, not
    // the app's own Postgres connection -- without this, ERROR_TRANSLATIONS'
    // substring scan mislabels any ECONNREFUSED/ETIMEDOUT here as a database error
    // ("Check PostgreSQL is running") on the dashboard, which is actively wrong.
    ErrorLogService.logBackgroundError('discovery-api-poller', msg, {
      dedupeKey: `poll-${sourceId}`,
      translation: {
        human: `Couldn't reach ${row.fingerprint_id} source for polling`,
        category: 'network',
        severity: 'warning',
        resolution: 'Check the source is online and reachable at its discovered address, and that the saved credential is still valid',
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
