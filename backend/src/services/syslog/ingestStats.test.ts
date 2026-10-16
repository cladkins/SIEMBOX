/**
 * The syslog queue-stats accessor (services/syslog/ingestStats.ts): null until
 * server.ts registers a running server, that server's live counters after,
 * and null again once shutdown clears it. No sockets, no database.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { getIngestQueueStats, registerIngestStats } from './ingestStats';
import { SyslogServer } from './syslogServer';

test('is null when no syslog server is running', () => {
  assert.equal(getIngestQueueStats(), null);
});

test("reads the registered server's live queue counters, including UDP drops", () => {
  const server = new SyslogServer(0);
  registerIngestStats(() => server.getIngestStats());
  try {
    const stats = getIngestQueueStats();
    assert.ok(stats);
    assert.deepEqual(stats, server.getIngestStats());
    assert.equal(stats.dropped, 0);
    assert.equal(typeof stats.storeFailures, 'number');
  } finally {
    registerIngestStats(null);
  }
});

test('is null again once shutdown clears it', () => {
  registerIngestStats(() => ({ active: 0, queued: 0, blocked: 0, dropped: 7, processed: 0, failed: 0, storeFailures: 0 }));
  assert.equal(getIngestQueueStats()?.dropped, 7);
  registerIngestStats(null);
  assert.equal(getIngestQueueStats(), null);
});

test('is null, not a throw, when reading the server fails', () => {
  registerIngestStats(() => {
    throw new Error('gone');
  });
  try {
    assert.equal(getIngestQueueStats(), null);
  } finally {
    registerIngestStats(null);
  }
});
