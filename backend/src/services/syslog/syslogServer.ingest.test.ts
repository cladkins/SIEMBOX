/**
 * Overload behaviour of the syslog server over REAL loopback sockets, with the
 * database steps stubbed (so no Postgres is needed):
 *   - UDP overload drops messages, COUNTS them, and reports once;
 *   - TCP overload throttles the sender instead -- nothing is dropped, order kept;
 *   - everything runs on the ingest pool context;
 *   - stop() lets already-accepted messages finish.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import type { TestContext } from 'node:test';
import assert from 'node:assert/strict';
import dgram from 'dgram';
import net from 'net';

// Small, known limits -- read by SyslogServer's constructor.
process.env.INGEST_CONCURRENCY = '2';
process.env.INGEST_QUEUE_MAX = '5';

import { SyslogServer } from './syslogServer';
import { RawLogModel } from '../../models/RawLog';
import { ParserEngine } from '../parser/parserEngine';
import { ErrorLogService } from '../errors/errorLogService';
import { isInIngestContext } from '../../config/database';

const sleep = (ms: number) => new Promise<void>((r) => setTimeout(r, ms));

async function waitFor(cond: () => boolean, what: string, timeoutMs = 5000) {
  const t0 = Date.now();
  while (!cond()) {
    if (Date.now() - t0 > timeoutMs) throw new Error(`timed out waiting for ${what}`);
    await sleep(5);
  }
}

const line = (i: number) => `<14>Oct  1 12:00:00 host app: msg-${i}`;

interface Rig {
  server: SyslogServer;
  udpPort: number;
  tcpPort: number;
  /** raw_message of every message whose database insert STARTED, in order. */
  started: string[];
  contexts: boolean[];
  release(): void;
}

/** A server whose database steps block on a gate until released. */
async function startRig(t: TestContext, { gated = true }: { gated?: boolean } = {}): Promise<Rig> {
  const started: string[] = [];
  const contexts: boolean[] = [];
  let release!: () => void;
  const gate = gated ? new Promise<void>((r) => (release = r)) : Promise.resolve();
  if (!gated) release = () => undefined;

  t.mock.method(ParserEngine.prototype, 'initialize', async () => undefined);
  t.mock.method(ParserEngine.prototype, 'processLog', async () => undefined);
  t.mock.method(RawLogModel, 'create', async (params: { raw_message: string }) => {
    started.push(params.raw_message);
    contexts.push(isInIngestContext());
    await gate;
    return { id: started.length } as any;
  });

  const server = new SyslogServer(0); // 0 = let the OS pick, for UDP and TCP independently
  await server.start();
  const udp = (server as any).udpServer as dgram.Socket;
  const tcp = (server as any).tcpServer as net.Server;
  await waitFor(() => {
    try {
      udp.address();
      return tcp.listening;
    } catch {
      return false;
    }
  }, 'sockets to bind');
  t.after(async () => {
    release(); // never leave workers parked on the gate
    await server.stop();
  });
  return { server, udpPort: udp.address().port, tcpPort: (tcp.address() as net.AddressInfo).port, started, contexts, release };
}

function sendUdp(port: number, lines: string[]): Promise<void> {
  const sock = dgram.createSocket('udp4');
  return new Promise((resolve) => {
    let left = lines.length;
    for (const l of lines) {
      sock.send(l, port, '127.0.0.1', () => {
        if (--left === 0) {
          sock.close();
          resolve();
        }
      });
    }
  });
}

test('UDP overload: messages beyond workers + backlog are dropped AND counted, the rest are all stored', async (t) => {
  const rig = await startRig(t);
  await sendUdp(rig.udpPort, Array.from({ length: 40 }, (_, i) => line(i)));
  // 2 running + 5 queued = 7 accepted; every other datagram was refused.
  await waitFor(() => rig.server.getIngestStats().dropped === 33, 'the overflow to be counted');
  assert.deepEqual(rig.server.getIngestStats(), {
    active: 2,
    queued: 5,
    blocked: 0,
    dropped: 33,
    processed: 0,
    failed: 0,
    storeFailures: 0,
  });

  rig.release();
  await waitFor(() => rig.server.getIngestStats().processed === 7, 'the accepted messages to finish');
  const s = rig.server.getIngestStats();
  assert.equal(s.processed + s.dropped, 40, 'every datagram is either stored or counted as dropped');
  assert.deepEqual(rig.started, Array.from({ length: 7 }, (_, i) => `msg-${i}`), 'the first 7 in arrival order were kept');
});

test('TCP overload: the sender is throttled, NOTHING is dropped, and order is preserved', async (t) => {
  const rig = await startRig(t);
  const sock = net.connect(rig.tcpPort, '127.0.0.1');
  await new Promise((r) => sock.once('connect', r));
  sock.write(Array.from({ length: 40 }, (_, i) => line(i)).join('\n') + '\n');

  // The queue takes 7; the connection then waits for room instead of dropping the rest.
  await waitFor(() => rig.server.getIngestStats().blocked === 1, 'the connection to be held back');
  assert.equal(rig.server.getIngestStats().dropped, 0);
  assert.equal(rig.server.getIngestStats().queued, 5);

  rig.release();
  await waitFor(() => rig.server.getIngestStats().processed === 40, 'all 40 lines to be stored');
  assert.equal(rig.server.getIngestStats().dropped, 0);
  assert.deepEqual(rig.started, Array.from({ length: 40 }, (_, i) => `msg-${i}`), 'strict order within a connection');
  sock.destroy();
});

test('TCP: later chunks wait their turn behind a full queue (nothing is read past what can be held)', async (t) => {
  const rig = await startRig(t);
  const sock = net.connect(rig.tcpPort, '127.0.0.1');
  await new Promise((r) => sock.once('connect', r));
  sock.write(Array.from({ length: 20 }, (_, i) => line(i)).join('\n') + '\n');
  await waitFor(() => rig.server.getIngestStats().blocked === 1, 'first chunk to block');
  sock.write(Array.from({ length: 20 }, (_, i) => line(20 + i)).join('\n') + '\n'); // second chunk, mid-stall
  await sleep(50);
  assert.equal(rig.server.getIngestStats().queued, 5, 'the second chunk is not being pulled into memory');
  assert.equal(rig.server.getIngestStats().blocked, 1);

  rig.release();
  await waitFor(() => rig.server.getIngestStats().processed === 40, 'both chunks to be stored');
  assert.deepEqual(rig.started, Array.from({ length: 40 }, (_, i) => `msg-${i}`));
  assert.equal(rig.server.getIngestStats().dropped, 0);
  sock.destroy();
});

test('TCP: a line split across two chunks, and an unterminated last line at close, are both delivered', async (t) => {
  const rig = await startRig(t, { gated: false });
  const sock = net.connect(rig.tcpPort, '127.0.0.1');
  await new Promise((r) => sock.once('connect', r));
  sock.write('<14>Oct  1 12:00:00 host app: first-');
  await sleep(30);
  sock.write('half\n<14>Oct  1 12:00:00 host app: no-newline-at-close');
  await sleep(30);
  sock.end();
  await waitFor(() => rig.server.getIngestStats().processed === 2, 'both lines');
  assert.deepEqual(rig.started, ['first-half', 'no-newline-at-close']);
});

test('TCP: a sender that closes while the queue is full still has EVERY line delivered, the unterminated tail last', async (t) => {
  const rig = await startRig(t);
  const sock = net.connect(rig.tcpPort, '127.0.0.1');
  await new Promise((r) => sock.once('connect', r));
  const lines = Array.from({ length: 40 }, (_, i) => line(i)).join('\n');
  sock.end(lines + '\n' + '<14>Oct  1 12:00:00 host app: msg-40'); // last line has no newline, then FIN
  await waitFor(() => rig.server.getIngestStats().blocked === 1, 'the connection to be held back');
  await sleep(50); // give the FIN time to arrive while the chunk is still blocked
  rig.release();
  await waitFor(() => rig.server.getIngestStats().processed === 41, 'all 41 lines to be stored');
  assert.deepEqual(rig.started, Array.from({ length: 41 }, (_, i) => `msg-${i}`), 'order kept, tail last, nothing lost');
  assert.equal(rig.server.getIngestStats().dropped, 0);
});

test('every message runs in the ingest context (UDP and TCP), and the context does not leak to the receiver', async (t) => {
  const rig = await startRig(t, { gated: false });
  await sendUdp(rig.udpPort, [line(1), line(2)]);
  const sock = net.connect(rig.tcpPort, '127.0.0.1');
  await new Promise((r) => sock.once('connect', r));
  sock.write(line(3) + '\n');
  await waitFor(() => rig.server.getIngestStats().processed === 3, 'three messages');
  assert.deepEqual(rig.contexts, [true, true, true]);
  assert.equal(isInIngestContext(), false);
  sock.destroy();
});

test('overload is reported ONCE per interval with the dropped count -- and not at all when nothing was dropped', async (t) => {
  const reports: Array<{ source: string; message: string; dedupeKey?: string; category?: string }> = [];
  t.mock.method(ErrorLogService, 'logBackgroundError', (source: string, error: unknown, ctx: any) => {
    reports.push({ source, message: (error as Error).message, dedupeKey: ctx?.dedupeKey, category: ctx?.translation?.category });
  });
  const rig = await startRig(t);
  const report = () => (rig.server as any).reportOverload();

  report();
  assert.equal(reports.length, 0, 'quiet when nothing was dropped');

  await sendUdp(rig.udpPort, Array.from({ length: 30 }, (_, i) => line(i)));
  await waitFor(() => rig.server.getIngestStats().dropped === 23, 'drops');
  report();
  assert.equal(reports.length, 1);
  assert.match(reports[0].message, /dropped 23 UDP syslog message\(s\)/);
  assert.equal(reports[0].source, 'syslog-ingest');
  assert.equal(reports[0].dedupeKey, 'overload');
  assert.equal(reports[0].category, 'application', 'explicit translation: must not be guessed as a database error');

  report();
  assert.equal(reports.length, 1, 'the same drops are not reported twice');
  rig.release();
});

test('stop() lets messages that were already accepted reach the database before it resolves', async (t) => {
  const rig = await startRig(t);
  await sendUdp(rig.udpPort, Array.from({ length: 7 }, (_, i) => line(i)));
  await waitFor(() => rig.server.getIngestStats().queued === 5, 'queue to fill');

  const stopped = rig.server.stop();
  let resolved = false;
  void stopped.then(() => (resolved = true));
  await sleep(100);
  assert.equal(resolved, false, 'stop() is waiting for the in-flight and queued work');

  rig.release();
  await stopped;
  assert.equal(rig.server.getIngestStats().processed, 7, 'all seven were stored before stop() returned');
});

test('stop() is idempotent and safe on a server that never started', async () => {
  const never = new SyslogServer(0);
  await never.stop();
  await never.stop();
});
