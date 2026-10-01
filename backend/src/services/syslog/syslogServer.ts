import dgram from 'dgram';
import net from 'net';
import { logger } from '../../utils/logger';
import { parseSyslogMessage } from './syslogParser';
import { RawLogModel } from '../../models/RawLog';
import { ParserEngine } from '../parser/parserEngine';
import { ErrorLogService } from '../errors/errorLogService';
import { getPoolStats, INGEST_POOL_MAX, runInIngestContext } from '../../config/database';
import { envInt } from '../../utils/envInt';
import { IngestQueue, IngestQueueStats } from './ingestQueue';

/**
 * Cap on the unterminated tail we'll hold for one TCP connection. A sender that
 * never emits a newline would otherwise grow this without bound. Comfortably
 * above any real syslog line (RFC 5424 recommends senders support 2048 octets;
 * CEF events from a UniFi gateway run past 1 KB).
 */
const MAX_TCP_LINE_BYTES = 256 * 1024;

/** How often overload (dropped messages) and database connection retries are summarised. */
const REPORT_INTERVAL_MS = 10_000;

/**
 * How long stop() lets already-accepted messages finish before giving up.
 * Kept under Docker's default 10 s stop grace period so the process exits on
 * its own instead of being killed.
 */
const SHUTDOWN_DRAIN_MS = 5_000;

/**
 * Split a received chunk into complete syslog lines plus whatever unterminated
 * remainder is left over.
 *
 * Both transports are newline-framed, and both used to get this wrong:
 *
 * - TCP is a byte STREAM, so `data` events break at arbitrary boundaries. The
 *   old code treated every chunk as a whole set of messages, so a line split
 *   across two events became two corrupt raw_logs — neither of which parses.
 *   Short lines (~100-200 bytes) almost always arrive intact, so this only ever
 *   bit long ones, which is exactly what CEF events are.
 * - UDP never split at all, so a datagram carrying more than one line was stored
 *   as a single raw_log. Nothing anchored with ^…$ can match that, because `.`
 *   doesn't cross a newline — the log lands in the unparsed bucket.
 *
 * Trailing CR is stripped so CRLF-framed senders don't leave a stray \r at the
 * end of the message, which would also defeat a $-anchored parser.
 */
export function splitSyslogFrames(
  chunk: string,
  { final = false }: { final?: boolean } = {}
): { lines: string[]; remainder: string } {
  const parts = chunk.split('\n');
  // Without a terminator the last element is an incomplete line; hold it back
  // until the rest of it arrives. On the final flush there is no more coming,
  // so take it as-is.
  const remainder = final ? '' : parts.pop() ?? '';
  const lines = parts
    .map((line) => line.replace(/\r+$/, ''))
    .filter((line) => line.trim().length > 0);
  return { lines, remainder };
}

export class SyslogServer {
  private udpServer: dgram.Socket | null = null;
  private tcpServer: net.Server | null = null;
  private port: number;
  private parserEngine: ParserEngine;

  /**
   * Every message, UDP or TCP, is processed through this bounded queue instead
   * of each datagram/chunk spawning its own un-capped async chain. When the
   * database slows down the queue fills and the overload becomes explicit:
   * TCP senders are throttled (nothing lost), UDP messages are dropped AND
   * counted -- the old behaviour was unbounded memory growth and silent loss.
   */
  private queue: IngestQueue;
  private maxQueued: number;
  /** Open TCP connections, each with a function that hands over its unterminated tail. */
  private tcpConnections = new Map<net.Socket, () => void>();
  private stopping = false;
  private stopPromise: Promise<void> | null = null;
  private reportTimer: NodeJS.Timeout | null = null;
  private lastReport = { dropped: 0, retries: 0 };
  /** Messages whose processing threw -- in practice, a database error. Each is also logged. */
  private storeFailures = 0;

  constructor(port: number = 514) {
    this.port = port;
    // Use the shared singleton so parser CRUD/catalog/pack endpoints can reload
    // the SAME engine this server processes logs through.
    this.parserEngine = ParserEngine.getInstance();

    // Stay below the ingest pool's size by default: a message holds one
    // connection at a time, but rule evaluation and the notification
    // dispatch it triggers can briefly want a second.
    const concurrency = envInt('INGEST_CONCURRENCY', Math.max(1, INGEST_POOL_MAX - 2), 1);
    if (concurrency > INGEST_POOL_MAX) {
      logger.warn(
        `INGEST_CONCURRENCY (${concurrency}) is larger than DB_INGEST_POOL_MAX (${INGEST_POOL_MAX}); ` +
          'workers will wait on each other for database connections. Raise the pool or lower the concurrency.'
      );
    }
    this.maxQueued = envInt('INGEST_QUEUE_MAX', 20_000, 0);
    this.queue = new IngestQueue({
      concurrency,
      maxQueued: this.maxQueued,
      onTaskError: (error) => logger.error('Unexpected error in ingest task:', error),
    });
  }

  /** Queue depth and loss counters, for diagnostics and tests. */
  getIngestStats(): IngestQueueStats & { storeFailures: number } {
    return { ...this.queue.stats(), storeFailures: this.storeFailures };
  }

  async start(): Promise<void> {
    try {
      // Initialize parser engine (load parsers from database)
      await this.parserEngine.initialize();

      // Start UDP server
      this.startUdpServer();

      // Start TCP server
      this.startTcpServer();

      this.reportTimer = setInterval(() => this.reportOverload(), REPORT_INTERVAL_MS);
      this.reportTimer.unref();

      logger.info(`Syslog server started on port ${this.port} (UDP/TCP)`);
    } catch (error) {
      logger.error('Failed to start syslog server:', error);
      ErrorLogService.logBackgroundError('syslog', error, { dedupeKey: 'start' });
      throw error;
    }
  }

  private startUdpServer(): void {
    this.udpServer = dgram.createSocket('udp4');

    this.udpServer.on('message', (msg, rinfo) => {
      try {
        const rawMessage = msg.toString('utf8');
        logger.debug(`UDP syslog received from ${rinfo.address}:${rinfo.port}`, {
          message: rawMessage.substring(0, 100),
        });

        // A datagram is a complete unit, but senders and relays do pack several
        // lines into one. `final: true` because there is no continuation.
        const { lines } = splitSyslogFrames(rawMessage, { final: true });
        for (const line of lines) {
          // UDP can't be slowed down, so a full queue means this message is
          // dropped. The queue counts every refusal and reportOverload() says so.
          this.queue.trySubmit(() => this.ingest(line, rinfo.address, 'udp'));
        }
      } catch (error) {
        logger.error('Error processing UDP syslog message:', error);
      }
    });

    this.udpServer.on('error', (err) => {
      logger.error('UDP server error:', err);
      ErrorLogService.logBackgroundError('syslog', err, { dedupeKey: 'udp-server' });
    });

    this.udpServer.bind(this.port, '0.0.0.0', () => {
      logger.info(`Syslog UDP server listening on port ${this.port}`);
    });
  }

  private startTcpServer(): void {
    this.tcpServer = net.createServer((socket) => {
      const remoteAddress = socket.remoteAddress || 'unknown';
      // Unterminated tail of the last chunk, carried into the next `data` event.
      let pending = '';
      // Hands this connection's lines to the queue strictly in order. A FIN can
      // arrive (and 'end' fire) while the previous chunk is still waiting for
      // room, and its unterminated tail must not overtake that chunk.
      let admission: Promise<void> = Promise.resolve();
      const admit = (lines: string[]) =>
        (admission = admission.then(() => this.admitLines(lines, remoteAddress)));

      socket.on('data', (data) => {
        try {
          logger.debug(`TCP syslog received from ${remoteAddress}`, {
            message: data.toString('utf8').substring(0, 100),
          });

          // Take complete lines synchronously, before the socket is paused
          // below, so the tail left in `pending` always belongs to this chunk.
          const { lines, remainder } = splitSyslogFrames(pending + data.toString('utf8'));
          pending = remainder;

          if (pending.length > MAX_TCP_LINE_BYTES) {
            // A sender that never terminates a line would otherwise grow this
            // forever. Drop it rather than hold the memory, and say so — a
            // silently discarded buffer is the kind of thing that turns into
            // "some of my logs just vanish".
            logger.warn(
              `TCP syslog from ${remoteAddress}: dropping ${pending.length} bytes of unterminated data ` +
                `(no newline within ${MAX_TCP_LINE_BYTES} bytes)`
            );
            pending = '';
          }

          if (lines.length === 0) return;

          // Backpressure. TCP, unlike UDP, can be slowed down: stop reading from
          // this connection until the queue has accepted every line of the chunk.
          // The kernel buffer then fills, the TCP window closes, and the sender
          // waits instead of us dropping anything. One chunk at a time per
          // connection also keeps its chunks in order.
          socket.pause();
          void admit(lines).then(() => {
            if (!this.stopping) socket.resume();
          });
        } catch (error) {
          logger.error('Error processing TCP syslog message:', error);
        }
      });

      // A sender that closes without a trailing newline still means the last
      // line to be delivered — don't lose it.
      const flushPending = () => {
        const { lines } = splitSyslogFrames(pending, { final: true });
        pending = '';
        void admit(lines);
      };

      this.tcpConnections.set(socket, flushPending);
      socket.on('close', () => this.tcpConnections.delete(socket));

      socket.on('end', flushPending);

      socket.on('error', (err) => {
        logger.error('TCP socket error:', err);
      });
    });

    this.tcpServer.listen(this.port, '0.0.0.0', () => {
      logger.info(`Syslog TCP server listening on port ${this.port}`);
    });

    this.tcpServer.on('error', (err) => {
      logger.error('TCP server error:', err);
      ErrorLogService.logBackgroundError('syslog', err, { dedupeKey: 'tcp-server' });
    });
  }

  /** Hand lines to the queue in order, waiting for room. Resolves once all are ACCEPTED (not processed). */
  private async admitLines(lines: string[], sourceIp: string): Promise<void> {
    for (const line of lines) {
      await this.queue.admit(() => this.ingest(line, sourceIp, 'tcp'));
    }
  }

  /**
   * One message, start to finish, on the ingest pool. The context is entered here
   * -- at the task boundary, not where the data was received -- so it is correct
   * no matter which code path the queue happens to start the task from, and so
   * everything the pipeline does underneath (parsers, rules, alerts, the
   * notifications they fire off) follows without knowing about pools.
   */
  private ingest(line: string, sourceIp: string, protocol: 'udp' | 'tcp'): Promise<void> {
    return runInIngestContext(() => this.processSyslogMessage(line, sourceIp, protocol));
  }

  private async processSyslogMessage(
    rawMessage: string,
    sourceIp: string,
    _protocol: 'udp' | 'tcp'
  ): Promise<void> {
    try {
      // Parse syslog message (RFC 3164 or RFC 5424)
      const parsed = parseSyslogMessage(rawMessage);

      // Store raw log in database
      const rawLog = await RawLogModel.create({
        timestamp: parsed.timestamp,
        raw_message: parsed.message,
        source_ip: sourceIp,
        facility: parsed.facility,
        severity: parsed.severity,
        hostname: parsed.hostname,
        app_name: parsed.appName,
        shipper_id: parsed.shipperId,
      });

      // rawLog is only ever null when a caller sets ingest_event_id (HTTP push
      // dedup, see 029_shipper_http_push.sql); syslog ingestion never does.
      if (!rawLog) {
        logger.error('Unexpected null from RawLogModel.create() during syslog ingestion');
        return;
      }

      logger.debug('Raw log stored', { id: rawLog.id, hostname: parsed.hostname });

      // Apply parsers to transform the log
      await this.parserEngine.processLog(rawLog);
    } catch (error) {
      this.storeFailures++;
      // An Error serialises to {} in the JSON metadata, so spell out what matters.
      logger.error('Error processing syslog message:', {
        error: error instanceof Error ? error.message : String(error),
        code: (error as { code?: string } | null)?.code,
        message: rawMessage.substring(0, 200),
      });
    }
  }

  /**
   * Say so when ingestion is struggling -- once per interval, however many
   * messages are affected, so an incident produces one line rather than a flood.
   * Drops are also recorded on the admin dashboard's error log.
   */
  private reportOverload(): void {
    const queue = this.queue.stats();
    const pools = getPoolStats();
    const dropped = queue.dropped - this.lastReport.dropped;
    const retries = pools.ingestRetries - this.lastReport.retries;
    this.lastReport = { dropped: queue.dropped, retries: pools.ingestRetries };
    const seconds = REPORT_INTERVAL_MS / 1000;
    const ingest = pools.ingest;
    const poolState = `ingest database pool: ${ingest.total}/${ingest.max} connections open, ${ingest.waiting} waiting`;

    if (dropped > 0) {
      const message =
        `Ingestion is overloaded: dropped ${dropped} UDP syslog message(s) in the last ${seconds}s ` +
        `(${queue.active} in progress, ${queue.queued}/${this.maxQueued} queued, ${queue.blocked} TCP sender(s) held back; ` +
        `${poolState}).`;
      logger.error(message);
      ErrorLogService.logBackgroundError('syslog-ingest', new Error(message), {
        dedupeKey: 'overload',
        translation: {
          human: 'Log ingestion is overloaded; some UDP syslog messages were dropped',
          category: 'application',
          severity: 'error',
          resolution:
            'Check database load (a long-running query or scan, slow disk) and see Troubleshooting → ' +
            '"Issue: Logs are dropped or ingestion is slow". Senders that use TCP or HTTP push are slowed down instead of dropped.',
        },
      });
    }

    if (retries > 0) {
      logger.warn(
        `Ingest database connections failed ${retries} time(s) in the last ${seconds}s and were retried ` +
          `(${poolState}). Postgres may be restarting, overloaded, or out of connections.`
      );
    }
  }

  stop(): Promise<void> {
    // Idempotent: a second signal while the first is still draining joins it.
    this.stopPromise ??= this.shutDown();
    return this.stopPromise;
  }

  private async shutDown(): Promise<void> {
    this.stopping = true;
    if (this.reportTimer) {
      clearInterval(this.reportTimer);
      this.reportTimer = null;
    }

    // Never rejects: a socket that never started (e.g. its bind failed) or is
    // already closed just counts as stopped.
    const closeServer = (label: string, close?: (cb: () => void) => void) =>
      new Promise<void>((resolve) => {
        if (!close) return resolve();
        try {
          close(() => {
            logger.info(`${label} server stopped`);
            resolve();
          });
        } catch {
          resolve();
        }
      });

    const closed = [
      closeServer('UDP', this.udpServer ? (cb) => this.udpServer!.close(cb) : undefined),
      closeServer('TCP', this.tcpServer ? (cb) => this.tcpServer!.close(cb) : undefined),
    ];

    // close() only stops LISTENING: its callback waits for every open
    // connection to end, and syslog senders keep theirs open indefinitely.
    // So stop reading from them, keep what they already sent (including any
    // unterminated last line), and let the drain below finish it.
    for (const [socket, flushPending] of this.tcpConnections) {
      socket.pause();
      flushPending();
    }

    // Everything already accepted -- running, queued, or waiting for room -- is
    // data the sender believes was delivered. Give it a chance to reach the database.
    const drained = await this.queue.drain(SHUTDOWN_DRAIN_MS);
    if (!drained) {
      const left = this.queue.stats();
      logger.warn(
        `Shutdown: ${left.active + left.queued + left.blocked} syslog message(s) were still unprocessed after ` +
          `${SHUTDOWN_DRAIN_MS}ms and are lost`
      );
    }

    for (const socket of this.tcpConnections.keys()) socket.destroy();
    await Promise.all(closed);
  }

  async reloadParsers(): Promise<void> {
    logger.info('Reloading parsers...');
    await this.parserEngine.reload();
  }
}
