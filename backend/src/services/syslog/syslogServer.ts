import dgram from 'dgram';
import net from 'net';
import { logger } from '../../utils/logger';
import { parseSyslogMessage } from './syslogParser';
import { RawLogModel } from '../../models/RawLog';
import { ParserEngine } from '../parser/parserEngine';
import { ErrorLogService } from '../errors/errorLogService';

/**
 * Cap on the unterminated tail we'll hold for one TCP connection. A sender that
 * never emits a newline would otherwise grow this without bound. Comfortably
 * above any real syslog line (RFC 5424 recommends senders support 2048 octets;
 * CEF events from a UniFi gateway run past 1 KB).
 */
const MAX_TCP_LINE_BYTES = 256 * 1024;

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

  constructor(port: number = 514) {
    this.port = port;
    // Use the shared singleton so parser CRUD/catalog/pack endpoints can reload
    // the SAME engine this server processes logs through.
    this.parserEngine = ParserEngine.getInstance();
  }

  async start(): Promise<void> {
    try {
      // Initialize parser engine (load parsers from database)
      await this.parserEngine.initialize();

      // Start UDP server
      this.startUdpServer();

      // Start TCP server
      this.startTcpServer();

      logger.info(`Syslog server started on port ${this.port} (UDP/TCP)`);
    } catch (error) {
      logger.error('Failed to start syslog server:', error);
      ErrorLogService.logBackgroundError('syslog', error, { dedupeKey: 'start' });
      throw error;
    }
  }

  private startUdpServer(): void {
    this.udpServer = dgram.createSocket('udp4');

    this.udpServer.on('message', async (msg, rinfo) => {
      try {
        const rawMessage = msg.toString('utf8');
        logger.debug(`UDP syslog received from ${rinfo.address}:${rinfo.port}`, {
          message: rawMessage.substring(0, 100),
        });

        // A datagram is a complete unit, but senders and relays do pack several
        // lines into one. `final: true` because there is no continuation.
        const { lines } = splitSyslogFrames(rawMessage, { final: true });
        for (const line of lines) {
          await this.processSyslogMessage(line, rinfo.address, 'udp');
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

      socket.on('data', async (data) => {
        try {
          logger.debug(`TCP syslog received from ${remoteAddress}`, {
            message: data.toString('utf8').substring(0, 100),
          });

          // Take complete lines synchronously before any await, so a `data`
          // event arriving mid-processing can only ever append to `pending`.
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

          for (const line of lines) {
            await this.processSyslogMessage(line, remoteAddress, 'tcp');
          }
        } catch (error) {
          logger.error('Error processing TCP syslog message:', error);
        }
      });

      // A sender that closes without a trailing newline still means the last
      // line to be delivered — don't lose it.
      const flushPending = async () => {
        const { lines } = splitSyslogFrames(pending, { final: true });
        pending = '';
        for (const line of lines) {
          try {
            await this.processSyslogMessage(line, remoteAddress, 'tcp');
          } catch (error) {
            logger.error('Error processing final TCP syslog message:', error);
          }
        }
      };

      socket.on('end', () => void flushPending());

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

      logger.debug('Raw log stored', { id: rawLog.id, hostname: parsed.hostname });

      // Apply parsers to transform the log
      await this.parserEngine.processLog(rawLog);
    } catch (error) {
      logger.error('Error processing syslog message:', {
        error,
        message: rawMessage.substring(0, 200),
      });
    }
  }

  async stop(): Promise<void> {
    return new Promise((resolve) => {
      if (this.udpServer) {
        this.udpServer.close(() => {
          logger.info('UDP server stopped');
        });
      }

      if (this.tcpServer) {
        this.tcpServer.close(() => {
          logger.info('TCP server stopped');
          resolve();
        });
      } else {
        resolve();
      }
    });
  }

  async reloadParsers(): Promise<void> {
    logger.info('Reloading parsers...');
    await this.parserEngine.reload();
  }
}
