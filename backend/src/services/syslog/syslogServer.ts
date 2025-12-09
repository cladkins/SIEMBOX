import dgram from 'dgram';
import net from 'net';
import { logger } from '../../utils/logger';
import { parseSyslogMessage } from './syslogParser';
import { RawLogModel } from '../../models/RawLog';
import { ParserEngine } from '../parser/parserEngine';

export class SyslogServer {
  private udpServer: dgram.Socket | null = null;
  private tcpServer: net.Server | null = null;
  private port: number;
  private parserEngine: ParserEngine;

  constructor(port: number = 514) {
    this.port = port;
    this.parserEngine = new ParserEngine();
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

        await this.processSyslogMessage(rawMessage, rinfo.address, 'udp');
      } catch (error) {
        logger.error('Error processing UDP syslog message:', error);
      }
    });

    this.udpServer.on('error', (err) => {
      logger.error('UDP server error:', err);
    });

    this.udpServer.bind(this.port, '0.0.0.0', () => {
      logger.info(`Syslog UDP server listening on port ${this.port}`);
    });
  }

  private startTcpServer(): void {
    this.tcpServer = net.createServer((socket) => {
      socket.on('data', async (data) => {
        try {
          const rawMessage = data.toString('utf8');
          const remoteAddress = socket.remoteAddress || 'unknown';

          logger.debug(`TCP syslog received from ${remoteAddress}`, {
            message: rawMessage.substring(0, 100),
          });

          // TCP can send multiple messages in one packet, split by newline
          const messages = rawMessage.split('\n').filter((m) => m.trim().length > 0);

          for (const message of messages) {
            await this.processSyslogMessage(message, remoteAddress, 'tcp');
          }
        } catch (error) {
          logger.error('Error processing TCP syslog message:', error);
        }
      });

      socket.on('error', (err) => {
        logger.error('TCP socket error:', err);
      });
    });

    this.tcpServer.listen(this.port, '0.0.0.0', () => {
      logger.info(`Syslog TCP server listening on port ${this.port}`);
    });

    this.tcpServer.on('error', (err) => {
      logger.error('TCP server error:', err);
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
    await this.parserEngine.initialize();
  }
}
