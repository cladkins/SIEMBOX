import dotenv from 'dotenv';
import app from './app';
import { logger } from './utils/logger';
import pool from './config/database';
import { SyslogServer } from './services/syslog/syslogServer';

dotenv.config();

const PORT = process.env.PORT || 3000;
const HOST = process.env.HOST || '0.0.0.0';
const SYSLOG_PORT = process.env.SYSLOG_PORT ? parseInt(process.env.SYSLOG_PORT) : 514;

let syslogServer: SyslogServer;

const startServer = async () => {
  try {
    // Test database connection
    await pool.query('SELECT NOW()');
    logger.info('Database connection successful');

    // Start syslog server
    syslogServer = new SyslogServer(SYSLOG_PORT);
    await syslogServer.start();

    // Start Express API server
    app.listen(PORT, () => {
      logger.info(`SIEMBox API server running on http://${HOST}:${PORT}`);
      logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
      logger.info(`Health check: http://${HOST}:${PORT}/health`);
      logger.info(`Syslog server listening on port ${SYSLOG_PORT} (UDP/TCP)`);
    });
  } catch (error) {
    logger.error('Failed to start server:', error);
    process.exit(1);
  }
};

// Graceful shutdown
process.on('SIGTERM', async () => {
  logger.info('SIGTERM signal received: closing servers');
  if (syslogServer) {
    await syslogServer.stop();
  }
  pool.end(() => {
    logger.info('Database pool closed');
    process.exit(0);
  });
});

process.on('SIGINT', async () => {
  logger.info('SIGINT signal received: closing servers');
  if (syslogServer) {
    await syslogServer.stop();
  }
  pool.end(() => {
    logger.info('Database pool closed');
    process.exit(0);
  });
});

startServer();
