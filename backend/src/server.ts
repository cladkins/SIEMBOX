import dotenv from 'dotenv';
import app from './app';
import { logger } from './utils/logger';
import pool from './config/database';
import { SyslogServer } from './services/syslog/syslogServer';
import { CleanupService } from './services/cleanup/cleanupService';
import { importRules } from './scripts/import-rules';
import { startAutoDiscoveryJob, stopAutoDiscoveryJob } from './jobs/autoDiscovery';
import { startScheduledScansJob, stopScheduledScansJob } from './jobs/scheduledScans';
import { reconcileInterruptedScans } from './services/scanner/scanReconciler';

dotenv.config();

const PORT = process.env.PORT || 8421;
const HOST = process.env.HOST || '0.0.0.0';
const SYSLOG_PORT = process.env.SYSLOG_PORT ? parseInt(process.env.SYSLOG_PORT) : 514;
const CLEANUP_INTERVAL_HOURS = process.env.CLEANUP_INTERVAL_HOURS
  ? parseInt(process.env.CLEANUP_INTERVAL_HOURS)
  : 24;

let syslogServer: SyslogServer;
let cleanupService: CleanupService;

const startServer = async () => {
  try {
    // Test database connection
    await pool.query('SELECT NOW()');
    logger.info('Database connection successful');

    // Mark scans left 'running'/'queued' by a previous process as failed.
    // Scan workers live in memory, so a restart orphans any in-flight scan —
    // without this they stay stuck forever and can't be cancelled normally.
    await reconcileInterruptedScans();

    // Auto-import detection rules on first startup
    logger.info('Checking for detection rules to import...');
    try {
      await importRules();
    } catch (error) {
      logger.error('Failed to import rules, but continuing startup:', error);
      logger.warn('Detection rules may need to be created manually');
    }

    // Start syslog server
    syslogServer = new SyslogServer(SYSLOG_PORT);
    await syslogServer.start();

    // Start cleanup service
    cleanupService = new CleanupService(CLEANUP_INTERVAL_HOURS);
    cleanupService.start();

    // Start auto-discovery job
    startAutoDiscoveryJob();

    // Start scheduled scans job
    startScheduledScansJob();

    // Start Express API server
    app.listen(PORT, () => {
      logger.info(`SIEMBox API server running on http://${HOST}:${PORT}`);
      logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
      logger.info(`Health check: http://${HOST}:${PORT}/health`);
      logger.info(`Syslog server listening on port ${SYSLOG_PORT} (UDP/TCP)`);
      logger.info(`Cleanup service running (interval: ${CLEANUP_INTERVAL_HOURS} hours)`);
      logger.info(`Auto-discovery job running (interval: 6 hours)`);
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
  if (cleanupService) {
    cleanupService.stop();
  }
  stopAutoDiscoveryJob();
  stopScheduledScansJob();
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
  if (cleanupService) {
    cleanupService.stop();
  }
  stopAutoDiscoveryJob();
  stopScheduledScansJob();
  pool.end(() => {
    logger.info('Database pool closed');
    process.exit(0);
  });
});

startServer();
