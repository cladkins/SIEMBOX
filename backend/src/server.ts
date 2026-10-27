import { loadDotenv } from './config/dotenv';
import type { Server } from 'node:http';
import app, { corsPolicy } from './app';
import { createApiServer, listenProxySocket, stopListening } from './net/apiListeners';
import { logCorsPolicy } from './net/cors';
import { clientAddressSummary } from './net/diagnostics';
import { trustedProxies } from './net/trustedProxies';
import { logger } from './utils/logger';
import pool, { closeIngestPool, closePools } from './config/database';
import { diagnoseDbConnectionError } from './config/dbDiagnostics';
import { SyslogServer } from './services/syslog/syslogServer';
import { registerIngestStats } from './services/syslog/ingestStats';
import { ingestCounter } from './services/ingest/ingestCounter';
import { CleanupService } from './services/cleanup/cleanupService';
import { importRules } from './scripts/import-rules';
import { startAutoDiscoveryJob, stopAutoDiscoveryJob } from './jobs/autoDiscovery';
import { startScheduledScansJob, stopScheduledScansJob } from './jobs/scheduledScans';
import { startShipperJobExpiryJob, stopShipperJobExpiryJob } from './jobs/shipperJobExpiry';
import { startIngestionHealthJob, stopIngestionHealthJob } from './jobs/ingestionHealth';
import { startThreatFeedsJob, stopThreatFeedsJob } from './jobs/threatFeeds';
import { startDiscoveryApiPollerJob, stopDiscoveryApiPollerJob } from './jobs/discoveryApiPoller';
import { startGeoipUpdateJob, stopGeoipUpdateJob } from './jobs/geoipUpdate';
import { startYaraRulesJob, stopYaraRulesJob } from './jobs/yaraRules';
import { startEdrAgentReleaseJob, stopEdrAgentReleaseJob } from './jobs/edrAgentRelease';
import { startSigmaLibraryJob, stopSigmaLibraryJob } from './jobs/sigmaLibrary';
import { startTriageReconcilerJob, stopTriageReconcilerJob } from './jobs/triageReconciler';
import { startLeakedCredsJob, stopLeakedCredsJob } from './jobs/leakedCreds';
import { startDomainMonitorJob, stopDomainMonitorJob } from './jobs/domainMonitor';
import { startSignInHousekeepingJob, stopSignInHousekeepingJob } from './jobs/signInHousekeeping';
import { startGraphLogEdgesJob, stopGraphLogEdgesJob } from './jobs/graphLogEdges';
import { startApplicationInventoryJob, stopApplicationInventoryJob } from './jobs/applicationInventory';
import { signInSettings } from './services/auth/signInPolicy';
import { getDummyHash } from './services/auth/signInService';
import { stopRefusalSummary } from './services/auth/authEvents';
import { raiseDefaultPasswordAlerts } from './services/auth/defaultPasswordAlerts';
import { reconcileInterruptedScans } from './services/scanner/scanReconciler';
import { TemplateService } from './services/scanner/templateService';
import { CredentialEncryption } from './services/credentials/credentialEncryption';
import { ErrorLogService } from './services/errors/errorLogService';
import { scanStoredRegexes } from './services/regex/storedRegexScan';
import { closeRegexScanPool } from './services/regex/regexSafety';
import { closeRegexTestPool } from './services/regex/boundedRegex';
import { enableLinearRegexFallback } from './services/regex/linearFallback';

loadDotenv();

// A parser or rule regex that backtracks catastrophically on a crafted log line
// would stall the event loop (API, syslog ingestion, every job). V8 can abandon
// such a match after 1,000,000 backtracks and finish it on its linear-time engine;
// see services/regex/linearFallback.ts for what that covers. Before anything runs.
const linearRegexFallback = enableLinearRegexFallback();

// Last-resort capture. Anything that escaped a service's own try/catch — a
// rejected promise nobody awaited, a throw from a timer callback — used to
// vanish into stdout, so the dashboard's Recent Errors panel could look clean
// while the process was failing. Log-only: an uncaught exception leaves the
// process in an undefined state, but crashing here would take the whole SIEM
// down for one bad callback, and the container restart policy is the safety net.
process.on('unhandledRejection', (reason) => {
  logger.error('Unhandled promise rejection:', reason);
  ErrorLogService.logBackgroundError('unhandled-rejection', reason, {
    dedupeKey: reason instanceof Error ? reason.message : String(reason),
  });
});

process.on('uncaughtException', (error) => {
  logger.error('Uncaught exception:', error);
  ErrorLogService.logBackgroundError('uncaught-exception', error, {
    dedupeKey: error?.message,
  });
});

const PORT = process.env.PORT || 8421;
const HOST = process.env.HOST || '0.0.0.0';
const SYSLOG_PORT = process.env.SYSLOG_PORT ? parseInt(process.env.SYSLOG_PORT) : 514;
const CLEANUP_INTERVAL_HOURS = process.env.CLEANUP_INTERVAL_HOURS
  ? parseInt(process.env.CLEANUP_INTERVAL_HOURS)
  : 24;

let syslogServer: SyslogServer;
let cleanupService: CleanupService;
let apiServer: Server | undefined;
let proxySocketServer: Server | null = null;

const startServer = async () => {
  try {
    // Test database connection
    await pool.query('SELECT NOW()');
    logger.info('Database connection successful');

    // Credential-encryption key health. Warn loudly (do NOT crash) if it's
    // missing or malformed: without a valid key, secrets entered in the UI
    // (scanner credentials, AI-builder API key) cannot be stored — so it's
    // better for operators to see this at boot than to hit a cryptic save error.
    const keyStatus = CredentialEncryption.getKeyStatus();
    if (!keyStatus.valid) {
      logger.warn(
        '============================================================\n' +
          `⚠️  CREDENTIAL_ENCRYPTION_KEY is not usable: ${keyStatus.reason}.\n` +
          '    Storing secrets from the UI (scanner credentials, AI-builder\n' +
          '    API key) will FAIL until this is fixed.\n' +
          '    Fix: generate one with `openssl rand -hex 32` and set\n' +
          '    CREDENTIAL_ENCRYPTION_KEY in your .env, then restart.\n' +
          '    Alternatively set ANTHROPIC_API_KEY / OPENAI_API_KEY to use the\n' +
          '    AI builder without storing a key in the UI.\n' +
          '============================================================'
      );
    } else {
      logger.info('Credential encryption key configured.');
    }

    // Mark scans left 'running'/'queued' by a previous process as failed.
    // Scan workers live in memory, so a restart orphans any in-flight scan —
    // without this they stay stuck forever and can't be cancelled normally.
    await reconcileInterruptedScans();

    // Catalog-only by default: a fresh install starts with no bundled
    // parsers/detections, and the operator installs exactly what they want from
    // the in-app catalog (Parsers / Detection Rules → Browse Catalog → Install
    // all). Set SEED_BUNDLED_CONTENT=true to opt back into auto-importing the
    // bundled detection rules on startup (legacy behaviour).
    if (process.env.SEED_BUNDLED_CONTENT === 'true') {
      logger.info('SEED_BUNDLED_CONTENT=true — checking for bundled detection rules to import...');
      try {
        await importRules();
      } catch (error) {
        logger.error('Failed to import rules, but continuing startup:', error);
        logger.warn('Detection rules may need to be created manually');
      }
    } else {
      logger.info(
        'Catalog-only install (SEED_BUNDLED_CONTENT not set to true) — skipping bundled detection import. Use Browse Catalog → Install all.'
      );
    }

    // The sources the per-minute ingest counts track one by one, as they were
    // before this start, so a restart doesn't reset them (one small read;
    // never fails the start).
    await ingestCounter.restore();

    // Start syslog server
    syslogServer = new SyslogServer(SYSLOG_PORT);
    await syslogServer.start();
    // Its queue counters (UDP drops among them), for code without a handle on it.
    registerIngestStats(() => syslogServer.getIngestStats());

    // Start cleanup service
    cleanupService = new CleanupService(CLEANUP_INTERVAL_HOURS);
    cleanupService.start();

    // Start auto-discovery job
    startAutoDiscoveryJob();

    // Start scheduled scans job
    startScheduledScansJob();

    // Expire scan jobs queued for a log shipper that never picked them up, so
    // a shipper coming back after days offline can't run old work.
    startShipperJobExpiryJob();

    // Start ingestion-health monitor (drives ingestion notifications)
    startIngestionHealthJob();

    // Start the external threat-feed refresher (populates blocklist indicators).
    startThreatFeedsJob();

    // Start the Log Discovery API poller (pulls events from sources configured
    // for polling instead of the manual cron+curl+logger recipe).
    startDiscoveryApiPollerJob();

    // Keep the GeoIP database current. Without it, country enrichment is off and
    // the GeoIP map / Threat Intel country tables have nothing to show.
    startGeoipUpdateJob();

    // Start the EDR YARA-Forge refresher (opt-in via EDR_YARA_FORGE_ENABLED).
    startYaraRulesJob();

    // Check GitHub for new endpoint-agent releases (feeds the Endpoints page's
    // update-available state and, when enabled, auto-update).
    startEdrAgentReleaseJob();

    // Keep the SigmaHQ library current (daily; SIGMAHQ_AUTO_REFRESH=false turns it off).
    startSigmaLibraryJob();

    // Start the AI triage reconciler (requeues runs orphaned by a restart;
    // backfills missed eligible alerts). No-ops on each tick while triage is
    // disabled in settings.
    startTriageReconcilerJob();

    // Start the leaked-credential checker (exposure monitoring). No-ops on each
    // tick until an HIBP key is saved and identities are added.
    startLeakedCredsJob();

    // Start the domain monitor (certificate transparency, lookalikes, RDAP,
    // DNS drift). No-ops on each tick until a domain is watched.
    startDomainMonitorJob();

    // Sign-in protection. Every start says so when it is off: it is meant for
    // recovering from a lockout, not to be left on.
    const signIn = signInSettings();
    if (!signIn.protection) {
      logger.warn(
        'LOGIN_PROTECTION=off: sign-in attempts are not counted or paused. Remove it once you are signed in ' +
          '(docs/operations/TROUBLESHOOTING.md, "Locked out of SIEMBox").'
      );
    } else {
      const { aip, ip, acct } = signIn.scopes;
      logger.info(
        `Sign-in protection on: pauses after ${aip.threshold} failures per account and network, ` +
          `${ip.threshold} per network, ` +
          (acct.threshold > 0 ? `${acct.threshold} per account from new browsers` : 'no account-wide limit') +
          `; alerts ${signIn.alerts ? 'on' : 'off'}.`
      );
    }
    // Which origins' pages may call the API from a browser. Every start warns
    // about CORS_ORIGIN=* and about each entry it ignored.
    logCorsPolicy(corsPolicy);
    if (!linearRegexFallback) {
      logger.warn(
        '[regex-safety] REGEX_LINEAR_FALLBACK is off: a regex that backtracks catastrophically on a log line runs on the event loop until it ends'
      );
    }
    // An account found on the default password "changeme" (flagged by
    // migrate's scan, or at a sign-in) raises a siembox-auth alert: once per
    // flag, so restarts add nothing. In the background; never fails the start.
    void raiseDefaultPasswordAlerts();
    // The dummy hash unknown usernames are checked against, made before the
    // first sign-in needs it.
    await getDummyHash();
    // Idle counters, unused browsers, expired sessions, old failure audit rows.
    startSignInHousekeepingJob();
    // Context Graph: the relationships logs show, rolled up every minute off
    // the ingest path (services/graph/logEdgeRollup.ts).
    startGraphLogEdgesJob();
    // Application Monitoring: the software inventory, rolled up every two
    // minutes off the ingest path (services/applications/rollup.ts).
    startApplicationInventoryJob();

    // Regex safety: give every stored parser and rule regex a ReDoS verdict
    // (cached in regex_safety_verdicts, so only new regexes cost anything) and
    // WARN for each vulnerable one; the Parsers / Detection Rules pages tag
    // them "Unsafe regex". Saved before the write-time gate existed, they still
    // run (disabling them would silently drop parsing). Background, off the
    // event loop; never fails the start.
    void scanStoredRegexes().catch((error) => {
      logger.warn('[regex-safety] startup scan of stored regexes failed', {
        error: error instanceof Error ? error.message : String(error),
      });
    });

    // Warm the Nuclei template cache in the background so the first request to
    // the (heavy) template endpoints hits a populated cache instead of parsing
    // ~10k files inline and tripping the client timeout. Fire-and-forget.
    void TemplateService.warmCache();

    // Look up the TRUSTED_PROXIES names first (at most 1 s), so the first
    // request the frontend proxies over TCP already gets its client's address.
    await trustedProxies.start();

    // Start the Express API: TCP for direct callers, the proxy socket for the
    // bundled nginx (see net/apiListeners.ts).
    apiServer = createApiServer(app);
    apiServer.listen(PORT, () => {
      logger.info(`SIEMBox API server running on http://${HOST}:${PORT}`);
      logger.info(`Environment: ${process.env.NODE_ENV || 'development'}`);
      logger.info(`Health check: http://${HOST}:${PORT}/health`);
      logger.info(`Syslog server listening on port ${SYSLOG_PORT} (UDP/TCP)`);
      logger.info(`Cleanup service running (interval: ${CLEANUP_INTERVAL_HOURS} hours)`);
      logger.info(`Auto-discovery job running (interval: 6 hours)`);
    });
    proxySocketServer = (await listenProxySocket(app)).server;
    logger.info(clientAddressSummary(PORT));
  } catch (error) {
    logger.error('Failed to start server:', error);
    const hint = diagnoseDbConnectionError(error);
    if (hint) logger.error(`Database unreachable -- ${hint}`);
    process.exit(1);
  }
};

// Graceful shutdown
let shuttingDown = false;

const shutdown = async (signal: string) => {
  // A second signal (SIGTERM then SIGINT, or a repeated Ctrl-C) must not start a
  // second teardown: the pools can only be closed once.
  if (shuttingDown) return;
  shuttingDown = true;
  logger.info(`${signal} signal received: closing servers`);
  // Stop taking API requests on both listeners (this also removes the proxy
  // socket's file, so nginx moves to its fallback at once).
  stopListening(apiServer);
  stopListening(proxySocketServer);
  trustedProxies.stop();
  if (syslogServer) {
    try {
      // Stops listening, then gives messages already accepted a few seconds to
      // reach the database before the pools below are closed under them.
      await syslogServer.stop();
    } catch (error) {
      logger.error('Error stopping syslog server:', error);
    }
    registerIngestStats(null);
  }
  if (cleanupService) {
    cleanupService.stop();
  }
  stopAutoDiscoveryJob();
  stopScheduledScansJob();
  stopShipperJobExpiryJob();
  stopIngestionHealthJob();
  stopThreatFeedsJob();
  stopDiscoveryApiPollerJob();
  stopGeoipUpdateJob();
  stopYaraRulesJob();
  stopEdrAgentReleaseJob();
  stopSigmaLibraryJob();
  stopTriageReconcilerJob();
  stopLeakedCredsJob();
  stopDomainMonitorJob();
  stopSignInHousekeepingJob();
  stopGraphLogEdgesJob();
  stopApplicationInventoryJob();
  stopRefusalSummary();
  await Promise.all([closeRegexScanPool(), closeRegexTestPool()]).catch(() => undefined);
  // The per-minute ingest counts not yet written. Ingest can still be storing
  // logs here (an HTTP push batch in flight, syslog messages that were running
  // when the drain gave up), so close() writes what it has, keeps counting
  // while it closes the ingest pool (after which nothing more can be stored),
  // and then writes the rest on the main pool. Waits at most 5 s; never throws.
  await ingestCounter.close(closeIngestPool);
  await closePools();
  logger.info('Database pools closed');
  process.exit(0);
};

process.on('SIGTERM', () => void shutdown('SIGTERM'));
process.on('SIGINT', () => void shutdown('SIGINT'));

startServer();
