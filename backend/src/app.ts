import express, { Application, NextFunction, Request, Response } from 'express';
import qs from 'qs';
import rateLimit from 'express-rate-limit';
import { bodyParserErrorHandler, errorHandler, notFoundHandler } from './middleware/errorHandler';
import { requestTimeoutLogger } from './middleware/requestTimeoutLogger';
import { authenticate, requireAdmin } from './middleware/auth';
import { query } from './config/database';
import { corsHeaders, parseCorsOrigin } from './net/cors';
import { ignoredForwardedForTracker, trustedProxies } from './net/trustedProxies';
import { rateLimitedHandler, requestLimitKey } from './net/requestLimits';
import { envInt } from './utils/envInt';

// Import routes
import authRoutes from './routes/auth';
import usersRoutes from './routes/users';
import logsRoutes from './routes/logs';
import parsersRoutes from './routes/parsers';
import rulesRoutes from './routes/rules';
import alertsRoutes from './routes/alerts';
import settingsRoutes from './routes/settings';
import shippersRoutes from './routes/shippers';
import assetsRoutes from './routes/assets';
import vulnerabilitiesRoutes from './routes/vulnerabilities';
import adminRoutes from './routes/admin';
import scheduledScansRoutes from './routes/scheduledScans';
import notificationsRoutes from './routes/notifications';
import aiRoutes from './routes/ai';
import containersRoutes from './routes/containers';
import threatIntelRoutes from './routes/threatIntel';
import threatFeedsRoutes from './routes/threatFeeds';
import edrRoutes from './routes/edr';
import packsRoutes from './routes/packs';
import logDiscoveryRoutes from './routes/logDiscovery';
import exposureRoutes from './routes/exposure';
import graphRoutes from './routes/graph';
import displayRoutes from './routes/display';
import displayLinksRoutes from './routes/displayLinks';
import bigDisplayRoutes from './routes/bigDisplay';

const app: Application = express();

// Client addresses (req.ip): only the bundled nginx, on the proxy socket, and
// the TRUSTED_PROXIES entries may set them through X-Forwarded-For; every other
// caller is its TCP peer address. See net/clientAddress.ts and
// net/trustedProxies.ts. Never a hop count: a hop count trusts whoever connects.
app.set('trust proxy', trustedProxies.trust);

// Query strings parse as they did under Express 4: qs (`a[]=1`, `a[b]=1`) with
// Express 4's options. Express 5 defaults to 'simple' (node:querystring), and its
// 'extended' drops arrayLimit to qs's default of 20, so a key repeated 21 times
// or an index above 20 would turn into an index-keyed object.
app.set('query parser', (str: string) => qs.parse(str, { allowPrototypes: true, arrayLimit: 1000 }));

// First: count requests whose X-Forwarded-For is ignored (from a direct caller,
// or from a proxy in front of nginx that isn't trusted), so a proxy that ought
// to be trusted shows up in the log and in /api/admin/client-address.
app.use(ignoredForwardedForTracker());

// CORS: same-origin only unless CORS_ORIGIN lists the origins (or `*`) whose
// pages may call the API from a browser. The web UI is same-origin through its
// nginx and needs none. See net/cors.ts; server.ts logs the policy at startup.
// Read here, after config/database.ts has loaded .env.
export const corsPolicy = parseCorsOrigin(process.env.CORS_ORIGIN);
app.use(corsHeaders(corsPolicy));

// Agent and log-push routes that sit behind their own limiter (edrAgentLimiter
// in routes/edr.ts, logPushLimiter in routes/shippers.ts) and identify the
// caller with a header. Many agents or shippers can share one NAT address, so
// these skip the general limit, but only with the method each route answers:
// any other method reaches no limiter of its own (a 404, which is logged to the
// database, or a shipper management route). HEAD goes with GET, as in Express's
// router. Enrollment is not among them: it is counted here whatever headers it
// carries.
const LIMITER_EXEMPT_ROUTES: ReadonlyArray<{ methods: readonly string[]; path: RegExp; header: string }> = [
  { methods: ['POST'], path: /^\/api\/edr\/agents\/[^/]+\/heartbeat\/?$/i, header: 'x-agent-id' },
  { methods: ['GET', 'HEAD'], path: /^\/api\/edr\/agents\/[^/]+\/(?:config|yara)\/?$/i, header: 'x-agent-id' },
  { methods: ['POST'], path: /^\/api\/edr\/(?:inventory|events|vulnerabilities)\/?$/i, header: 'x-agent-id' },
  { methods: ['POST'], path: /^\/api\/shippers\/logs\/?$/i, header: 'x-shipper-id' },
];

/**
 * The general limit for /api: API_RATE_LIMIT_MAX requests (default 1000) per
 * 15 minutes per client address, generous enough for the UI's polling. Mounted
 * before the body parsers, so oversized or malformed bodies count too. A 429 is
 * JSON (code RATE_LIMITED) with Retry-After; the X-RateLimit-* headers stay.
 */
export const apiRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: envInt('API_RATE_LIMIT_MAX', 1000, 1),
  legacyHeaders: true,
  standardHeaders: false,
  keyGenerator: requestLimitKey,
  handler: rateLimitedHandler('Too many requests from your address.'),
  skip: (req: Request) => {
    const path = (req.originalUrl || req.url || '').split('?')[0];
    return LIMITER_EXEMPT_ROUTES.some(
      (route) => Boolean(req.headers[route.header]) && route.methods.includes(req.method) && route.path.test(path)
    );
  },
});

app.use('/api/', apiRateLimiter);

// Sign-in and account requests carry a few short fields: cap their bodies at
// 16 kB (larger ones get 413) before the general 10 MB parsers, which then
// skip the already-parsed body.
app.use('/api/auth', express.json({ limit: '16kb' }), express.urlencoded({ extended: true, limit: '16kb' }));
// Display links carry a name and a board layout (at most 16 kB of config,
// services/display/config.ts), and a screen's read carries no body: cap both
// at 32 kB. Mount paths match whole segments, so /api/display never covers
// /api/display-links.
app.use('/api/display', express.json({ limit: '32kb' }), express.urlencoded({ extended: true, limit: '32kb' }));
app.use('/api/display-links', express.json({ limit: '32kb' }), express.urlencoded({ extended: true, limit: '32kb' }));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Express 5's parsers leave req.body undefined when they read no body (a GET, a
// DELETE, a POST without a JSON or form Content-Type); Express 4's set it to {}.
// Keep {}, so handlers that destructure req.body answer with their own 400s.
app.use(function emptyBodyDefault(req: Request, _res: Response, next: NextFunction) {
  if (req.body === undefined) req.body = {};
  next();
});

// Surface client-side request timeouts (slow endpoints the browser gave up on)
// in the Admin dashboard's Recent Errors panel — the server doesn't throw on
// these, so they were otherwise invisible. Registered before routes so it wraps
// every API request's lifecycle.
app.use(requestTimeoutLogger());

// Health check endpoint
app.get('/health', (_req, res) => {
  res.status(200).json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
  });
});

// Database status endpoint
app.get('/health/database-status', async (_req: Request, res: Response) => {
  try {
    const parsers = await query('SELECT COUNT(*) as count FROM parsers');
    const rules = await query('SELECT COUNT(*) as count FROM detection_rules');
    const parserCount = parseInt(parsers.rows[0].count, 10);
    const ruleCount = parseInt(rules.rows[0].count, 10);

    res.status(200).json({
      parsers: parserCount,
      rules: ruleCount,
      ready: parserCount >= 18 && ruleCount >= 40
    });
  } catch {
    res.status(500).json({
      error: 'Failed to check database status',
      parsers: 0,
      rules: 0,
      ready: false
    });
  }
});

// API routes
app.use('/api/auth', authRoutes);
app.use('/api/users', usersRoutes);

// Protected routes (require authentication)
app.use('/api/logs', authenticate, logsRoutes);
app.use('/api/parsers', authenticate, parsersRoutes);
app.use('/api/rules', authenticate, rulesRoutes);
app.use('/api/alerts', authenticate, alertsRoutes);
app.use('/api/settings', authenticate, settingsRoutes);
// Not gated here: the shipper agent's own endpoints (register, config, scan-jobs,
// results, HTTP log push) authenticate with the shipper's key instead of a login.
// Every management route in routes/shippers.ts requires `authenticate` itself.
app.use('/api/shippers', shippersRoutes);
app.use('/api/assets', authenticate, assetsRoutes); // Asset discovery and management
app.use('/api/vulnerabilities', authenticate, vulnerabilitiesRoutes); // Vulnerability scanning and management
app.use('/api/admin', adminRoutes); // Admin dashboard (requires admin role)
app.use('/api/scheduled-scans', authenticate, scheduledScansRoutes); // Recurring scheduled scans
app.use('/api/notifications', authenticate, notificationsRoutes);
app.use('/api/ai', authenticate, aiRoutes); // "Explain this" assistant (any authed user)
app.use('/api/containers', authenticate, containersRoutes); // Trivy container image scanning
app.use('/api/threat-intel', authenticate, threatIntelRoutes); // IP-centric geo/event/alert lookup
app.use('/api/threat-feeds', authenticate, threatFeedsRoutes); // External threat feeds + IP reputation
app.use('/api/edr', edrRoutes); // EDR endpoint agents (enroll + agent-auth ingest + admin UI)
app.use('/api/packs', authenticate, packsRoutes); // Content Packs (curated parser+detection bundles)
app.use('/api/log-discovery', authenticate, logDiscoveryRoutes); // Log source discovery, fingerprinting + onboarding
app.use('/api/exposure', authenticate, exposureRoutes); // Digital Risk: leaked credentials, watched domains, findings
app.use('/api/graph', authenticate, graphRoutes); // Context Graph: read-only pivots between alerts, IPs, assets, findings, rules

// Big Display (docs/architecture/BIG-DISPLAY.md). A wall screen's read takes
// its display link in X-Display-Token, never a login: each route gates itself
// (routes/display.ts). Display links themselves are configured by admins; the
// signed-in board uses the user's own session and role.
app.use('/api/display', displayRoutes);
app.use('/api/display-links', authenticate, requireAdmin, displayLinksRoutes);
app.use('/api/big-display', authenticate, bigDisplayRoutes);

// Error handlers (must be last)
app.use(notFoundHandler);
// Malformed/oversized bodies: answer 4xx without logging the parse error, which
// quotes the raw body (and so could carry a password or API key).
app.use(bodyParserErrorHandler);
app.use(errorHandler);

export default app;
