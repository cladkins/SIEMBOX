/**
 * Every route the API serves and who may call it, checked against the real app
 * (app.ts with every router and middleware).
 *
 * ADDING, REMOVING OR CHANGING A ROUTE IS A ONE-LINE CHANGE TO `INVENTORY` BELOW:
 *   [method, full path as the router declares it (with :params), who, AUDITED?]
 * `who` is PUBLIC (no login: sign-in and /health), AGENT (a shipper or EDR
 * agent's own key, never a login), DISPLAY (a wall screen's display link in
 * X-Display-Token, never a login), or the roles that may call it: the roles of
 * the UI page(s) that make the call (allowedRoles in frontend/src/router/index.ts).
 * Viewers are read-only: a POST, PUT, PATCH or DELETE open to them must also be
 * in VIEWER_SAFE_WRITES, with the reason it changes nothing shared. AUDITED
 * marks the gates built on middleware/scanPermissions.ts, which write each
 * refusal to audit_logs.
 *
 * The test fails when the app serves a route the inventory doesn't list, when
 * the inventory lists a route the app no longer serves, and when a route lets
 * in or keeps out the wrong roles. Only routes (router.get/post/...) can be
 * listed, so anything else mounted with app.use() or router.use() fails it too
 * unless it is a known pass-through (PASS_THROUGH): a handler function, a
 * mounted sub-app or express.static could answer requests no line covers. As a
 * backstop, an admin's request for a path no route declares, under every mount,
 * must reach the not-found handler.
 *
 * How it runs: the app listens on an ephemeral port, and each route's own
 * handler is swapped for a stub that answers with the route it belongs to. So
 * everything in front of the handler (the mount-level authenticate in app.ts,
 * router.use() gates, per-route role gates, agent-key checks) runs exactly as
 * Express dispatches it, and no handler does any work. Each route is then called
 * without a login and with one session per role. Rate limiters (express-rate-limit
 * middleware, recognized by its resetKey()) are swapped for pass-throughs: they
 * are not role gates, and this file calls every route several times.
 *
 * Hermetic: before app.ts (and so config/database.ts) is loaded, DB_HOST and
 * DB_PORT point at a local port nothing listens on; the pool is also mocked to
 * throw. Sessions come from stubbed SessionModel/UserModel lookups, agent and
 * shipper key lookups find nothing, display links are three stubbed ones (live,
 * paused, revoked; DisplayLinkModel), and AuditService.log and
 * ErrorLogService.logError are recorded instead of written.
 * Run with `npm test` (tsx --test).
 */
import { test, before, after, mock } from 'node:test';
import assert from 'node:assert/strict';
import { once } from 'node:events';
import net from 'node:net';
import type { Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import express, { type Application } from 'express';

type Role = 'admin' | 'operator' | 'analyst' | 'viewer';
const ROLES: Role[] = ['admin', 'operator', 'analyst', 'viewer'];

/** Any signed-in role. For reads, and for VIEWER_SAFE_WRITES. */
const ANY_ROLE: Role[] = ROLES;
/** Analyst and up: detection content, alert triage, the AI Analyst, Asset Inventory and Templates. */
const ANALYST_UP: Role[] = ['admin', 'operator', 'analyst'];
/** Operator and up: scanning, log discovery, shipper management, feed refresh. */
const OPERATOR_UP: Role[] = ['admin', 'operator'];
const ADMIN_ONLY: Role[] = ['admin'];
/** No login. */
const PUBLIC = 'public';
/** A shipper's or EDR agent's own key (in a header, the body or the URL), never a login. */
const AGENT = 'agent';
/** A wall screen's display link secret in X-Display-Token (middleware/displayAuth.ts), never a login. */
const DISPLAY = 'display';
/** The gate writes each refusal to audit_logs (middleware/scanPermissions.ts). */
const AUDITED = true;

type Who = Role[] | typeof PUBLIC | typeof AGENT | typeof DISPLAY;
type Method = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';
type Row = [method: Method, path: string, who: Who, audited?: boolean];

// One line per route. Keep each router's lines in the order the router declares them.
const INVENTORY: Row[] = [
  // app.ts
  ['GET', '/health', PUBLIC],
  ['GET', '/health/database-status', PUBLIC],

  // routes/auth.ts: sign-in, and the caller's own account
  ['POST', '/api/auth/login', PUBLIC],
  ['POST', '/api/auth/logout', ANY_ROLE],
  ['GET', '/api/auth/me', ANY_ROLE],
  ['PUT', '/api/auth/me/password', ANY_ROLE],
  ['POST', '/api/auth/me/mfa/setup', ANY_ROLE],
  ['POST', '/api/auth/me/mfa/enable', ANY_ROLE],
  ['POST', '/api/auth/me/mfa/disable', ANY_ROLE],
  ['POST', '/api/auth/cleanup', ADMIN_ONLY],

  // routes/users.ts: Users page
  ['GET', '/api/users', ADMIN_ONLY],
  ['GET', '/api/users/:id', ADMIN_ONLY],
  ['POST', '/api/users', ADMIN_ONLY],
  ['PUT', '/api/users/:id', ADMIN_ONLY],
  ['DELETE', '/api/users/:id', ADMIN_ONLY],
  ['POST', '/api/users/:id/unlock', ADMIN_ONLY],

  // routes/logs.ts
  ['GET', '/api/logs/parse-coverage', ANY_ROLE],
  ['GET', '/api/logs/raw', ANY_ROLE],
  ['GET', '/api/logs/parsed', ANY_ROLE],
  ['GET', '/api/logs/parsed/search', ANY_ROLE],

  // routes/parsers.ts: Parsers page. /validate and /test run a regex the caller
  // supplies (in a time-bounded worker), so they sit with the writes; /:id/test
  // runs a saved parser.
  ['GET', '/api/parsers', ANY_ROLE],
  ['GET', '/api/parsers/match-stats', ANY_ROLE],
  ['GET', '/api/parsers/recommendations', ANY_ROLE],
  ['POST', '/api/parsers/validate', ANALYST_UP, AUDITED],
  ['POST', '/api/parsers/import', ANALYST_UP, AUDITED],
  ['POST', '/api/parsers/ai/generate', ADMIN_ONLY],
  ['GET', '/api/parsers/catalog', ANY_ROLE],
  ['GET', '/api/parsers/catalog/source', ANY_ROLE],
  ['POST', '/api/parsers/catalog/install', ANALYST_UP, AUDITED],
  ['POST', '/api/parsers/catalog/install-all', ANALYST_UP, AUDITED],
  ['POST', '/api/parsers/catalog/refresh', ANALYST_UP, AUDITED],
  ['GET', '/api/parsers/:id', ANY_ROLE],
  ['GET', '/api/parsers/:id/export', ANY_ROLE],
  ['GET', '/api/parsers/:id/contribute', ANY_ROLE],
  ['POST', '/api/parsers', ANALYST_UP, AUDITED],
  ['PUT', '/api/parsers/:id', ANALYST_UP, AUDITED],
  ['DELETE', '/api/parsers/:id', ANALYST_UP, AUDITED],
  ['POST', '/api/parsers/:id/test', ANY_ROLE],
  ['POST', '/api/parsers/test', ANALYST_UP, AUDITED],

  // routes/rules.ts: Rules page
  ['GET', '/api/rules', ANY_ROLE],
  ['POST', '/api/rules/ai/generate', ADMIN_ONLY],
  ['GET', '/api/rules/recommendations', ANY_ROLE],
  ['GET', '/api/rules/catalog', ANY_ROLE],
  ['GET', '/api/rules/catalog/source', ANY_ROLE],
  ['POST', '/api/rules/catalog/install', ANALYST_UP, AUDITED],
  ['POST', '/api/rules/catalog/install-all', ANALYST_UP, AUDITED],
  ['POST', '/api/rules/catalog/refresh', ANALYST_UP, AUDITED],
  ['POST', '/api/rules/import/sigma/preview', ADMIN_ONLY],
  ['POST', '/api/rules/import/sigma', ADMIN_ONLY],
  ['GET', '/api/rules/:id', ANY_ROLE],
  ['GET', '/api/rules/:id/contribute', ANY_ROLE],
  ['POST', '/api/rules', ANALYST_UP, AUDITED],
  ['PUT', '/api/rules/:id', ANALYST_UP, AUDITED],
  ['DELETE', '/api/rules/:id', ANALYST_UP, AUDITED],

  // routes/alerts.ts: Alerts and SOC Triage pages. Deleting destroys evidence.
  ['GET', '/api/alerts', ANY_ROLE],
  ['GET', '/api/alerts/export', ANY_ROLE],
  ['GET', '/api/alerts/statistics', ANY_ROLE],
  ['GET', '/api/alerts/by-country', ANY_ROLE],
  ['GET', '/api/alerts/triage-risk-summary', ANY_ROLE],
  ['GET', '/api/alerts/:id', ANY_ROLE],
  ['GET', '/api/alerts/:id/triage', ANY_ROLE],
  ['POST', '/api/alerts/:id/triage/rerun', ANALYST_UP],
  ['PUT', '/api/alerts/:id', ANALYST_UP, AUDITED],
  ['DELETE', '/api/alerts/:id', ADMIN_ONLY, AUDITED],

  // routes/settings.ts: Settings hub (admin areas)
  ['GET', '/api/settings/ai', ADMIN_ONLY],
  ['PUT', '/api/settings/ai', ADMIN_ONLY],
  ['GET', '/api/settings/ai-chat', ADMIN_ONLY],
  ['PUT', '/api/settings/ai-chat', ADMIN_ONLY],
  ['GET', '/api/settings/ai-triage', ADMIN_ONLY],
  ['PUT', '/api/settings/ai-triage', ADMIN_ONLY],
  ['GET', '/api/settings', ADMIN_ONLY],
  ['GET', '/api/settings/retention', ADMIN_ONLY],
  ['PUT', '/api/settings/retention', ADMIN_ONLY],
  ['GET', '/api/settings/context-graph', ADMIN_ONLY],
  ['PUT', '/api/settings/context-graph', ADMIN_ONLY],
  ['POST', '/api/settings/retention/cleanup', ADMIN_ONLY],
  ['GET', '/api/settings/retention/cleanup/status', ADMIN_ONLY],
  ['GET', '/api/settings/retention/stats', ADMIN_ONLY],
  ['GET', '/api/settings/syslog', ANY_ROLE],
  ['PUT', '/api/settings/syslog', ADMIN_ONLY],
  ['GET', '/api/settings/syslog/status', ADMIN_ONLY],
  ['GET', '/api/settings/ip-whitelist', ADMIN_ONLY],
  ['POST', '/api/settings/ip-whitelist', ADMIN_ONLY],
  ['PUT', '/api/settings/ip-whitelist/:id', ADMIN_ONLY],
  ['DELETE', '/api/settings/ip-whitelist/:id', ADMIN_ONLY],
  ['POST', '/api/settings/ip-whitelist/check', ADMIN_ONLY],
  ['GET', '/api/settings/auto-discovery', ADMIN_ONLY],
  ['PUT', '/api/settings/auto-discovery', ADMIN_ONLY],
  ['GET', '/api/settings/auto-discovery/stats', ADMIN_ONLY],
  // Getting Started: every role reads whether setup is done; only admins mark
  // it done or reopen it
  ['GET', '/api/settings/onboarding', ANY_ROLE],
  ['PUT', '/api/settings/onboarding', ADMIN_ONLY],

  // routes/shippers.ts: Shippers page, then the shipper agent's own endpoints
  ['GET', '/api/shippers', ANY_ROLE],
  ['GET', '/api/shippers/unknown-sources', ANY_ROLE],
  ['GET', '/api/shippers/direct-syslog-sources', ANY_ROLE],
  ['GET', '/api/shippers/:id', ANY_ROLE],
  ['POST', '/api/shippers', OPERATOR_UP],
  ['PUT', '/api/shippers/:id', OPERATOR_UP],
  ['DELETE', '/api/shippers/:id', OPERATOR_UP],
  ['GET', '/api/shippers/:id/sources', ANY_ROLE],
  ['POST', '/api/shippers/:id/sources', OPERATOR_UP],
  ['PUT', '/api/shippers/sources/:sourceId', OPERATOR_UP],
  ['DELETE', '/api/shippers/sources/:sourceId', OPERATOR_UP],
  ['GET', '/api/shippers/:id/volumes', ANY_ROLE],
  ['POST', '/api/shippers/:id/volumes', OPERATOR_UP],
  ['DELETE', '/api/shippers/volumes/:volumeId', OPERATOR_UP],
  ['GET', '/api/shippers/:id/activity', ANY_ROLE],
  ['POST', '/api/shippers/:id/regenerate-key', ADMIN_ONLY],
  ['POST', '/api/shippers/:id/http-push-key', ADMIN_ONLY],
  ['DELETE', '/api/shippers/:id/http-push-key', ADMIN_ONLY],
  ['POST', '/api/shippers/register', AGENT],
  ['POST', '/api/shippers/containers', AGENT],
  ['GET', '/api/shippers/config/:api_key', AGENT],
  ['GET', '/api/shippers/scan-jobs/:api_key', AGENT],
  ['POST', '/api/shippers/scan-results', AGENT],
  ['POST', '/api/shippers/discovery-results', AGENT],
  ['POST', '/api/shippers/logs', AGENT],

  // routes/assets.ts: Asset Inventory page
  ['GET', '/api/assets', ANY_ROLE],
  ['GET', '/api/assets/statistics', ANY_ROLE],
  ['GET', '/api/assets/scans/active', ANY_ROLE],
  ['GET', '/api/assets/scans/statistics', ANY_ROLE],
  ['GET', '/api/assets/scans', ANY_ROLE],
  ['GET', '/api/assets/scans/:scanId', ANY_ROLE],
  ['GET', '/api/assets/:id', ANY_ROLE],
  ['GET', '/api/assets/:id/related', ANY_ROLE],
  ['POST', '/api/assets', ANALYST_UP, AUDITED],
  ['PUT', '/api/assets/:id', ANALYST_UP, AUDITED],
  ['DELETE', '/api/assets/:id', ANALYST_UP, AUDITED],
  ['GET', '/api/assets/:id/services', ANY_ROLE],
  ['POST', '/api/assets/scan', ANALYST_UP, AUDITED],
  ['POST', '/api/assets/discover', ANALYST_UP, AUDITED],

  // routes/vulnerabilities.ts: Templates (refresh) and Vulnerability Scanning and Management pages
  ['GET', '/api/vulnerabilities/summary', ANY_ROLE],
  ['GET', '/api/vulnerabilities/templates', ANY_ROLE],
  ['GET', '/api/vulnerabilities/templates/categories', ANY_ROLE],
  ['GET', '/api/vulnerabilities/templates/tags', ANY_ROLE],
  ['GET', '/api/vulnerabilities/templates/search', ANY_ROLE],
  ['GET', '/api/vulnerabilities/templates/category/:categoryId', ANY_ROLE],
  ['GET', '/api/vulnerabilities/templates/tag/:tag', ANY_ROLE],
  ['GET', '/api/vulnerabilities/templates/severity/:severity', ANY_ROLE],
  ['POST', '/api/vulnerabilities/templates/refresh', ANALYST_UP, AUDITED],
  ['POST', '/api/vulnerabilities/templates/download', OPERATOR_UP, AUDITED],
  ['GET', '/api/vulnerabilities/scans/active', ANY_ROLE],
  ['GET', '/api/vulnerabilities/scans', ANY_ROLE],
  ['GET', '/api/vulnerabilities/scans/:scanId', ANY_ROLE],
  ['GET', '/api/vulnerabilities/scans/:scanId/status', ANY_ROLE],
  ['POST', '/api/vulnerabilities/scans', OPERATOR_UP, AUDITED],
  ['POST', '/api/vulnerabilities/scans/:scanId/cancel', OPERATOR_UP, AUDITED],
  ['GET', '/api/vulnerabilities', ANY_ROLE],
  ['GET', '/api/vulnerabilities/:id', ANY_ROLE],
  ['GET', '/api/vulnerabilities/asset/:assetId', ANY_ROLE],
  ['PATCH', '/api/vulnerabilities/:assetId/:vulnId', OPERATOR_UP, AUDITED],

  // routes/admin.ts: Admin dashboard
  ['GET', '/api/admin/overview', ADMIN_ONLY],
  ['GET', '/api/admin/users/search', ADMIN_ONLY],
  ['GET', '/api/admin/users/:id/activity', ADMIN_ONLY],
  ['GET', '/api/admin/errors', ADMIN_ONLY],
  ['GET', '/api/admin/jobs', ADMIN_ONLY],
  ['GET', '/api/admin/client-address', ADMIN_ONLY],
  ['GET', '/api/admin/sign-in-protection', ADMIN_ONLY],
  ['POST', '/api/admin/sign-in-protection/clear', ADMIN_ONLY],

  // routes/scheduledScans.ts: Scheduled Scans page
  ['GET', '/api/scheduled-scans', ANY_ROLE],
  ['POST', '/api/scheduled-scans', OPERATOR_UP, AUDITED],
  ['PUT', '/api/scheduled-scans/:id', OPERATOR_UP, AUDITED],
  ['DELETE', '/api/scheduled-scans/:id', OPERATOR_UP, AUDITED],
  ['POST', '/api/scheduled-scans/:id/run', OPERATOR_UP, AUDITED],

  // routes/notifications.ts: Settings > Notifications (channel config is redacted for non-admins)
  ['GET', '/api/notifications/channels', ANY_ROLE],
  ['POST', '/api/notifications/channels', ADMIN_ONLY],
  ['PUT', '/api/notifications/channels/:id', ADMIN_ONLY],
  ['DELETE', '/api/notifications/channels/:id', ADMIN_ONLY],
  ['POST', '/api/notifications/channels/:id/test', ADMIN_ONLY],
  ['POST', '/api/notifications/test-alert', ADMIN_ONLY],
  ['GET', '/api/notifications/settings', ANY_ROLE],
  ['PUT', '/api/notifications/settings', ADMIN_ONLY],

  // routes/ai.ts: "Explain this" for everyone; the AI Analyst (chat) is analyst and up
  ['POST', '/api/ai/explain', ANY_ROLE],
  ['GET', '/api/ai/chat/health', ANY_ROLE],
  ['GET', '/api/ai/triage/health', ANY_ROLE],
  ['GET', '/api/ai/chat/sessions', ANY_ROLE],
  ['GET', '/api/ai/chat/sessions/:id', ANY_ROLE],
  ['PATCH', '/api/ai/chat/sessions/:id', ANALYST_UP, AUDITED],
  ['DELETE', '/api/ai/chat/sessions/:id', ANALYST_UP, AUDITED],
  ['POST', '/api/ai/chat', ANALYST_UP, AUDITED],

  // routes/containers.ts: Container Scanning page
  ['GET', '/api/containers/discovered', ANY_ROLE],
  ['GET', '/api/containers/inventory', ANY_ROLE],
  ['POST', '/api/containers/scan', OPERATOR_UP, AUDITED],
  ['GET', '/api/containers/scans', ANY_ROLE],
  ['GET', '/api/containers/scans/:id', ANY_ROLE],

  // routes/threatIntel.ts
  ['GET', '/api/threat-intel/ip/:ip', ANY_ROLE],
  ['GET', '/api/threat-intel/country/:code', ANY_ROLE],

  // routes/threatFeeds.ts: Threat Intel page (feed refresh for operators, configuration for admins)
  ['GET', '/api/threat-feeds/summary', ANY_ROLE],
  ['GET', '/api/threat-feeds', ANY_ROLE],
  ['PUT', '/api/threat-feeds/feeds/:id', ADMIN_ONLY],
  ['POST', '/api/threat-feeds/feeds/:id/refresh', OPERATOR_UP],
  ['POST', '/api/threat-feeds/refresh', OPERATOR_UP],
  ['PUT', '/api/threat-feeds/providers/:name', ADMIN_ONLY],
  ['GET', '/api/threat-feeds/lookup/:ip', ANY_ROLE],

  // routes/edr.ts: the endpoint agent's own endpoints, then the Endpoints page
  ['POST', '/api/edr/agents/enroll', AGENT],
  ['POST', '/api/edr/agents/:id/heartbeat', AGENT],
  ['GET', '/api/edr/agents/:id/config', AGENT],
  ['GET', '/api/edr/agents/:id/yara', AGENT],
  ['POST', '/api/edr/inventory', AGENT],
  ['POST', '/api/edr/events', AGENT],
  ['POST', '/api/edr/vulnerabilities', AGENT],
  ['GET', '/api/edr/agents', ADMIN_ONLY],
  ['POST', '/api/edr/tokens', ADMIN_ONLY],
  ['GET', '/api/edr/tokens', ADMIN_ONLY],
  ['DELETE', '/api/edr/tokens/:hash', ADMIN_ONLY],
  ['GET', '/api/edr/yara', ADMIN_ONLY],
  ['POST', '/api/edr/yara/refresh', ADMIN_ONLY],
  ['GET', '/api/edr/agent-updates', ADMIN_ONLY],
  ['POST', '/api/edr/agent-updates/check', ADMIN_ONLY],
  ['PUT', '/api/edr/agent-updates/settings', ADMIN_ONLY],
  ['POST', '/api/edr/agents/update-outdated', ADMIN_ONLY],
  ['POST', '/api/edr/agents/:id/update', ADMIN_ONLY],
  ['DELETE', '/api/edr/agents/:id/update', ADMIN_ONLY],
  ['GET', '/api/edr/agents/:id', ADMIN_ONLY],
  ['GET', '/api/edr/agents/:id/vulnerabilities', ADMIN_ONLY],
  ['GET', '/api/edr/agents/:id/detections', ADMIN_ONLY],
  ['DELETE', '/api/edr/agents/:id', ADMIN_ONLY],

  // routes/packs.ts: Content Packs page
  ['GET', '/api/packs', ANY_ROLE],
  ['POST', '/api/packs/:id/install', ADMIN_ONLY],

  // routes/logDiscovery.ts: Log Discovery page. Scope, manual sources and poll
  // credentials are admin-only.
  ['GET', '/api/log-discovery/scope', ANY_ROLE],
  ['GET', '/api/log-discovery/scope/cidrs', ANY_ROLE],
  ['PUT', '/api/log-discovery/scope/cidrs', ADMIN_ONLY],
  ['GET', '/api/log-discovery/fingerprints', ANY_ROLE],
  ['POST', '/api/log-discovery/scans', OPERATOR_UP, AUDITED],
  ['GET', '/api/log-discovery/scans', ANY_ROLE],
  ['GET', '/api/log-discovery/scans/:id', ANY_ROLE],
  ['POST', '/api/log-discovery/scans/:id/cancel', OPERATOR_UP, AUDITED],
  ['GET', '/api/log-discovery/sources', ANY_ROLE],
  ['POST', '/api/log-discovery/sources/manual', ADMIN_ONLY],
  ['DELETE', '/api/log-discovery/sources/:id', ADMIN_ONLY],
  ['PATCH', '/api/log-discovery/sources/:id', ADMIN_ONLY],
  ['POST', '/api/log-discovery/sources/:id/confirm', OPERATOR_UP],
  ['POST', '/api/log-discovery/sources/:id/ignore', OPERATOR_UP],
  ['POST', '/api/log-discovery/sources/:id/onboard/preview', ANY_ROLE],
  ['POST', '/api/log-discovery/sources/:id/onboard/confirm', OPERATOR_UP],
  ['GET', '/api/log-discovery/poller/supported-fingerprints', ANY_ROLE],
  ['GET', '/api/log-discovery/sources/:id/poller', ANY_ROLE],
  ['POST', '/api/log-discovery/sources/:id/poller/credential', ADMIN_ONLY],
  ['DELETE', '/api/log-discovery/sources/:id/poller/credential', ADMIN_ONLY],
  ['PATCH', '/api/log-discovery/sources/:id/poller', ADMIN_ONLY],
  ['POST', '/api/log-discovery/sources/:id/poller/run-now', ADMIN_ONLY],

  // routes/exposure.ts: Digital Risk (readable by every role; configured by admins)
  ['GET', '/api/exposure/status', ANY_ROLE],
  ['GET', '/api/exposure/summary', ANY_ROLE],
  ['GET', '/api/exposure/settings', ANY_ROLE],
  ['PUT', '/api/exposure/settings', ADMIN_ONLY],
  ['GET', '/api/exposure/providers', ANY_ROLE],
  ['PUT', '/api/exposure/providers/hibp', ADMIN_ONLY],
  ['POST', '/api/exposure/providers/hibp/test', ADMIN_ONLY],
  ['GET', '/api/exposure/providers/hibp/verified-domains', ADMIN_ONLY],
  ['POST', '/api/exposure/providers/hibp/verified-domains/refresh', ADMIN_ONLY],
  ['GET', '/api/exposure/domains', ANY_ROLE],
  ['POST', '/api/exposure/domains', ADMIN_ONLY],
  ['PUT', '/api/exposure/domains/:id', ADMIN_ONLY],
  ['DELETE', '/api/exposure/domains/:id', ADMIN_ONLY],
  ['POST', '/api/exposure/domains/:id/run-now', ADMIN_ONLY],
  ['GET', '/api/exposure/identities', ANY_ROLE],
  ['POST', '/api/exposure/identities', ADMIN_ONLY],
  ['PUT', '/api/exposure/identities/:id', ADMIN_ONLY],
  ['DELETE', '/api/exposure/identities/:id', ADMIN_ONLY],
  ['GET', '/api/exposure/findings', ANY_ROLE],
  ['POST', '/api/exposure/findings/:id/resolve', ADMIN_ONLY],
  ['POST', '/api/exposure/run-now', ADMIN_ONLY],
  ['POST', '/api/exposure/password-check', ANY_ROLE],

  // routes/graph.ts: Context Graph (every role reads; services/graph/visibility.ts
  // decides what each role's graph holds, and the mirror test below keeps it
  // within these routes' roles)
  ['GET', '/api/graph/search', ANY_ROLE],
  ['GET', '/api/graph/neighborhood', ANY_ROLE],
  ['GET', '/api/graph/relation', ANY_ROLE],
  ['GET', '/api/graph/evidence', ANY_ROLE],

  // routes/display.ts: a wall screen's own read (its display link in X-Display-Token, never a login)
  ['GET', '/api/display/snapshot', DISPLAY],

  // routes/displayLinks.ts: Settings > Display links (admins create, configure and revoke)
  ['GET', '/api/display-links', ADMIN_ONLY],
  ['POST', '/api/display-links', ADMIN_ONLY],
  ['POST', '/api/display-links/preview', ADMIN_ONLY],
  ['GET', '/api/display-links/:id', ADMIN_ONLY],
  ['PUT', '/api/display-links/:id', ADMIN_ONLY],
  ['DELETE', '/api/display-links/:id', ADMIN_ONLY],
  ['POST', '/api/display-links/:id/rotate', ADMIN_ONLY],
  ['GET', '/api/display-links/:id/snapshot', ADMIN_ONLY],

  // routes/bigDisplay.ts: Big Display while signed in (endpoint health admin-only inside)
  ['GET', '/api/big-display/snapshot', ANY_ROLE],
];

/**
 * The only non-GET routes open to viewers. None changes anything shared: each
 * acts on the caller's own session or account, or computes an answer and stores
 * nothing. A new entry needs the same kind of reason.
 */
const VIEWER_SAFE_WRITES = new Set([
  'POST /api/auth/logout', // the caller's own session
  'PUT /api/auth/me/password', // the caller's own account
  'POST /api/auth/me/mfa/setup',
  'POST /api/auth/me/mfa/enable',
  'POST /api/auth/me/mfa/disable',
  'POST /api/parsers/:id/test', // runs a saved parser on a sample; stores nothing
  'POST /api/ai/explain', // explains what the caller can already see; stores nothing
  'POST /api/log-discovery/sources/:id/onboard/preview', // renders instructions; stores nothing
  'POST /api/exposure/password-check', // k-anonymity lookup; stores nothing
]);

/**
 * The only routes a session that must change its password may call
 * (middleware/auth.ts authenticateAllowingPasswordChange); every other route
 * that takes a login answers 403 PASSWORD_CHANGE_REQUIRED. A new entry needs a
 * reason it can't be used to get around the change.
 */
const PASSWORD_CHANGE_ALLOWED = new Set([
  'GET /api/auth/me', // the profile, with the reason
  'PUT /api/auth/me/password', // the change itself (current password required)
  'POST /api/auth/logout', // giving up
]);

// ---------------------------------------------------------------------------

const TOKENS = Object.fromEntries(ROLES.map((role) => [role, `route-inventory-session-${role}`])) as Record<Role, string>;
const USER_IDS = Object.fromEntries(ROLES.map((role, i) => [role, 900_001 + i])) as Record<Role, number>;
/** Sessions of accounts that must change their password (reason 'default'): an admin, and a viewer for one spot check. */
const RESTRICTED = {
  admin: { token: 'route-inventory-session-must-change', id: 900_101, role: 'admin' as Role },
  viewer: { token: 'route-inventory-session-must-change-viewer', id: 900_102, role: 'viewer' as Role },
};

// eslint-disable-next-line @typescript-eslint/no-explicit-any -- any Express middleware or handler
type Handler = (...args: any[]) => unknown;
interface Layer {
  name: string;
  handle: Handler & { stack?: Layer[]; resetKey?: unknown };
  method?: string;
  /** The path use() mounted it at, as recordMountPaths() saw it. */
  mountPath?: unknown;
  route?: { path: unknown; methods: Record<string, boolean>; stack: Layer[] };
}

/**
 * Express 5's router keeps no mount path on a use() layer, only a matcher
 * function, so record the path each router.use() / app.use() call was given on
 * the layers it adds. Installed when this file loads, before app.ts builds its
 * routers.
 */
function recordMountPaths(): void {
  type Use = (this: { stack: Layer[] }, ...args: unknown[]) => unknown;
  const proto = express.Router.prototype as { use: Use };
  const use = proto.use;
  proto.use = function (this: { stack: Layer[] }, ...args: unknown[]) {
    const before = this.stack.length;
    const result = use.apply(this, args);
    // As router.use() reads it: a leading non-function argument is the path.
    let first = args[0];
    while (Array.isArray(first) && first.length > 0) first = first[0];
    const path = typeof first === 'function' ? '/' : args[0];
    for (const layer of this.stack.slice(before)) layer.mountPath = path;
    return result;
  };
}
recordMountPaths();

/** One (method, path) the app serves, with its route layer. */
interface Served {
  id: string;
  method: string;
  path: string;
  route: NonNullable<Layer['route']>;
}

let server: Server | undefined;
let base = '';
let closePools: (() => Promise<void>) | undefined;
let served: Served[] = [];
/** Every router mount path, '' (the app itself) included. */
const mounts = new Set<string>(['']);
let swappedLimiters = 0;
const restoreLogger: Array<() => void> = [];
/** What this file reads back from a mock.method() stub. */
interface Recorder {
  mock: { callCount(): number; resetCalls(): void; calls: Array<{ arguments: unknown[] }> };
}
let poolQuery: Recorder | undefined;
let poolConnect: Recorder | undefined;
let auditLog: Recorder | undefined;
let errorLog: Recorder | undefined;
/** Every layer mounted with use() (app or router), as walkUseLayers() found them. */
let useLayers: Layer[] = [];

/** A local TCP port that nothing listens on (bound, then released). */
async function closedPort(): Promise<number> {
  const probe = net.createServer().listen(0, '127.0.0.1');
  await once(probe, 'listening');
  const { port } = probe.address() as AddressInfo;
  await new Promise<void>((resolve) => probe.close(() => resolve()));
  return port;
}

/** The path an app.use(path, ...) layer is mounted at ('' for a path-less one). */
function mountPathOf(layer: Layer): string {
  const path = layer.mountPath;
  if (path === '/') return '';
  assert.ok(
    typeof path === 'string' && /^(?:\/[\w.~-]+)+$/.test(path),
    `cannot read a mount path from ${String(path)}: teach mountPathOf() this form`
  );
  return path;
}

/**
 * Middleware mounted with app.use() or router.use() that only passes a request
 * on, or ends it with an error, so it needs no INVENTORY line: the address
 * tracker, CORS (net/cors.ts; it also answers every OPTIONS request itself, with
 * an empty 204), the body parsers and their {} default, the timeout logger, the
 * Cache-Control header on /api/auth (routes/auth.ts noStore), the login check,
 * the role gates (middleware/auth.ts authorize(), scanPermissions.ts
 * requireScanPermission()) and the closing 404 and error handlers. (Express 5
 * mounts no middleware of its own.) Rate limiters are recognized by their
 * resetKey(). walk() refuses any other non-route layer.
 */
const PASS_THROUGH = new Set([
  'ignoredForwardedForTracker',
  'corsHeaders',
  'jsonParser',
  'urlencodedParser',
  'emptyBodyDefault',
  'logClientTimeouts',
  'noStore',
  'authenticate',
  'authorizeRoles',
  'requireRole',
  'notFoundHandler',
  'bodyParserErrorHandler',
  'errorHandler',
]);

/** Where a layer is mounted, for an error message. */
function describeMount(layer: Layer, prefix: string): string {
  try {
    return prefix + mountPathOf(layer) || '/';
  } catch {
    return `${prefix} ${String(layer.mountPath)}`;
  }
}

/**
 * Every route under `stack`, with nested routers' mount paths prefixed. Each
 * router's mount path goes into `mounts`. Fails on a non-route layer that is
 * neither a router nor a known pass-through.
 */
function walk(stack: Layer[], prefix = '', mounts = new Set<string>()): Served[] {
  const out: Served[] = [];
  for (const layer of stack) {
    if (layer.route) {
      const { route } = layer;
      assert.equal(typeof route.path, 'string', `route paths are strings (got ${String(route.path)} under ${prefix})`);
      const path = prefix && route.path === '/' ? prefix : prefix + (route.path as string);
      for (const method of Object.keys(route.methods)) {
        assert.notEqual(method, '_all', `${path} uses router.all(): list each method instead`);
        out.push({ id: `${method.toUpperCase()} ${path}`, method: method.toUpperCase(), path, route });
      }
    } else if (layer.handle.stack) {
      const mount = prefix + mountPathOf(layer);
      mounts.add(mount);
      out.push(...walk(layer.handle.stack, mount, mounts));
    } else {
      assert.ok(
        PASS_THROUGH.has(layer.name) || typeof layer.handle.resetKey === 'function',
        `unclassified handler "${layer.name}" mounted with use() at ${describeMount(layer, prefix)}: it could answer ` +
          'requests INVENTORY does not list (a handler, a sub-app, express.static). Serve it as routes ' +
          '(router.get/post/...) and list them, or, if it only passes requests on, add its name to PASS_THROUGH'
      );
    }
  }
  return out;
}

/** Every non-route layer under `stack`, routers' own included: what use() mounted. */
function walkUseLayers(stack: Layer[]): Layer[] {
  return stack.flatMap((layer) => (layer.route ? [] : [layer, ...(layer.handle.stack ? walkUseLayers(layer.handle.stack) : [])]));
}

/** Every layer under `stack`: middleware, routers, routes and the layers inside routes. */
function allLayers(stack: Layer[]): Layer[] {
  return stack.flatMap((layer) => [
    layer,
    ...(layer.route ? layer.route.stack : []),
    ...(layer.handle.stack ? allLayers(layer.handle.stack) : []),
  ]);
}

before(async () => {
  const port = await closedPort();
  process.env.DB_HOST = '127.0.0.1';
  process.env.DB_PORT = String(port);
  const db = await import('../config/database');
  closePools = db.closePools;
  const { host, port: poolPort } = (db.default as unknown as { options: { host?: string; port?: number } }).options;
  assert.deepEqual({ host, port: poolPort }, { host: '127.0.0.1', port }, 'the pool must point at the closed port');
  const noSql = async () => {
    throw new Error('SQL must not run in routeInventory.test.ts');
  };
  poolQuery = mock.method(db.default, 'query', noSql) as unknown as Recorder;
  poolConnect = mock.method(db.default, 'connect', noSql) as unknown as Recorder;

  // 403s and 401s are logged at error level; keep this file's output readable.
  const { logger } = await import('../utils/logger');
  for (const transport of logger.transports) {
    const was = transport.silent;
    transport.silent = true;
    restoreLogger.push(() => (transport.silent = was));
  }

  const { AuditService } = await import('../services/audit/auditService');
  auditLog = mock.method(AuditService, 'log', async () => undefined) as unknown as Recorder;
  const { ErrorLogService } = await import('../services/errors/errorLogService');
  errorLog = mock.method(ErrorLogService, 'logError', async () => undefined) as unknown as Recorder;

  // One signed-in user per role: authenticate() looks the token's session and
  // user up together (SessionModel.findUserByToken). Plus the restricted
  // sessions, whose accounts must change their password. UserModel.findById
  // is what the routes that reload the caller read.
  const { SessionModel } = await import('../models/Session');
  const { UserModel } = await import('../models/User');
  const userOfToken = new Map<string, { id: number; role: Role; restricted: boolean }>([
    ...ROLES.map((role) => [TOKENS[role], { id: USER_IDS[role], role, restricted: false }] as const),
    ...Object.values(RESTRICTED).map(({ token, id, role }) => [token, { id, role, restricted: true }] as const),
  ]);
  const userOfId = new Map([...userOfToken.values()].map((user) => [user.id, user]));
  const userRow = (id: number) => {
    const user = userOfId.get(id);
    if (!user) return null;
    const name = `inventory-${user.role}${user.restricted ? '-must-change' : ''}`;
    return {
      id,
      username: name,
      email: `${name}@siembox.invalid`,
      role: user.role,
      enabled: true,
      must_change_password: user.restricted,
      must_change_password_reason: user.restricted ? 'default' : null,
      must_change_password_since: user.restricted ? new Date() : null,
    };
  };
  mock.method(SessionModel, 'findUserByToken', async (token: string) => {
    const user = userOfToken.get(token);
    return user ? userRow(user.id) : null;
  });
  mock.method(UserModel, 'findById', async (id: number) => userRow(id));
  // No EDR agent or shipper exists, so no key (a login's included) can pass.
  const { EdrAgentModel } = await import('../models/EdrAgent');
  mock.method(EdrAgentModel, 'findById', async () => null);
  const { LogShipperModel } = await import('../models/LogShipper');
  mock.method(LogShipperModel, 'findById', async () => null);
  // Three display links, found by the hash of their secret; recording a use does nothing.
  const { DisplayLinkModel } = await import('../models/DisplayLink');
  const { sha256hex } = await import('../models/EdrAgent');
  const displayLink = (id: number, fields: { enabled?: boolean; revoked_at?: Date | null }) => ({
    id,
    name: `inventory-display-${id}`,
    config: { views: [{ title: 'Inventory', panels: [{ id: 'open_alerts' }] }] },
    config_version: 1,
    enabled: fields.enabled ?? true,
    expires_at: null,
    revoked_at: fields.revoked_at ?? null,
    address_allowed: true,
  });
  const displayLinks = new Map([
    [sha256hex(DISPLAY_TOKENS.live), displayLink(1, {})],
    [sha256hex(DISPLAY_TOKENS.paused), displayLink(2, { enabled: false })],
    [sha256hex(DISPLAY_TOKENS.revoked), displayLink(3, { revoked_at: new Date(Date.now() - 1000) })],
  ]);
  mock.method(DisplayLinkModel, 'findForAuth', async (hash: string) => displayLinks.get(hash) ?? null);
  mock.method(DisplayLinkModel, 'touch', async () => false);
  mock.method(DisplayLinkModel, 'touchLastUsed', async () => undefined);
  mock.method(DisplayLinkModel, 'trimClients', async () => 0);

  const app = (await import('../app')).default;
  const stack = (app.router as unknown as { stack?: Layer[] }).stack;
  assert.ok(stack, 'Express internals changed (no app.router.stack): update walk() and mountPathOf()');
  served = walk(stack, '', mounts);
  useLayers = walkUseLayers(stack);

  // Each route's handler (its method's last layer) answers with the route it belongs to.
  for (const { id, method, route } of served) {
    const own = route.stack.filter((l) => l.method === undefined || l.method === method.toLowerCase());
    own[own.length - 1].handle = (_req: unknown, res: { status(code: number): { json(body: unknown): void } }) =>
      res.status(200).json({ reached: id });
  }
  for (const layer of allLayers(stack)) {
    if (typeof layer.handle.resetKey === 'function') {
      layer.handle = (_req: unknown, _res: unknown, next: () => void) => next();
      swappedLimiters++;
    }
  }

  server = app.listen(0, '127.0.0.1');
  await once(server, 'listening');
  base = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

after(async () => {
  if (server) await new Promise<void>((resolve) => server!.close(() => resolve()));
  await closePools?.();
  for (const restore of restoreLogger) restore();
});

interface Outcome {
  status: number;
  /** The route whose (stub) handler answered, if one did. */
  reached?: string;
  message?: string;
  code?: string;
  reason?: string | null;
}

async function call(method: string, path: string, headers: Record<string, string> = {}): Promise<Outcome> {
  const res = await fetch(base + path, {
    method,
    headers: { 'Content-Type': 'application/json', ...headers },
    body: method === 'GET' ? undefined : '{}',
  });
  // API errors are { status: 'error', statusCode, message } (middleware/errorHandler.ts),
  // plus code and reason for PASSWORD_CHANGE_REQUIRED (middleware/auth.ts).
  const json = (await res.json().catch(() => null)) as Omit<Outcome, 'status'> | null;
  return { status: res.status, reached: json?.reached, message: json?.message, code: json?.code, reason: json?.reason };
}

/** Display link secrets the stubbed DisplayLinkModel.findForAuth knows: live, paused and revoked. */
const DISPLAY_TOKENS = { live: 'sbd1_' + 'L'.repeat(43), paused: 'sbd1_' + 'P'.repeat(43), revoked: 'sbd1_' + 'R'.repeat(43) };
/** Well formed, and no link has it. */
const UNKNOWN_DISPLAY_TOKEN = 'sbd1_' + 'U'.repeat(43);

const asRole = (role: Role) => ({ Authorization: `Bearer ${TOKENS[role]}` });
/** A session whose account must change its password. */
const asRestricted = (who: keyof typeof RESTRICTED = 'admin') => ({ Authorization: `Bearer ${RESTRICTED[who].token}` });
/** A route's path with every :param filled in. */
const urlOf = (path: string) => path.replace(/:\w+/g, '1');

function describeWho(who: Who): string {
  if (who === PUBLIC) return 'no login';
  if (who === AGENT) return 'agent key, never a login';
  if (who === DISPLAY) return 'display link token, never a login';
  return who === ANY_ROLE ? 'any role' : who.join(', ');
}

test('the inventory lists every route the app serves, and nothing else', () => {
  const listed = INVENTORY.map(([method, path]) => `${method} ${path}`);
  assert.deepEqual(
    listed.filter((id, i) => listed.indexOf(id) !== i),
    [],
    'each route is listed once'
  );
  const servedIds = served.map((s) => s.id);
  assert.deepEqual(
    servedIds.filter((id, i) => servedIds.indexOf(id) !== i),
    [],
    'no route is declared twice (the second would never run)'
  );
  assert.deepEqual(
    servedIds.filter((id) => !listed.includes(id)),
    [],
    'routes the app serves that INVENTORY does not classify: add one line each, with the roles that may call it'
  );
  assert.deepEqual(
    listed.filter((id) => !servedIds.includes(id)),
    [],
    'routes INVENTORY lists that the app no longer serves: remove their lines'
  );
});

test('walk() refuses whatever use() mounts that is not a router or a known pass-through', () => {
  const handler = (_req: unknown, res: { json(body: unknown): void }) => res.json({});
  const inRouter = express.Router();
  inRouter.use('/dummy-mw', handler);
  const subApp = express();
  subApp.post('/purge', handler);
  const withSubApp = express();
  withSubApp.use('/api/dummy-subapp', subApp);
  const withStatic = express();
  withStatic.use('/api/dummy-static', express.static('/nonexistent'));
  const stackOf = (app: Application) => app.router.stack as unknown as Layer[];
  for (const [what, stack] of [
    ['router.use() of a handler', inRouter.stack as unknown as Layer[]],
    ['a mounted sub-app', stackOf(withSubApp)],
    ['express.static', stackOf(withStatic)],
  ] as const) {
    assert.throws(() => walk(stack), /unclassified handler/, what);
  }

  // Routers, gates, body parsers and limiters are fine.
  const fine = express.Router();
  fine.use(express.json());
  const nested = express.Router();
  nested.get('/x', handler);
  fine.use('/nested', nested);
  assert.deepEqual(
    walk(fine.stack as unknown as Layer[], '/api/fine').map((s) => s.id),
    ['GET /api/fine/nested/x']
  );
});

test('a path no route declares, under every mount and with every method, reaches the not-found handler', async () => {
  // Deeper than any route, so no :param route matches it; an admin passes every gate.
  const unlisted = '/__inventory_unlisted__'.repeat(6);
  for (const mount of mounts) {
    for (const method of ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']) {
      const url = mount + unlisted;
      const outcome = await call(method, url, asRole('admin'));
      assert.deepEqual(
        { status: outcome.status, reached: outcome.reached, message: outcome.message },
        { status: 404, reached: undefined, message: `Route ${url} not found` },
        `${method} ${url}: something mounted under ${mount || '/'} answered a path no route declares`
      );
    }
  }
  assert.ok(mounts.size > 20, `found ${mounts.size} router mounts`);
});

test('viewers are read-only: every non-GET route open to them is a known safe one', () => {
  const viewerWrites = INVENTORY.filter(([method, , who]) => method !== 'GET' && Array.isArray(who) && who.includes('viewer')).map(
    ([method, path]) => `${method} ${path}`
  );
  assert.deepEqual(viewerWrites.filter((id) => !VIEWER_SAFE_WRITES.has(id)), [], 'writes a viewer may call');
  assert.deepEqual([...VIEWER_SAFE_WRITES].filter((id) => !viewerWrites.includes(id)), [], 'stale VIEWER_SAFE_WRITES entries');
});

test('every PASSWORD_CHANGE_ALLOWED entry is a route that takes a login', () => {
  const sessionRoutes = INVENTORY.filter(([, , who]) => Array.isArray(who)).map(([method, path]) => `${method} ${path}`);
  assert.deepEqual([...PASSWORD_CHANGE_ALLOWED].filter((id) => !sessionRoutes.includes(id)), [], 'stale PASSWORD_CHANGE_ALLOWED entries');
});

test('the gate that lets a restricted session through sits on exactly the PASSWORD_CHANGE_ALLOWED routes', () => {
  const gate = 'authenticateAllowingPasswordChange';
  const gated = served
    .filter(({ method, route }) =>
      route.stack.some((layer) => (layer.method === undefined || layer.method === method.toLowerCase()) && layer.name === gate)
    )
    .map(({ id }) => id)
    .sort();
  assert.deepEqual(gated, [...PASSWORD_CHANGE_ALLOWED].sort());
  assert.ok(useLayers.length > 20, `found ${useLayers.length} use() layers`);
  assert.deepEqual(
    useLayers.filter((layer) => layer.name === gate).map((layer) => String(layer.mountPath)),
    [],
    `${gate} is never mounted with use(): it would open every route under the mount to a restricted session`
  );
});

test('a restricted session is refused before any role gate: a viewer on an admin-only route gets PASSWORD_CHANGE_REQUIRED', async () => {
  for (const [method, path] of [
    ['GET', '/api/users'],
    ['POST', '/api/auth/cleanup'],
    ['GET', '/api/admin/sign-in-protection'],
  ] as const) {
    auditLog!.mock.resetCalls();
    const outcome = await call(method, path, asRestricted('viewer'));
    assert.deepEqual(
      { status: outcome.status, code: outcome.code, reason: outcome.reason, reached: outcome.reached },
      { status: 403, code: 'PASSWORD_CHANGE_REQUIRED', reason: 'default', reached: undefined },
      `${method} ${path}`
    );
    assert.equal(auditLog!.mock.callCount(), 0, 'no access.denied row: the role gate never ran');
  }
  // The routes it may call let the viewer through too.
  for (const id of PASSWORD_CHANGE_ALLOWED) {
    const [method, path] = id.split(' ');
    assert.equal((await call(method, path, asRestricted('viewer'))).reached, id);
  }
});

test('the Context Graph shows a role nothing the routes it mirrors refuse that role', async () => {
  // services/graph/visibility.ts names, for each node type (and for account
  // details), the routes whose data it carries; each must be listed here and
  // admit every role the graph shows it to.
  const { NODE_VISIBILITY } = await import('../services/graph/visibility');
  const whoOf = new Map(INVENTORY.map(([method, path, who]) => [`${method} ${path}`, who]));
  const subjects = Object.entries(NODE_VISIBILITY);
  assert.ok(subjects.length >= 15, `found ${subjects.length} visibility entries`);
  for (const [subject, entry] of subjects) {
    assert.ok(entry.mirrors.length > 0, `${subject}: name the routes it mirrors`);
    for (const id of entry.mirrors) {
      const who = whoOf.get(id);
      assert.ok(who !== undefined, `${subject} mirrors ${id}, which INVENTORY does not list`);
      assert.ok(Array.isArray(who), `${subject} mirrors ${id}, which takes no login`);
      for (const role of entry.roles) {
        assert.ok(who.includes(role), `the graph shows ${subject} to ${role}, but ${id} refuses ${role}`);
      }
    }
  }
  // The graph's own routes are open to every role that sees anything in it.
  for (const path of ['/api/graph/search', '/api/graph/neighborhood', '/api/graph/relation']) {
    assert.deepEqual(whoOf.get(`GET ${path}`), ANY_ROLE, path);
  }
});

test('display links show only what every role can read', async () => {
  // services/display/panels.ts names, for each panel kind, the routes whose
  // data it mirrors. A kind a display link may hold (minRole 'viewer') must
  // mirror only routes every signed-in role reads; any other kind must be
  // refused in a link's config. So a panel backed by an admin-only route can't
  // reach a wall screen without failing here.
  const { PANEL_KINDS } = await import('../services/display/panels');
  const { parseDisplayConfig } = await import('../services/display/config');
  const whoOf = new Map(INVENTORY.map(([method, path, who]) => [`${method} ${path}`, who]));
  const kinds = Object.values(PANEL_KINDS);
  assert.ok(kinds.length >= 12, `found ${kinds.length} panel kinds`);
  for (const kind of kinds) {
    assert.ok(kind.viewerRoutes.length > 0, `${kind.id}: name the routes it mirrors`);
    for (const id of kind.viewerRoutes) assert.ok(whoOf.has(id), `${kind.id} mirrors ${id}, which INVENTORY does not list`);
    const linkConfig = { views: [{ title: 'T', panels: [{ id: kind.id }] }] };
    if (kind.minRole === 'viewer') {
      for (const id of kind.viewerRoutes) assert.deepEqual(whoOf.get(id), ANY_ROLE, `${kind.id} is allowed on display links but mirrors ${id}`);
      assert.equal(parseDisplayConfig(linkConfig).ok, true, `${kind.id}: allowed in a link config`);
    } else {
      assert.equal(parseDisplayConfig(linkConfig).ok, false, `${kind.id} (minRole ${kind.minRole}) must be refused in a link config`);
      assert.equal(parseDisplayConfig(linkConfig, { forLink: false }).ok, true, `${kind.id}: allowed on the signed-in board`);
    }
  }
});

test('the rate limiters were found and set aside', () => {
  // The general /api limiter at least; scan, agent and log-push routes have their own.
  assert.ok(swappedLimiters >= 1, 'no express-rate-limit middleware found: did the way limiters are recognized change?');
});

for (const [method, path, who, audited = false] of INVENTORY) {
  const id = `${method} ${path}`;
  const url = urlOf(path);

  test(`${id}: ${describeWho(who)}`, async () => {
    if (who === PUBLIC) {
      assert.equal((await call(method, url)).reached, id, 'reachable without a login');
      assert.equal((await call(method, url, asRestricted())).reached, id, 'and with a session that must change its password');
      return;
    }

    if (who === DISPLAY) {
      // The display link's gate answers, never the login check; refusals are
      // neither audited nor written to application_errors.
      auditLog!.mock.resetCalls();
      errorLog!.mock.resetCalls();
      const anonymous = await call(method, url);
      assert.deepEqual(
        { status: anonymous.status, code: anonymous.code, reached: anonymous.reached },
        { status: 401, code: 'DISPLAY_TOKEN_REQUIRED', reached: undefined },
        'without a display token'
      );
      assert.notEqual(anonymous.message, 'Authentication required', 'does not ask for a login');
      const invalid = await call(method, url, { 'X-Display-Token': 'not-a-display-token' });
      assert.deepEqual({ status: invalid.status, code: invalid.code, reached: invalid.reached }, { status: 401, code: 'DISPLAY_LINK_INVALID', reached: undefined });
      const unknown = await call(method, url, { 'X-Display-Token': UNKNOWN_DISPLAY_TOKEN });
      assert.deepEqual({ status: unknown.status, code: unknown.code, reached: unknown.reached }, { status: 401, code: 'DISPLAY_LINK_INVALID', reached: undefined });

      // A login neither unlocks a display route nor is refused by role: every
      // role's session, and both restricted ones, get exactly what no token
      // (as Authorization) or a wrong one (as X-Display-Token) gets.
      const sessions = [
        ...ROLES.map((role) => [role, TOKENS[role]] as const),
        ...Object.entries(RESTRICTED).map(([who, { token }]) => [`restricted ${who}`, token] as const),
      ];
      for (const [name, token] of sessions) {
        const asBearer = await call(method, url, { Authorization: `Bearer ${token}` });
        assert.deepEqual({ status: asBearer.status, reached: asBearer.reached }, { status: anonymous.status, reached: undefined }, `${name}'s session as Authorization`);
        assert.equal(asBearer.code, 'DISPLAY_TOKEN_REQUIRED');
        const asDisplay = await call(method, url, { 'X-Display-Token': token });
        assert.deepEqual({ status: asDisplay.status, reached: asDisplay.reached }, { status: invalid.status, reached: undefined }, `${name}'s session as X-Display-Token`);
        assert.equal(asDisplay.code, 'DISPLAY_LINK_INVALID');
      }

      assert.equal((await call(method, url, { 'X-Display-Token': DISPLAY_TOKENS.live })).reached, id, 'a live display link gets through');
      const paused = await call(method, url, { 'X-Display-Token': DISPLAY_TOKENS.paused });
      assert.deepEqual({ status: paused.status, code: paused.code, reached: paused.reached }, { status: 403, code: 'DISPLAY_LINK_PAUSED', reached: undefined });
      const revoked = await call(method, url, { 'X-Display-Token': DISPLAY_TOKENS.revoked });
      assert.deepEqual({ status: revoked.status, code: revoked.code, reached: revoked.reached }, { status: 401, code: 'DISPLAY_LINK_REVOKED', reached: undefined });
      assert.equal(auditLog!.mock.callCount(), 0, 'no refusal is audited');
      assert.equal(errorLog!.mock.callCount(), 0, 'no refusal writes an application_errors row');
      return;
    }

    if (who === AGENT) {
      // No login gate in front: without credentials the route's own check answers.
      const anonymous = await call(method, url);
      assert.notEqual(anonymous.message, 'Authentication required', 'does not ask for a login');
      assert.notEqual(anonymous.status, 403);
      // A login is no agent key: with the agent headers, a session token gets
      // exactly what any other non-key token gets, whatever the role.
      const agentHeaders = { 'X-Agent-ID': '1', 'X-Shipper-ID': '1' };
      const stranger = await call(method, url, { ...agentHeaders, Authorization: 'Bearer not-an-agent-key' });
      assert.notEqual(stranger.status, 403);
      for (const role of ROLES) {
        const withLogin = await call(method, url, { ...agentHeaders, ...asRole(role) });
        assert.deepEqual(
          { status: withLogin.status, reached: withLogin.reached },
          { status: stranger.status, reached: stranger.reached },
          `${role}'s session neither unlocks nor is refused by role`
        );
      }
      // Agent keys are not sessions: a session that must change its password
      // changes nothing here either.
      const restricted = await call(method, url, { ...agentHeaders, ...asRestricted() });
      assert.deepEqual(
        { status: restricted.status, reached: restricted.reached, code: restricted.code },
        { status: stranger.status, reached: stranger.reached, code: stranger.code },
        'a restricted session neither unlocks nor is refused'
      );
      return;
    }

    const anonymous = await call(method, url);
    assert.equal(anonymous.status, 401, 'needs a login');
    assert.equal(anonymous.message, 'Authentication required');

    // A session whose account must change its password: only the allowed
    // routes; everything else, present or added later, is refused before any
    // role gate, with nothing written to audit_logs or application_errors.
    auditLog!.mock.resetCalls();
    errorLog!.mock.resetCalls();
    const restricted = await call(method, url, asRestricted());
    if (PASSWORD_CHANGE_ALLOWED.has(id)) {
      assert.equal(restricted.reached, id, `a restricted session may call this route (status ${restricted.status})`);
    } else {
      assert.deepEqual(
        { status: restricted.status, code: restricted.code, reason: restricted.reason, reached: restricted.reached },
        { status: 403, code: 'PASSWORD_CHANGE_REQUIRED', reason: 'default', reached: undefined },
        'a restricted session is refused with PASSWORD_CHANGE_REQUIRED'
      );
      assert.equal(auditLog!.mock.callCount(), 0, 'the refusal is not audited');
      assert.equal(errorLog!.mock.callCount(), 0, 'the refusal writes no application_errors row');
    }

    for (const role of ROLES) {
      auditLog!.mock.resetCalls();
      const outcome = await call(method, url, asRole(role));
      if (who.includes(role)) {
        assert.equal(outcome.reached, id, `${role} gets through to this route's handler (status ${outcome.status}: ${outcome.message ?? ''})`);
        assert.equal(auditLog!.mock.callCount(), 0, `${role}: nothing is audited when the gates pass`);
        continue;
      }
      assert.equal(outcome.status, 403, `${role} is refused with 403`);
      assert.equal(outcome.reached, undefined);
      if (!audited) {
        assert.equal(auditLog!.mock.callCount(), 0, `${role}: this gate does not audit (mark the line AUDITED if it now does)`);
        continue;
      }
      assert.equal(auditLog!.mock.callCount(), 1, `${role}: the refusal is written to the audit log`);
      const [entry] = auditLog!.mock.calls[0].arguments as unknown as [
        { action: string; userId: number; responseStatus: number; details: { userRole: string; method: string } },
      ];
      assert.equal(entry.action, 'access.denied');
      assert.equal(entry.userId, USER_IDS[role]);
      assert.equal(entry.responseStatus, 403);
      assert.equal(entry.details.userRole, role);
      assert.equal(entry.details.method, method);
    }
  });
}

test('a display token is never a login: no route that takes a session, or an agent key, accepts one', async () => {
  const valid = DISPLAY_TOKENS.live;
  const agentHeaders = { 'X-Agent-ID': '1', 'X-Shipper-ID': '1' };
  let checked = 0;
  for (const [method, path, who] of INVENTORY) {
    if (who === DISPLAY) continue;
    const id = `${method} ${path}`;
    const url = urlOf(path);
    if (who === PUBLIC) {
      assert.equal((await call(method, url, { 'X-Display-Token': valid })).reached, id, `${id}: still reachable`);
      continue;
    }
    if (who === AGENT) {
      // Exactly what a stranger's credentials get.
      const plain = await call(method, url, agentHeaders);
      const withDisplay = await call(method, url, { ...agentHeaders, 'X-Display-Token': valid });
      assert.deepEqual({ status: withDisplay.status, reached: withDisplay.reached }, { status: plain.status, reached: plain.reached }, `${id}: X-Display-Token`);
      const stranger = await call(method, url, { ...agentHeaders, Authorization: 'Bearer not-an-agent-key' });
      const asBearer = await call(method, url, { ...agentHeaders, Authorization: `Bearer ${valid}` });
      assert.deepEqual({ status: asBearer.status, reached: asBearer.reached }, { status: stranger.status, reached: stranger.reached }, `${id}: as Bearer`);
      continue;
    }
    const asHeader = await call(method, url, { 'X-Display-Token': valid });
    assert.deepEqual(
      { status: asHeader.status, message: asHeader.message, reached: asHeader.reached },
      { status: 401, message: 'Authentication required', reached: undefined },
      `${id}: X-Display-Token is not a login`
    );
    const asBearer = await call(method, url, { Authorization: `Bearer ${valid}` });
    assert.deepEqual(
      { status: asBearer.status, message: asBearer.message, reached: asBearer.reached },
      { status: 401, message: 'Invalid or expired session', reached: undefined },
      `${id}: a display token as Bearer is no session`
    );
    checked++;
  }
  assert.ok(checked > 200, `checked ${checked} routes that take a login`);
});

// Keep last: proves the file stayed hermetic.
test('nothing in this file reached the database', () => {
  assert.equal(poolQuery!.mock.callCount(), 0, 'no query may run');
  assert.equal(poolConnect!.mock.callCount(), 0, 'no connection may be opened');
});
