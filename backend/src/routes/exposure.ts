/**
 * Exposure monitoring ("Digital Risk") API — mounted at /api/exposure behind
 * `authenticate`. Reads are open to any authenticated user; every write is
 * admin-only.
 *
 * Privacy: the HIBP API key is write-only (stored encrypted, never echoed), and
 * POST /password-check never logs or persists the password — the body is
 * dropped from the request as soon as it is read, the check is k-anonymous
 * (only 5 hex chars of a SHA-1 leave the server), and a strict per-IP rate
 * limit keeps the endpoint from becoming a password oracle.
 */
import { Router, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import { ApiError } from '../middleware/errorHandler';
import { authorize } from '../middleware/auth';
import { listRecurringJobs } from '../services/jobs/jobRegistry';
import {
  DEFAULT_COLLECTORS,
  ExposureFindingModel,
  MonitoredIdentityModel,
  WatchedDomainModel,
  getExposureCounts,
  type DomainCollectors,
  type DomainScope,
  type ExposureFindingSource,
  type ExposureSeverity,
} from '../models/Exposure';
import {
  EXPIRY_WARNING_DAYS_RANGE,
  HIBP_API_KEY_RE,
  LOOKALIKE_CANDIDATES_RANGE,
  getExposureSettings,
  getHibpApiKey,
  getHibpProviderPublic,
  isExposureSeverity,
  isValidResolverSetting,
  saveHibpProvider,
  updateExposureSettings,
  type ExposureSettings,
} from '../services/exposure/settings';
import {
  DOMAIN_MONITOR_JOB_KEY,
  getDomainMonitorRunState,
  runDomainNow,
} from '../services/exposure/domainMonitor/domainMonitorService';
import {
  isIdentityKind,
  normalizeDomain,
  normalizeIdentityValue,
} from '../services/exposure/validation';
import {
  LEAKED_CREDS_ALREADY_RUNNING,
  LEAKED_CREDS_JOB_KEY,
  MANUAL_RUN_BUDGET_MS,
  getLeakedCredentialRunState,
  resetLeakedCredentialPause,
  runLeakedCredentialChecks,
} from '../services/exposure/leakedCredentialService';
import { HibpClient, HibpError } from '../services/exposure/hibpClient';
import { checkPassword, type PwnedPasswordResult } from '../services/exposure/pwnedPasswords';

const router = Router();
const adminOnly = authorize('admin');

const MIN_INTERVAL_MINUTES = 60;
const MAX_INTERVAL_MINUTES = 43_200; // 30 days
const MAX_PASSWORD_LENGTH = 1024;
const MAX_EXPECTED_CAS = 50;
const FINDING_SOURCES: readonly ExposureFindingSource[] = ['leaked-creds', 'domain-monitor'];
const MAX_INT4 = 2_147_483_647;

// The k-anonymity check is stateless, but uncapped it would let any account
// use this server as a high-volume password oracle (and lean on the free
// Pwned Passwords API). Per client IP, with no admin exemption.
const passwordCheckLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  handler: (_req, res) => {
    res.status(429).json({
      status: 'error',
      statusCode: 429,
      message: 'Too many password checks from this address; try again in a few minutes.',
    });
  },
});

// ---- Input helpers -----------------------------------------------------------

function bodyOf(req: Request): Record<string, unknown> {
  const body = req.body;
  return body !== null && typeof body === 'object' && !Array.isArray(body) ? body : {};
}

function parseId(raw: string, what: string, max = MAX_INT4): number {
  const id = /^\d{1,16}$/.test(raw) ? Number(raw) : NaN;
  if (!Number.isSafeInteger(id) || id < 1 || id > max)
    throw new ApiError(400, `Invalid ${what} id`);
  return id;
}

function optionalBoolean(body: Record<string, unknown>, field: string): boolean | undefined {
  const value = body[field];
  if (value === undefined) return undefined;
  if (typeof value !== 'boolean') throw new ApiError(400, `${field} must be true or false`);
  return value;
}

function optionalIntInRange(
  body: Record<string, unknown>,
  field: string,
  range: { min: number; max: number }
): number | undefined {
  const value = body[field];
  if (value === undefined) return undefined;
  if (
    typeof value !== 'number' ||
    !Number.isInteger(value) ||
    value < range.min ||
    value > range.max
  ) {
    throw new ApiError(
      400,
      `${field} must be a whole number between ${range.min} and ${range.max}`
    );
  }
  return value;
}

function optionalInterval(body: Record<string, unknown>): number | undefined {
  const value = body.interval_minutes;
  if (value === undefined) return undefined;
  if (
    typeof value !== 'number' ||
    !Number.isInteger(value) ||
    value < MIN_INTERVAL_MINUTES ||
    value > MAX_INTERVAL_MINUTES
  ) {
    throw new ApiError(
      400,
      `interval_minutes must be a whole number between ${MIN_INTERVAL_MINUTES} and ${MAX_INTERVAL_MINUTES}`
    );
  }
  return value;
}

function parseScope(value: unknown): DomainScope {
  if (value !== 'own' && value !== 'brand')
    throw new ApiError(400, "scope must be 'own' or 'brand'");
  return value;
}

function parseCollectors(value: unknown, base: DomainCollectors): DomainCollectors {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new ApiError(400, 'collectors must be an object such as {"ct": true, "dns": false}');
  }
  const out: DomainCollectors = { ...base };
  for (const [key, enabled] of Object.entries(value)) {
    if (!Object.prototype.hasOwnProperty.call(DEFAULT_COLLECTORS, key)) {
      throw new ApiError(
        400,
        `collectors may only contain: ${Object.keys(DEFAULT_COLLECTORS).join(', ')}`
      );
    }
    if (typeof enabled !== 'boolean')
      throw new ApiError(400, `collectors.${key} must be true or false`);
    out[key as keyof DomainCollectors] = enabled;
  }
  return out;
}

function parseExpectedCas(value: unknown): string[] {
  if (!Array.isArray(value) || value.length > MAX_EXPECTED_CAS) {
    throw new ApiError(
      400,
      `expected_cas must be an array of at most ${MAX_EXPECTED_CAS} CA names`
    );
  }
  const out: string[] = [];
  for (const item of value) {
    const name = typeof item === 'string' ? item.trim() : '';
    if (!name || name.length > 200)
      throw new ApiError(400, 'each expected_cas entry must be 1-200 characters');
    if (!out.includes(name)) out.push(name);
  }
  return out;
}

function isUniqueViolation(err: unknown): boolean {
  return (err as { code?: unknown } | null)?.code === '23505';
}

// ---- Status & settings ---------------------------------------------------------

type RecurringJobView = ReturnType<typeof listRecurringJobs>[number];

function jobView(job: RecurringJobView | undefined) {
  return job
    ? {
        status: job.status,
        last_run_at: job.lastRunAt,
        last_result: job.lastResult,
        last_error: job.lastError,
        next_run_at: job.nextRunAt,
      }
    : null;
}

router.get('/status', async (_req: Request, res: Response) => {
  const [settings, hibp, counts] = await Promise.all([
    getExposureSettings(),
    getHibpProviderPublic(),
    getExposureCounts(),
  ]);
  const jobs = listRecurringJobs();
  res.json({
    features: {
      leaked_creds_enabled: settings.exposure_leaked_creds_enabled,
      password_check_available: true,
      domain_monitor_available: true,
      domain_monitor_enabled: settings.exposure_domain_monitor_enabled,
    },
    notifications: {
      enabled: settings.notify_exposure_enabled,
      min_severity: settings.notify_exposure_min_severity,
    },
    providers: [hibp],
    counts,
    leaked_creds: {
      ...getLeakedCredentialRunState(),
      job: jobView(jobs.find((j) => j.key === LEAKED_CREDS_JOB_KEY)),
    },
    domain_monitor: {
      ...getDomainMonitorRunState(),
      job: jobView(jobs.find((j) => j.key === DOMAIN_MONITOR_JOB_KEY)),
    },
  });
});

router.get('/settings', async (_req: Request, res: Response) => {
  res.json(await getExposureSettings());
});

router.put('/settings', adminOnly, async (req: Request, res: Response) => {
  const body = bodyOf(req);
  const update: Partial<ExposureSettings> = {
    notify_exposure_enabled: optionalBoolean(body, 'notify_exposure_enabled'),
    exposure_leaked_creds_enabled: optionalBoolean(body, 'exposure_leaked_creds_enabled'),
    exposure_domain_monitor_enabled: optionalBoolean(body, 'exposure_domain_monitor_enabled'),
    exposure_domain_expiry_warning_days: optionalIntInRange(
      body,
      'exposure_domain_expiry_warning_days',
      EXPIRY_WARNING_DAYS_RANGE
    ),
    exposure_lookalike_max_candidates: optionalIntInRange(
      body,
      'exposure_lookalike_max_candidates',
      LOOKALIKE_CANDIDATES_RANGE
    ),
  };
  if (body.exposure_dns_secondary_resolver !== undefined) {
    const resolver =
      typeof body.exposure_dns_secondary_resolver === 'string'
        ? body.exposure_dns_secondary_resolver.trim()
        : null;
    if (resolver === null || !isValidResolverSetting(resolver)) {
      throw new ApiError(
        400,
        'exposure_dns_secondary_resolver must be "" (off) or an IPv4/IPv6 address such as 9.9.9.9'
      );
    }
    update.exposure_dns_secondary_resolver = resolver;
  }
  if (body.notify_exposure_min_severity !== undefined) {
    if (!isExposureSeverity(body.notify_exposure_min_severity)) {
      throw new ApiError(
        400,
        'notify_exposure_min_severity must be one of: low, medium, high, critical'
      );
    }
    update.notify_exposure_min_severity = body.notify_exposure_min_severity;
  }
  res.json(await updateExposureSettings(update));
});

// ---- Providers (bring-your-own-key) --------------------------------------------

router.get('/providers', async (_req: Request, res: Response) => {
  res.json([await getHibpProviderPublic()]);
});

// Save the HIBP key (encrypted at rest; '' or null clears it) and/or enable it.
// The key is write-only: the response is the public view, never the key.
router.put('/providers/hibp', adminOnly, async (req: Request, res: Response) => {
  const body = bodyOf(req);
  let apiKey: string | null | undefined;
  if (body.api_key === null) apiKey = null;
  else if (body.api_key !== undefined) {
    if (typeof body.api_key !== 'string') throw new ApiError(400, 'api_key must be a string');
    apiKey = body.api_key.trim();
    if (apiKey !== '' && !HIBP_API_KEY_RE.test(apiKey)) {
      throw new ApiError(400, 'api_key must be a 32-character hexadecimal HIBP API key');
    }
  }
  const enabled = optionalBoolean(body, 'enabled');

  try {
    await saveHibpProvider({ apiKey, enabled });
  } catch (error) {
    const message = error instanceof Error ? error.message : '';
    if (message.includes('CREDENTIAL_ENCRYPTION_KEY')) {
      throw new ApiError(
        400,
        'Set a valid CREDENTIAL_ENCRYPTION_KEY (64 hex characters, e.g. `openssl rand -hex 32`) to store an API key.'
      );
    }
    throw new ApiError(500, 'Failed to save the HIBP provider settings');
  }
  // A new key (or re-enabling) deserves a fresh start: lift any rate-limit or
  // rejected-key pause and re-read the plan's rate limit.
  resetLeakedCredentialPause();
  res.json(await getHibpProviderPublic());
});

// Validate a key with HIBP's cheapest call (subscription/status): the key in
// the body if given (test before saving), else the stored one.
router.post('/providers/hibp/test', adminOnly, async (req: Request, res: Response) => {
  const raw = bodyOf(req).api_key;
  if (raw !== undefined && raw !== null && typeof raw !== 'string') {
    throw new ApiError(400, 'api_key must be a string');
  }
  let apiKey = typeof raw === 'string' ? raw.trim() : '';
  if (apiKey !== '') {
    if (!HIBP_API_KEY_RE.test(apiKey)) {
      throw new ApiError(400, 'api_key must be a 32-character hexadecimal HIBP API key');
    }
  } else {
    apiKey = (await getHibpApiKey()) ?? '';
    if (!apiKey) throw new ApiError(400, 'No usable HIBP API key is saved; enter one to test it.');
  }

  try {
    const status = await new HibpClient({ apiKey }).subscriptionStatus();
    res.json({
      ok: true,
      subscription: {
        name: status.SubscriptionName ?? null,
        description: status.Description ?? null,
        subscribed_until: status.SubscribedUntil ?? null,
        rpm: typeof status.Rpm === 'number' ? status.Rpm : null,
        domain_search_max_breached_accounts: status.DomainSearchMaxBreachedAccounts ?? null,
        includes_stealer_logs: status.IncludesStealerLogs ?? null,
      },
    });
  } catch (error) {
    if (!(error instanceof HibpError)) throw error;
    if (error.kind === 'rate_limited')
      throw new ApiError(429, `HIBP key test failed: ${error.message}`);
    if (error.kind === 'transient')
      throw new ApiError(502, `HIBP key test failed: ${error.message}`);
    throw new ApiError(400, `HIBP key test failed: ${error.message}`);
  }
});

// ---- Watched domains ---------------------------------------------------------------

router.get('/domains', async (_req: Request, res: Response) => {
  res.json(await WatchedDomainModel.findAll());
});

router.post('/domains', adminOnly, async (req: Request, res: Response) => {
  const body = bodyOf(req);
  const domain = normalizeDomain(body.domain);
  if (!domain.ok) throw new ApiError(400, domain.error);
  const input = {
    domain: domain.value,
    scope: body.scope === undefined ? ('own' as const) : parseScope(body.scope),
    enabled: optionalBoolean(body, 'enabled'),
    interval_minutes: optionalInterval(body),
    collectors:
      body.collectors === undefined
        ? undefined
        : parseCollectors(body.collectors, DEFAULT_COLLECTORS),
    expected_cas: body.expected_cas === undefined ? undefined : parseExpectedCas(body.expected_cas),
  };
  try {
    res.status(201).json(await WatchedDomainModel.create(input));
  } catch (error) {
    if (isUniqueViolation(error))
      throw new ApiError(409, `${domain.value} is already being watched`);
    throw error;
  }
});

router.put('/domains/:id', adminOnly, async (req: Request, res: Response) => {
  const id = parseId(req.params.id, 'domain');
  const body = bodyOf(req);
  if (body.domain !== undefined) {
    throw new ApiError(400, 'The domain itself cannot be changed; delete it and add the new one');
  }
  const existing = await WatchedDomainModel.findById(id);
  if (!existing) throw new ApiError(404, 'Watched domain not found');
  const updated = await WatchedDomainModel.update(id, {
    scope: body.scope === undefined ? undefined : parseScope(body.scope),
    enabled: optionalBoolean(body, 'enabled'),
    interval_minutes: optionalInterval(body),
    collectors:
      body.collectors === undefined
        ? undefined
        : parseCollectors(body.collectors, existing.collectors),
    expected_cas: body.expected_cas === undefined ? undefined : parseExpectedCas(body.expected_cas),
  });
  if (!updated) throw new ApiError(404, 'Watched domain not found');
  res.json(updated);
});

router.delete('/domains/:id', adminOnly, async (req: Request, res: Response) => {
  const id = parseId(req.params.id, 'domain');
  if (!(await WatchedDomainModel.delete(id))) throw new ApiError(404, 'Watched domain not found');
  res.json({ message: 'Watched domain deleted' });
});

// Run this domain's collectors now, whatever its schedule (also when the domain
// is switched off). Each collector has its own timeouts; allow a few minutes.
router.post('/domains/:id/run-now', adminOnly, async (req: Request, res: Response) => {
  const id = parseId(req.params.id, 'domain');
  const result = await runDomainNow(id);
  if (result.kind === 'not_found') throw new ApiError(404, 'Watched domain not found');
  if (result.kind === 'busy') {
    throw new ApiError(409, 'This domain is already being checked; try again shortly');
  }
  if (result.kind === 'disabled') {
    throw new ApiError(
      409,
      'Domain monitoring is disabled in settings; enable exposure_domain_monitor_enabled to run checks'
    );
  }
  res.json(result.summary);
});

// ---- Monitored identities ----------------------------------------------------------

router.get('/identities', async (_req: Request, res: Response) => {
  res.json(await MonitoredIdentityModel.findAll());
});

router.post('/identities', adminOnly, async (req: Request, res: Response) => {
  const body = bodyOf(req);
  if (!isIdentityKind(body.kind)) throw new ApiError(400, "kind must be 'email' or 'email_domain'");
  const value = normalizeIdentityValue(body.kind, body.value);
  if (!value.ok) throw new ApiError(400, value.error);
  const input = {
    kind: body.kind,
    value: value.value,
    enabled: optionalBoolean(body, 'enabled'),
    interval_minutes: optionalInterval(body),
  };
  try {
    res.status(201).json(await MonitoredIdentityModel.create(input));
  } catch (error) {
    if (isUniqueViolation(error))
      throw new ApiError(409, `${value.value} is already being monitored`);
    throw error;
  }
});

router.put('/identities/:id', adminOnly, async (req: Request, res: Response) => {
  const id = parseId(req.params.id, 'identity');
  const body = bodyOf(req);
  if (body.kind !== undefined || body.value !== undefined) {
    throw new ApiError(
      400,
      'kind and value cannot be changed; delete the identity and add the new one'
    );
  }
  const updated = await MonitoredIdentityModel.update(id, {
    enabled: optionalBoolean(body, 'enabled'),
    interval_minutes: optionalInterval(body),
  });
  if (!updated) throw new ApiError(404, 'Monitored identity not found');
  res.json(updated);
});

router.delete('/identities/:id', adminOnly, async (req: Request, res: Response) => {
  const id = parseId(req.params.id, 'identity');
  if (!(await MonitoredIdentityModel.delete(id)))
    throw new ApiError(404, 'Monitored identity not found');
  res.json({ message: 'Monitored identity deleted' });
});

// ---- Findings -------------------------------------------------------------------------

function queryInt(value: unknown, fallback: number, min: number, max: number): number {
  if (typeof value !== 'string' || value === '') return fallback;
  const n = Number(value);
  if (!Number.isInteger(n)) throw new ApiError(400, 'limit and offset must be whole numbers');
  return Math.min(Math.max(n, min), max);
}

router.get('/findings', async (req: Request, res: Response) => {
  const q = req.query;
  const source = typeof q.source === 'string' && q.source !== '' ? q.source : undefined;
  if (source !== undefined && !(FINDING_SOURCES as readonly string[]).includes(source)) {
    throw new ApiError(400, `source must be one of: ${FINDING_SOURCES.join(', ')}`);
  }
  const severity = typeof q.severity === 'string' && q.severity !== '' ? q.severity : undefined;
  if (severity !== undefined && !isExposureSeverity(severity)) {
    throw new ApiError(400, 'severity must be one of: low, medium, high, critical');
  }
  const limit = queryInt(q.limit, 50, 1, 200);
  const offset = queryInt(q.offset, 0, 0, 1_000_000);
  const result = await ExposureFindingModel.list({
    source: source as ExposureFindingSource | undefined,
    severity: severity as ExposureSeverity | undefined,
    unresolved: q.unresolved === 'true' || q.unresolved === '1',
    identityId: typeof q.identity_id === 'string' ? parseId(q.identity_id, 'identity') : undefined,
    domainId: typeof q.domain_id === 'string' ? parseId(q.domain_id, 'domain') : undefined,
    limit,
    offset,
  });
  res.json({ ...result, limit, offset });
});

router.post('/findings/:id/resolve', adminOnly, async (req: Request, res: Response) => {
  const id = parseId(req.params.id, 'finding', Number.MAX_SAFE_INTEGER);
  const finding = await ExposureFindingModel.resolve(id);
  if (!finding) throw new ApiError(404, 'Finding not found');
  res.json(finding);
});

// ---- Leaked-credential checks -----------------------------------------------------

// Run the check now instead of waiting for the job. Due identities only, unless
// {"force": true}, which re-checks every enabled identity. Bounded to ~90 s of
// work (HIBP calls are paced to the key's plan); anything left over stays due
// for the scheduled job, and `remaining` says how many.
router.post('/run-now', adminOnly, async (req: Request, res: Response) => {
  const force = optionalBoolean(bodyOf(req), 'force') ?? false;
  const summary = await runLeakedCredentialChecks({
    trigger: 'manual',
    force,
    budgetMs: MANUAL_RUN_BUDGET_MS,
  });
  if (summary.skipped && summary.reason === LEAKED_CREDS_ALREADY_RUNNING) {
    throw new ApiError(409, 'A leaked-credential check is already running; try again shortly');
  }
  res.json(summary);
});

// Stateless k-anonymity check of one password against Pwned Passwords.
router.post('/password-check', passwordCheckLimiter, async (req: Request, res: Response) => {
  const password: unknown = bodyOf(req).password;
  // Drop the body as soon as it's read so nothing downstream — the error
  // handler included — can ever see the password.
  req.body = {};
  if (typeof password !== 'string' || password.length === 0)
    throw new ApiError(400, 'password is required');
  if (password.length > MAX_PASSWORD_LENGTH) {
    throw new ApiError(400, `password must be at most ${MAX_PASSWORD_LENGTH} characters`);
  }

  let result: PwnedPasswordResult;
  try {
    result = await checkPassword(password);
  } catch {
    throw new ApiError(502, 'The Pwned Passwords service could not be reached; try again shortly');
  }
  res.set('Cache-Control', 'no-store');
  res.json(result);
});

export default router;
