/**
 * GET/PUT /api/settings/ai-budgets and the triage bounds on PUT /ai-triage,
 * through the real route handlers, against an in-memory system_settings table
 * (the database pool is mocked: no Postgres needed). Role gates are covered by
 * settingsRouteGates.test.ts and routeInventory.test.ts. `npm test` (tsx --test).
 */
import { test, mock, beforeEach } from 'node:test';
import assert from 'node:assert/strict';
import pool from '../config/database';
import { ApiError } from '../middleware/errorHandler';
import settingsRouter from './settings';
import { getTriageOperationalConfig } from '../services/ai/aiService';

/** The in-memory system_settings table. */
const rows = new Map<string, string>();

function runSql(text: string, params: any[] = []): { rows: any[]; rowCount: number } {
  const sql = text.replace(/\s+/g, ' ').trim();
  if (/^(BEGIN|COMMIT|ROLLBACK)$/.test(sql) || sql.startsWith('SELECT pg_advisory_xact_lock')) {
    return { rows: [], rowCount: 0 };
  }
  if (sql.startsWith('SELECT key, value FROM system_settings WHERE key = ANY($1)')) {
    const keys: string[] = params[0];
    const out = keys.filter((k) => rows.has(k)).map((k) => ({ key: k, value: rows.get(k)! }));
    return { rows: out, rowCount: out.length };
  }
  if (sql.startsWith('SELECT value FROM system_settings WHERE key = $1')) {
    return rows.has(params[0]) ? { rows: [{ value: rows.get(params[0]) }], rowCount: 1 } : { rows: [], rowCount: 0 };
  }
  if (sql.startsWith('INSERT INTO system_settings (key, value) VALUES ($1, $2) ON CONFLICT (key) DO UPDATE')) {
    rows.set(params[0], params[1]);
    return { rows: [], rowCount: 1 };
  }
  if (sql.startsWith('DELETE FROM system_settings WHERE key = $1')) {
    const had = rows.delete(params[0]);
    return { rows: [], rowCount: had ? 1 : 0 };
  }
  throw new Error(`unexpected SQL in aiBudgetsRoute.test.ts: ${sql}`);
}

mock.method(pool, 'query', async (text: string, params?: any[]) => runSql(text, params));
mock.method(pool, 'connect', async () => ({
  query: async (text: string, params?: any[]) => runSql(text, params),
  release: () => undefined,
}));

beforeEach(() => rows.clear());

type Handler = (req: unknown, res: unknown, next: (err?: unknown) => void) => unknown;
interface StackLayer {
  handle: Handler;
  route?: { path: string; methods: Record<string, boolean>; stack: StackLayer[] };
}

/** Call a settings route's own handler (behind its gates) as an admin. */
async function call(method: 'get' | 'put', path: string, body?: unknown): Promise<{ status: number; json: any }> {
  const layer = ((settingsRouter as unknown as { stack: StackLayer[] }).stack).find(
    (l) => l.route && l.route.path === path && l.route.methods[method]
  );
  assert.ok(layer?.route, `route ${method} ${path} exists`);
  const handler = layer.route.stack[layer.route.stack.length - 1].handle;
  let json: any;
  const res = {
    statusCode: 200,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(v: unknown) {
      json = v;
      return this;
    },
  };
  const req = { user: { id: 1, role: 'admin' }, method: method.toUpperCase(), path, headers: {}, params: {}, query: {}, body };
  try {
    await handler(req, res, (err?: unknown) => {
      if (err) throw err;
    });
    return { status: res.statusCode, json };
  } catch (e) {
    if (e instanceof ApiError) return { status: e.statusCode, json: { message: e.message } };
    throw e;
  }
}

test('GET: a fresh install reports the defaults and every bound', async () => {
  const r = await call('get', '/ai-budgets');
  assert.equal(r.status, 200);
  assert.deepEqual(r.json.budgets.analyst, {
    answerMaxTokens: 4000,
    stepMaxTokens: 1500,
    maxToolCalls: 10,
    wallBudgetSeconds: 180,
  });
  assert.deepEqual(r.json.budgets.triage, {
    answerMaxTokens: 3000,
    stepMaxTokens: 1500,
    maxToolCalls: 6,
    wallBudgetSeconds: 110,
  });
  assert.deepEqual(r.json.budgets.builder, { maxTokens: 8000 });
  assert.deepEqual(r.json.bounds.analyst.wallBudgetSeconds, { min: 30, max: 240, default: 180 });
  assert.deepEqual(r.json.bounds.builder.maxTokens, { min: 256, max: 32000, default: 8000 });
});

test('GET: an install that saved the AI Triage form keeps its tool-call and time budgets', async () => {
  rows.set('ai_triage_max_tool_calls', '8');
  rows.set('ai_triage_wall_budget_seconds', '150');
  const r = await call('get', '/ai-budgets');
  assert.equal(r.json.budgets.triage.maxToolCalls, 8);
  assert.equal(r.json.budgets.triage.wallBudgetSeconds, 150);
  assert.equal(r.json.budgets.triage.answerMaxTokens, 3000, 'the new budgets start at their defaults');
});

test('PUT: valid values are stored and answered back; a value equal to its default stores no row', async () => {
  const r = await call('put', '/ai-budgets', {
    analyst: { answerMaxTokens: 12000, stepMaxTokens: 2000, maxToolCalls: 15, wallBudgetSeconds: 240 },
    triage: { answerMaxTokens: 3000, maxToolCalls: 12 },
    builder: { maxTokens: 16000 },
  });
  assert.equal(r.status, 200, JSON.stringify(r.json));
  assert.deepEqual(r.json.budgets.analyst, {
    answerMaxTokens: 12000,
    stepMaxTokens: 2000,
    maxToolCalls: 15,
    wallBudgetSeconds: 240,
  });
  assert.equal(r.json.budgets.builder.maxTokens, 16000);
  assert.equal(rows.get('ai_chat_answer_max_output'), '12000');
  assert.equal(rows.get('ai_triage_max_tool_calls'), '12');
  assert.equal(rows.has('ai_triage_answer_max_output'), false, 'a default value follows the default');

  // The triage queue reads the same rows.
  const op = await getTriageOperationalConfig();
  assert.equal(op.maxToolCalls, 12);
  assert.equal(op.answerMaxTokens, 3000);

  // Setting a value back to its default removes its row.
  await call('put', '/ai-budgets', { analyst: { answerMaxTokens: 4000 } });
  assert.equal(rows.has('ai_chat_answer_max_output'), false);
});

test('PUT: out-of-bounds or malformed values are a 400 and nothing is saved', async () => {
  for (const body of [
    { analyst: { answerMaxTokens: 100 } },
    { analyst: { answerMaxTokens: 50000 } },
    { analyst: { maxToolCalls: 26 } },
    { analyst: { wallBudgetSeconds: 600 } },
    { analyst: { wallBudgetSeconds: 10 } },
    { triage: { stepMaxTokens: '2000' } },
    { builder: { maxTokens: 8000.5 } },
    { nope: {} },
    // One bad field refuses the whole body.
    { analyst: { answerMaxTokens: 6000 }, builder: { maxTokens: 1 } },
  ]) {
    const r = await call('put', '/ai-budgets', body);
    assert.equal(r.status, 400, JSON.stringify(body));
    assert.equal(rows.size, 0, `nothing was saved for ${JSON.stringify(body)}`);
  }
  const r = await call('put', '/ai-budgets', { analyst: { wallBudgetSeconds: 241 } });
  assert.match(r.json.message, /analyst\.wallBudgetSeconds \(AI Analyst time budget\) must be a whole number between 30 and 240/);
});

test('PUT /ai-triage: tool calls now go up to 25 (was 12), same bounds as the budgets page', async () => {
  const ok = await call('put', '/ai-triage', { maxToolCalls: 20 });
  assert.equal(ok.status, 200, JSON.stringify(ok.json));
  assert.equal(rows.get('ai_triage_max_tool_calls'), '20');
  assert.equal(ok.json.maxToolCalls, 20);

  const bad = await call('put', '/ai-triage', { maxToolCalls: 26 });
  assert.equal(bad.status, 400);
  assert.match(bad.json.message, /maxToolCalls must be between 1 and 25/);
  const badWall = await call('put', '/ai-triage', { wallBudgetSeconds: 281 });
  assert.equal(badWall.status, 400);
});
