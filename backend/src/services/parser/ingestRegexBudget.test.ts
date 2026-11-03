/**
 * The ingest path's per-line regex budget: a flagged parser runs in a worker
 * and is cut off at the budget; a slow unflagged parser is demoted after
 * repeated overruns; a normal parser keeps the inline fast path. Uses the
 * legacy vaultwarden-access pattern that migration 007 used to write on every
 * startup (polynomial, degree 2). DB-free; `npm test`.
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'fs';
import * as path from 'path';
import { IngestRegexGuard, SLOW_RUNS_BEFORE_DEMOTION, type ParserLike } from './ingestRegexBudget';
import { runParser } from './runParser';
import { assessRegexes, closeRegexScanPool, setVerdictStore } from '../regex/regexSafety';

setVerdictStore(null);

/** The vaultwarden-access pattern migration 007 shipped (and re-wrote on every start until this fix). */
const LEGACY_VAULTWARDEN =
  '^\\[(?<timestamp>\\d{4}-\\d{2}-\\d{2}[ T]\\d{2}:\\d{2}:\\d{2}(?:\\.\\d{1,9})?)\\]\\[(?<module>[^\\]]+)\\]\\[(?<log_level>\\w+)\\]\\s+(?<message>.*?)(?:\\s+for\\s+(?<user_email>[^\\s,.]+))?(?:\\s+by\\s+(?<admin_email>\\S+)\\s+from\\s+(?<admin_ip>\\d{1,3}(?:\\.\\d{1,3}){3})|(?:[.,]?\\s+(?:from\\s+)?(?:IP:\\s*)?(?<client_ip>\\d{1,3}(?:\\.\\d{1,3}){3})))?(?:[.,]?\\s+(?:Email|Username):\\s*(?<login_email>[^\\s,]+?)\\.?)?(?:,\\s+Device:\\s+(?<device>[^,]+))?\\.?\\s*$';

/** recheck's attack string for that pattern: about 2 s inline at this size. */
const attack = (n: number) => '[0000-00-00T00:00:00][\n][f]\n,' + '\t'.repeat(n) + 's';

function parser(id: number, pattern: string): ParserLike {
  return { id, name: `p${id}`, parser_type: 'regex', pattern, field_mappings: {}, derivations: null, event_type: null };
}

const guards: IngestRegexGuard[] = [];
function guard(opts: ConstructorParameters<typeof IngestRegexGuard>[0]): IngestRegexGuard {
  const g = new IngestRegexGuard(opts);
  guards.push(g);
  return g;
}
after(async () => {
  await Promise.all(guards.map((g) => g.close()));
  await closeRegexScanPool();
});

test('the legacy migration-007 pattern is vulnerable; the catalog vaultwarden-access pattern is not', { timeout: 120_000 }, async () => {
  const legacy = await assessRegexes([{ location: 'pattern', source: LEGACY_VAULTWARDEN, flags: '' }]);
  assert.equal(legacy.vulnerable.length, 1, 'legacy pattern flagged');
  const catalog = JSON.parse(
    fs.readFileSync(path.join(__dirname, '..', '..', '..', '..', 'catalog', 'parsers', 'vaultwarden-access.parser.json'), 'utf8')
  );
  const current = await assessRegexes([{ location: 'pattern', source: catalog.pattern, flags: '' }]);
  assert.equal(current.vulnerable.length, 0, 'catalog pattern is linear');
});

test('migration 007 no longer rewrites the vaultwarden-access pattern on startup', () => {
  const sql = fs.readFileSync(path.join(__dirname, '..', '..', '..', 'migrations', '007_fix_vaultwarden_parser.sql'), 'utf8');
  const statements = sql.replace(/--.*$/gm, '').trim();
  assert.doesNotMatch(statements, /\bUPDATE\b/i);
});

test('a flagged parser runs in a worker and is cut off at the budget', { timeout: 60_000 }, async () => {
  const g = guard({ budgetMs: 100, isFlagged: () => true });
  const p = parser(122, LEGACY_VAULTWARDEN);
  // Warm the worker so its start-up time is not counted against the line.
  assert.equal(await g.run(p, 'warm-up', {}), null);
  const t0 = Date.now();
  const result = await g.run(p, attack(20000), {});
  const elapsed = Date.now() - t0;
  assert.equal(result, null, 'over budget counts as no match');
  assert.ok(elapsed < 1500, `returned after ${elapsed} ms, not the ~2 s the match needs`);
  assert.equal(g.stats().timeouts, 1);
  // A normal line still parses on the bounded path.
  const ok = await g.run(p, '[2024-01-15 12:00:00][vaultwarden::api::identity][ERROR] Username or password is incorrect. Try again. IP: 1.2.3.4.', {});
  assert.ok(ok, 'normal line matches');
});

test('the event loop keeps running while a flagged parser chews on a hostile line', { timeout: 60_000 }, async () => {
  const g = guard({ budgetMs: 200, isFlagged: () => true });
  const p = parser(1, LEGACY_VAULTWARDEN);
  await g.run(p, 'warm-up', {});
  let ticks = 0;
  const timer = setInterval(() => ticks++, 10);
  await g.run(p, attack(20000), {});
  clearInterval(timer);
  assert.ok(ticks >= 5, `only ${ticks} timer ticks ran during the match`);
});

test('an unflagged parser that overruns the budget repeatedly is demoted to the worker', { timeout: 60_000 }, async () => {
  const g = guard({ budgetMs: 5, isFlagged: () => false });
  const p = parser(7, LEGACY_VAULTWARDEN);
  for (let i = 0; i < SLOW_RUNS_BEFORE_DEMOTION; i++) await g.run(p, attack(4000), {});
  assert.deepEqual(g.stats().boundedParsers, [7]);
  assert.equal(g.stats().slowInline, SLOW_RUNS_BEFORE_DEMOTION);
});

test('a normal parser stays inline and matches exactly like runParser', async () => {
  const g = guard({ budgetMs: 100, isFlagged: () => false });
  const p = parser(3, '^(?<user>\\w+) logged in from (?<source_ip>\\S+)$');
  const line = 'alice logged in from 203.0.113.5';
  assert.deepEqual(await g.run(p, line, {}), runParser(p, line, {}));
  assert.deepEqual(g.stats().boundedParsers, []);
});

test('a pending verdict is looked up again; reset() forgets routes', async () => {
  let verdict: boolean | null = null;
  const g = guard({ budgetMs: 100, isFlagged: () => verdict });
  const p = parser(9, '^x$');
  await g.run(p, 'x', {});
  assert.deepEqual(g.stats().boundedParsers, []);
  verdict = true;
  await g.run(p, 'x', {});
  assert.deepEqual(g.stats().boundedParsers, [9]);
  g.reset();
  verdict = false;
  await g.run(p, 'x', {});
  assert.deepEqual(g.stats().boundedParsers, []);
});
