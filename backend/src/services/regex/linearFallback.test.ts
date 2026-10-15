/**
 * The live ingest path's bound on a backtracking regex (linearFallback.ts): with
 * V8's linear-time fallback on, a parser whose pattern backtracks for seconds on
 * a crafted line answers in milliseconds, on the main thread, with the same
 * result. Each case runs in a child process (V8 flags are process-wide, and a
 * child without the fallback is stopped by spawnSync's timeout instead of
 * stalling the test run). DB-free; `npm test`.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as path from 'node:path';
import { enableLinearRegexFallback, linearFallbackWanted } from './linearFallback';

/** Ten groups of eight identical alternatives: 8^10 backtracking steps (about 14 s) on ATTACK. */
const PATTERN = `^(?<x>${'(?:a|a|a|a|a|a|a|a)'.repeat(10)})$`;
const ATTACK = 'a'.repeat(10) + '!';

/**
 * Run `body` in a fresh Node process that can import the backend's .ts modules.
 * `body` sees `fallback` (linearFallback.ts) and `runParser` (parser/runParser.ts)
 * and prints one JSON line.
 */
function child(body: string, env: Record<string, string> = {}, timeoutMs = 8000) {
  const script = [
    `require(${JSON.stringify(require.resolve('tsx/cjs'))});`,
    `const fallback = require(${JSON.stringify(path.join(__dirname, 'linearFallback.ts'))});`,
    `const { runParser } = require(${JSON.stringify(path.join(__dirname, '..', 'parser', 'runParser.ts'))});`,
    body,
  ].join('\n');
  const r = spawnSync(process.execPath, ['-e', script], {
    encoding: 'utf8',
    timeout: timeoutMs,
    env: { ...process.env, ...env, LOG_LEVEL: 'error' },
  });
  return { timedOut: r.error !== undefined || r.signal !== null, stdout: r.stdout, stderr: r.stderr, status: r.status };
}

test('with the fallback on, a parser pattern that backtracks for seconds answers in milliseconds on the main thread', () => {
  const r = child(`
    const on = fallback.enableLinearRegexFallback();
    const parser = { name: 'p', parser_type: 'regex', pattern: ${JSON.stringify(PATTERN)}, field_mappings: { x: 'user' } };
    const started = Date.now();
    const miss = runParser(parser, ${JSON.stringify(ATTACK)}, {});
    const ms = Date.now() - started;
    const hit = runParser(parser, 'a'.repeat(10), {});
    console.log(JSON.stringify({ on, ms, miss, hit: hit && hit.fields }));
  `);
  assert.equal(r.timedOut, false, `the match was not bounded (the child ran past 8 s)\n${r.stderr}`);
  assert.equal(r.status, 0, r.stderr);
  const out = JSON.parse(r.stdout.trim().split('\n').pop()!);
  assert.equal(out.on, true);
  assert.ok(out.ms < 1000, `a crafted line took ${out.ms} ms`);
  assert.equal(out.miss, null, 'same result as the backtracking engine: no match');
  assert.equal(out.hit?.user, 'a'.repeat(10), 'and a matching line still parses');
});

test('REGEX_LINEAR_FALLBACK=false leaves V8 alone; anything else turns the fallback on', () => {
  for (const off of ['false', 'FALSE', '0', 'off', 'no', ' false ']) {
    assert.equal(linearFallbackWanted({ REGEX_LINEAR_FALLBACK: off }), false, off);
    assert.equal(enableLinearRegexFallback({ REGEX_LINEAR_FALLBACK: off }), false, off);
  }
  for (const on of [undefined, '', 'true', '1', 'on', 'yes']) {
    assert.equal(linearFallbackWanted({ REGEX_LINEAR_FALLBACK: on }), true, String(on));
  }
  // Without the fallback the same match backtracks: the child is still in it when it is stopped.
  const r = child(
    `console.log('on=' + fallback.enableLinearRegexFallback());
     const started = Date.now();
     runParser({ name: 'p', parser_type: 'regex', pattern: ${JSON.stringify(PATTERN)}, field_mappings: {} }, ${JSON.stringify(ATTACK)}, {});
     console.log('finished in ' + (Date.now() - started) + ' ms');`,
    { REGEX_LINEAR_FALLBACK: 'false' },
    4000
  );
  assert.match(r.stdout, /^on=false$/m, `the child started: ${r.stderr}`);
  assert.equal(r.timedOut, true, `expected the unbounded match to outlive the child, got: ${r.stdout}`);
  assert.doesNotMatch(r.stdout, /finished/);
});
