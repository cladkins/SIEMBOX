/**
 * The live ingest path's bound on a backtracking regex (linearFallback.ts): with
 * V8's linear-time fallback on, a parser whose pattern backtracks for seconds on
 * a crafted line answers in milliseconds, on the main thread, with the same
 * result; a linear pattern on a long line never leaves the backtracking engine;
 * and the gate can ask which regexes the fallback covers. The matching cases run
 * in a child process (V8 flags are process-wide, and a child whose fallback does
 * not work is stopped by spawnSync's timeout instead of stalling the test run).
 * DB-free; `npm test` (CI and the images run Node 22). The Node 20 branches
 * cover a custom build on older Node, whose fallback engine differs.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import * as path from 'node:path';
import {
  enableLinearRegexFallback,
  LINEAR_FALLBACK_BACKTRACKS,
  LINEAR_FALLBACK_V8_FLAG,
  LINEAR_FALLBACK_V8_FLAGS,
  linearFallbackCovers,
  linearFallbackObstacle,
  linearFallbackWanted,
} from './linearFallback';

/** Ten groups of eight identical alternatives: 8^10 backtracking steps (about 14 s) on ATTACK. */
const PATTERN = `^(?<x>${'(?:a|a|a|a|a|a|a|a)'.repeat(10)})$`;
const ATTACK = 'a'.repeat(10) + '!';
/** Linear (the gate rates it safe), but it backtracks about once per character of a line. */
const LINEAR = '^(?<prefix>.*?)?user=(?<user>\\S+)';

/**
 * Run `body` in a fresh Node process that can import the backend's .ts modules.
 * `body` sees `fallback` (linearFallback.ts) and `runParser` (parser/runParser.ts)
 * and prints one JSON line.
 */
function child(body: string, env: Record<string, string> = {}, timeoutMs = 8000, execArgv: string[] = []) {
  const script = [
    `require(${JSON.stringify(require.resolve('tsx/cjs'))});`,
    `const fallback = require(${JSON.stringify(path.join(__dirname, 'linearFallback.ts'))});`,
    `const { runParser } = require(${JSON.stringify(path.join(__dirname, '..', 'parser', 'runParser.ts'))});`,
    body,
  ].join('\n');
  const r = spawnSync(process.execPath, [...execArgv, '-e', script], {
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
    const set: string[] = [];
    assert.equal(linearFallbackWanted({ REGEX_LINEAR_FALLBACK: off }), false, off);
    assert.equal(enableLinearRegexFallback({ REGEX_LINEAR_FALLBACK: off }, (f) => set.push(f)), false, off);
    assert.deepEqual(set, [], `${off}: no V8 flag is set`);
  }
  for (const on of [undefined, '', 'true', '1', 'on', 'yes']) {
    const set: string[] = [];
    assert.equal(linearFallbackWanted({ REGEX_LINEAR_FALLBACK: on }), true, String(on));
    assert.equal(enableLinearRegexFallback({ REGEX_LINEAR_FALLBACK: on }, (f) => set.push(f)), true, String(on));
    assert.deepEqual(set, [...LINEAR_FALLBACK_V8_FLAGS]);
  }
  // The fallback, and a threshold well above V8's default of 50,000 backtracks.
  assert.deepEqual(LINEAR_FALLBACK_V8_FLAGS, [LINEAR_FALLBACK_V8_FLAG, '--regexp-backtracks-before-fallback=1000000']);
  assert.equal(LINEAR_FALLBACK_BACKTRACKS, 1_000_000);
});

test('a linear pattern on a long line never takes the fallback, so it keeps the fast engine and its exact result', () => {
  // ^(?<prefix>.*?)?user=(?<user>\S+) backtracks about once per character. With
  // V8's default threshold (50,000) a 250 KB TCP line went to the linear engine:
  // about 35 times slower (73-80 ms against 2 ms), and on Node 20 that engine
  // set `prefix` to "" where the backtracking engine leaves it unset. V8 prints
  // one "Experimental execution" line per fallback run with this trace flag.
  const r = child(
    `
    fallback.enableLinearRegexFallback();
    const parser = { name: 'p', parser_type: 'regex', pattern: ${JSON.stringify(LINEAR)}, field_mappings: { prefix: 'context', user: 'user' } };
    const long = runParser(parser, 'user=alice ' + 'x'.repeat(250000), {});
    console.log('--- linear done');
    const crafted = runParser({ ...parser, pattern: ${JSON.stringify(PATTERN)}, field_mappings: { x: 'user' } }, ${JSON.stringify(ATTACK)}, {});
    console.log(JSON.stringify({ long: long && long.fields, crafted }));
  `,
    {},
    8000,
    ['--trace-experimental-regexp-engine']
  );
  assert.equal(r.timedOut, false, r.stderr);
  assert.equal(r.status, 0, r.stderr);
  const lines = r.stdout.trim().split('\n');
  const split = lines.indexOf('--- linear done');
  assert.ok(split >= 0, r.stdout);
  const fellBack = (part: string[]) => part.filter((l) => l.startsWith('Experimental execution')).length;
  assert.equal(fellBack(lines.slice(0, split)), 0, `the linear pattern took the fallback:\n${lines.slice(0, split).join('\n')}`);
  assert.ok(fellBack(lines.slice(split)) >= 1, 'the crafted line still takes it');
  const out = JSON.parse(lines[lines.length - 1]);
  assert.equal(out.long.user, 'alice');
  assert.equal('context' in out.long, false, 'an unmatched optional group stays unset (no "" from the linear engine)');
  assert.equal(out.crafted, null);
});

test('linearFallbackCovers asks V8 which regexes its linear engine can run', () => {
  // Coverage depends on the syntax, not on whether the regex is catastrophic,
  // so harmless shapes stand in for the dangerous ones.
  // Inside: no flags or m/s, \b, lazy and greedy quantifiers, counted repeats up to 16.
  for (const [source, flags] of [
    ['^a+$', ''],
    ['^(?<x>\\S+) \\d{1,16}\\b.*?$', 'ms'],
    ['^a+\\u{1}$', ''],
  ]) {
    assert.equal(linearFallbackCovers(source, flags), true, `/${source}/${flags}`);
  }
  // Outside: the i and u flags, lookahead, backreferences, a counted repeat over 16.
  for (const [source, flags] of [
    ['^a+$', 'i'],
    ['^a+$', 'u'],
    ['^(?=a)a+$', ''],
    ['^(?!b)a+$', ''],
    ['^(a)\\1$', ''],
    ['^(?<x>a)\\k<x>$', ''],
    ['^a{1,17}$', ''],
    ['^a+\\u{17}$', ''],
  ]) {
    assert.equal(linearFallbackCovers(source, flags), false, `/${source}/${flags}`);
  }
  // Lookbehind: inside on Node 22 (the images' runtime), outside on Node 20 (a custom build on older Node).
  const node20 = Number(process.versions.node.split('.')[0]) < 22;
  assert.equal(linearFallbackCovers('(?<=user=)\\S+', ''), !node20);
  if (node20) assert.match(linearFallbackObstacle('(?<=user=)\\S+', ''), /lookbehind, on Node 20\./);

  // With the fallback off, nothing is covered, and the gate is told why.
  const off = { REGEX_LINEAR_FALLBACK: 'false' };
  assert.equal(linearFallbackCovers('^a+$', '', off), false);
  assert.equal(linearFallbackObstacle('^a+$', '', off), "V8's linear-time fallback is off (REGEX_LINEAR_FALLBACK=false)");
  assert.equal(
    linearFallbackObstacle('^a+$', 'i'),
    "V8's linear-time fallback cannot run it (the i flag, which every derivation `matches` has)"
  );
});
