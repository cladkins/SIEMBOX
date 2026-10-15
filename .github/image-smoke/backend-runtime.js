// Runtime checks for the backend image, run inside the built image by
// .github/workflows/image-check.yml:
//
//   docker run --rm -v "$PWD/.github/image-smoke:/smoke:ro" <image> node /smoke/backend-runtime.js <check>
//
// Modules resolve from the working directory (the image's /app), so the checks
// exercise the image's own node_modules and dist/. Each check prints what it saw
// and exits non-zero on a failure. Locally: `cd backend && npm run build`, then
// `node ../.github/image-smoke/backend-runtime.js <check>`.
'use strict';

const assert = require('node:assert/strict');
const { createRequire } = require('node:module');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const appDir = process.cwd();
const appRequire = createRequire(path.join(appDir, 'package.json'));

const checks = {
  node() {
    const libc = process.report.getReport().header.glibcVersionRuntime;
    console.log(
      `node ${process.version} (V8 ${process.versions.v8}, ${process.platform}/${process.arch}, ${libc ? `glibc ${libc}` : 'musl'})`
    );
    assert.equal(Number(process.versions.node.split('.')[0]), 22, 'the image runs Node 22');
  },

  async bcrypt() {
    const bcrypt = appRequire('bcrypt');
    const hash = bcrypt.hashSync('correct horse battery staple', 10);
    assert.match(hash, /^\$2b\$10\$/);
    assert.equal(bcrypt.compareSync('correct horse battery staple', hash), true);
    assert.equal(bcrypt.compareSync('wrong password', hash), false);
    // The async API runs on libuv's thread pool, as the sign-in path does.
    const asyncHash = await bcrypt.hash('another password', 10);
    assert.equal(await bcrypt.compare('another password', asyncHash), true);
    assert.equal(await bcrypt.compare('correct horse battery staple', asyncHash), false);
    console.log(
      `bcrypt ok: hash ${hash.slice(0, 7)}..., compare true for the password and false otherwise (sync and async)`
    );
  },

  recheck() {
    const backend = process.env.RECHECK_BACKEND || 'auto';
    // What 'auto' can use here: the native binary is built for glibc on x64
    // only, so on Alpine (musl), and on arm64, it falls back to the pure-JS
    // analyzer.
    let native = 'not installed';
    try {
      const bin = appRequire
        .resolve('recheck-linux-x64/package.json')
        .replace(/package\.json$/, 'recheck');
      const run = spawnSync(bin, ['--version'], { encoding: 'utf8', timeout: 10_000 });
      native = run.error
        ? `not runnable (${run.error.code || run.error.message})`
        : `runnable (exit ${run.status})`;
    } catch {
      // recheck-linux-x64 is an optional dependency for x64 only.
    }
    const { checkSync } = appRequire('recheck');
    const verdict = (source) => {
      const started = Date.now();
      const r = checkSync(source, '', { timeout: 60_000 });
      return {
        status: r.status,
        checker: r.checker,
        complexity: r.complexity && r.complexity.type,
        ms: Date.now() - started,
      };
    };
    const vulnerable = verdict('^(a+)+$');
    const safe = verdict('^[a-z]+=\\d+$');
    console.log(`recheck (RECHECK_BACKEND=${backend}; native binary ${native})`);
    console.log(`  /^(a+)+$/ -> ${JSON.stringify(vulnerable)}`);
    console.log(`  /^[a-z]+=\\d+$/ -> ${JSON.stringify(safe)}`);
    assert.equal(vulnerable.status, 'vulnerable');
    assert.equal(safe.status, 'safe');
  },

  linearFallback() {
    const fallback = appRequire('./dist/services/regex/linearFallback.js');
    const on = fallback.enableLinearRegexFallback();
    // Nine groups of eight identical alternatives: 8^9 backtracking steps on
    // 'a' x 9 + '!' (seconds on V8's backtracking engine).
    const pattern = new RegExp(`^(?<x>${'(?:a|a|a|a|a|a|a|a)'.repeat(9)})$`);
    const attack = 'a'.repeat(9) + '!';
    const started = Date.now();
    const match = pattern.exec(attack);
    const ms = Date.now() - started;
    const lookbehind = fallback.linearFallbackCovers('(?<=user=)\\S+', '');
    console.log(
      `linear fallback ${on ? 'on' : 'off'} (V8 flags: ${on ? fallback.LINEAR_FALLBACK_V8_FLAGS.join(' ') : 'none'})`
    );
    console.log(
      `  catastrophic pattern on '${attack}': ${match === null ? 'no match' : 'MATCHED'} in ${ms} ms`
    );
    console.log(`  covers lookbehind (?<=user=)\\S+: ${lookbehind}`);
    assert.equal(match, null);
    if (on) {
      assert.ok(ms < 1000, `the fallback should bound the match (took ${ms} ms)`);
      assert.equal(lookbehind, true, "Node 22's linear engine runs lookbehind");
    }
  },

  // The production path for every regex check and Test run: the save-time gate
  // (scan pool) and the bounded test runs (test pool) execute in worker threads
  // started from the compiled dist/services/regex/regexWorker.js, with
  // resourceLimits. Inside a scan worker, recheck's async check cannot start its
  // native binary on Alpine (or arm64) and falls back to a worker of its own.
  // The checks above run on the main thread and never start a pool.
  async regexPools() {
    const fallback = appRequire('./dist/services/regex/linearFallback.js');
    const on = fallback.enableLinearRegexFallback();
    const safety = appRequire('./dist/services/regex/regexSafety.js');
    const bounded = appRequire('./dist/services/regex/boundedRegex.js');
    // No database here: analyze every regex afresh instead of reading stored verdicts.
    safety.setVerdictStore(null);
    try {
      let started = Date.now();
      const report = await safety.assessRegexes([
        { location: 'a', source: '^(a+)+$', flags: '' },
        { location: 'b', source: '^[a-z]+=\\d+$', flags: '' },
      ]);
      const gateMs = Date.now() - started;
      const where = (findings) => findings.map((f) => f.location).join(',') || 'none';
      console.log(
        `regex safety gate (scan pool, RECHECK_BACKEND=${process.env.RECHECK_BACKEND || 'auto'}): ` +
          `refused=${safety.isRefused(report)}, vulnerable=${where(report.vulnerable)}, ` +
          `undecided=${where(report.undecided)}, unknown=${where(report.unknown)} in ${gateMs} ms`
      );
      for (const f of [...report.undecided, ...report.unknown]) console.log(`  ${f.location}: ${f.detail}`);
      assert.equal(safety.isRefused(report), true, 'the gate refuses ^(a+)+$');
      assert.equal(where(report.vulnerable), 'a', 'only ^(a+)+$ is vulnerable');
      assert.equal(where(report.undecided), 'none');
      assert.equal(where(report.unknown), 'none', 'both regexes get a verdict from the analyzer');

      // Start a test worker first, so the budget below times the match rather
      // than the worker's start.
      const warm = await bounded.runParserBounded(
        { name: 'kv', parser_type: 'regex', pattern: '^(?<key>[a-z]+)=(?<value>\\d+)$', field_mappings: {} },
        'port=8421'
      );
      assert.ok(warm && warm.fields, 'a test worker runs a parser');
      const budget = bounded.regexTestPool().options.timeoutMs;
      started = Date.now();
      let outcome;
      try {
        outcome = await bounded.runParserBounded(
          {
            name: 'x',
            parser_type: 'regex',
            pattern: `^(?<x>${'(?:a|a|a|a|a|a|a|a)'.repeat(9)})$`,
            field_mappings: {},
          },
          'a'.repeat(9) + '!'
        );
      } catch (err) {
        throw new Error(
          `the catastrophic test run did not finish (linear fallback ${on ? 'on' : 'off'}): ${err && err.message}`
        );
      }
      const runMs = Date.now() - started;
      console.log(
        `regex test pool (budget ${budget} ms, linear fallback ${on ? 'on' : 'off'}): ` +
          `catastrophic pattern on 'aaaaaaaaa!' -> ${JSON.stringify(outcome)} in ${runMs} ms`
      );
      assert.equal(outcome, null);
    } finally {
      await Promise.all([safety.closeRegexScanPool(), bounded.closeRegexTestPool()]);
    }
  },
};

const name = process.argv[2];
if (!checks[name]) {
  console.error(`usage: node backend-runtime.js <${Object.keys(checks).join('|')}>`);
  process.exit(2);
}
Promise.resolve()
  .then(() => checks[name]())
  .then(
    () => process.exit(0),
    (err) => {
      console.error(`FAILED ${name}: ${err && err.stack ? err.stack : err}`);
      process.exit(1);
    }
  );
