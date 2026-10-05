/**
 * validateScanTargets is the one DB-free piece of the asset-scan path, and the
 * authoritative gate against node-nmap's own argument handling: node-nmap
 * builds its argv by splitting the joined target string on whitespace before
 * spawning the real `nmap` binary, so an unvalidated target containing a space
 * can smuggle in extra nmap flags. Mirrors how validateLogPushEntry and
 * buildRawLogFilters are the pure, route-adjacent functions tested this way.
 * Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { NmapScanner, validateScanTargets } from './nmapScanner';

test('accepts a non-empty array of IPs, CIDRs, and hostnames', () => {
  assert.equal(validateScanTargets(['192.168.1.1', '10.0.0.0/24', 'nas01.lan', '::1']), null);
});

test('rejects a missing, empty, or non-array targets value', () => {
  for (const bad of [undefined, null, [], '192.168.1.1', {}]) {
    assert.match(validateScanTargets(bad) ?? '', /non-empty array/, JSON.stringify(bad));
  }
});

test('rejects a non-string entry', () => {
  for (const bad of [[123], [null], [{ ip: '127.0.0.1' }]]) {
    assert.match(validateScanTargets(bad) ?? '', /Invalid target/, JSON.stringify(bad));
  }
});

test('rejects a target with an embedded nmap flag -- the actual attack this guards against', () => {
  assert.match(validateScanTargets(['127.0.0.1 -oN /tmp/pwned.txt']) ?? '', /Invalid target/);
  assert.match(validateScanTargets(['127.0.0.1 --script=/tmp/evil.nse']) ?? '', /Invalid target/);
});

test('rejects any internal whitespace, even without a recognizable flag', () => {
  assert.match(validateScanTargets(['127.0.0.1 127.0.0.2']) ?? '', /Invalid target/);
});

test('rejects a bare flag with nothing valid in it', () => {
  assert.match(validateScanTargets(['-iL', '/etc/passwd']) ?? '', /Invalid target/);
});

test('one bad target among otherwise-good ones still fails the whole batch', () => {
  assert.match(validateScanTargets(['127.0.0.1', '10.0.0.0/24 -iL /etc/passwd']) ?? '', /Invalid target/);
});

test('rejects leading/trailing whitespace too -- callers must send a bare target', () => {
  // isValidScanTarget does an exact match, so this is strict by default; the
  // Assets page already trims each line before sending, so this never bites
  // normal use. A non-UI caller that sends untrimmed input gets a clear 400
  // rather than it being silently accepted.
  assert.match(validateScanTargets([' 127.0.0.1 ']) ?? '', /Invalid target/);
});

test('NmapScanner.scan() rejects a bad target before it ever touches the database', async () => {
  // No database is configured for this test file; if validation did not run
  // FIRST, this would hang or fail on a connection error instead of on the
  // validation message below -- so the specific rejection proves the ordering.
  await assert.rejects(
    NmapScanner.scan({ targets: ['127.0.0.1 -oN /tmp/pwned.txt'], scanType: 'ping', userId: 1 }),
    /Invalid target/
  );
});
