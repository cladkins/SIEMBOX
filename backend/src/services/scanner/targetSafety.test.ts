/**
 * The public/private scan-target classifier and its typo hints
 * (targetSafety.ts), and the 400 the scan routes send for unconfirmed public
 * targets (publicTargetGuard.ts). DB-free. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import type { Request } from 'express';
import { assessTarget, describePublicTarget, findPublicTargets, splitTargets } from './targetSafety';
import { checkPublicTargets, PUBLIC_TARGETS_REFUSED, publicTargetsConfirmed } from './publicTargetGuard';

const kind = (t: string) => assessTarget(t).kind;

test('private and reserved IPv4 space is private', () => {
  for (const t of [
    '10.0.0.1',
    '10.255.255.255',
    '10.0.0.0/8',
    '172.16.0.1',
    '172.31.255.254',
    '172.16.0.0/12',
    '192.168.1.1',
    '192.168.0.0/16',
    '192.168.1.0/24',
    '100.64.0.1',
    '100.127.255.255',
    '127.0.0.1',
    '169.254.10.20',
    '192.0.2.1', // TEST-NET-1
    '198.51.100.7', // TEST-NET-2
    '203.0.113.9', // TEST-NET-3
    '198.18.0.1',
    '224.0.0.251',
    '255.255.255.255',
    '0.0.0.0',
    '192.168.1.1-254',
    '10.0-3.0.1',
  ]) {
    assert.equal(kind(t), 'private', t);
  }
});

test('public IPv4 space is public', () => {
  for (const t of [
    '8.8.8.8',
    '1.1.1.1',
    '192.169.1.1',
    '192.169.1.0/24', // the incident: a typo of 192.168.1.0/24
    '172.32.0.1',
    '172.15.255.255',
    '100.63.255.255',
    '100.128.0.0',
    '11.0.0.1',
    '193.168.1.1',
    '192.169.1.1-254',
  ]) {
    assert.equal(kind(t), 'public', t);
  }
});

test('a range that only partly covers private space is public, flagged partly private', () => {
  for (const t of ['10.0.0.0/7', '172.0.0.0/8', '192.0.0.0/8', '0.0.0.0/0', '192.168.0.0/15']) {
    const a = assessTarget(t);
    assert.equal(a.kind, 'public', t);
    assert.equal(a.partlyPrivate, true, t);
  }
  // A range touching no private space at all is not "partly private".
  assert.equal(assessTarget('8.8.8.0/24').partlyPrivate, undefined);
});

test('IPv6: loopback, ULA, link-local and documentation are private; global unicast is public', () => {
  for (const t of ['::1', 'fd00::1', 'fc00::/7', 'fd12:3456::/48', 'fe80::1', 'fe80::1%eth0', 'fe80::/10', '2001:db8::1', '::ffff:10.0.0.1', '[fd00::1]:443']) {
    assert.equal(kind(t), 'private', t);
  }
  for (const t of ['2001:4860:4860::8888', '2606:4700::/32', '::ffff:8.8.8.8', '::/0']) {
    assert.equal(kind(t), 'public', t);
  }
});

test('URLs, ports and paths are judged by their host', () => {
  assert.equal(kind('http://10.0.0.5'), 'private');
  assert.equal(kind('https://192.168.1.10:8443/login?next=/'), 'private');
  assert.equal(kind('https://user:pw@10.1.1.1/'), 'private');
  assert.equal(kind('10.0.0.5:8080'), 'private');
  assert.equal(kind('https://[fd00::5]:8443/'), 'private');
  assert.equal(kind('https://8.8.8.8/'), 'public');
  assert.equal(kind('8.8.8.8:53'), 'public');
});

test('hostnames are not resolved: only a warning', () => {
  for (const t of ['nas01.lan', 'example.com', 'https://router.home.arpa/admin', 'printer']) {
    assert.equal(kind(t), 'hostname', t);
  }
  assert.equal(kind('localhost'), 'private');
  // Digits-and-dots that aren't a full address may still be read as one by a
  // resolver (192.169.1 -> 192.169.0.1), so they can't be shown private.
  assert.equal(kind('192.169.1'), 'public');
  assert.equal(kind('3232235777'), 'public');
});

test('garbage is invalid, not private', () => {
  for (const t of ['', '   ', '10.0.0.0/33', '999.1.1.1', '10.0.0.0/123', 'fe80::zz', '1.2.3.4-1']) {
    assert.equal(kind(t), 'invalid', JSON.stringify(t));
  }
});

test('typo hints: one octet away from a private range', () => {
  const hint = (t: string) => assessTarget(t).suggestion;
  assert.equal(hint('192.169.1.0/24'), '192.168.1.0/24');
  assert.equal(hint('192.169.1.1'), '192.168.1.1');
  assert.equal(hint('192.167.0.10'), '192.168.0.10');
  assert.equal(hint('192.186.1.1'), '192.168.1.1', 'swapped digits');
  assert.equal(hint('193.168.1.1'), '192.168.1.1');
  assert.equal(hint('19.168.1.1'), '192.168.1.1', 'dropped digit');
  assert.equal(hint('192.169.1.1-254'), '192.168.1.1-254');
  assert.equal(hint('https://192.169.1.5:8443/x'), 'https://192.168.1.5:8443/x');
  assert.equal(hint('172.32.0.0/16'), '172.31.0.0/16');
  assert.equal(hint('172.15.1.1'), '172.16.1.1');
  assert.equal(hint('172.61.0.1'), '172.16.0.1', 'swapped digits');
  assert.equal(hint('173.16.0.1'), '172.16.0.1');
  assert.equal(hint('11.0.0.1'), '10.0.0.1');
  assert.equal(hint('100.1.2.3'), '10.1.2.3');
  // Nothing close: no hint.
  assert.equal(hint('8.8.8.8'), undefined);
  assert.equal(hint('203.0.114.1'), undefined);
  assert.equal(hint('2001:4860::8888'), undefined);
  // Private targets never get one.
  assert.equal(hint('10.1.2.3'), undefined);
  assert.equal(hint('192.168.1.1'), undefined);
  assert.equal(hint('172.20.0.1'), undefined);
});

test('findPublicTargets splits public targets from hostnames; describePublicTarget explains each', () => {
  const report = findPublicTargets(['192.168.1.0/24', '192.169.1.0/24', 'nas.lan', '10.0.0.0/7']);
  assert.deepEqual(
    report.publicTargets.map((t) => t.target),
    ['192.169.1.0/24', '10.0.0.0/7']
  );
  assert.deepEqual(report.hostnames, ['nas.lan']);
  assert.equal(describePublicTarget(report.publicTargets[0]), '192.169.1.0/24 (did you mean 192.168.1.0/24?)');
  assert.equal(describePublicTarget(report.publicTargets[1]), '10.0.0.0/7 (partly public)');
  assert.deepEqual(splitTargets(' 10.0.0.1,\n192.168.1.0/24  nas.lan '), ['10.0.0.1', '192.168.1.0/24', 'nas.lan']);
});

test('the guard refuses unconfirmed public targets with a 400 body naming them', () => {
  const req = (body: unknown) => ({ body, user: { id: 7, username: 'alice', role: 'analyst' } }) as unknown as Request;

  const clean = checkPublicTargets(['192.168.1.0/24', 'nas.lan'], req({}));
  assert.equal(clean.ok, true);
  assert.equal(clean.ok && clean.confirmation, null);

  const refused = checkPublicTargets(['192.169.1.0/24'], req({ allow_public_targets: 'true' }));
  assert.equal(refused.ok, false, 'only a literal true confirms');
  if (refused.ok) return;
  assert.equal(refused.body.code, PUBLIC_TARGETS_REFUSED);
  assert.deepEqual(refused.body.public_targets, [{ target: '192.169.1.0/24', suggestion: '192.168.1.0/24' }]);
  assert.match(String(refused.body.error), /192\.169\.1\.0\/24 \(did you mean 192\.168\.1\.0\/24\?\)/);
  assert.match(String(refused.body.error), /allow_public_targets: true/);

  const confirmed = checkPublicTargets(['192.169.1.0/24', '10.0.0.1'], req({ allow_public_targets: true }));
  assert.equal(confirmed.ok, true);
  if (!confirmed.ok) return;
  assert.equal(confirmed.confirmation?.confirmedBy, 7);
  assert.equal(confirmed.confirmation?.confirmedByUsername, 'alice');
  assert.deepEqual(confirmed.confirmation?.publicTargets, ['192.169.1.0/24']);
  assert.ok(!Number.isNaN(Date.parse(confirmed.confirmation!.confirmedAt)));

  assert.equal(publicTargetsConfirmed({ allowPublicTargets: true }), true);
  assert.equal(publicTargetsConfirmed({ allow_public_targets: 1 }), false);
  assert.equal(publicTargetsConfirmed(undefined), false);
});

test('the frontend copy (frontend/src/utils/targetSafety.ts) is byte for byte this file', () => {
  const here = fs.readFileSync(path.join(__dirname, 'targetSafety.ts'), 'utf8');
  const page = fs.readFileSync(path.join(__dirname, '../../../../frontend/src/utils/targetSafety.ts'), 'utf8');
  assert.equal(page, here, 'copy backend/src/services/scanner/targetSafety.ts over frontend/src/utils/targetSafety.ts');
});
