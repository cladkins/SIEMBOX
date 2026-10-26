/**
 * Local application signatures, DB-free: the merge with the catalog (a local
 * id overrides), the catalog-ready YAML (every mirror file round-trips through
 * it unchanged), the catalog status, the save/contribute checks, and the
 * Not identified drafts (each kind's draft becomes a valid signature whose
 * test passes once its category is set). Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'fs';
import * as path from 'path';
import * as yaml from '../../utils/yaml';
import { validateApplication, type AppSignature } from './appFormat';
import { AppIndex, runAppTests } from './matchers';
import { catalogPath, catalogStatus, checkSignature, mergeSignatures, readSignatureInput, signatureDocument, signatureToYaml } from './customSignatures';
import { draftForGap, guessNames, isNoise, isSystemPackage, registrableDomain, serviceKey, serviceProduct, slugify } from './gaps';
import { emptyReport } from '../regex/regexSafety';

const MIRROR = path.join(__dirname, '../../../../catalog/applications');

const sig = (doc: Record<string, unknown>): AppSignature => {
  const v = validateApplication({ schema: 'siembox.app/v1', vendor: 'Test', category: 'web-server', ...doc });
  assert.ok(v.ok, v.errors.join('; '));
  return v.app!;
};
const NGINX = sig({ id: 'nginx', name: 'nginx', match: { syslog_program: ['nginx'] }, tests: [{ source: 'syslog_program', input: 'nginx' }] });
const PLEX = sig({ id: 'plex', name: 'Plex', category: 'media-server', match: { package: ['plexmediaserver'] }, tests: [{ source: 'package', input: 'plexmediaserver' }] });

test('merge: a local signature joins the set, and one with a catalog id overrides it', () => {
  const localPlex = sig({ id: 'plex', name: 'Plex (mine)', category: 'media-server', match: { package: ['plexmediaserver', 'plex-media-server'] } });
  const widget = sig({ id: 'widget', name: 'Widget', match: { syslog_program: ['widgetd'] } });
  const { apps, origins } = mergeSignatures([NGINX, PLEX], [localPlex, widget]);
  assert.deepEqual(apps.map((a) => [a.id, a.name]), [['nginx', 'nginx'], ['plex', 'Plex (mine)'], ['widget', 'Widget']]);
  assert.equal(origins.get('nginx'), 'catalog');
  assert.equal(origins.get('plex'), 'override');
  assert.equal(origins.get('widget'), 'local');
});

test('catalog-ready YAML: every catalog mirror signature round-trips unchanged', () => {
  const files = fs.readdirSync(MIRROR).filter((f) => f.endsWith('.app.yaml'));
  assert.ok(files.length > 50);
  for (const f of files) {
    const v = validateApplication(yaml.load(fs.readFileSync(path.join(MIRROR, f), 'utf8')), { strict: true, expectId: f.replace('.app.yaml', '') });
    assert.ok(v.ok, `${f}: ${v.errors.join('; ')}`);
    const again = validateApplication(yaml.load(signatureToYaml(v.app!)), { strict: true, expectId: v.app!.id });
    assert.deepEqual(again.errors, [], f);
    assert.deepEqual(again.app, v.app, f);
  }
  assert.equal(catalogPath('plex'), 'applications/plex.app.yaml');
  const doc = signatureDocument(PLEX);
  assert.deepEqual(Object.keys(doc), ['schema', 'id', 'name', 'vendor', 'category', 'match', 'tests'], 'empty optional fields are left out');
});

test('catalog status: same, differs, not in the catalog', () => {
  assert.equal(catalogStatus(PLEX, undefined), 'not_in_catalog');
  assert.equal(catalogStatus(PLEX, sig({ ...signatureDocument(PLEX) })), 'same');
  assert.equal(catalogStatus(PLEX, sig({ ...signatureDocument(PLEX), name: 'Plex Media Server' })), 'differs');
});

test('input: YAML text or a JSON document; a bad one says why', () => {
  assert.equal((readSignatureInput({ yaml: 'id: x\n' }).doc as any).id, 'x');
  assert.match(readSignatureInput({ yaml: 'a: [' }).error ?? '', /YAML parse error/);
  assert.equal((readSignatureInput({ signature: { id: 'y' } }).doc as any).id, 'y');
  assert.match(readSignatureInput({}).error ?? '', /send the signature/);
  assert.match(readSignatureInput({ yaml: 'x'.repeat(70 * 1024) }).error ?? '', /larger than/);
});

test('checks: a good signature saves and is ready to contribute; strict-only problems block only the contribution', () => {
  const doc = { ...signatureDocument(sig({ id: 'widget', name: 'Widget', match: { syslog_program: ['widgetd'] }, tests: [{ source: 'syslog_program', input: 'widgetd' }] })) };
  const ok = checkSignature(doc, { effective: [NGINX, PLEX] });
  assert.deepEqual(ok.errors, []);
  assert.equal(ok.ok, true);
  assert.equal(ok.ready, true);
  assert.match(ok.yaml ?? '', /syslog_program:\n\s+- widgetd/);

  // No tests and an unknown key: saves (with warnings), cannot be contributed.
  const loose = checkSignature({ ...doc, tests: [], homepage: 'x' }, { effective: [NGINX] });
  assert.equal(loose.ok, true);
  assert.equal(loose.ready, false);
  assert.ok(loose.contribute_errors.some((e) => e.includes('unknown key "homepage"')), loose.contribute_errors.join('; '));
  assert.ok(loose.contribute_errors.some((e) => e.includes('add at least one matching test for match.syslog_program')));
  assert.ok(loose.warnings.some((w) => w.startsWith('no tests')));
});

test('checks: a value another signature claims, a failing test, an unsafe regex, a renamed id', () => {
  const claim = checkSignature({ ...signatureDocument(NGINX), id: 'nginx-copy' }, { effective: [NGINX] });
  assert.equal(claim.ok, false);
  assert.ok(claim.errors.some((e) => e.includes('is also claimed by nginx')), claim.errors.join('; '));
  // Overriding the catalog signature with the same id is not a claim conflict.
  assert.equal(checkSignature(signatureDocument(NGINX), { effective: [NGINX] }).ok, true);

  const failing = checkSignature({ ...signatureDocument(PLEX), id: 'plex2', match: { package: ['plex2'] } }, { effective: [] });
  assert.ok(failing.errors.some((e) => e.includes('does not match')), failing.errors.join('; '));

  const ua = { schema: 'siembox.app/v1', id: 'acme-bot', name: 'Acme Bot', vendor: 'Acme', category: 'http-client', match: { user_agent: ['^AcmeBot/(\\d+)'] }, tests: [{ source: 'user_agent', input: 'AcmeBot/3', version: '3' }] };
  const unchecked = checkSignature(ua, { effective: [] });
  assert.ok(unchecked.warnings.some((w) => w.includes('regexes were not checked')));
  assert.equal(unchecked.tests.total, 0, 'regex tests do not run before the gate');
  const safe = checkSignature(ua, { effective: [], regex: emptyReport() });
  assert.deepEqual(safe.errors, []);
  assert.equal(safe.tests.total, 1);
  const refused = { ...emptyReport(), vulnerable: [{ location: 'match.user_agent[0]', source: '^AcmeBot/(\\d+)', flags: '', status: 'vulnerable' as const }], errors: ['ReDoS: refused'] };
  const bad = checkSignature(ua, { effective: [], regex: refused });
  assert.equal(bad.ok, false);
  assert.deepEqual(bad.errors, ['ReDoS: refused']);
  assert.equal(bad.tests.total, 0, 'a refused regex is never run');

  const renamed = checkSignature({ ...signatureDocument(PLEX), id: 'plex-two' }, { effective: [], expectId: 'plex' });
  assert.ok(renamed.errors.some((e) => e.includes('must match the file name')));
});

test('gaps: service products, registrable domains, system packages, noise', () => {
  assert.equal(serviceProduct('Apache httpd 2.4.41 ((Ubuntu))'), 'Apache httpd');
  assert.equal(serviceProduct('OpenSSH 8.9p1 Ubuntu 3ubuntu0.6'), 'OpenSSH');
  assert.equal(serviceProduct(''), null);
  assert.equal(serviceKey({ service_name: 'HTTP', service_version: null }), 'http');
  assert.equal(registrableDomain('us04web.zoom.us'), 'zoom.us');
  assert.equal(registrableDomain('www.bbc.co.uk'), 'bbc.co.uk');
  assert.equal(registrableDomain('nas.lan'), null);
  assert.equal(registrableDomain('4.3.2.1.in-addr.arpa'), null);
  assert.equal(registrableDomain('localhost'), null);
  for (const n of ['libc6', 'libssl3', 'python3-yaml', 'gcc-12', 'linux-image-6.8.0-45-generic', 'systemd-timesyncd', 'tzdata', 'KB5034441', 'bash', 'fonts-dejavu-core', 'zlib1g']) {
    assert.equal(isSystemPackage(n), true, n);
  }
  for (const n of ['plexmediaserver', 'libreoffice-calc', 'docker-ce', 'tailscale', 'jellyfin', 'grafana', 'influxdb', 'tarsnap', 'makemkv']) {
    assert.equal(isSystemPackage(n), false, n);
  }
  assert.equal(isSystemPackage('requests', 'pypi'), true, 'language libraries are not applications');
  assert.equal(isNoise('service', 'http', { service_version: null }), true);
  assert.equal(isNoise('service', 'Apache httpd', { service_version: 'Apache httpd 2.4' }), false);
  assert.equal(isNoise('dns', 'akamaiedge.net'), true);
  assert.equal(isNoise('dns', 'tailscale.com'), false);
  assert.equal(slugify('  Apache httpd!! '), 'apache-httpd');
  assert.deepEqual(guessNames({ source: 'container', value: 'ghcr.io/linuxserver/sonarr' }), { name: 'Sonarr', vendor: 'Linuxserver' });
});

test('drafts: each kind becomes a valid signature whose own test passes', () => {
  const items = [
    { source: 'syslog_program', value: 'widgetd' },
    { source: 'parser', value: 'acme-access' },
    { source: 'container', value: 'ghcr.io/acme/widget', sample: 'ghcr.io/acme/widget:2.1.0' },
    { source: 'package', value: 'acme-agent', detail: { version: '1.2.3', type: 'deb' } },
    { source: 'service', value: 'Acme Server', detail: { service_name: 'http', service_version: 'Acme Server 4.2.1 (Linux)' } },
    { source: 'service', value: 'acme-rpc', detail: { service_name: 'acme-rpc', service_version: null } },
    { source: 'user_agent', value: 'AcmeBot', sample: 'AcmeBot/1.2 (+https://acme.example)' },
    { source: 'dns', value: 'acme.example.com', sample: 'api.acme.example.com' },
  ];
  for (const item of items) {
    const draft = draftForGap(item);
    const v = validateApplication({ ...draft, vendor: draft.vendor || 'Acme', category: draft.category || 'web-server' }, { strict: true });
    assert.deepEqual(v.errors, [], `${item.source}: ${JSON.stringify(draft)}`);
    assert.deepEqual(runAppTests(v.app!, new AppIndex([v.app!])), [], `${item.source}: its test passes`);
  }
  const svc = draftForGap(items[4]);
  assert.equal((svc.tests as any[])[0].version, '4.2.1');
  assert.equal(draftForGap(items[7]).category, 'saas');
});
