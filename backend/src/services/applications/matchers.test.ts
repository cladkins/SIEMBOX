/**
 * Matching evidence to signatures, per source, with the data shapes SIEMBox
 * really stores (see matchers.ts): syslogParser app names, catalog parser
 * names, node-nmap services, docker ps image references, grype findings, the
 * endpoint agent's OS facts, user agents from the catalog parsers' samples,
 * Pi-hole query names. Also: the whole catalog/applications mirror validates
 * and its tests pass. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'fs';
import * as path from 'path';
import * as yaml from '../../utils/yaml';
import { APP_FILE_SUFFIX, crossCheckApplications, validateApplication, type AppSignature } from './appFormat';
import { AppIndex, cleanDomain, cleanVersion, globMatch, parseImageRef, runAppTests, userAgentProduct, versionFromTag } from './matchers';

const MIRROR = path.join(__dirname, '../../../../catalog/applications');
const PARSERS = path.join(__dirname, '../../../../catalog/parsers');

function loadMirror(): AppSignature[] {
  return fs
    .readdirSync(MIRROR)
    .filter((f) => f.endsWith(APP_FILE_SUFFIX))
    .sort()
    .map((f) => {
      const v = validateApplication(yaml.load(fs.readFileSync(path.join(MIRROR, f), 'utf8')), { strict: true, expectId: f.slice(0, -APP_FILE_SUFFIX.length) });
      assert.ok(v.ok, `${f}: ${v.errors.join('; ')}`);
      return v.app!;
    });
}
const CATALOG = loadMirror();
const index = new AppIndex(CATALOG);
const ids = (m: Array<{ appId: string; version: string | null }>) => m.map((x) => (x.version ? `${x.appId}@${x.version}` : x.appId)).sort();

test('the catalog/applications mirror: every file validates, no claim twice, every test passes, parsers exist', () => {
  assert.ok(CATALOG.length >= 60, `${CATALOG.length} signatures`);
  assert.deepEqual(crossCheckApplications(CATALOG), []);
  for (const app of CATALOG) assert.deepEqual(runAppTests(app, index), [], app.id);
  const parserNames = new Set(
    fs.readdirSync(PARSERS).filter((f) => f.endsWith('.parser.json')).map((f) => JSON.parse(fs.readFileSync(path.join(PARSERS, f), 'utf8')).name)
  );
  for (const app of CATALOG) for (const p of app.match.parser) assert.ok(parserNames.has(p), `${app.id}: parser ${p}`);
});

test('syslog_program: raw_logs.app_name as syslogParser extracts it', () => {
  assert.deepEqual(ids(index.matchProgram('sshd')), ['openssh']);
  assert.deepEqual(ids(index.matchProgram('Authentik Server')), ['authentik'], 'a multi-word TAG, case-insensitive');
  assert.deepEqual(ids(index.matchProgram('postfix/smtpd')), ['postfix']);
  assert.deepEqual(ids(index.matchProgram('postfix')), [], 'postfix/* needs a sub-program');
  assert.deepEqual(ids(index.matchProgram('dnsmasq')), ['dnsmasq'], 'Pi-hole query lines carry the dnsmasq tag');
  assert.deepEqual(ids(index.matchProgram('CRON')), ['cron']);
  assert.deepEqual(ids(index.matchProgram('npm-access')), [], "a shipper's own tag names no product");
});

test('parser: the catalog parser that matched', () => {
  assert.deepEqual(ids(index.matchParser('pihole-query')), ['pihole']);
  assert.deepEqual(ids(index.matchParser('traefik-access')), ['traefik']);
  assert.deepEqual(ids(index.matchParser('generic-syslog')), []);
});

test('service: node-nmap fills service_name only; a banner (when a scanner sets one) gives the version', () => {
  assert.deepEqual(ids(index.matchService({ name: 'postgresql', version: null, banner: null })), ['postgresql']);
  assert.deepEqual(ids(index.matchService({ name: 'ms-wbt-server' })), ['rdp']);
  assert.deepEqual(ids(index.matchService({ name: 'https', banner: 'ssl' })), [], "the TLS tunnel in banner names nothing");
  assert.deepEqual(ids(index.matchService({ name: 'ssh' })), [], 'ssh could be OpenSSH or Dropbear');
  assert.deepEqual(ids(index.matchService({ name: 'ssh', banner: 'OpenSSH 8.9p1 Ubuntu 3ubuntu0.6' })), ['openssh@8.9p1']);
  assert.deepEqual(ids(index.matchService({ name: 'ssh', banner: 'Dropbear sshd 2022.83' })), ['dropbear@2022.83']);
});

test('container_image: docker ps references; the tag is the version when it starts with a number', () => {
  assert.deepEqual(ids(index.matchImage('lscr.io/linuxserver/plex:1.40.0.7998-c29d4c0c8-ls210')), ['plex@1.40.0.7998']);
  assert.deepEqual(ids(index.matchImage('linuxserver/plex:latest')), ['plex']);
  assert.deepEqual(ids(index.matchImage('nginx:1.25.3-alpine')), ['nginx@1.25.3']);
  assert.deepEqual(ids(index.matchImage('docker.io/library/postgres:16')), ['postgresql@16']);
  assert.deepEqual(ids(index.matchImage('ghcr.io/home-assistant/home-assistant:stable')), ['home-assistant']);
  assert.deepEqual(ids(index.matchImage('traefik:v2.10.7@sha256:' + 'a'.repeat(64))), ['traefik@2.10.7']);
  assert.deepEqual(ids(index.matchImage('jc21/nginx-proxy-manager:2.11.1')), ['nginx-proxy-manager@2.11.1'], 'not nginx');
  assert.deepEqual(ids(index.matchImage('sha256:' + 'b'.repeat(64))), [], 'a bare image id has no name');
  assert.deepEqual(ids(index.matchImage('localhost:5000/myapp:1.0')), []);
});

test('package: grype findings (package=, installed=)', () => {
  assert.deepEqual(ids(index.matchPackage('openssh-server', '1:8.9p1-3ubuntu0.6')), ['openssh@1:8.9p1-3ubuntu0.6']);
  assert.deepEqual(ids(index.matchPackage('docker-ce', '5:24.0.7-1~ubuntu.22.04~jammy')), ['docker@5:24.0.7-1~ubuntu.22.04~jammy']);
  assert.deepEqual(ids(index.matchPackage('libssl3', '3.0.2')), []);
});

test('user_agent: the catalog parsers\' sample agents, and supersedes', () => {
  // standard-nginx-access / traefik-access / caddy-access test samples
  assert.deepEqual(ids(index.matchUserAgent('curl/7.81.0')), ['curl@7.81.0']);
  assert.deepEqual(ids(index.matchUserAgent('curl/8.0')), ['curl@8.0']);
  assert.deepEqual(ids(index.matchUserAgent('python-requests/2.31.0')), ['python-requests@2.31.0']);
  assert.deepEqual(ids(index.matchUserAgent('Mozilla/5.0')), [], 'a bare Mozilla/5.0 names nothing');
  assert.deepEqual(ids(index.matchUserAgent('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36')), []);
  // authentik-asgi-access sample (truncated real agent)
  const mac = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';
  assert.deepEqual(ids(index.matchUserAgent(mac)), ['chrome@120.0.0.0', 'macos@10_15_7']);
  const edge = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.2210.91';
  assert.deepEqual(ids(index.matchUserAgent(edge)), ['edge@120.0.2210.91', 'windows@10.0'], 'Edge supersedes Chrome');
  assert.deepEqual(ids(index.matchUserAgent('HomeAssistant/2024.1.5 aiohttp/3.9.1 Python/3.11')), ['home-assistant@2024.1.5']);
  // An overlong agent is cut, not scanned whole.
  assert.deepEqual(ids(index.matchUserAgent('x'.repeat(5000) + ' curl/8.0')), []);
});

test('dns: Pi-hole query names; suffixes and *.subdomain-only entries', () => {
  assert.deepEqual(ids(index.matchDomain('us04web.zoom.us')), ['zoom']);
  assert.deepEqual(ids(index.matchDomain('zoom.us')), ['zoom']);
  assert.deepEqual(ids(index.matchDomain('notzoom.us')), [], 'a suffix match is on a label boundary');
  assert.deepEqual(ids(index.matchDomain('firebaselogging-pa.googleapis.com')), [], 'the pihole-dns-adblock sample');
  assert.deepEqual(ids(index.matchDomain('Relay-1.NET.AnyDesk.com.')), ['anydesk'], 'case and the trailing dot');
  assert.deepEqual(ids(index.matchDomain('tracker.example.com')), []);
});

test('os: the endpoint agent sends GOOS and /etc/os-release PRETTY_NAME', () => {
  assert.deepEqual(ids(index.matchOs('linux', 'Ubuntu 22.04.4 LTS')), ['ubuntu@22.04.4']);
  assert.deepEqual(ids(index.matchOs('linux', 'Debian GNU/Linux 12 (bookworm)')), ['debian@12']);
  assert.deepEqual(ids(index.matchOs('windows', 'windows')), ['windows']);
  assert.deepEqual(ids(index.matchOs('darwin', 'darwin')), ['macos']);
  assert.deepEqual(ids(index.matchOs('linux', 'linux')), [], 'no os-release: no distribution');
});

test('helpers: versions, tags, globs, domains, user-agent products', () => {
  assert.equal(cleanVersion('v2.10.4'), '2.10.4');
  assert.equal(cleanVersion('latest'), null);
  assert.equal(cleanVersion('1'.repeat(65)), null);
  assert.equal(versionFromTag('16-alpine'), '16');
  assert.equal(versionFromTag('version-1.40.0.7998-c29d4c0c8'), '1.40.0.7998');
  assert.equal(versionFromTag('stable'), null);
  assert.deepEqual(parseImageRef('registry.example.com:5000/team/app:1.2'), { name: 'registry.example.com:5000/team/app', tag: '1.2' });
  assert.deepEqual(parseImageRef('docker.io/library/redis'), { name: 'redis', tag: null });
  assert.equal(globMatch('*/linuxserver/plex', 'lscr.io/linuxserver/plex'), true);
  assert.equal(globMatch('*/linuxserver/plex', 'linuxserver/plex'), false);
  assert.equal(globMatch('*/moghtech/komodo-*', 'ghcr.io/moghtech/komodo-core'), true);
  assert.equal(globMatch('nginx', 'nginxinc/nginx'), false);
  assert.equal(cleanDomain('Example.COM.'), 'example.com');
  assert.equal(cleanDomain('localhost'), null);
  assert.equal(userAgentProduct('python-requests/2.31.0'), 'python-requests');
  assert.equal(userAgentProduct('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Foo/1.2 Safari/537.36'), 'Foo');
  assert.equal(userAgentProduct('Mozilla/5.0'), 'Mozilla');
  assert.equal(userAgentProduct('-'), null);
});
