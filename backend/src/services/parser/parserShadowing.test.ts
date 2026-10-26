/**
 * Cross-parser shadowing check (parserShadowing.ts): a parser can pass its own
 * self-tests and still never fire, because an earlier parser in engine order
 * (lower priority number) claims its logs first. These use small synthetic
 * parsers so each rule of the check is pinned down on its own; the real-catalog
 * guard lives in parserPriority.test.ts.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'fs';
import * as path from 'path';
import {
  engineOrder,
  findShadowingConflicts,
  formatShadowConflict,
  isCatchAll,
  selectFirstMatch,
  ShadowingParser,
} from './parserShadowing';
import { sampleEngineInput } from './parserPortable';

// A specific parser for "login failed for <user> from <ip>" lines.
const specific: ShadowingParser = {
  name: 'acme-login',
  parser_type: 'regex',
  priority: 30,
  pattern: '^login failed for (?<user>\\S+) from (?<ip>\\S+)$',
  field_mappings: { user: 'user', ip: 'source_ip' },
  derivations: [{ set: { event: 'login_failure', service: 'acme' } }],
  test_samples: [
    {
      input: 'login failed for alice from 203.0.113.5',
      expect: { user: 'alice', source_ip: '203.0.113.5', event: 'login_failure', service: 'acme' },
    },
  ],
};

// A looser parser that matches anything starting with "login" and maps only the message.
const loose: ShadowingParser = {
  name: 'loose-login',
  parser_type: 'regex',
  priority: 20,
  pattern: '^login (?<rest>.+)$',
  field_mappings: { rest: 'detail' },
  test_samples: [{ input: 'login ok', expect: { detail: 'ok' } }],
};

test('a looser parser with a lower priority number shadows a specific one', () => {
  const conflicts = findShadowingConflicts([specific, loose]);

  assert.equal(conflicts.length, 1);
  const [c] = conflicts;
  assert.equal(c.owner, 'acme-login');
  assert.equal(c.ownerPriority, 30);
  assert.equal(c.claimedBy, 'loose-login');
  assert.equal(c.claimedByPriority, 20);
  assert.equal(c.sampleIndex, 0);
  assert.equal(c.stripped, false);
  assert.deepEqual(
    c.mismatches.map((m) => m.field).sort(),
    ['event', 'service', 'source_ip', 'user']
  );
});

test('the conflict message names the sample, both parsers, both priorities and each lost field', () => {
  const text = formatShadowConflict(findShadowingConflicts([specific, loose])[0]).join('\n');

  assert.match(text, /acme-login sample\[0\]/);
  assert.match(text, /claimed by loose-login \(priority 20\) before acme-login \(priority 30\)/);
  assert.match(text, /user: expected "alice", loose-login gives undefined/);
  assert.match(text, /source_ip: expected "203\.0\.113\.5"/);
  assert.match(text, /login failed for alice from 203\.0\.113\.5/);
});

test('reordering fixes it: the specific parser first means no conflict', () => {
  assert.deepEqual(findShadowingConflicts([{ ...specific, priority: 10 }, loose]), []);
});

test('an earlier parser that yields every expected field may claim the line', () => {
  // A stricter parser producing a superset of the owner's fields is not a loss.
  const superset: ShadowingParser = {
    ...specific,
    name: 'acme-login-strict',
    priority: 5,
    derivations: [{ set: { event: 'login_failure', service: 'acme', extra: 'yes' } }],
    test_samples: [],
  };
  assert.deepEqual(findShadowingConflicts([specific, superset]), []);
});

test('a catch-all (no field_mappings) is exempt as owner but counts as claimer', () => {
  const catchAll: ShadowingParser = {
    name: 'anything',
    parser_type: 'regex',
    priority: 50,
    pattern: '.',
    field_mappings: {},
    test_samples: [{ input: 'login failed for bob from 198.51.100.1', expect: { message: 'login failed for bob from 198.51.100.1' } }],
  };
  assert.equal(isCatchAll(catchAll), true);

  // Owner side: the specific parser at 30 takes the catch-all's sample — fine.
  assert.deepEqual(findShadowingConflicts([specific, catchAll]), []);

  // Claimer side: with the specific parser behind the catch-all, its sample is lost.
  const conflicts = findShadowingConflicts([{ ...specific, priority: 200 }, catchAll]);
  assert.equal(conflicts.length, 1);
  assert.equal(conflicts[0].claimedBy, 'anything');
});

test('engine order is ascending priority, ties by name, missing priority = 100', () => {
  const names = engineOrder([
    { ...loose, name: 'b', priority: 10 },
    { ...loose, name: 'a', priority: 10 },
    { ...loose, name: 'c', priority: undefined },
    { ...loose, name: 'd', priority: 99 },
  ]).map((p) => p.name);
  assert.deepEqual(names, ['a', 'b', 'd', 'c']);
});

test('a same-priority tie is reported and flagged as install-order dependent', () => {
  const tied = { ...loose, name: 'aaa-loose', priority: 30 };
  const conflicts = findShadowingConflicts([specific, tied]);
  assert.equal(conflicts.length, 1);
  assert.match(formatShadowConflict(conflicts[0])[0], /same priority/);
});

test("negative samples (the owner doesn't match) are not conflicts", () => {
  const withNegative: ShadowingParser = {
    ...specific,
    priority: 10,
    test_samples: [...specific.test_samples!, { input: 'login ok', expect: { user: null } }],
  };
  assert.deepEqual(findShadowingConflicts([withNegative, loose]), []);
});

// --- two-stage transport -----------------------------------------------------
// A full syslog sample reaches the engine header-stripped, so the check must
// select on the stripped message, the same input runSelfTests' two-stage check
// uses. An `embedded_syslog` sample keeps its header (the inner line survives
// inside the shipper's envelope), so it is selected on as written.

const SYSLOG_LINE = '<38>Jan 15 12:00:00 host1 acme[42]: login failed for alice from 203.0.113.5';

const headerTolerant: ShadowingParser = {
  ...specific,
  pattern: '^(?:<\\d+>\\w{3} \\d{1,2} \\d{2}:\\d{2}:\\d{2} \\S+ acme\\[\\d+\\]: )?login failed for (?<user>\\S+) from (?<ip>\\S+)$',
  test_samples: [
    {
      input: SYSLOG_LINE,
      expect: { user: 'alice', source_ip: '203.0.113.5', event: 'login_failure', service: 'acme' },
    },
  ],
};

test('a full syslog sample is checked on its header-stripped message', () => {
  assert.deepEqual(sampleEngineInput({ input: SYSLOG_LINE }), {
    input: 'login failed for alice from 203.0.113.5',
    stripped: true,
  });

  // loose-login is anchored on the message, so it never matches the raw line —
  // only the stripped one. Selecting on the raw sample would miss this.
  const conflicts = findShadowingConflicts([headerTolerant, loose]);
  assert.equal(conflicts.length, 1);
  assert.equal(conflicts[0].stripped, true);
  assert.equal(conflicts[0].input, 'login failed for alice from 203.0.113.5');
  assert.match(formatShadowConflict(conflicts[0]).join('\n'), /header-stripped/);
});

test('an embedded_syslog sample is checked as written', () => {
  const embedded: ShadowingParser = {
    ...headerTolerant,
    test_samples: [{ ...headerTolerant.test_samples![0], embedded_syslog: true }],
  };
  assert.deepEqual(sampleEngineInput(embedded.test_samples![0]), { input: SYSLOG_LINE, stripped: false });
  assert.deepEqual(findShadowingConflicts([embedded, loose]), []);
});

test('on the stripped message only the fields the owner still yields there are at stake', () => {
  // The owner captures `host` from the header, which the engine never shows it.
  // A claimer that lacks `host` is not blamed for it; it is blamed for the rest.
  const withHost: ShadowingParser = {
    ...headerTolerant,
    pattern:
      '^(?:<\\d+>\\w{3} \\d{1,2} \\d{2}:\\d{2}:\\d{2} (?<host>\\S+) acme\\[\\d+\\]: )?login failed for (?<user>\\S+) from (?<ip>\\S+)$',
    field_mappings: { host: 'host', user: 'user', ip: 'source_ip' },
    test_samples: [{ input: SYSLOG_LINE, expect: { host: 'host1', user: 'alice' } }],
  };
  const [c] = findShadowingConflicts([withHost, loose]);
  assert.deepEqual(c.mismatches.map((m) => m.field), ['user']);
});

test('selectFirstMatch returns the first matching parser in the given order', () => {
  const ordered = engineOrder([specific, loose]);
  assert.equal(selectFirstMatch(ordered, 'login failed for x from y')?.parser.name, 'loose-login');
  assert.equal(selectFirstMatch(ordered, 'nothing here'), null);
});

// --- the real bugs this check was written for --------------------------------

const CATALOG = path.join(__dirname, '../../../../catalog/parsers');
function loadCatalog(): ShadowingParser[] {
  return fs
    .readdirSync(CATALOG)
    .filter((f) => f.endsWith('.parser.json'))
    .map((f) => JSON.parse(fs.readFileSync(path.join(CATALOG, f), 'utf8')) as ShadowingParser);
}
function withPriorities(overrides: Record<string, number>): ShadowingParser[] {
  return loadCatalog().map((p) => (p.name in overrides ? { ...p, priority: overrides[p.name] } : p));
}

test('regression: pihole-dns-adblock at 200 is swallowed by json-parser (50)', () => {
  const c = findShadowingConflicts(withPriorities({ 'pihole-dns-adblock': 200 })).filter(
    (x) => x.owner === 'pihole-dns-adblock'
  );
  assert.equal(c.length, 1);
  assert.equal(c[0].claimedBy, 'json-parser');
  assert.ok(c[0].mismatches.some((m) => m.field === 'event'));
});

test('regression: nginx-komodo-error at 44 is shadowed by standard-nginx-error (39)', () => {
  const c = findShadowingConflicts(withPriorities({ 'nginx-komodo-error': 44 })).filter(
    (x) => x.owner === 'nginx-komodo-error'
  );
  assert.equal(c.length, 1);
  assert.equal(c[0].claimedBy, 'standard-nginx-error');
  assert.deepEqual(c[0].mismatches.map((m) => m.field).sort(), ['connection_id', 'pid', 'worker_id']);
});

test('regression: a JSON parser keyed only on generic envelope keys hijacks authentik at a low priority', () => {
  // The shape of the first Proxmox parser: parser_type json, empty pattern,
  // mappings only on host/message/service. At 15 it claimed authentik's JSON.
  const genericJson: ShadowingParser = {
    name: 'generic-envelope-json',
    parser_type: 'json',
    priority: 15,
    pattern: '',
    field_mappings: { host: 'host', message: 'message', service: 'service' },
  };
  const c = findShadowingConflicts([...loadCatalog(), genericJson]).filter(
    (x) => x.claimedBy === 'generic-envelope-json'
  );
  assert.ok(c.some((x) => x.owner === 'authentik-asgi-access'), JSON.stringify(c.map((x) => x.owner)));
});
