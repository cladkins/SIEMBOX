/**
 * The alert lookup expressions: migration 043 holds exactly the indexes and
 * statistics alertKeys.ts describes (so every lookup is served by one), each
 * lookup carries its index's size guard, "the latest alerts naming X" is one
 * ordered scan per key (never an OR), and the IP spellings cover how logs
 * write addresses. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import {
  ALERT_KEY_INDEXES,
  alertIpArms,
  alertIpMatch,
  alertKeyEquals,
  alertKeyExpr,
  alertKeyIndexSql,
  alertKeyStatsName,
  alertKeyStatsSql,
  IP_KEYS,
  latestAlerts,
  MAX_INDEXED_BYTES,
} from './alertKeys';
import { ipForms } from './resolvers/alerts';
import { canonicalDomain, canonicalHost, canonicalIp, canonicalUser } from './entityKey';
import { UNKNOWN_SOURCES_SQL } from '../shippers/unknownSources';
import { SHIPPER_TAGS_SQL } from './shipperTags';

const MIGRATION = fs.readFileSync(path.join(__dirname, '../../../migrations/043_context_graph_lookups.sql'), 'utf8');

test('migration 043 holds exactly the alert key indexes alertKeys.ts describes', () => {
  for (const entry of ALERT_KEY_INDEXES) {
    assert.ok(MIGRATION.includes(alertKeyIndexSql(entry)), `043 has: ${alertKeyIndexSql(entry)}`);
  }
  const names = [...MIGRATION.matchAll(/CREATE INDEX IF NOT EXISTS (idx_graph_alerts_md_\w+|idx_graph_alerts_(?:auth|edr|dm)_\w+)/g)].map((m) => m[1]);
  assert.deepEqual(names.sort(), ALERT_KEY_INDEXES.map((e) => e.name).sort());
  // Every index on matched_data is partial on the size guard: a huge log value can't fail an alert insert.
  for (const line of MIGRATION.split('\n').filter((l) => l.startsWith('CREATE INDEX') && l.includes('matched_data'))) {
    assert.match(line, new RegExp(`WHERE .*octet_length\\(.*\\) <= ${MAX_INDEXED_BYTES};$`), line);
  }
  // And statistics on each index's expression, which Postgres keeps for no partial index.
  for (const entry of ALERT_KEY_INDEXES) {
    assert.ok(MIGRATION.includes(alertKeyStatsSql(entry)), `043 has: ${alertKeyStatsSql(entry)}`);
  }
  const stats = [...MIGRATION.matchAll(/^CREATE STATISTICS IF NOT EXISTS (\w+)/gm)].map((m) => m[1]);
  assert.deepEqual(stats.sort(), ALERT_KEY_INDEXES.map(alertKeyStatsName).sort());
  assert.ok(stats.every((name) => name.startsWith('graph_alerts_')), 'the first-fill ANALYZE finds them by that prefix');
});

test('every lookup states its index guard, so the planner can use the partial index', () => {
  assert.equal(
    alertKeyEquals('host', '$1'),
    `(lower(btrim(a.matched_data->>'host')) = $1 AND octet_length(lower(btrim(a.matched_data->>'host'))) <= ${MAX_INDEXED_BYTES})`
  );
  const ip = alertIpMatch('$2', { any: true, column: 'matched_data' });
  for (const key of ['source_ip', 'client_ip', 'dest_ip']) {
    assert.ok(ip.includes(`matched_data->>'${key}' = ANY($2::text[]) AND octet_length(matched_data->>'${key}') <= ${MAX_INDEXED_BYTES}`), ip);
  }
  // No canonical key comes near the guard: nothing a lookup can match is left out.
  assert.ok(253 * 4 < MAX_INDEXED_BYTES);
});

test('latestAlerts: one ordered scan per arm, each stopping at the limit; never an OR of keys', () => {
  const sql = latestAlerts(alertIpArms('$1'), 'a.id', 50, 'a.created_at >= $2');
  const arms = sql.split(' UNION ');
  assert.equal(arms.length, IP_KEYS.length);
  IP_KEYS.forEach((key, i) => {
    assert.equal(arms[i], `(SELECT a.id FROM alerts a WHERE ${alertKeyEquals(key, '$1')} AND a.created_at >= $2 ORDER BY a.created_at DESC LIMIT 50)`);
  });
  assert.ok(!sql.includes(' OR '), sql);
  // A single value per arm (not ANY): only then does the (key, created_at DESC) index return it in order.
  assert.ok(!sql.includes('ANY('), sql);
  assert.throws(() => latestAlerts([], 'a.id', 50), /no arms/);
  assert.throws(() => latestAlerts(['true'], 'a.id', 0), /positive integer/);
  assert.throws(() => latestAlerts(['true'], 'a.id', 1.5), /positive integer/);
});

test('the SQL expressions apply the same text rules as entityKey.ts (ASCII inputs)', () => {
  // What the SQL computes, by hand, for the inputs that differ from their key.
  const sqlLike = {
    user: (v: string) => v.replace(/^ +/, '').replace(/ +$/, ''),
    host: (v: string) => v.replace(/^ +/, '').replace(/ +$/, '').toLowerCase(),
    domain: (v: string) => v.replace(/^ +/, '').replace(/ +$/, '').toLowerCase().replace(/\.+$/, ''),
  };
  for (const v of [' root ', 'Root', 'admin  ']) assert.equal(sqlLike.user(v), canonicalUser(v));
  for (const v of [' NAS ', 'Web01.LAN']) assert.equal(sqlLike.host(v), canonicalHost(v));
  for (const v of ['Example.COM.', ' example.com.. ', 'a.b']) assert.equal(sqlLike.domain(v), canonicalDomain(v));
  assert.equal(alertKeyExpr('domain'), `rtrim(lower(btrim(matched_data->>'domain')), '.')`);
  assert.equal(alertKeyExpr('user'), `btrim(matched_data->>'user')`);
});

test('ipForms: IPv4 also as IPv4-mapped; IPv6 compressed, uncompressed and zero-padded, both cases', () => {
  assert.deepEqual(ipForms('198.51.100.7'), ['198.51.100.7', '::ffff:198.51.100.7']);
  const forms = ipForms('2001:db8::1');
  for (const spelling of ['2001:db8::1', '2001:DB8::1', '2001:db8:0:0:0:0:0:1', '2001:DB8:0:0:0:0:0:1', '2001:0db8:0000:0000:0000:0000:0000:0001', '2001:0DB8:0000:0000:0000:0000:0000:0001']) {
    assert.ok(forms.includes(spelling), spelling);
    assert.equal(canonicalIp(spelling), '2001:db8::1', 'and each spelling has that key');
  }
  assert.deepEqual(ipForms('::1').slice(0, 3), ['::1', '0:0:0:0:0:0:0:1', '0000:0000:0000:0000:0000:0000:0000:0001']);
  assert.ok(ipForms('fe80::a:b').includes('fe80:0:0:0:0:0:a:b'));
  assert.ok(ipForms('2001:db8:1::').includes('2001:db8:1:0:0:0:0:0'));
});

test('the shipper tag formula is the one Unknown Sources uses (both copies change together)', () => {
  const norm = (sql: string) => sql.replace(/\s+/g, ' ').toLowerCase();
  for (const formula of ["substring(md5(decode(api_key, 'hex')), 1, 8)", "substring(encode(sha256(decode(api_key, 'hex')), 'hex'), 1, 8)", 'substring(http_push_key_hash, 1, 8)']) {
    assert.ok(norm(SHIPPER_TAGS_SQL).includes(formula), `graph: ${formula}`);
    assert.ok(norm(UNKNOWN_SOURCES_SQL).includes(formula), `unknown sources: ${formula}`);
  }
});
