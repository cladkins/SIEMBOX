/**
 * Can a rule ever fire at all?
 *
 * A detection rule is data, and nothing checks it against the vocabulary the
 * parsers actually speak. `validate-detections` proves a rule is well-formed;
 * it cannot tell you that no log will ever satisfy it. Such a rule installs
 * cleanly, shows as enabled, and silently never fires.
 *
 * This was found the hard way. A rule for blocked traffic from a malicious IP
 * was written as:
 *
 *     event_type equals "firewall_event"   AND   action equals "blocked"
 *
 * Both values are real — but they belong to DIFFERENT subsystems.
 * netfilter-firewall emits firewall_event with action drop/reject; the UniFi
 * IDS/IPS parsers emit ids_ips_alert with action blocked. No parser emits that
 * pair, so the rule matched nothing at all. Checking each field on its own does
 * not catch it: both values pass in isolation. The bug is the CO-OCCURRENCE.
 *
 * Two checks below, in increasing strength:
 *   1. every event_type a rule pins must be one some parser can emit;
 *   2. any rule pinning both event_type and action must be satisfiable by some
 *      field-set the catalog's own test samples really produce.
 *
 * Disabled rules are exempt: APP-001 and IOT-001 are parked precisely because
 * their event_type is unreachable, and say so in a comment. Run with `npm test`.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'fs';
import * as path from 'path';
import * as yaml from 'js-yaml';
import { runParser, ParserDef } from '../parser/runParser';
import { evaluatePureCondition, PURE_CONDITION_OPERATORS } from './conditionMatch';

const CATALOG = path.join(__dirname, '../../../../catalog/parsers');
const RULES = path.join(__dirname, '../../../../rules');

function loadParsers(): ParserDef[] {
  return fs
    .readdirSync(CATALOG)
    .filter((f) => f.endsWith('.parser.json'))
    .map((f) => JSON.parse(fs.readFileSync(path.join(CATALOG, f), 'utf8')) as ParserDef);
}

function loadRules(): Array<{ file: string; doc: any }> {
  const out: Array<{ file: string; doc: any }> = [];
  (function walk(dir: string) {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) walk(full);
      else if (entry.name.endsWith('.yaml')) {
        out.push({ file: path.relative(RULES, full), doc: yaml.load(fs.readFileSync(full, 'utf8')) });
      }
    }
  })(RULES);
  return out;
}

/** event_type values reachable from the catalog: declared, or set by a derivation. */
function emittableEventTypes(): Set<string> {
  const types = new Set<string>();
  for (const parser of loadParsers()) {
    if (parser.event_type) types.add(parser.event_type);
    for (const d of (parser.derivations as any[]) || []) {
      if (d?.set?.event_type) types.add(String(d.set.event_type));
    }
  }
  // runParser.determineEventType synthesises these when a parser declares none,
  // so they are reachable without appearing in any parser file.
  for (const synthesised of [
    'ssh_failed_login', 'ssh_successful_login', 'ssh_auth',
    'vaultwarden_failed_login', 'vaultwarden_successful_login',
    'vaultwarden_vault_export', 'vaultwarden_device_registered', 'vaultwarden_event',
    'http_request', 'sudo_command', 'firewall_event', 'generic',
  ]) types.add(synthesised);
  return types;
}

/**
 * Every field-set the catalog can really produce, by running each parser's own
 * test_samples through the real parse -> derive -> normalize pipeline. Samples
 * are not exhaustive, which is why this backs a co-occurrence check rather than
 * a per-value one — a pair no sample produces is a strong smell.
 */
function sampleFieldSets(): Array<Record<string, any>> {
  const sets: Array<Record<string, any>> = [];
  for (const parser of loadParsers()) {
    for (const sample of ((parser as any).test_samples as any[]) || []) {
      const input = typeof sample === 'string' ? sample : sample.input;
      const result = runParser(parser, input, { packetSourceIp: '203.0.113.1' });
      if (result) sets.push(result.fields);
    }
  }
  return sets;
}

const PINNABLE = ['event_type', 'action'];

function pinnedConditions(doc: any): any[] {
  return (doc?.conditions || []).filter(
    (c: any) => PURE_CONDITION_OPERATORS.has(c.operator) && PINNABLE.includes(c.field)
  );
}

test('every rule pins an event_type some parser can actually emit', () => {
  const emittable = emittableEventTypes();
  const unreachable: string[] = [];

  for (const { file, doc } of loadRules()) {
    if (doc?.enabled === false) continue;
    for (const cond of doc?.conditions || []) {
      if (cond.field !== 'event_type') continue;
      if (cond.operator !== 'equals' && cond.operator !== 'in') continue;
      const values = Array.isArray(cond.value) ? cond.value.map(String) : [String(cond.value)];
      const missing = values.filter((v) => !emittable.has(v));
      if (missing.length) unreachable.push(`${file}: ${JSON.stringify(missing)}`);
    }
  }

  assert.deepEqual(unreachable, [], `rules gated on an event_type no parser emits:\n${unreachable.join('\n')}`);
});

test('a rule pinning both event_type and action is satisfiable by real parser output', () => {
  // The check that would have caught firewall_event + blocked.
  const universe = sampleFieldSets();
  assert.ok(universe.length > 50, `expected a broad sample corpus, got ${universe.length}`);

  const unsatisfiable: string[] = [];
  for (const { file, doc } of loadRules()) {
    if (doc?.enabled === false) continue;
    const pinned = pinnedConditions(doc);
    if (pinned.length < 2) continue; // co-occurrence needs at least two pinned fields

    const satisfiable = universe.some((fields) =>
      pinned.every((c) => evaluatePureCondition(c.operator, fields[c.field], c.value))
    );
    if (!satisfiable) {
      unsatisfiable.push(`${file}: ${pinned.map((c) => `${c.field} ${c.operator} ${JSON.stringify(c.value)}`).join(' AND ')}`);
    }
  }

  assert.deepEqual(
    unsatisfiable,
    [],
    `no parser output satisfies these rules — check the event_type and action vocabularies match the same subsystem:\n${unsatisfiable.join('\n')}`
  );
});

test('the co-occurrence check actually catches the bug it was written for', () => {
  // A check that never fires is indistinguishable from a broken one. This pins
  // that the real, historical mistake IS rejected, and that the fix passes.
  const universe = sampleFieldSets();
  const satisfiedBy = (conds: Array<{ field: string; operator: string; value: any }>) =>
    universe.some((f) => conds.every((c) => evaluatePureCondition(c.operator, f[c.field], c.value)));

  const broken = [
    { field: 'event_type', operator: 'equals', value: 'firewall_event' },
    { field: 'action', operator: 'equals', value: 'blocked' },
  ];
  assert.equal(satisfiedBy(broken), false, 'the known-dead pairing should be unsatisfiable');

  // ...while each half is individually fine, which is why per-field checks miss it.
  assert.equal(satisfiedBy([broken[0]]), true, 'firewall_event alone is emitted');
  assert.equal(satisfiedBy([broken[1]]), true, 'action=blocked alone is emitted');

  const fixed = [
    { field: 'event_type', operator: 'in', value: ['firewall_event', 'ids_ips_alert'] },
    { field: 'action', operator: 'in', value: ['drop', 'reject', 'blocked'] },
  ];
  assert.equal(satisfiedBy(fixed), true, 'TI-002 as shipped must be satisfiable');
});

test('TI-002 covers both blocking subsystems, not just one', () => {
  // The rule's whole point: a firewall drop and an IPS block are the same event
  // class described in two vocabularies. Losing either half silently halves it.
  const doc: any = yaml.load(
    fs.readFileSync(path.join(RULES, 'network/TI-002-blocked-malicious-ip.yaml'), 'utf8')
  );
  const pinned = pinnedConditions(doc);

  for (const [label, parserName] of [
    ['IDS/IPS block', 'ubiquiti-unifi-ids-ips'],
    ['firewall drop', 'netfilter-firewall'],
  ] as Array<[string, string]>) {
    const parser = loadParsers().find((p) => p.name === parserName)!;
    const matched = ((parser as any).test_samples as any[]).some((s) => {
      const result = runParser(parser, typeof s === 'string' ? s : s.input, {});
      return result && pinned.every((c) => evaluatePureCondition(c.operator, result.fields[c.field], c.value));
    });
    assert.ok(matched, `TI-002 no longer matches a ${label} (${parserName})`);
  }
});
