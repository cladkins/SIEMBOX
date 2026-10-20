/**
 * The bundled ATT&CK dataset and the attack.* tag checks shared by
 * validate-detections, the rule routes, catalog/pack installs and Sigma import.
 * DB-free. Run with `npm test` (tsx --test).
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import {
  attackDataset,
  getTechnique,
  techniqueAndSubtechniques,
  techniqueDisplayName,
  techniquesForTactic,
} from './attackData';
import {
  analyzeAttackTags,
  dropInvalidAttackTags,
  resolveTacticName,
  techniqueIdFromTag,
  techniqueIdsFromTags,
} from './attackTags';
import { validateRule } from '../rules/rulePortable';
import { convertSigmaYaml } from '../rules/sigmaConvert';

const rule = (tags: string[]) => ({
  name: 'attack tag test',
  severity: 'low',
  tags,
  conditions: [{ field: 'event_type', operator: 'equals', value: 'x' }],
  alert: { title: 't', description: 'd' },
});

test('dataset: version, attribution, tactics in order, every live technique has a known tactic', () => {
  const data = attackDataset();
  assert.match(data.version, /^\d+\.\d+$/);
  assert.match(data.attribution, /MITRE/);
  assert.ok(data.tactics.length >= 14);
  assert.deepEqual(
    data.tactics.map((t) => t.order),
    data.tactics.map((_t, i) => i + 1)
  );
  const tactics = new Set(data.tactics.map((t) => t.shortname));
  let live = 0;
  for (const [id, t] of Object.entries(data.techniques)) {
    assert.match(id, /^T\d{4}(\.\d{3})?$/);
    if (t.revoked || t.deprecated) continue;
    live++;
    assert.ok(t.tactics.length > 0, `${id} has a tactic`);
    for (const tac of t.tactics) assert.ok(tactics.has(tac), `${id}: ${tac} is a tactic`);
  }
  assert.ok(live > 500, `${live} live techniques`);
});

test('dataset: every revoked technique names a live replacement', () => {
  for (const [id, t] of Object.entries(attackDataset().techniques)) {
    if (!t.revoked || !t.revokedBy) continue;
    const to = getTechnique(t.revokedBy);
    assert.ok(to, `${id} -> ${t.revokedBy} exists`);
    assert.ok(!to!.revoked, `${id} -> ${t.revokedBy} is not revoked itself`);
  }
  assert.equal(getTechnique('T1086')?.revokedBy, 'T1059.001');
});

test('dataset: sub-technique lookups and names', () => {
  assert.equal(techniqueDisplayName('T1110.001'), 'Brute Force: Password Guessing');
  const fam = techniqueAndSubtechniques('T1110');
  assert.ok(fam.includes('T1110') && fam.includes('T1110.001') && fam.includes('T1110.004'));
  assert.ok(!fam.some((id) => id.startsWith('T1111')));
  assert.deepEqual(techniqueAndSubtechniques('T1110.001'), ['T1110.001']);
  assert.ok(techniquesForTactic('credential-access').includes('T1110.003'));
  assert.equal(getTechnique('constructor'), undefined);
});

test('tag parsing: canonical IDs, case-insensitive, non-attack tags ignored', () => {
  assert.equal(techniqueIdFromTag('attack.t1110.001'), 'T1110.001');
  assert.equal(techniqueIdFromTag('ATTACK.T1110'), 'T1110');
  assert.equal(techniqueIdFromTag('attack.t1110.01'), null);
  assert.equal(techniqueIdFromTag('attack.credential_access'), null);
  assert.equal(techniqueIdFromTag('ssh'), null);
  assert.deepEqual(techniqueIdsFromTags(['ssh', 'attack.t1110.001', 'attack.T1110.001', 'attack.t1078', 7]), [
    'T1078',
    'T1110.001',
  ]);
  assert.deepEqual(techniqueIdsFromTags(undefined), []);
  assert.equal(resolveTacticName('credential_access'), 'credential-access');
  assert.equal(resolveTacticName('Credential-Access'), 'credential-access');
  assert.equal(resolveTacticName('nope'), null);
  assert.equal(resolveTacticName('defense_evasion'), null);
});

test('analyze: tactics derived from techniques, explicit consistent tactic is quiet', () => {
  const r = analyzeAttackTags(['ssh', 'attack.t1110.001', 'attack.credential_access', 'attack.g0016', 'attack.s0002']);
  assert.deepEqual(r.errors, []);
  assert.deepEqual(r.warnings, []);
  assert.deepEqual(r.techniques, ['T1110.001']);
  assert.deepEqual(r.tactics, ['credential-access']);
  assert.deepEqual(r.explicitTactics, ['credential-access']);
});

test('analyze: unknown, malformed, revoked, deprecated technique and unknown tactic are errors', () => {
  const r = analyzeAttackTags(['attack.t1110.01', 'attack.t9999', 'attack.t1086', 'attack.t1026', 'attack.lunch_break']);
  assert.deepEqual(r.invalidTags, ['attack.t1110.01', 'attack.t9999', 'attack.t1086', 'attack.t1026', 'attack.lunch_break']);
  assert.match(r.errors[0], /attack\.t1110\.01: not an ATT&CK technique ID/);
  assert.match(r.errors[1], /T9999 is not a technique in ATT&CK/);
  assert.match(r.errors[2], /T1086 "PowerShell" was revoked .*; use attack\.t1059\.001 \(T1059\.001 "Command and Scripting Interpreter: PowerShell"\)/);
  assert.match(r.errors[3], /T1026 .* is deprecated/);
  assert.match(r.errors[4], /attack\.lunch_break: unknown ATT&CK tactic \(one of .*credential_access/);
  assert.deepEqual(r.techniques, []);
});

test('analyze: a tactic tag inconsistent with every technique warns; legacy defense_evasion warns', () => {
  const r = analyzeAttackTags(['attack.t1110.001', 'attack.discovery']);
  assert.deepEqual(r.errors, []);
  assert.equal(r.warnings.length, 1);
  assert.match(r.warnings[0], /attack\.discovery: none of the rule's techniques \(T1110\.001\)/);

  // Consistent with one of two techniques: no warning.
  assert.deepEqual(analyzeAttackTags(['attack.t1110.001', 'attack.t1087', 'attack.discovery']).warnings, []);
  // A tactic alone (no technique) is fine.
  assert.deepEqual(analyzeAttackTags(['attack.discovery']).warnings, []);

  const legacy = analyzeAttackTags(['attack.defense_evasion']);
  assert.deepEqual(legacy.errors, []);
  assert.match(legacy.warnings[0], /became attack\.stealth and attack\.defense_impairment/);
});

test('validateRule: attack errors fail in strict and non-strict mode, warnings pass', () => {
  for (const strict of [true, false]) {
    const bad = validateRule(rule(['attack.t1110.01']), { strict });
    assert.equal(bad.ok, false);
    assert.match(bad.errors.join('\n'), /attack\.t1110\.01/);
    const revoked = validateRule(rule(['attack.t1086']), { strict });
    assert.equal(revoked.ok, false);
    assert.match(revoked.errors.join('\n'), /use attack\.t1059\.001/);
    const tactic = validateRule(rule(['attack.credentials']), { strict });
    assert.equal(tactic.ok, false);
  }
  const warn = validateRule(rule(['attack.t1110.001', 'attack.impact']), { strict: true });
  assert.equal(warn.ok, true);
  assert.equal(warn.warnings.length, 1);
  assert.equal(validateRule(rule(['ssh', 'brute-force', 'attack.t1110.001']), { strict: true }).ok, true);
});

test('dropInvalidAttackTags keeps good tags and explains each dropped one', () => {
  const d = dropInvalidAttackTags(['sigma', 'attack.t1086', 'attack.t1059.001', 'attack.execution', 'attack.bogus']);
  assert.deepEqual(d.tags, ['sigma', 'attack.t1059.001', 'attack.execution']);
  assert.equal(d.warnings.length, 2);
  assert.match(d.warnings[0], /^Dropped ATT&CK tag attack\.t1086: .*use attack\.t1059\.001/);
  assert.match(d.warnings[1], /^Dropped ATT&CK tag attack\.bogus/);
  const same = ['a', 'attack.t1110'];
  assert.equal(dropInvalidAttackTags(same).tags, same);
});

test('Sigma conversion drops unknown/revoked attack tags with a warning and still converts', () => {
  const [r] = convertSigmaYaml(
    [
      'title: Stale community rule',
      'level: high',
      'tags: [attack.execution, attack.t1086, attack.t1059.001, attack.t1110.01]',
      'detection:',
      '  sel:',
      '    CommandLine|contains: powershell',
      '  condition: sel',
    ].join('\n')
  );
  assert.ok(r.rule, r.errors.join('; '));
  assert.deepEqual(r.rule!.tags, ['sigma', 'imported', 'attack.execution', 'attack.t1059.001']);
  assert.ok(r.warnings.some((w) => /Dropped ATT&CK tag attack\.t1086: .*revoked/.test(w)));
  assert.ok(r.warnings.some((w) => /Dropped ATT&CK tag attack\.t1110\.01/.test(w)));
  assert.equal(validateRule(r.rule, { strict: false }).ok, true);
});
