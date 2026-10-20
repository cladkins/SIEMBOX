#!/usr/bin/env node
// Builds backend/src/data/attack/enterprise.json, the trimmed MITRE ATT&CK
// Enterprise dataset SIEMBox bundles (no runtime network access).
//
// A maintainer runs this at each ATT&CK release and commits the result; the
// PR diff shows which techniques were added, renamed, revoked or deprecated.
//
//   curl -sSfLO https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json
//   node backend/scripts/update-attack.mjs enterprise-attack.json
//
// ATT&CK is (c) The MITRE Corporation, used under its terms of use
// (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';

const input = process.argv[2];
if (!input) {
  console.error('usage: node backend/scripts/update-attack.mjs <enterprise-attack.json> [out.json]');
  process.exit(2);
}
const out = process.argv[3] ?? join(import.meta.dirname, '../src/data/attack/enterprise.json');

const bundle = JSON.parse(readFileSync(input, 'utf8'));
const objects = bundle.objects ?? [];
const byStixId = new Map(objects.map((o) => [o.id, o]));
const attackId = (o) =>
  (o?.external_references ?? []).find((r) => r.source_name === 'mitre-attack')?.external_id;

const collection = objects.find((o) => o.type === 'x-mitre-collection');
const matrix = objects.find((o) => o.type === 'x-mitre-matrix' && !o.revoked && !o.x_mitre_deprecated);
if (!collection || !matrix) {
  console.error('input is not an ATT&CK Enterprise STIX bundle (no collection or matrix)');
  process.exit(1);
}

// Tactics in matrix order. Shortnames use hyphens, as in STIX kill chain phases.
const tactics = matrix.tactic_refs.map((ref, i) => {
  const t = byStixId.get(ref);
  return { id: attackId(t), shortname: t.x_mitre_shortname, name: t.name, order: i + 1 };
});
const tacticNames = new Set(tactics.map((t) => t.shortname));

// Tactic shortnames that older ATT&CK releases (and many Sigma rules) still
// use. ATT&CK v20 split Defense Evasion (TA0005) into Stealth (TA0005) and
// Defense Impairment (TA0112). Accepted with a warning, and mapped to the
// current tactics for consistency checks. Kept here so a re-run preserves it.
const legacyTactics = { 'defense-evasion': ['stealth', 'defense-impairment'] };
for (const [legacy, current] of Object.entries(legacyTactics)) {
  if (tacticNames.has(legacy)) delete legacyTactics[legacy];
  else if (!current.every((c) => tacticNames.has(c))) {
    console.error(`legacy tactic ${legacy} maps to unknown tactics ${current.join(', ')}`);
    process.exit(1);
  }
}

const revokedBy = new Map();
for (const o of objects) {
  if (o.type === 'relationship' && o.relationship_type === 'revoked-by' && !o.revoked) {
    revokedBy.set(o.source_ref, o.target_ref);
  }
}

const techniques = {};
for (const o of objects) {
  if (o.type !== 'attack-pattern') continue;
  const id = attackId(o);
  if (!id || !/^T\d{4}(\.\d{3})?$/.test(id)) continue;
  const entry = {
    name: o.name,
    tactics: (o.kill_chain_phases ?? [])
      .filter((p) => p.kill_chain_name === 'mitre-attack')
      .map((p) => p.phase_name),
    platforms: o.x_mitre_platforms ?? [],
  };
  if (o.revoked) {
    entry.revoked = true;
    // Follow chains (A revoked by B, B revoked by C) to the live technique.
    let target = revokedBy.get(o.id);
    const seen = new Set();
    while (target && byStixId.get(target)?.revoked && !seen.has(target)) {
      seen.add(target);
      target = revokedBy.get(target);
    }
    const replacement = attackId(byStixId.get(target));
    if (replacement) entry.revokedBy = replacement;
  }
  if (o.x_mitre_deprecated) entry.deprecated = true;
  const prev = techniques[id];
  // An ID appears twice only when an old object was revoked; keep the live one.
  if (prev && !prev.revoked && !prev.deprecated) continue;
  techniques[id] = entry;
}

const sortedIds = Object.keys(techniques).sort();
for (const id of sortedIds) {
  const t = techniques[id];
  if (t.revoked || t.deprecated) continue;
  if (t.tactics.length === 0) {
    console.error(`${id} has no tactic`);
    process.exit(1);
  }
  const unknown = t.tactics.filter((tac) => !tacticNames.has(tac));
  if (unknown.length > 0) {
    console.error(`${id} uses unknown tactic ${unknown.join(', ')}`);
    process.exit(1);
  }
}

const header = {
  attribution:
    'MITRE ATT&CK(R) Enterprise. (c) The MITRE Corporation. Reproduced and distributed with the permission of The MITRE Corporation under the ATT&CK terms of use: https://attack.mitre.org/resources/legal-and-branding/terms-of-use/',
  source: 'https://github.com/mitre-attack/attack-stix-data (enterprise-attack/enterprise-attack.json)',
  version: collection.x_mitre_version,
  modified: collection.modified,
};
// One technique per line keeps the file compact and the release diff readable.
const lines = ['{'];
for (const [k, v] of Object.entries(header)) lines.push(`  ${JSON.stringify(k)}: ${JSON.stringify(v)},`);
lines.push('  "tactics": [');
lines.push(tactics.map((t) => `    ${JSON.stringify(t)}`).join(',\n'));
lines.push('  ],');
lines.push(`  "legacyTactics": ${JSON.stringify(legacyTactics)},`);
lines.push('  "techniques": {');
lines.push(sortedIds.map((id) => `    ${JSON.stringify(id)}: ${JSON.stringify(techniques[id])}`).join(',\n'));
lines.push('  }');
lines.push('}');
writeFileSync(out, lines.join('\n') + '\n');

const live = sortedIds.filter((id) => !techniques[id].revoked && !techniques[id].deprecated);
console.log(
  `ATT&CK Enterprise ${header.version}: ${tactics.length} tactics, ${live.length} live techniques ` +
    `(${sortedIds.length - live.length} revoked/deprecated) -> ${out}`,
);
