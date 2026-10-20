/**
 * The bundled MITRE ATT&CK Enterprise dataset (src/data/attack/enterprise.json,
 * built by backend/scripts/update-attack.mjs from MITRE's STIX bundle; no
 * runtime network access). Loaded once, on first use.
 *
 * ATT&CK is (c) The MITRE Corporation, used under its terms of use
 * (https://attack.mitre.org/resources/legal-and-branding/terms-of-use/).
 */
import * as fs from 'fs';
import * as path from 'path';

export interface AttackTactic {
  /** TA0006 */
  id: string;
  /** credential-access (STIX form, hyphens; tags use underscores) */
  shortname: string;
  name: string;
  /** 1-based column order in the Enterprise matrix */
  order: number;
}

export interface AttackTechnique {
  name: string;
  /** Tactic shortnames (hyphen form). */
  tactics: string[];
  platforms: string[];
  revoked?: boolean;
  /** The live technique a revoked one was replaced by. */
  revokedBy?: string;
  deprecated?: boolean;
}

export interface AttackDataset {
  attribution: string;
  source: string;
  version: string;
  modified: string;
  tactics: AttackTactic[];
  /** Old tactic shortnames still seen in rules (e.g. defense-evasion) -> current ones. */
  legacyTactics: Record<string, string[]>;
  /** Keyed by canonical ID (T1110, T1110.001). */
  techniques: Record<string, AttackTechnique>;
}

const DATA_FILE = path.join(__dirname, '../../data/attack/enterprise.json');

let dataset: AttackDataset | null = null;
let tacticIndex: Map<string, AttackTactic> | null = null;

export function attackDataset(): AttackDataset {
  if (!dataset) {
    dataset = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')) as AttackDataset;
    tacticIndex = new Map(dataset.tactics.map((t) => [t.shortname, t]));
  }
  return dataset;
}

export function attackVersion(): string {
  return attackDataset().version;
}

/** A technique by canonical ID (T1110 / T1110.001), revoked and deprecated ones included. */
export function getTechnique(id: string): AttackTechnique | undefined {
  const t = attackDataset().techniques;
  return Object.prototype.hasOwnProperty.call(t, id) ? t[id] : undefined;
}

/** A current tactic by shortname (hyphen form). */
export function getTactic(shortname: string): AttackTactic | undefined {
  attackDataset();
  return tacticIndex!.get(shortname);
}

/** "Brute Force: Password Guessing" for a sub-technique, the plain name otherwise. */
export function techniqueDisplayName(id: string): string {
  const t = getTechnique(id);
  if (!t) return id;
  const dot = id.indexOf('.');
  if (dot < 0) return t.name;
  const parent = getTechnique(id.slice(0, dot));
  return parent ? `${parent.name}: ${t.name}` : t.name;
}

/** Every technique ID that is `id` or one of its sub-techniques (dataset IDs only, plus `id`). */
export function techniqueAndSubtechniques(id: string): string[] {
  const out = new Set<string>([id]);
  if (!id.includes('.')) {
    const prefix = `${id}.`;
    for (const key of Object.keys(attackDataset().techniques)) if (key.startsWith(prefix)) out.add(key);
  }
  return [...out].sort();
}

/** Every technique ID (revoked/deprecated included) listed under a tactic. */
export function techniquesForTactic(shortname: string): string[] {
  const out: string[] = [];
  for (const [id, t] of Object.entries(attackDataset().techniques)) {
    if (t.tactics.includes(shortname)) out.push(id);
  }
  return out.sort();
}
