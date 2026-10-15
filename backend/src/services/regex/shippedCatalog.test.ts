/**
 * Every parser in catalog/parsers and every rule in rules/ passes the write-time
 * regex gate: the content SIEMBox ships must still install once the gate is
 * on. (Indeterminate verdicts are allowed, as the gate allows them; a proven
 * vulnerable regex fails here before it can fail a user's install.) Analyses
 * run in the scan workers, a few items at a time. DB-free; `npm test`.
 */
import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'fs';
import * as path from 'path';
import * as yaml from '../../utils/yaml';
import { assessParserRegexes, assessRuleRegexes, closeRegexScanPool, setVerdictStore, type RegexSafetyReport } from './regexSafety';

setVerdictStore(null);
after(async () => {
  await closeRegexScanPool();
});

const ROOT = path.join(__dirname, '..', '..', '..', '..');

function filesUnder(dir: string, suffix: string): string[] {
  return fs
    .readdirSync(dir, { recursive: true, withFileTypes: true })
    .filter((e) => e.isFile() && e.name.endsWith(suffix))
    .map((e) => path.join(e.parentPath ?? (e as any).path, e.name))
    .sort();
}

async function inBatches<T>(items: T[], size: number, run: (item: T) => Promise<void>): Promise<void> {
  for (let i = 0; i < items.length; i += size) await Promise.all(items.slice(i, i + size).map(run));
}

function vulnerableLines(file: string, report: RegexSafetyReport): string[] {
  return report.errors.map((e) => `${path.relative(ROOT, file)}: ${e}`);
}

test('every shipped catalog parser and detection rule passes the regex gate', { timeout: 600_000 }, async () => {
  const parsers = filesUnder(path.join(ROOT, 'catalog', 'parsers'), '.parser.json');
  const rules = filesUnder(path.join(ROOT, 'rules'), '.yaml');
  assert.ok(parsers.length > 20 && rules.length > 20, `found ${parsers.length} parsers and ${rules.length} rules`);

  const refused: string[] = [];
  await inBatches(parsers, 4, async (file) => {
    refused.push(...vulnerableLines(file, await assessParserRegexes(JSON.parse(fs.readFileSync(file, 'utf8')))));
  });
  await inBatches(rules, 4, async (file) => {
    refused.push(...vulnerableLines(file, await assessRuleRegexes(yaml.load(fs.readFileSync(file, 'utf8')))));
  });
  assert.deepEqual(refused, [], `shipped content the gate would refuse:\n${refused.join('\n')}`);
});
