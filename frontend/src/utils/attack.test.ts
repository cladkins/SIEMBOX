import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import {
  addTechniqueTag,
  alertBucket,
  attackTechniqueUrl,
  buildMatrixColumns,
  buildTechniqueIndex,
  compareTechniqueIds,
  formatPercent,
  gapsFilled,
  isTechniqueId,
  nothingTagged,
  removeTechniqueTag,
  searchTechniques,
  tacticFromTag,
  tagsMatchAttackFilter,
  techniqueIdFromTag,
  techniqueIdsFromTags,
  techniqueLabel,
  techniqueTag,
  type CoverageTechnique,
  type CoverageTactic,
} from './attack.ts';
import { problemFromError } from './regexSafety.ts';

const matrix = {
  tactics: [
    {
      id: 'TA0006',
      shortname: 'credential-access',
      name: 'Credential Access',
      order: 9,
      techniques: [
        {
          id: 'T1110',
          name: 'Brute Force',
          platforms: ['Linux'],
          subtechniques: [
            { id: 'T1110.001', name: 'Password Guessing', platforms: ['Linux'] },
            { id: 'T1110.003', name: 'Password Spraying', platforms: ['Linux'] },
          ],
        },
      ],
    },
    {
      id: 'TA0002',
      shortname: 'execution',
      name: 'Execution',
      order: 3,
      techniques: [
        {
          id: 'T1059',
          name: 'Command and Scripting Interpreter',
          platforms: ['Linux'],
          subtechniques: [{ id: 'T1059.004', name: 'Unix Shell', platforms: ['Linux'] }],
        },
      ],
    },
    {
      id: 'TA0004',
      shortname: 'privilege-escalation',
      name: 'Privilege Escalation',
      order: 5,
      techniques: [{ id: 'T1078', name: 'Valid Accounts', platforms: ['Linux'], subtechniques: [] }],
    },
    {
      id: 'TA0001',
      shortname: 'initial-access',
      name: 'Initial Access',
      order: 2,
      techniques: [{ id: 'T1078', name: 'Valid Accounts', platforms: ['Linux'], subtechniques: [] }],
    },
  ],
};
const index = buildTechniqueIndex(matrix);

describe('technique tags', () => {
  it('parses technique and sub-technique tags in any case', () => {
    assert.equal(techniqueIdFromTag('attack.t1110.001'), 'T1110.001');
    assert.equal(techniqueIdFromTag('ATTACK.T1110'), 'T1110');
    assert.equal(techniqueIdFromTag('attack.t1110.01'), null);
    assert.equal(techniqueIdFromTag('attack.credential_access'), null);
    assert.equal(techniqueIdFromTag('ssh'), null);
  });

  it('writes the lower-case Sigma form', () => {
    assert.equal(techniqueTag('T1110.001'), 'attack.t1110.001');
  });

  it('reads tactic tags as hyphenated shortnames, not groups or software', () => {
    assert.equal(tacticFromTag('attack.credential_access'), 'credential-access');
    assert.equal(tacticFromTag('attack.g0016'), null);
    assert.equal(tacticFromTag('attack.t1110'), null);
  });

  it('collects technique IDs once, sorted', () => {
    assert.deepEqual(techniqueIdsFromTags(['attack.t1110.001', 'ssh', 'ATTACK.T1110.001', 'attack.t1059']), [
      'T1059',
      'T1110.001',
    ]);
    assert.deepEqual(techniqueIdsFromTags('nope'), []);
  });

  it('adds a technique tag once and removes it in any case', () => {
    const tags = addTechniqueTag(['ssh'], 't1110.001');
    assert.deepEqual(tags, ['ssh', 'attack.t1110.001']);
    assert.deepEqual(addTechniqueTag(tags, 'T1110.001'), tags);
    assert.deepEqual(addTechniqueTag(tags, 'bogus'), tags);
    assert.deepEqual(removeTechniqueTag(['ATTACK.T1110.001', 'ssh'], 'T1110.001'), ['ssh']);
  });

  it('validates IDs', () => {
    assert.ok(isTechniqueId('t1110'));
    assert.ok(isTechniqueId('T1110.001'));
    assert.ok(!isTechniqueId('T111'));
  });
});

describe('attackTechniqueUrl', () => {
  it('links techniques and sub-techniques', () => {
    assert.equal(attackTechniqueUrl('T1110'), 'https://attack.mitre.org/techniques/T1110/');
    assert.equal(attackTechniqueUrl('t1110.001'), 'https://attack.mitre.org/techniques/T1110/001/');
  });
});

describe('technique index and search', () => {
  it('names sub-techniques with their parent and merges tactics', () => {
    assert.equal(index.byId.get('T1110.001')?.fullName, 'Brute Force: Password Guessing');
    assert.equal(index.byId.get('T1110.001')?.parentId, 'T1110');
    assert.deepEqual(index.byId.get('T1078')?.tactics, ['initial-access', 'privilege-escalation']);
    assert.deepEqual(
      index.tactics.map((t) => t.shortname),
      ['initial-access', 'execution', 'privilege-escalation', 'credential-access']
    );
    assert.equal(techniqueLabel(index, 'T1059.004'), 'T1059.004 Command and Scripting Interpreter: Unix Shell');
    assert.equal(techniqueLabel(index, 'T9999'), 'T9999');
  });

  it('orders IDs numerically with sub-techniques after their parent', () => {
    assert.deepEqual(['T1110.001', 'T1078', 'T1110', 'T1059.004'].sort(compareTechniqueIds), [
      'T1059.004',
      'T1078',
      'T1110',
      'T1110.001',
    ]);
  });

  it('ranks exact ID, ID prefix, name prefix, then substring', () => {
    assert.deepEqual(
      searchTechniques(index, 't1110').map((t) => t.id),
      ['T1110', 'T1110.001', 'T1110.003']
    );
    assert.deepEqual(
      searchTechniques(index, 'password').map((t) => t.id),
      ['T1110.001', 'T1110.003']
    );
    assert.deepEqual(
      searchTechniques(index, 'shell').map((t) => t.id),
      ['T1059.004']
    );
    assert.equal(searchTechniques(index, '', 2).length, 2);
    assert.deepEqual(searchTechniques(null, 'x'), []);
  });
});

describe('tagsMatchAttackFilter', () => {
  const tags = ['ssh', 'attack.t1110.001'];
  it('matches a parent filter on a sub-technique tag, not the reverse', () => {
    assert.ok(tagsMatchAttackFilter(tags, { technique: 'T1110' }, index));
    assert.ok(tagsMatchAttackFilter(tags, { technique: 't1110.001' }, index));
    assert.ok(!tagsMatchAttackFilter(['attack.t1110'], { technique: 'T1110.001' }, index));
    assert.ok(!tagsMatchAttackFilter(tags, { technique: 'T1059' }, index));
  });

  it('matches a tactic through the techniques or an explicit tactic tag', () => {
    assert.ok(tagsMatchAttackFilter(tags, { tactic: 'credential_access' }, index));
    assert.ok(!tagsMatchAttackFilter(tags, { tactic: 'execution' }, index));
    assert.ok(tagsMatchAttackFilter(['attack.execution'], { tactic: 'execution' }, index));
  });

  it('passes everything with no filter, and nothing tagged with one', () => {
    assert.ok(tagsMatchAttackFilter(['ssh'], {}, index));
    assert.ok(!tagsMatchAttackFilter(undefined, { technique: 'T1110' }, index));
  });
});

function tech(id: string, level: CoverageTechnique['level'], extra: Partial<CoverageTechnique> = {}): CoverageTechnique {
  return {
    id,
    name: id,
    parent_id: id.includes('.') ? id.split('.')[0] : null,
    tactics: ['credential-access'],
    platforms: ['Linux'],
    level,
    proven_by: null,
    excluded: false,
    exclusion: null,
    alerts_30d: 0,
    last_alert: null,
    rules: [],
    ...extra,
  };
}

describe('gapsFilled', () => {
  it('lists tagged techniques at none that are not excluded', () => {
    const coverage = new Map([
      ['T1110', tech('T1110', 'covered')],
      ['T1110.003', tech('T1110.003', 'none')],
      ['T1059', tech('T1059', 'none', { excluded: true })],
    ]);
    assert.deepEqual(gapsFilled(['attack.t1110', 'attack.t1110.003', 'attack.t1059', 'attack.t1078'], coverage), [
      'T1110.003',
    ]);
    assert.deepEqual(gapsFilled([], coverage), []);
  });
});

describe('formatting', () => {
  it('formats percentages', () => {
    assert.equal(formatPercent(null), '–');
    assert.equal(formatPercent(3), '3 %');
    assert.equal(formatPercent(11.76), '11.8 %');
  });

  it('buckets alert counts on fixed steps', () => {
    assert.deepEqual([0, 1, 9, 10, 99, 100, 1000, -1].map(alertBucket), [0, 1, 1, 2, 2, 3, 4, 0]);
  });

  it('detects a coverage with nothing tagged', () => {
    const by = { none: 10, disabled: 0, no_data: 0, covered: 0, proven: 0 };
    assert.ok(nothingTagged({ in_scope: 10, by_level: by }));
    assert.ok(!nothingTagged({ in_scope: 10, by_level: { ...by, none: 9, covered: 1 } }));
    assert.ok(!nothingTagged({ in_scope: 0, by_level: by }));
  });
});

describe('buildMatrixColumns', () => {
  const tactic = (shortname: string, order: number): CoverageTactic => ({
    id: shortname,
    shortname,
    name: shortname,
    order,
    in_scope: 0,
    excluded: 0,
    counted: 0,
    covered: 0,
    proven: 0,
    percent: null,
    by_level: { none: 0, disabled: 0, no_data: 0, covered: 0, proven: 0 },
  });
  const coverage = {
    tactics: [tactic('credential-access', 9), tactic('execution', 3)],
    techniques: [
      tech('T1110', 'proven', { name: 'Brute Force' }),
      tech('T1110.001', 'proven', { name: 'Password Guessing' }),
      tech('T1110.003', 'none', { name: 'Password Spraying' }),
      tech('T1003', 'none', { name: 'OS Credential Dumping' }),
      tech('T1059', 'none', { name: 'Command and Scripting Interpreter', tactics: ['execution'] }),
    ],
  };

  it('orders columns by tactic and cells by name, with no sub-techniques by default', () => {
    const cols = buildMatrixColumns(coverage);
    assert.deepEqual(
      cols.map((c) => c.tactic.shortname),
      ['execution', 'credential-access']
    );
    assert.deepEqual(
      cols[1].cells.map((c) => c.technique.id),
      ['T1110', 'T1003']
    );
    assert.ok(cols.every((c) => c.cells.every((cell) => cell.subs.length === 0)));
  });

  it('shows sub-techniques when asked', () => {
    const cols = buildMatrixColumns(coverage, { showSubtechniques: true });
    assert.deepEqual(
      cols[1].cells[0].subs.map((s) => s.id),
      ['T1110.001', 'T1110.003']
    );
  });

  it('keeps a parent whose sub-technique matches the search, showing only that one', () => {
    const cols = buildMatrixColumns(coverage, { search: 'spraying' });
    assert.deepEqual(
      cols[1].cells.map((c) => [c.technique.id, c.subs.map((s) => s.id)]),
      [['T1110', ['T1110.003']]]
    );
    assert.equal(cols[0].cells.length, 0);
  });

  it('searches by ID', () => {
    const cols = buildMatrixColumns(coverage, { search: 't1059' });
    assert.deepEqual(
      cols[0].cells.map((c) => c.technique.id),
      ['T1059']
    );
  });
});

describe('problemFromError (ATTACK_TAG_INVALID)', () => {
  it('lists each refused tag inline, like a refused regex', () => {
    const problem = problemFromError(
      {
        response: {
          status: 422,
          data: {
            code: 'ATTACK_TAG_INVALID',
            message: 'Rule "x" was not saved: attack.t1086: …',
            errors: ['attack.t1086: T1086 "PowerShell" was revoked in ATT&CK 20.0; use attack.t1059.001'],
          },
        },
      },
      'Failed to save rule'
    );
    assert.equal(problem.type, 'error');
    assert.equal(problem.code, 'ATTACK_TAG_INVALID');
    assert.match(problem.title, /ATT&CK tag/);
    assert.deepEqual(problem.lines, [
      'attack.t1086: T1086 "PowerShell" was revoked in ATT&CK 20.0; use attack.t1059.001',
    ]);
  });

  it('falls back to the message without an errors list', () => {
    const problem = problemFromError({ response: { data: { code: 'ATTACK_TAG_INVALID', message: 'bad tag' } } }, 'x');
    assert.deepEqual(problem.lines, ['bad tag']);
  });
});
