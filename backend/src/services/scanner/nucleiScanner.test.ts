import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

// NUCLEI_TEMPLATES_DIR is read at module load time by both templateService.ts
// and nucleiScanner.ts, so it must be set before either is first imported. The
// imports themselves must stay un-awaited at the top level (this project
// transpiles tests as CJS, which rejects top-level await) -- each test awaits
// the same promises instead.
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nuclei-templates-test-'));
fs.mkdirSync(path.join(tmpDir, 'http', 'exposed-panels'), { recursive: true });
const panelPath = path.join(tmpDir, 'http', 'exposed-panels', 'openwebui-panel.yaml');
fs.writeFileSync(
  panelPath,
  'id: openwebui-panel\ninfo:\n  name: OpenWebUI Panel\n  author: test\n  severity: info\n  tags: panel,openwebui\n'
);
process.env.NUCLEI_TEMPLATES_DIR = tmpDir;

const nucleiScannerPromise = import('./nucleiScanner');
const errorLogServicePromise = import('../errors/errorLogService');

type Scanner = {
  buildNucleiArgs(scanId: number, options: unknown): Promise<string[]>;
};

async function getScanner(): Promise<Scanner> {
  const [{ NucleiScanner }, { ErrorLogService }] = await Promise.all([nucleiScannerPromise, errorLogServicePromise]);
  // Resolution failures log a background error, which writes to the
  // database. Stub it so these tests don't depend on a live database.
  ErrorLogService.logBackgroundError = () => {};
  return NucleiScanner as unknown as Scanner;
}

test('buildNucleiArgs resolves a bare template ID to its real file path, not the literal ID', async () => {
  const scanner = await getScanner();
  const args = await scanner.buildNucleiArgs(1, {
    target: 'https://example.com',
    templateSelection: { templates: ['openwebui-panel'] },
    userId: 1,
  });

  assert.ok(args.includes(panelPath), `expected resolved path in args, got: ${args.join(' ')}`);
  assert.ok(!args.includes('openwebui-panel'), 'bare template ID must not be passed straight to nuclei');
});

test('buildNucleiArgs throws a clear error instead of invoking nuclei with zero templates', async () => {
  const scanner = await getScanner();
  await assert.rejects(
    () =>
      scanner.buildNucleiArgs(2, {
        target: 'https://example.com',
        templateSelection: { templates: ['openwebui-panel-typo', 'openwebui-default-login'] },
        userId: 1,
      }),
    /None of the selected templates could be found/
  );
});

test('buildNucleiArgs still runs on a tag fallback when some selected templates are unresolvable', async () => {
  const scanner = await getScanner();
  const args = await scanner.buildNucleiArgs(3, {
    target: 'https://example.com',
    templateSelection: { templates: ['does-not-exist'], tags: ['cve'] },
    userId: 1,
  });

  assert.ok(args.includes('-tags'));
  assert.ok(args.includes('cve'));
});

test('buildNucleiArgs passes category directories through untouched', async () => {
  const scanner = await getScanner();
  const args = await scanner.buildNucleiArgs(4, {
    target: 'https://example.com',
    templateSelection: { templates: ['http/'] },
    userId: 1,
  });

  const flagIndex = args.indexOf('-t');
  assert.equal(args[flagIndex + 1], 'http/');
});
