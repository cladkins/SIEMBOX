import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';

// TEMPLATES_DIR is read from NUCLEI_TEMPLATES_DIR at module load time, so it
// must be set before this module is first imported. The import itself must
// stay un-awaited at the top level (this project transpiles tests as CJS,
// which rejects top-level await) -- each test awaits the same promise instead.
const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'nuclei-templates-test-'));
fs.mkdirSync(path.join(tmpDir, 'http', 'exposed-panels'), { recursive: true });
const panelPath = path.join(tmpDir, 'http', 'exposed-panels', 'openwebui-panel.yaml');
fs.writeFileSync(
  panelPath,
  'id: openwebui-panel\ninfo:\n  name: OpenWebUI Panel\n  author: test\n  severity: info\n  tags: panel,openwebui\n'
);
process.env.NUCLEI_TEMPLATES_DIR = tmpDir;

const templateServicePromise = import('./templateService');

test('resolveTemplateIds resolves a known template ID to its on-disk file path', async () => {
  const { TemplateService } = await templateServicePromise;
  const { found, missing } = await TemplateService.resolveTemplateIds(['openwebui-panel']);
  assert.deepEqual(missing, []);
  assert.equal(found.get('openwebui-panel'), panelPath);
});

test('resolveTemplateIds reports an unknown ID as missing rather than guessing a path', async () => {
  const { TemplateService } = await templateServicePromise;
  const { found, missing } = await TemplateService.resolveTemplateIds(['openwebui-panel', 'openwebui-default-login']);
  assert.equal(found.size, 1);
  assert.deepEqual(missing, ['openwebui-default-login']);
});
