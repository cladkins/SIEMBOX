/**
 * The lint fixture for the display page's isolation (BIG-DISPLAY.md §4.4):
 * code under src/display that imports the app's auth store, API client,
 * router or Element Plus, or touches browser storage, fails `npm run lint`.
 * Runs the project's own eslint.config.js on snippets placed in src/display.
 */
import { describe, it } from 'node:test';
import assert from 'node:assert/strict';
import { fileURLToPath } from 'node:url';
import { ESLint } from 'eslint';

const cwd = fileURLToPath(new URL('../..', import.meta.url));
const eslint = new ESLint({ cwd });

async function problems(code: string, file = 'src/display/fixture.ts'): Promise<string[]> {
  const [result] = await eslint.lintText(code, { filePath: `${cwd}/${file}` });
  return result.messages.filter((m) => m.severity === 2).map((m) => m.ruleId ?? 'parse');
}

describe('display isolation lint rules', () => {
  it("refuse the app's session, API client, router and components", async () => {
    for (const source of [
      '@/stores/auth',
      '@/services/api',
      '@/router',
      '@/views/Dashboard.vue',
      '@/components/AlertsCountryMap.vue',
      '../stores/auth',
      '../../services/api',
      'axios',
      'pinia',
      'vue-router',
      'element-plus',
      '@element-plus/icons-vue',
    ]) {
      assert.deepEqual(await problems(`import x from '${source}';\nexport default x;\n`), ['no-restricted-imports'], source);
    }
  });

  it('refuse localStorage and sessionStorage, however they are reached', async () => {
    for (const code of [
      "localStorage.getItem('token');",
      "window.localStorage.getItem('token');",
      "globalThis.localStorage.setItem('user', '');",
      "sessionStorage.setItem('x', '1');",
      "window.sessionStorage.clear();",
    ]) {
      const found = await problems(`${code}\n`);
      assert.ok(found.length === 1 && /no-restricted-(globals|properties)/.test(found[0]), `${code}: ${found}`);
    }
  });

  it('apply to .vue files too', async () => {
    const sfc = `<script setup lang="ts">\nimport { useAuthStore } from '@/stores/auth';\nuseAuthStore();\n</script>\n<template><p /></template>\n`;
    assert.deepEqual(await problems(sfc, 'src/display/board/BoardFixture.vue'), ['no-restricted-imports']);
  });

  it('let reload.ts use sessionStorage for its flag, but never localStorage', async () => {
    assert.deepEqual(await problems("sessionStorage.setItem('siembox.display.chunk-reloaded', '1');\n", 'src/display/reload.ts'), []);
    assert.equal((await problems("localStorage.getItem('token');\n", 'src/display/reload.ts')).length, 1);
  });

  it('leave the rest of the app alone', async () => {
    assert.deepEqual(await problems("import { useAuthStore } from '@/stores/auth';\nuseAuthStore();\n", 'src/views/Fixture.ts'), []);
  });
});
