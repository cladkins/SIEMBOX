/* ESLint flat config for the Vue 3 + TypeScript frontend. ESLint 10 dropped
 * the eslintrc format; this replaces .eslintrc.cjs and keeps its rule set.
 *
 * Linted surface is `src` only (see the `lint` script). The script needs no
 * `--ext`: in flat config the `files` patterns of the configs below select the
 * `.vue` and `.ts` files.
 *
 * withVueTs() (@vue/eslint-config-typescript) parses `.vue` files with
 * vue-eslint-parser, routes their `<script lang="ts">` blocks to the
 * TypeScript parser, and requires `lang="ts"` on every SFC script block
 * (vue/block-lang).
 *
 * Presets, same tiers as before:
 * - Vue's `flat/essential` (was `plugin:vue/vue3-essential`): bug-prevention
 *   rules only, not the stylistic tiers, since Prettier owns formatting here
 *   (`npm run format`) and the two would otherwise fight.
 * - `@eslint/js` recommended (was `eslint:recommended`).
 * - typescript-eslint's parser and plugin, plus its `eslint-recommended`
 *   compatibility set for .ts files. That is all the old
 *   `@vue/eslint-config-typescript` (v12) default export applied; the larger
 *   typescript-eslint `recommended` set was only in that package's separate
 *   `/recommended` entry, which this project did not extend.
 *
 * Rules mirror the backend's house style (backend/eslint.config.mjs) where
 * they apply: `any` is a warning, explicit return types are not required, and
 * unused vars error unless prefixed with `_`. One deliberate divergence: this
 * config pins `caughtErrors: 'none'`, so unused `catch (e)` bindings stay
 * allowed as they always were here (src has many), while the backend takes
 * typescript-eslint 8's default of 'all'.
 */
import js from '@eslint/js';
import { vueTsConfigs, withVueTs } from '@vue/eslint-config-typescript';
import pluginVue from 'eslint-plugin-vue';
import globals from 'globals';
import tseslint from 'typescript-eslint';

export default withVueTs(
  pluginVue.configs['flat/essential'],
  js.configs.recommended,
  vueTsConfigs.base,
  tseslint.configs.eslintRecommended,
  {
    languageOptions: {
      globals: {
        ...globals.browser,
      },
    },
    rules: {
      '@typescript-eslint/no-explicit-any': 'warn',
      '@typescript-eslint/explicit-function-return-type': 'off',
      // caughtErrors: typescript-eslint 8 changed the default from 'none' to
      // 'all'; keep allowing unused `catch (e)` bindings as before.
      '@typescript-eslint/no-unused-vars': [
        'error',
        { argsIgnorePattern: '^_', caughtErrors: 'none' },
      ],
      // Superseded by the @typescript-eslint version above for .ts/.vue files.
      'no-unused-vars': 'off',
    },
  },
  {
    // no-undef duplicates TypeScript's own check (vue-tsc covers SFCs) and
    // misfires on global types. The old @vue/eslint-config-typescript turned
    // it off for .vue files; eslint-recommended above does so for .ts files.
    files: ['**/*.vue'],
    rules: {
      'no-undef': 'off',
    },
  },
  {
    // Route/page components are single-word by convention (Dashboard, Login,
    // Assets, ...) and are never used as in-template tags that could clash
    // with current or future HTML elements, so multi-word-component-names
    // adds no safety here. It stays on for src/components/** (reusable
    // components), where a name collision would be a real bug.
    files: ['src/views/**/*.vue'],
    rules: {
      'vue/multi-word-component-names': 'off',
    },
  },
);
