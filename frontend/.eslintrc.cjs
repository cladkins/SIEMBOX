/* ESLint config for the Vue 3 + TypeScript frontend.
 *
 * Uses the eslintrc format (not flat config) to match the installed toolchain:
 * eslint 8, @vue/eslint-config-typescript 12, eslint-plugin-vue 9. Must be
 * `.cjs` because package.json is `"type": "module"`.
 *
 * Linted surface is `src` only (see the `lint` script). Extends order matters:
 * eslint-plugin-vue sets vue-eslint-parser as the top-level parser, and
 * @vue/eslint-config-typescript must come last so its parser map (routing
 * `<script lang="ts">` and .ts files to @typescript-eslint/parser) wins.
 *
 * Scope matches the backend's errors-only philosophy: Vue's `vue3-essential`
 * tier (bug-prevention rules, no formatting) rather than the stylistic
 * `vue3-recommended`, since Prettier owns formatting here (`npm run format`)
 * and the two would otherwise fight.
 *
 * Rules mirror the backend's .eslintrc.json house style where they apply:
 * `any` is a warning, explicit return types are not required, and unused vars
 * error unless prefixed with `_`.
 */
module.exports = {
  root: true,
  env: {
    browser: true,
    es2022: true,
  },
  extends: [
    'plugin:vue/vue3-essential',
    'eslint:recommended',
    '@vue/eslint-config-typescript',
  ],
  parserOptions: {
    ecmaVersion: 'latest',
    sourceType: 'module',
  },
  rules: {
    '@typescript-eslint/no-explicit-any': 'warn',
    '@typescript-eslint/explicit-function-return-type': 'off',
    '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    // Superseded by the @typescript-eslint version above for .ts/.vue files.
    'no-unused-vars': 'off',
  },
  overrides: [
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
  ],
};
