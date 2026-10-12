// @ts-check
//
// ESLint flat config for the backend (ESLint 10, typescript-eslint 8).
//
// A direct translation of the old .eslintrc.json:
//   extends eslint:recommended + plugin:@typescript-eslint/recommended
//     -> js.configs.recommended + tseslint.configs.recommended (the latter also
//        sets @typescript-eslint/parser and the TS overrides for core rules)
//   parserOptions { ecmaVersion: 2022, sourceType: module } -> languageOptions
//   `eslint src --ext .ts` -> files: ['**/*.ts'], so plain `eslint src` lints .ts
// plus the same three rule overrides below.
import js from '@eslint/js';
import { defineConfig } from 'eslint/config';
import tseslint from 'typescript-eslint';

export default defineConfig({
  name: 'siembox/backend',
  files: ['**/*.ts'],
  extends: [js.configs.recommended, tseslint.configs.recommended],
  languageOptions: {
    ecmaVersion: 2022,
    sourceType: 'module',
  },
  rules: {
    '@typescript-eslint/no-explicit-any': 'warn',
    '@typescript-eslint/explicit-function-return-type': 'off',
    '@typescript-eslint/no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
  },
});
