import { defineConfig } from 'vitest/config';
import vue from '@vitejs/plugin-vue';
import path from 'path';

export default defineConfig({
  plugins: [vue()],
  test: {
    globals: true,
    environment: 'happy-dom',
    setupFiles: ['./test/setup.ts'],
    coverage: {
      provider: 'v8',
      reporter: ['text', 'html', 'lcov', 'json-summary'],
      include: ['src/**/*.{js,ts,vue}'],
      exclude: [
        '**/*.test.{js,ts}',
        '**/*.spec.{js,ts}',
        '**/node_modules/**',
        '**/test/**',
        '**/*.d.ts',
        '**/types/**',
      ],
      thresholds: {
        lines: 50,
        functions: 50,
        branches: 50,
        statements: 50,
        // Higher thresholds for critical stores
        'src/stores/auth.ts': {
          lines: 85,
          functions: 85,
          branches: 85,
          statements: 85,
        },
      },
    },
  },
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src'),
    },
  },
});
