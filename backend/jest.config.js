module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/tests'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],

  // Coverage configuration
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.d.ts',
    '!src/server.ts',
    '!src/types/**/*.ts',
    '!src/**/*.interface.ts',
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html', 'json-summary'],
  // Coverage thresholds temporarily disabled while tests are being developed
  // TODO: Re-enable once test coverage improves
  // coverageThreshold: {
  //   global: {
  //     branches: 60,
  //     functions: 60,
  //     lines: 60,
  //     statements: 60,
  //   },
  //   './src/services/auth/**/*.ts': {
  //     branches: 95,
  //     functions: 95,
  //     lines: 95,
  //     statements: 95,
  //   },
  //   './src/services/parser/**/*.ts': {
  //     branches: 85,
  //     functions: 85,
  //     lines: 85,
  //     statements: 85,
  //   },
  //   './src/services/rules/**/*.ts': {
  //     branches: 85,
  //     functions: 85,
  //     lines: 85,
  //     statements: 85,
  //   },
  // },

  // Testcontainers configuration
  maxWorkers: 4,
  testTimeout: 60000, // 60 seconds for container startup

  // Setup files
  setupFilesAfterEnv: ['<rootDir>/tests/setup.ts'],

  // Module paths
  moduleNameMapper: {
    '^@/(.*)$': '<rootDir>/src/$1',
  },
};
