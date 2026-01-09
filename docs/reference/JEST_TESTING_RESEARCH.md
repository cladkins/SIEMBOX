# Jest and TypeScript Testing Best Practices for Node.js Backend Applications (2025-2026)

This document provides comprehensive research on Jest and TypeScript testing best practices for Node.js backend applications, focusing on configuration, testing patterns, coverage tools, and CI/CD integration.

## Table of Contents

1. [Jest Configuration for TypeScript](#jest-configuration-for-typescript)
2. [Testing Patterns](#testing-patterns)
3. [Coverage Tools](#coverage-tools)
4. [CI/CD Integration](#cicd-integration)
5. [Recommended Packages](#recommended-packages)
6. [Complete Configuration Examples](#complete-configuration-examples)

---

## Jest Configuration for TypeScript

### ts-jest Setup and Configuration

**Installation:**

```bash
npm install --save-dev jest ts-jest @types/jest typescript
```

**Basic Configuration (jest.config.ts):**

```typescript
import type { JestConfigWithTsJest } from 'ts-jest';

const jestConfig: JestConfigWithTsJest = {
  preset: 'ts-jest',
  testEnvironment: 'node',

  // Test file patterns
  testMatch: [
    '**/__tests__/**/*.[jt]s?(x)',
    '**/?(*.)+(spec|test).[jt]s?(x)'
  ],

  // Transform TypeScript files
  transform: {
    '^.+\\.tsx?$': ['ts-jest', {
      // Inline TypeScript compiler options
      tsconfig: {
        target: 'ES2020',
        module: 'commonjs',
        lib: ['ES2020'],
        esModuleInterop: true,
        allowSyntheticDefaultImports: true,
        strict: true,
        skipLibCheck: true,
        resolveJsonModule: true,
        isolatedModules: true
      },

      // Diagnostics configuration
      diagnostics: {
        pretty: true,
        ignoreCodes: [6059, 18002, 18003],
        exclude: ['**/*.spec.ts', '**/__tests__/**'],
        warnOnly: false
      }
    }]
  },

  // Module resolution
  roots: ['<rootDir>/src'],
  modulePaths: ['<rootDir>/src'],

  // Coverage configuration
  collectCoverageFrom: [
    'src/**/*.{ts,tsx}',
    '!src/**/*.d.ts',
    '!src/**/*.test.ts',
    '!src/**/*.spec.ts'
  ]
};

export default jestConfig;
```

### ESM vs CommonJS Considerations

**CommonJS (Default, More Stable):**

```typescript
// jest.config.ts
import type { JestConfigWithTsJest } from 'ts-jest';

const jestConfig: JestConfigWithTsJest = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  transform: {
    '^.+\\.tsx?$': ['ts-jest', {
      tsconfig: {
        target: 'ES2020',
        module: 'commonjs', // Use CommonJS for Jest
        esModuleInterop: true
      }
    }]
  }
};

export default jestConfig;
```

**ESM (Experimental, Requires Node.js Flag):**

```typescript
// jest.config.ts
import type { JestConfigWithTsJest } from 'ts-jest';
import { createDefaultEsmPreset } from 'ts-jest';

const esmPreset = createDefaultEsmPreset();

const jestConfig: JestConfigWithTsJest = {
  ...esmPreset,
  testEnvironment: 'node',

  // Treat these extensions as ESM
  extensionsToTreatAsEsm: ['.ts', '.tsx', '.mts'],

  // Module name mapper for ESM imports
  moduleNameMapper: {
    '^(\\.{1,2}/.*)\\.js$': '$1', // Map .js imports to TypeScript files
  },

  transform: {
    '^.+\\.m?tsx?$': ['ts-jest', {
      useESM: true,
      tsconfig: {
        module: 'ESNext',
        target: 'ESNext',
        esModuleInterop: true
      }
    }]
  }
};

export default jestConfig;
```

**Running Jest with ESM:**

```bash
# Add to package.json scripts
{
  "scripts": {
    "test": "node --experimental-vm-modules node_modules/jest/bin/jest.js"
  }
}

# Or use directly
node --experimental-vm-modules node_modules/jest/bin/jest.js
```

**Recommendation for 2025-2026:**
- **Use CommonJS** for production backends unless you have specific ESM requirements
- ESM support in Jest is still experimental and may have compatibility issues
- Most Node.js backend libraries still primarily target CommonJS
- Wait for Jest ESM support to stabilize before migrating production code

### TypeScript Path Mapping in Tests

**Using ts-jest's pathsToModuleNameMapper:**

```typescript
// jest.config.ts
import type { JestConfigWithTsJest } from 'ts-jest';
import { pathsToModuleNameMapper } from 'ts-jest';
import { compilerOptions } from './tsconfig.json';

const jestConfig: JestConfigWithTsJest = {
  preset: 'ts-jest',
  testEnvironment: 'node',

  // Set base URL for module resolution
  roots: ['<rootDir>'],
  modulePaths: [compilerOptions.baseUrl],

  // Automatically map TypeScript paths to Jest moduleNameMapper
  moduleNameMapper: pathsToModuleNameMapper(compilerOptions.paths, {
    prefix: '<rootDir>/'
  })
};

export default jestConfig;
```

**Example tsconfig.json paths:**

```json
{
  "compilerOptions": {
    "baseUrl": ".",
    "paths": {
      "@/services/*": ["src/services/*"],
      "@/models/*": ["src/models/*"],
      "@/utils/*": ["src/utils/*"],
      "@/config": ["src/config/index.ts"]
    }
  }
}
```

**Resulting moduleNameMapper:**

```typescript
{
  moduleNameMapper: {
    '^@/services/(.*)$': '<rootDir>/src/services/$1',
    '^@/models/(.*)$': '<rootDir>/src/models/$1',
    '^@/utils/(.*)$': '<rootDir>/src/utils/$1',
    '^@/config$': '<rootDir>/src/config/index.ts'
  }
}
```

---

## Testing Patterns

### Unit Testing Services and Business Logic

**Example: Testing a Service with Mocked Dependencies**

```typescript
// src/services/userService.ts
import { UserRepository } from '../repositories/userRepository';
import { EmailService } from './emailService';

export class UserService {
  constructor(
    private userRepository: UserRepository,
    private emailService: EmailService
  ) {}

  async createUser(name: string, email: string) {
    const user = await this.userRepository.create({ name, email });
    await this.emailService.sendWelcomeEmail(email);
    return user;
  }

  async getUserById(id: string) {
    return this.userRepository.findById(id);
  }
}
```

```typescript
// src/services/userService.test.ts
import { UserService } from './userService';
import { UserRepository } from '../repositories/userRepository';
import { EmailService } from './emailService';

// Mock the dependencies
jest.mock('../repositories/userRepository');
jest.mock('./emailService');

describe('UserService', () => {
  let userService: UserService;
  let mockUserRepository: jest.Mocked<UserRepository>;
  let mockEmailService: jest.Mocked<EmailService>;

  beforeEach(() => {
    // Create mocked instances
    mockUserRepository = new UserRepository() as jest.Mocked<UserRepository>;
    mockEmailService = new EmailService() as jest.Mocked<EmailService>;

    // Initialize service with mocks
    userService = new UserService(mockUserRepository, mockEmailService);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('createUser', () => {
    it('should create a user and send welcome email', async () => {
      // Arrange
      const mockUser = { id: '1', name: 'John Doe', email: 'john@example.com' };
      mockUserRepository.create.mockResolvedValue(mockUser);
      mockEmailService.sendWelcomeEmail.mockResolvedValue(undefined);

      // Act
      const result = await userService.createUser('John Doe', 'john@example.com');

      // Assert
      expect(mockUserRepository.create).toHaveBeenCalledWith({
        name: 'John Doe',
        email: 'john@example.com'
      });
      expect(mockEmailService.sendWelcomeEmail).toHaveBeenCalledWith('john@example.com');
      expect(result).toEqual(mockUser);
    });

    it('should handle repository errors', async () => {
      // Arrange
      const error = new Error('Database connection failed');
      mockUserRepository.create.mockRejectedValue(error);

      // Act & Assert
      await expect(
        userService.createUser('John Doe', 'john@example.com')
      ).rejects.toThrow('Database connection failed');
    });
  });

  describe('getUserById', () => {
    it('should return user when found', async () => {
      // Arrange
      const mockUser = { id: '1', name: 'John Doe', email: 'john@example.com' };
      mockUserRepository.findById.mockResolvedValue(mockUser);

      // Act
      const result = await userService.getUserById('1');

      // Assert
      expect(mockUserRepository.findById).toHaveBeenCalledWith('1');
      expect(result).toEqual(mockUser);
    });

    it('should return null when user not found', async () => {
      // Arrange
      mockUserRepository.findById.mockResolvedValue(null);

      // Act
      const result = await userService.getUserById('999');

      // Assert
      expect(result).toBeNull();
    });
  });
});
```

### Integration Testing Express APIs

**Using SuperTest for HTTP Testing:**

```bash
npm install --save-dev supertest @types/supertest
```

```typescript
// src/app.ts
import express from 'express';
import { userRouter } from './routes/userRouter';

export function createApp() {
  const app = express();
  app.use(express.json());
  app.use('/api/users', userRouter);
  return app;
}
```

```typescript
// src/routes/userRouter.test.ts
import request from 'supertest';
import { createApp } from '../app';
import { UserService } from '../services/userService';

// Mock the service layer
jest.mock('../services/userService');

describe('User API Routes', () => {
  let app: Express.Application;
  let mockUserService: jest.Mocked<UserService>;

  beforeEach(() => {
    app = createApp();
    mockUserService = UserService.prototype as jest.Mocked<UserService>;
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  describe('POST /api/users', () => {
    it('should create a user and return 201', async () => {
      // Arrange
      const newUser = { name: 'John Doe', email: 'john@example.com' };
      const createdUser = { id: '1', ...newUser };
      mockUserService.createUser.mockResolvedValue(createdUser);

      // Act
      const response = await request(app)
        .post('/api/users')
        .send(newUser)
        .set('Accept', 'application/json');

      // Assert
      expect(response.status).toBe(201);
      expect(response.headers['content-type']).toMatch(/json/);
      expect(response.body).toEqual(createdUser);
    });

    it('should return 400 for invalid input', async () => {
      // Act
      const response = await request(app)
        .post('/api/users')
        .send({ name: '' }) // Missing email
        .set('Accept', 'application/json');

      // Assert
      expect(response.status).toBe(400);
      expect(response.body).toHaveProperty('error');
    });

    it('should return 500 on service error', async () => {
      // Arrange
      mockUserService.createUser.mockRejectedValue(new Error('Database error'));

      // Act
      const response = await request(app)
        .post('/api/users')
        .send({ name: 'John Doe', email: 'john@example.com' });

      // Assert
      expect(response.status).toBe(500);
    });
  });

  describe('GET /api/users/:id', () => {
    it('should return user when found', async () => {
      // Arrange
      const user = { id: '1', name: 'John Doe', email: 'john@example.com' };
      mockUserService.getUserById.mockResolvedValue(user);

      // Act
      const response = await request(app)
        .get('/api/users/1')
        .set('Accept', 'application/json');

      // Assert
      expect(response.status).toBe(200);
      expect(response.body).toEqual(user);
    });

    it('should return 404 when user not found', async () => {
      // Arrange
      mockUserService.getUserById.mockResolvedValue(null);

      // Act
      const response = await request(app).get('/api/users/999');

      // Assert
      expect(response.status).toBe(404);
    });
  });
});
```

### Database Testing Strategies

#### Strategy 1: Test Databases (Recommended for Integration Tests)

**Setup a separate test database:**

```typescript
// src/config/database.ts
import { Pool } from 'pg';

export function createDatabasePool() {
  const isTest = process.env.NODE_ENV === 'test';

  return new Pool({
    host: process.env.DB_HOST || 'localhost',
    port: parseInt(process.env.DB_PORT || '5432'),
    database: isTest ? process.env.TEST_DB_NAME : process.env.DB_NAME,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD
  });
}
```

```typescript
// src/tests/setup.ts
import { createDatabasePool } from '../config/database';

let pool: Pool;

beforeAll(async () => {
  pool = createDatabasePool();

  // Run migrations
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      email TEXT UNIQUE NOT NULL,
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);
});

afterAll(async () => {
  // Clean up
  await pool.query('DROP TABLE IF EXISTS users;');
  await pool.end();
});

beforeEach(async () => {
  // Clear data before each test
  await pool.query('TRUNCATE TABLE users RESTART IDENTITY CASCADE;');
});
```

#### Strategy 2: Testcontainers (Best for True Integration Tests)

**Using Testcontainers for PostgreSQL:**

```bash
npm install --save-dev @testcontainers/postgresql
```

```typescript
// src/tests/integration/userRepository.integration.test.ts
import { Pool } from 'pg';
import { PostgreSqlContainer, StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import { UserRepository } from '../../repositories/userRepository';

describe('UserRepository Integration Tests', () => {
  let container: StartedPostgreSqlContainer;
  let pool: Pool;
  let userRepository: UserRepository;

  beforeAll(async () => {
    // Start PostgreSQL container
    container = await new PostgreSqlContainer('postgres:15')
      .withDatabase('testdb')
      .withUsername('testuser')
      .withPassword('testpass')
      .start();

    // Create connection pool
    pool = new Pool({
      connectionString: container.getConnectionUri()
    });

    // Run migrations
    await pool.query(`
      CREATE TABLE users (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL,
        created_at TIMESTAMP DEFAULT NOW()
      );
    `);

    // Create snapshot after migrations for faster test resets
    await container.snapshot('migrated_template');

    userRepository = new UserRepository(pool);
  }, 60000); // Increase timeout for container startup

  afterAll(async () => {
    await pool.end();
    await container.stop();
  });

  beforeEach(async () => {
    // Restore to clean state (faster than truncating)
    await container.restoreSnapshot('migrated_template');
  });

  describe('create', () => {
    it('should create a new user', async () => {
      // Arrange
      const userData = { name: 'John Doe', email: 'john@example.com' };

      // Act
      const user = await userRepository.create(userData);

      // Assert
      expect(user).toMatchObject(userData);
      expect(user.id).toBeDefined();
      expect(user.created_at).toBeInstanceOf(Date);
    });

    it('should throw error for duplicate email', async () => {
      // Arrange
      await userRepository.create({ name: 'John', email: 'john@example.com' });

      // Act & Assert
      await expect(
        userRepository.create({ name: 'Jane', email: 'john@example.com' })
      ).rejects.toThrow('duplicate key');
    });
  });

  describe('findById', () => {
    it('should return user when found', async () => {
      // Arrange
      const created = await userRepository.create({
        name: 'John Doe',
        email: 'john@example.com'
      });

      // Act
      const found = await userRepository.findById(created.id);

      // Assert
      expect(found).toEqual(created);
    });

    it('should return null when user not found', async () => {
      // Act
      const found = await userRepository.findById(999);

      // Assert
      expect(found).toBeNull();
    });
  });
});
```

#### Strategy 3: In-Memory Databases (Fast but Limited)

**Best for simple use cases, not recommended for PostgreSQL-specific features:**

```bash
npm install --save-dev sqlite3
```

```typescript
// Only use for simple scenarios where database-specific features aren't tested
// PostgreSQL-specific features (JSONB, arrays, etc.) won't work in SQLite
```

### Mocking Strategies

#### Manual Mocks

**Create a manual mock in __mocks__ directory:**

```typescript
// src/services/__mocks__/emailService.ts
export class EmailService {
  sendWelcomeEmail = jest.fn().mockResolvedValue(undefined);
  sendPasswordReset = jest.fn().mockResolvedValue(undefined);
}
```

```typescript
// src/services/userService.test.ts
import { EmailService } from './emailService';

// Jest will automatically use the mock from __mocks__
jest.mock('./emailService');

describe('UserService', () => {
  it('should send welcome email', async () => {
    const emailService = new EmailService();
    await emailService.sendWelcomeEmail('test@example.com');

    expect(emailService.sendWelcomeEmail).toHaveBeenCalledWith('test@example.com');
  });
});
```

#### jest.mock() with Factory

```typescript
import { EmailService } from './emailService';

// Mock with custom implementation
jest.mock('./emailService', () => {
  return {
    EmailService: jest.fn().mockImplementation(() => {
      return {
        sendWelcomeEmail: jest.fn().mockResolvedValue(undefined),
        sendPasswordReset: jest.fn().mockResolvedValue(undefined)
      };
    })
  };
});
```

#### Dependency Injection (Recommended)

**Design services to accept dependencies:**

```typescript
// src/services/userService.ts
export class UserService {
  constructor(
    private userRepository: UserRepository,
    private emailService: EmailService
  ) {}

  // Methods that use injected dependencies
}
```

```typescript
// src/services/userService.test.ts
describe('UserService', () => {
  it('should create user with mocked dependencies', async () => {
    // Create mock instances
    const mockUserRepo = {
      create: jest.fn().mockResolvedValue({ id: '1', name: 'John' })
    } as unknown as UserRepository;

    const mockEmailService = {
      sendWelcomeEmail: jest.fn().mockResolvedValue(undefined)
    } as unknown as EmailService;

    // Inject mocks
    const userService = new UserService(mockUserRepo, mockEmailService);

    // Test with mocked dependencies
    await userService.createUser('John', 'john@example.com');

    expect(mockUserRepo.create).toHaveBeenCalled();
    expect(mockEmailService.sendWelcomeEmail).toHaveBeenCalled();
  });
});
```

### Async Testing Patterns

**Using async/await (Recommended):**

```typescript
test('async operation succeeds', async () => {
  const result = await fetchData();
  expect(result).toBe('expected value');
});

test('async operation fails', async () => {
  await expect(fetchData()).rejects.toThrow('Error message');
});
```

**Using .resolves and .rejects:**

```typescript
test('promise resolves', async () => {
  await expect(fetchData()).resolves.toBe('expected value');
});

test('promise rejects', async () => {
  await expect(fetchData()).rejects.toThrow('Error message');
});
```

**Error handling with try/catch:**

```typescript
test('handles async errors', async () => {
  expect.assertions(1);

  try {
    await riskyOperation();
  } catch (error) {
    expect(error.message).toBe('Expected error');
  }
});
```

---

## Coverage Tools

### Jest Coverage Configuration

**Basic Coverage Setup:**

```typescript
// jest.config.ts
import type { JestConfigWithTsJest } from 'ts-jest';

const jestConfig: JestConfigWithTsJest = {
  preset: 'ts-jest',
  testEnvironment: 'node',

  // Enable coverage collection
  collectCoverage: true,

  // Specify files to collect coverage from
  collectCoverageFrom: [
    'src/**/*.{ts,tsx}',
    '!src/**/*.d.ts',
    '!src/**/*.test.ts',
    '!src/**/*.spec.ts',
    '!src/types/**',
    '!src/migrations/**',
    '!src/**/__tests__/**'
  ],

  // Coverage directory
  coverageDirectory: 'coverage',

  // Coverage reporters
  coverageReporters: [
    'text',           // Terminal output
    'text-summary',   // Summary in terminal
    'lcov',           // For CI tools
    'html',           // HTML report
    'json'            // JSON for programmatic access
  ],

  // Coverage thresholds (fail if not met)
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80
    }
  }
};

export default jestConfig;
```

### Coverage Thresholds and Enforcement

**Global and Path-Specific Thresholds:**

```typescript
coverageThreshold: {
  // Global threshold for entire codebase
  global: {
    branches: 80,
    functions: 80,
    lines: 80,
    statements: 80
  },

  // Higher threshold for critical services
  './src/services/': {
    branches: 90,
    functions: 90,
    lines: 90,
    statements: 90
  },

  // Specific threshold for important files
  './src/services/authService.ts': {
    branches: 100,
    functions: 100,
    lines: 100,
    statements: 100
  },

  // Lower threshold for utilities (can be more lenient)
  './src/utils/': {
    branches: 70,
    statements: 70
  }
}
```

### Excluding Files from Coverage

**Using collectCoverageFrom:**

```typescript
collectCoverageFrom: [
  // Include all TypeScript files in src
  'src/**/*.{ts,tsx}',

  // Exclude type definitions
  '!src/**/*.d.ts',

  // Exclude test files
  '!src/**/*.test.ts',
  '!src/**/*.spec.ts',
  '!src/**/__tests__/**',

  // Exclude specific directories
  '!src/migrations/**',
  '!src/types/**',
  '!src/config/**',

  // Exclude generated files
  '!src/generated/**',

  // Exclude specific files
  '!src/index.ts',
  '!src/server.ts'
]
```

**Using coveragePathIgnorePatterns:**

```typescript
coveragePathIgnorePatterns: [
  '/node_modules/',
  '/dist/',
  '/coverage/',
  '/__tests__/',
  '\\.test\\.ts$',
  '\\.spec\\.ts$'
]
```

### Coverage Reports

**Available Reporter Options:**

```typescript
coverageReporters: [
  'text',              // Console output during test run
  'text-summary',      // Brief summary in console
  'lcov',              // Standard format for CI tools (Codecov, Coveralls)
  'html',              // Interactive HTML report
  'json',              // JSON format for custom processing
  'json-summary',      // Summary in JSON format
  'cobertura',         // XML format (Azure DevOps, Jenkins)
  'clover',            // XML format (legacy CI tools)

  // Custom reporter with options
  ['text', { skipFull: true }]  // Hide fully-covered files
]
```

**Package.json Scripts:**

```json
{
  "scripts": {
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "test:coverage:watch": "jest --coverage --watch",
    "test:ci": "jest --ci --coverage --maxWorkers=2"
  }
}
```

---

## CI/CD Integration

### Running Tests in GitHub Actions

**Basic GitHub Actions Workflow:**

```yaml
# .github/workflows/test.yml
name: Test

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

jobs:
  test:
    runs-on: ubuntu-latest

    strategy:
      matrix:
        node-version: [18.x, 20.x]

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Node.js ${{ matrix.node-version }}
        uses: actions/setup-node@v4
        with:
          node-version: ${{ matrix.node-version }}
          cache: 'npm'

      - name: Install dependencies
        run: npm ci

      - name: Run linter
        run: npm run lint

      - name: Run tests with coverage
        run: npm run test:ci

      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v4
        with:
          files: ./coverage/lcov.info
          flags: unittests
          name: codecov-umbrella
          fail_ci_if_error: true
```

**With Database (PostgreSQL):**

```yaml
# .github/workflows/test.yml
name: Test

on:
  push:
    branches: [main, develop]
  pull_request:
    branches: [main, develop]

jobs:
  test:
    runs-on: ubuntu-latest

    services:
      postgres:
        image: postgres:15
        env:
          POSTGRES_USER: test
          POSTGRES_PASSWORD: test
          POSTGRES_DB: testdb
        options: >-
          --health-cmd pg_isready
          --health-interval 10s
          --health-timeout 5s
          --health-retries 5
        ports:
          - 5432:5432

    steps:
      - name: Checkout code
        uses: actions/checkout@v4

      - name: Setup Node.js
        uses: actions/setup-node@v4
        with:
          node-version: '20.x'
          cache: 'npm'

      - name: Get number of CPU cores
        id: cpu-cores
        uses: SimenB/github-actions-cpu-cores@v2

      - name: Install dependencies
        run: npm ci

      - name: Run database migrations
        env:
          DATABASE_URL: postgresql://test:test@localhost:5432/testdb
        run: npm run migrate

      - name: Run tests with coverage
        env:
          DATABASE_URL: postgresql://test:test@localhost:5432/testdb
          NODE_ENV: test
        run: npm test -- --coverage --maxWorkers=${{ steps.cpu-cores.outputs.count }}

      - name: Upload coverage reports
        uses: actions/upload-artifact@v4
        with:
          name: coverage-reports
          path: coverage/
```

### Jest Configuration for CI

```typescript
// jest.config.ci.ts
import type { JestConfigWithTsJest } from 'ts-jest';
import baseConfig from './jest.config';

const ciConfig: JestConfigWithTsJest = {
  ...baseConfig,

  // Use GitHub Actions reporter for better CI integration
  reporters: [
    'default',
    ['github-actions', { silent: false }],
    'summary'
  ],

  // Optimize for CI environment
  maxWorkers: process.env.CI ? 2 : '50%',

  // Disable watch mode
  watch: false,
  watchAll: false,

  // Run tests sequentially if needed (for Docker/CI)
  // runInBand: true,

  // Fail fast on first error
  bail: 1,

  // Increase timeout for slower CI environments
  testTimeout: 10000,

  // Force coverage collection
  collectCoverage: true,

  // Fail if coverage thresholds not met
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80
    }
  }
};

export default ciConfig;
```

### Coverage Reporting to Services

#### Codecov

```yaml
- name: Upload coverage to Codecov
  uses: codecov/codecov-action@v4
  with:
    token: ${{ secrets.CODECOV_TOKEN }}
    files: ./coverage/lcov.info
    flags: unittests
    name: codecov-umbrella
    fail_ci_if_error: true
    verbose: true
```

#### Coveralls

```yaml
- name: Upload coverage to Coveralls
  uses: coverallsapp/github-action@v2
  with:
    github-token: ${{ secrets.GITHUB_TOKEN }}
    path-to-lcov: ./coverage/lcov.info
```

#### SonarCloud

```yaml
- name: SonarCloud Scan
  uses: SonarSource/sonarcloud-github-action@master
  env:
    GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
    SONAR_TOKEN: ${{ secrets.SONAR_TOKEN }}
  with:
    args: >
      -Dsonar.projectKey=your_project_key
      -Dsonar.organization=your_org
      -Dsonar.javascript.lcov.reportPaths=coverage/lcov.info
      -Dsonar.coverage.exclusions=**/*.test.ts,**/*.spec.ts
```

---

## Recommended Packages

### Essential Testing Packages

```json
{
  "devDependencies": {
    "@types/jest": "^29.5.0",
    "@types/node": "^20.0.0",
    "@types/supertest": "^6.0.0",
    "jest": "^29.7.0",
    "supertest": "^6.3.0",
    "ts-jest": "^29.1.0",
    "ts-node": "^10.9.0",
    "typescript": "^5.3.0"
  }
}
```

### Database Testing

```json
{
  "devDependencies": {
    "@testcontainers/postgresql": "^10.5.0",
    "@types/pg": "^8.10.0",
    "pg": "^8.11.0"
  }
}
```

### Additional Testing Utilities

```json
{
  "devDependencies": {
    "@faker-js/faker": "^8.4.0",        // Generate fake data
    "jest-extended": "^4.0.0",          // Additional Jest matchers
    "jest-mock-extended": "^3.0.0",     // Enhanced mocking
    "nock": "^13.5.0",                  // HTTP mocking
    "@golevelup/ts-jest": "^0.4.0"      // Deep mock generation
  }
}
```

---

## Complete Configuration Examples

### Small Project Configuration

```typescript
// jest.config.ts
import type { JestConfigWithTsJest } from 'ts-jest';

const jestConfig: JestConfigWithTsJest = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/__tests__/**/*.test.ts', '**/?(*.)+(spec|test).ts'],
  collectCoverageFrom: [
    'src/**/*.ts',
    '!src/**/*.test.ts',
    '!src/**/*.spec.ts'
  ],
  coverageDirectory: 'coverage',
  coverageReporters: ['text', 'lcov', 'html']
};

export default jestConfig;
```

### Large Project Configuration

```typescript
// jest.config.ts
import type { JestConfigWithTsJest } from 'ts-jest';
import { pathsToModuleNameMapper } from 'ts-jest';
import { compilerOptions } from './tsconfig.json';

const jestConfig: JestConfigWithTsJest = {
  preset: 'ts-jest',
  testEnvironment: 'node',

  // Test configuration
  roots: ['<rootDir>/src'],
  testMatch: [
    '**/__tests__/**/*.test.ts',
    '**/?(*.)+(spec|test).ts'
  ],
  testPathIgnorePatterns: [
    '/node_modules/',
    '/dist/'
  ],

  // Module resolution
  modulePaths: [compilerOptions.baseUrl],
  moduleNameMapper: pathsToModuleNameMapper(compilerOptions.paths, {
    prefix: '<rootDir>/'
  }),

  // Transform configuration
  transform: {
    '^.+\\.tsx?$': ['ts-jest', {
      tsconfig: {
        target: 'ES2020',
        module: 'commonjs',
        esModuleInterop: true,
        strict: true
      },
      diagnostics: {
        pretty: true,
        warnOnly: false
      }
    }]
  },

  // Coverage configuration
  collectCoverage: false, // Enable via CLI: --coverage
  collectCoverageFrom: [
    'src/**/*.{ts,tsx}',
    '!src/**/*.d.ts',
    '!src/**/*.test.ts',
    '!src/**/*.spec.ts',
    '!src/**/__tests__/**',
    '!src/migrations/**',
    '!src/types/**',
    '!src/index.ts'
  ],
  coverageDirectory: 'coverage',
  coverageReporters: [
    'text',
    'text-summary',
    'lcov',
    'html',
    'json-summary'
  ],
  coverageThreshold: {
    global: {
      branches: 80,
      functions: 80,
      lines: 80,
      statements: 80
    },
    './src/services/': {
      branches: 90,
      functions: 90,
      lines: 90,
      statements: 90
    }
  },

  // Setup files
  setupFilesAfterEnv: ['<rootDir>/src/tests/setup.ts'],

  // Performance
  maxWorkers: '50%',

  // CI configuration
  bail: process.env.CI ? 1 : 0,
  verbose: true
};

export default jestConfig;
```

### package.json Scripts

```json
{
  "scripts": {
    "test": "jest",
    "test:watch": "jest --watch",
    "test:coverage": "jest --coverage",
    "test:unit": "jest --testPathPattern='.*.test.ts$'",
    "test:integration": "jest --testPathPattern='.*.integration.test.ts$'",
    "test:ci": "jest --ci --coverage --maxWorkers=2 --bail",
    "test:debug": "node --inspect-brk node_modules/.bin/jest --runInBand"
  }
}
```

---

## Best Practices Summary

### 2025-2026 Recommendations

1. **Use CommonJS for Stability**: Stick with CommonJS module system for Jest tests unless you have specific ESM requirements. ESM support is still experimental.

2. **Dependency Injection**: Design services with constructor injection for easier testing and mocking.

3. **Test Organization**:
   - Unit tests: `*.test.ts` or `*.spec.ts` next to source files
   - Integration tests: `*.integration.test.ts` in `__tests__` directory
   - Setup files: Centralized in `src/tests/setup.ts`

4. **Coverage Goals**:
   - Global: 80% minimum
   - Critical services: 90%+
   - Database repositories: 85%+
   - Utility functions: 70%+

5. **Database Testing**:
   - Use Testcontainers for true integration tests
   - Use test databases for faster feedback
   - Leverage snapshots for quick test resets

6. **Mocking Strategy**:
   - Mock external dependencies (APIs, email services)
   - Use real databases with Testcontainers for integration tests
   - Prefer dependency injection over jest.mock()

7. **CI/CD**:
   - Run tests on every push and PR
   - Use GitHub Actions with database services
   - Upload coverage to Codecov or similar
   - Optimize test runs with CPU core detection

8. **Performance**:
   - Use `maxWorkers` to optimize parallel test execution
   - Consider `--runInBand` for Docker/CI environments
   - Leverage Testcontainers snapshots for faster resets

---

## Sources

This research is based on official documentation from:

- [Jest Documentation](https://jestjs.io/docs/getting-started) (/jestjs/jest)
- [ts-jest Documentation](https://kulshekhar.github.io/ts-jest/) (/kulshekhar/ts-jest)
- [SuperTest Documentation](https://github.com/ladjs/supertest) (/ladjs/supertest)
- [Testcontainers Node Documentation](https://node.testcontainers.org/) (/testcontainers/testcontainers-node)

Research conducted: January 2026
