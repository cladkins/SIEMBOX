# Testing Quick Start Guide

## Overview

This guide provides quick-start templates for common testing scenarios in SIEMBox. For detailed explanations, see [TESTING_STRATEGIES.md](./TESTING_STRATEGIES.md).

---

## Quick Setup: Testcontainers + PostgreSQL

```bash
npm install --save-dev @testcontainers/postgresql testcontainers pg
npm install --save-dev jest @types/jest ts-jest
```

### Basic Test Template

```typescript
// test/integration/database.test.ts
import { PostgreSqlContainer } from '@testcontainers/postgresql';
import { Client } from 'pg';

describe('Database Integration Tests', () => {
  let container: any;
  let client: Client;

  beforeAll(async () => {
    // Start PostgreSQL container
    container = await new PostgreSqlContainer('postgres:15')
      .withDatabase('testdb')
      .withUsername('testuser')
      .withPassword('testpass')
      .start();

    // Connect to database
    client = new Client({
      connectionString: container.getConnectionUri(),
    });
    await client.connect();

    // Run migrations
    await runMigrations(client);

    // Create snapshot for fast test isolation
    await container.snapshot('clean');
  }, 60000); // 60 second timeout for container startup

  beforeEach(async () => {
    // Restore clean state before each test
    await container.restoreSnapshot('clean');
  });

  afterAll(async () => {
    await client.end();
    await container.stop();
  });

  it('should insert and query data', async () => {
    await client.query(
      'INSERT INTO users (username, email) VALUES ($1, $2)',
      ['testuser', 'test@example.com']
    );

    const result = await client.query('SELECT * FROM users WHERE username = $1', ['testuser']);
    expect(result.rows).toHaveLength(1);
  });
});
```

---

## Quick Setup: Mocking child_process (NMAP)

```bash
npm install --save-dev mock-spawn
```

### Mock Template

```typescript
// test/unit/scanner.test.ts
import mockSpawn from 'mock-spawn';
import { scanService } from '../../src/services/scanner';

describe('NMAP Scanner', () => {
  let originalSpawn: any;
  let mySpawn: any;

  beforeEach(() => {
    originalSpawn = require('child_process').spawn;
    mySpawn = mockSpawn();
    require('child_process').spawn = mySpawn;
  });

  afterEach(() => {
    require('child_process').spawn = originalSpawn;
  });

  it('should parse nmap output', async () => {
    // Mock nmap command with successful output
    mySpawn.setDefault(mySpawn.simple(0, JSON.stringify({
      scan: {
        '192.168.1.1': {
          hostname: 'router.local',
          ports: [{ port: 80, state: 'open', service: 'http' }]
        }
      }
    })));

    const results = await scanService.runScan('192.168.1.0/24');

    expect(results.hosts).toHaveLength(1);
    expect(results.hosts[0].ports[0].port).toBe(80);
  });

  it('should handle nmap errors', async () => {
    mySpawn.setDefault(mySpawn.simple(1, '', 'Error: Invalid target'));

    await expect(scanService.runScan('invalid'))
      .rejects.toThrow('Invalid target');
  });
});
```

---

## Quick Setup: Mocking File System (Log Shipper)

```bash
npm install --save-dev mock-fs
```

### Mock Template

```typescript
// test/unit/logShipper.test.ts
import mockFs from 'mock-fs';
import { LogShipper } from '../../src/services/logShipper';

describe('Log Shipper', () => {
  beforeEach(() => {
    mockFs({
      '/var/log': {
        'nginx': {
          'access.log': 'GET /page HTTP/1.1 200\nGET /api HTTP/1.1 404\n',
          'error.log': '[error] Connection refused\n'
        }
      }
    });
  });

  afterEach(() => {
    mockFs.restore();
  });

  it('should read log files', async () => {
    const shipper = new LogShipper({
      sources: ['/var/log/nginx/access.log']
    });

    const logs = await shipper.collectLogs();

    expect(logs).toHaveLength(2);
    expect(logs[0]).toContain('GET /page');
  });
});
```

---

## Quick Setup: UDP/TCP Socket Testing (Syslog)

### Integration Test Template

```typescript
// test/integration/syslog.test.ts
import dgram from 'dgram';
import { SyslogServer } from '../../src/services/syslog/syslogServer';

describe('Syslog Server', () => {
  let server: SyslogServer;
  let client: dgram.Socket;
  let testPort: number;

  beforeAll(async () => {
    // Use port 0 for dynamic assignment
    server = new SyslogServer({ port: 0 });
    await server.start();
    testPort = server.getPort();
  });

  beforeEach(() => {
    client = dgram.createSocket('udp4');
  });

  afterEach(() => {
    client.close();
  });

  afterAll(async () => {
    await server.stop();
  });

  it('should receive and parse syslog messages', (done) => {
    const testMessage = '<134>Dec 09 20:36:20 webserver NGINX: test log';

    server.once('parsed', (log) => {
      expect(log.hostname).toBe('webserver');
      expect(log.app_name).toBe('NGINX');
      expect(log.message).toBe('test log');
      done();
    });

    client.send(testMessage, testPort, '127.0.0.1');
  });
});
```

---

## Quick Setup: Test Data Factories

```bash
npm install --save-dev fishery @faker-js/faker
```

### Factory Template

```typescript
// test/factories/user.factory.ts
import { Factory } from 'fishery';
import { faker } from '@faker-js/faker';

interface User {
  id?: number;
  username: string;
  email: string;
  role: 'admin' | 'analyst' | 'viewer';
}

export const userFactory = Factory.define<User>(({ sequence }) => ({
  username: `user${sequence}`,
  email: faker.internet.email(),
  role: 'viewer',
}));

// Usage in tests
const admin = userFactory.build({ role: 'admin' });
const analysts = userFactory.buildList(3, { role: 'analyst' });
```

---

## Quick Setup: Parallel Testing with Jest

### Jest Configuration

```javascript
// jest.config.js
module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  maxWorkers: 4,
  testTimeout: 30000,
  setupFilesAfterEnv: ['<rootDir>/test/setup.ts'],
  collectCoverageFrom: [
    'src/**/*.{ts,tsx}',
    '!src/**/*.d.ts',
  ],
};
```

### Worker-Specific Setup

```typescript
// test/setup.ts
import { PostgreSqlContainer } from '@testcontainers/postgresql';

let container: any;

beforeAll(async () => {
  const workerId = process.env.JEST_WORKER_ID || '1';

  container = await new PostgreSqlContainer('postgres:15')
    .withDatabase(`testdb_${workerId}`)
    .start();

  process.env.DATABASE_URL = container.getConnectionUri();
}, 60000);

afterAll(async () => {
  await container?.stop();
});
```

---

## Quick Setup: Test Utilities

### Database Helper

```typescript
// test/helpers/database.helper.ts
import { Client } from 'pg';

export class DatabaseTestHelper {
  constructor(private client: Client) {}

  async createUser(overrides: Partial<User> = {}) {
    const user = {
      username: `user_${Date.now()}`,
      email: `test${Date.now()}@example.com`,
      role: 'viewer',
      ...overrides,
    };

    const result = await this.client.query(
      'INSERT INTO users (username, email, role) VALUES ($1, $2, $3) RETURNING *',
      [user.username, user.email, user.role]
    );

    return result.rows[0];
  }

  async clearTable(tableName: string) {
    await this.client.query(`TRUNCATE ${tableName} CASCADE`);
  }

  async getConnectionStats() {
    const result = await this.client.query(`
      SELECT
        count(*) as total,
        count(*) FILTER (WHERE state = 'idle') as idle,
        count(*) FILTER (WHERE state = 'active') as active
      FROM pg_stat_activity
      WHERE datname = current_database()
    `);
    return result.rows[0];
  }
}
```

---

## Common Patterns

### Pattern 1: Transaction Rollback for Test Isolation

```typescript
describe('Tests with transaction rollback', () => {
  let client: Client;

  beforeEach(async () => {
    client = await pool.connect();
    await client.query('BEGIN');
  });

  afterEach(async () => {
    await client.query('ROLLBACK');
    client.release();
  });

  it('changes are isolated', async () => {
    await client.query('INSERT INTO users (username) VALUES ($1)', ['test']);
    // Changes rolled back after test
  });
});
```

### Pattern 2: Preventing Connection Leaks

```typescript
// GOOD: Always use try/finally
it('properly manages connections', async () => {
  const client = await pool.connect();
  try {
    const result = await client.query('SELECT * FROM users');
    expect(result.rows).toBeDefined();
  } finally {
    client.release();
  }
});

// BETTER: Use pool.query() which manages lifecycle automatically
it('uses pool query', async () => {
  const result = await pool.query('SELECT * FROM users');
  expect(result.rows).toBeDefined();
});
```

### Pattern 3: Handling Async Race Conditions

```typescript
import { Mutex } from 'async-mutex';

describe('Concurrent operations', () => {
  it('uses mutex for thread safety', async () => {
    const mutex = new Mutex();
    let counter = 0;

    async function increment() {
      const release = await mutex.acquire();
      try {
        counter++;
      } finally {
        release();
      }
    }

    await Promise.all([increment(), increment(), increment()]);
    expect(counter).toBe(3);
  });
});
```

### Pattern 4: Dynamic Port Assignment

```typescript
// GOOD: Let OS assign port
beforeAll(async () => {
  server = new Server({ port: 0 });
  await server.start();
  testPort = server.address().port;
});

// ALSO GOOD: Testcontainers handles this automatically
const postgres = await new PostgreSqlContainer('postgres:15')
  .withExposedPorts(5432)
  .start();
const port = postgres.getMappedPort(5432); // Random available port
```

---

## Troubleshooting

### Issue: Tests Timeout

```typescript
// Increase timeout for container operations
beforeAll(async () => {
  container = await new PostgreSqlContainer('postgres:15').start();
}, 60000); // 60 seconds

// Or use container reuse to avoid startup delays
container = await new PostgreSqlContainer('postgres:15')
  .withReuse()
  .start();
```

### Issue: Port Conflicts

```typescript
// Use dynamic ports (port: 0)
server = new SyslogServer({ port: 0 });

// Or use worker-specific ports
const workerId = parseInt(process.env.JEST_WORKER_ID || '1');
const port = 10000 + workerId;
```

### Issue: Connection Pool Exhausted

```typescript
// Monitor pool stats
afterEach(async () => {
  const stats = await pool.query(`
    SELECT count(*) as total FROM pg_stat_activity
    WHERE datname = current_database()
  `);
  console.log('Active connections:', stats.rows[0].total);
});

// Ensure clients are released
afterEach(async () => {
  // Force release all clients if needed
  await pool.end();
  pool = new Pool({ connectionString: process.env.DATABASE_URL });
});
```

### Issue: Flaky Tests Due to Timing

```typescript
// Use proper async/await patterns
it('waits for async operations', async () => {
  await server.start(); // Wait for startup
  await delay(100);     // Allow event loop to process

  const result = await makeRequest();
  expect(result).toBeDefined();
});

// Add explicit timeouts with Promise.race
const timeout = (ms: number) => new Promise((_, reject) =>
  setTimeout(() => reject(new Error('Timeout')), ms)
);

it('handles timeouts', async () => {
  await Promise.race([
    slowOperation(),
    timeout(5000)
  ]);
});
```

---

## Running Tests

```bash
# Run all tests
npm test

# Run with coverage
npm test -- --coverage

# Run specific test file
npm test -- test/integration/syslog.test.ts

# Run in watch mode
npm test -- --watch

# Run with verbose output
npm test -- --verbose

# Run tests sequentially (disable parallel)
npm test -- --runInBand

# Run with specific number of workers
npm test -- --maxWorkers=2
```

---

## Next Steps

1. Review [TESTING_STRATEGIES.md](./TESTING_STRATEGIES.md) for detailed explanations
2. Set up your test environment with the Quick Setup templates
3. Create test factories for your domain models
4. Write integration tests for critical paths
5. Add unit tests for business logic
6. Configure CI/CD pipeline to run tests on every commit

---

**Last Updated:** January 2026
