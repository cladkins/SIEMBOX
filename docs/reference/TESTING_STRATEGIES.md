# PostgreSQL Testing Strategies and Mocking for Node.js Integration Tests

## Table of Contents

1. [PostgreSQL Testing Strategies](#postgresql-testing-strategies)
2. [Testcontainers-Node for PostgreSQL](#testcontainers-node-for-postgresql)
3. [Transaction Rollback Patterns](#transaction-rollback-patterns)
4. [Database Seeding and Fixtures](#database-seeding-and-fixtures)
5. [Mocking External Services](#mocking-external-services)
6. [Integration Test Patterns](#integration-test-patterns)
7. [Common Pitfalls and Solutions](#common-pitfalls-and-solutions)

---

## PostgreSQL Testing Strategies

### Overview

Modern Node.js PostgreSQL testing in 2025-2026 focuses on three primary approaches:

1. **Testcontainers**: Real PostgreSQL instances in Docker containers
2. **Transaction-based isolation**: Rollback patterns for test cleanup
3. **Parallel execution**: Multiple test databases for concurrent tests

### Recommended Approach

Use **Testcontainers with snapshot/restore capabilities** for:
- Fast test execution (cached container images)
- Real database behavior (no mocking quirks)
- Parallel test execution support
- Automatic cleanup and isolation

---

## Testcontainers-Node for PostgreSQL

### Installation

```bash
npm install --save-dev @testcontainers/postgresql
npm install --save-dev testcontainers
npm install pg
```

### Basic Setup

```javascript
const { PostgreSqlContainer } = require("@testcontainers/postgresql");
const { Client } = require("pg");

describe("Database Integration Tests", () => {
  let container;
  let client;

  beforeAll(async () => {
    // Start PostgreSQL container
    container = await new PostgreSqlContainer("postgres:15")
      .withDatabase("testdb")
      .withUsername("testuser")
      .withPassword("testpass")
      .start();

    // Create database client
    client = new Client({
      connectionString: container.getConnectionUri()
    });
    await client.connect();

    // Run migrations
    await client.query(`
      CREATE TABLE users (
        id SERIAL PRIMARY KEY,
        name TEXT NOT NULL,
        email TEXT UNIQUE NOT NULL
      );
    `);
  });

  afterAll(async () => {
    await client.end();
    await container.stop();
  });

  it("should insert and query users", async () => {
    await client.query(
      "INSERT INTO users (name, email) VALUES ($1, $2)",
      ["Alice", "alice@example.com"]
    );

    const result = await client.query("SELECT * FROM users WHERE name = $1", ["Alice"]);
    expect(result.rows).toHaveLength(1);
    expect(result.rows[0].email).toBe("alice@example.com");
  });
});
```

### Snapshot and Restore for Fast Test Isolation

One of the most powerful features of Testcontainers-node is database snapshots:

```javascript
describe("Tests with snapshot isolation", () => {
  let container;
  let client;

  beforeAll(async () => {
    container = await new PostgreSqlContainer("postgres:15").start();
    client = new Client({ connectionString: container.getConnectionUri() });
    await client.connect();

    // Run migrations
    await client.query(`
      CREATE TABLE products (id SERIAL PRIMARY KEY, name TEXT, price NUMERIC);
      INSERT INTO products (name, price) VALUES ('Widget', 9.99);
    `);

    // Create snapshot after migrations
    await container.snapshot("migrated_template");
  });

  beforeEach(async () => {
    // Restore clean state before each test
    await container.restoreSnapshot("migrated_template");
  });

  afterAll(async () => {
    await client.end();
    await container.stop();
  });

  it("test 1 modifies data", async () => {
    await client.query("INSERT INTO products (name, price) VALUES ('Gadget', 19.99)");
    const { rows } = await client.query("SELECT COUNT(*) FROM products");
    expect(rows[0].count).toBe("2");
  });

  it("test 2 starts with clean data", async () => {
    // Data from test 1 is not present
    const { rows } = await client.query("SELECT COUNT(*) FROM products");
    expect(rows[0].count).toBe("1");
  });
});
```

**Benefits:**
- Much faster than recreating containers for each test
- Guarantees clean state without manual cleanup
- Works with complex database schemas and seed data

**Sources:**
- [Testcontainers Node Documentation](https://context7.com/testcontainers/testcontainers-node/llms.txt)

---

## Transaction Rollback Patterns

### Overview

Transaction-based testing provides test isolation by wrapping each test in a transaction and rolling it back afterward. This is faster than snapshots for simple cases.

### Pattern 1: Manual Transaction Management

```javascript
describe("Transaction rollback tests", () => {
  let pool;

  beforeAll(async () => {
    pool = new Pool({ connectionString: process.env.DATABASE_URL });
  });

  afterAll(async () => {
    await pool.end();
  });

  it("should rollback changes after test", async () => {
    const client = await pool.connect();
    try {
      await client.query("BEGIN ISOLATION LEVEL SERIALIZABLE");

      // Run test operations
      await client.query("INSERT INTO users (name, email) VALUES ($1, $2)",
        ["Bob", "bob@example.com"]);

      const result = await client.query("SELECT * FROM users WHERE name = $1", ["Bob"]);
      expect(result.rows).toHaveLength(1);

      // Rollback transaction
      await client.query("ROLLBACK");
    } finally {
      client.release();
    }
  });
});
```

### Pattern 2: Using `@databases/pg-test`

The `@databases/pg-test` library provides automatic transaction management:

```javascript
const connect = require('@databases/pg');
const { sql } = require('@databases/pg');
const getDatabase = require('@databases/pg-test');

describe("Tests with @databases/pg-test", () => {
  it("automatically wraps in transaction", async () => {
    const db = await getDatabase();

    await db.query(sql`
      INSERT INTO users (name, email) VALUES ('Charlie', 'charlie@example.com')
    `);

    const users = await db.query(sql`SELECT * FROM users WHERE name = 'Charlie'`);
    expect(users).toHaveLength(1);

    // Transaction is automatically rolled back after test
  });
});
```

### Pattern 3: Savepoints for Nested Tests

```javascript
it("should use savepoints for nested operations", async () => {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    await client.query("INSERT INTO users (name) VALUES ('Test1')");

    // Create savepoint
    await client.query("SAVEPOINT sp1");
    await client.query("INSERT INTO users (name) VALUES ('Test2')");

    // Rollback to savepoint
    await client.query("ROLLBACK TO SAVEPOINT sp1");

    const result = await client.query("SELECT * FROM users WHERE name = 'Test2'");
    expect(result.rows).toHaveLength(0); // Test2 was rolled back

    await client.query("ROLLBACK");
  } finally {
    client.release();
  }
});
```

### Isolation Levels

Choose appropriate isolation levels based on your testing needs:

- **READ COMMITTED** (default): Prevents dirty reads
- **REPEATABLE READ**: Prevents non-repeatable reads
- **SERIALIZABLE**: Full isolation, prevents phantom reads

```javascript
await client.query("BEGIN ISOLATION LEVEL SERIALIZABLE");
```

**Trade-offs:**
- Higher isolation = fewer race conditions
- Higher isolation = potentially worse performance
- SERIALIZABLE recommended for critical business logic tests

**Sources:**
- [PostgreSQL Transactions Guide](https://www.atdatabases.org/docs/pg-guide-transactions)
- [PostgreSQL Handling Transactions](https://www.cybertechmind.com/2025/03/postgress-transactions.html)
- [pgsql-test npm package](https://www.npmjs.com/package/pgsql-test?activeTab=readme)

---

## Database Seeding and Fixtures

### Test Data Builders with Fishery

Fishery is a modern TypeScript-friendly factory library:

```bash
npm install --save-dev fishery
```

```typescript
// factories/user.factory.ts
import { Factory } from 'fishery';
import { faker } from '@faker-js/faker';

interface User {
  id?: number;
  name: string;
  email: string;
  role: 'admin' | 'analyst' | 'viewer';
}

export const userFactory = Factory.define<User>(({ sequence }) => ({
  name: faker.person.fullName(),
  email: `user${sequence}@example.com`,
  role: 'viewer',
}));

// Usage in tests
const adminUser = userFactory.build({ role: 'admin' });
const users = userFactory.buildList(5);
```

### Seed Data Pattern

```javascript
// test/helpers/seeds.js
async function seedDatabase(client) {
  // Clear existing data
  await client.query('TRUNCATE users, logs, parsers CASCADE');

  // Insert seed data
  await client.query(`
    INSERT INTO users (username, email, role) VALUES
      ('admin', 'admin@siembox.local', 'admin'),
      ('analyst1', 'analyst@siembox.local', 'analyst'),
      ('viewer1', 'viewer@siembox.local', 'viewer')
  `);

  await client.query(`
    INSERT INTO parsers (name, pattern, priority) VALUES
      ('nginx-access', '^\\[(?<timestamp>[^\\]]+)\\]', 10),
      ('syslog-generic', '(?<message>.*)', 100)
  `);
}

// Usage
beforeAll(async () => {
  container = await new PostgreSqlContainer("postgres:15").start();
  client = new Client({ connectionString: container.getConnectionUri() });
  await client.connect();
  await runMigrations(client);
  await seedDatabase(client);
  await container.snapshot("seeded");
});

beforeEach(async () => {
  await container.restoreSnapshot("seeded");
});
```

### SQL Fixtures Library

For complex fixture management:

```bash
npm install --save-dev sql-fixtures
```

```javascript
const Fixtures = require('sql-fixtures');

const dataSpec = {
  users: [
    { username: 'admin', email: 'admin@test.com', role: 'admin' },
    { username: 'analyst', email: 'analyst@test.com', role: 'analyst' }
  ],
  parsers: [
    { name: 'nginx', pattern: '^\\[.*', priority: 10 }
  ]
};

beforeAll(async () => {
  const fixtures = new Fixtures({ client: 'pg' });
  await fixtures.create(dataSpec);
});
```

**Sources:**
- [Fishery - TypeScript Factory Library](https://github.com/thoughtbot/fishery)
- [sql-fixtures for Node.js](https://github.com/city41/node-sql-fixtures)
- [Stepping up Test Fixture Game with Fishery](https://medium.com/leaselock-engineering/stepping-up-our-test-fixture-game-with-fishery-be22b76d1f22)

---

## Mocking External Services

### Mocking child_process (NMAP Integration)

#### Approach 1: Using mock-spawn

```bash
npm install --save-dev mock-spawn
```

```javascript
const mockSpawn = require('mock-spawn');
const { spawn } = require('child_process');

describe("NMAP Scanner", () => {
  let originalSpawn;
  let mySpawn;

  beforeEach(() => {
    originalSpawn = spawn;
    mySpawn = mockSpawn();
    require('child_process').spawn = mySpawn;
  });

  afterEach(() => {
    require('child_process').spawn = originalSpawn;
  });

  it("should parse nmap scan results", (done) => {
    // Mock nmap command
    mySpawn.setDefault(mySpawn.simple(0, JSON.stringify({
      scan: {
        '192.168.1.1': {
          hostname: 'router.local',
          ports: [{ port: 80, state: 'open' }]
        }
      }
    })));

    // Run your scan service
    scanService.runNmapScan('192.168.1.0/24')
      .then(results => {
        expect(results.hosts).toHaveLength(1);
        expect(results.hosts[0].openPorts).toContain(80);
        done();
      });
  });
});
```

#### Approach 2: Dependency Injection

```typescript
// scanner.service.ts
export class ScannerService {
  constructor(private readonly processSpawner = spawn) {}

  async runScan(target: string): Promise<ScanResult> {
    return new Promise((resolve, reject) => {
      const process = this.processSpawner('nmap', ['-sV', '-oX', '-', target]);
      // ... handle output
    });
  }
}

// scanner.service.spec.ts
it("should scan with injected spawner", async () => {
  const mockSpawner = jest.fn().mockReturnValue({
    stdout: { on: jest.fn() },
    stderr: { on: jest.fn() },
    on: jest.fn((event, callback) => {
      if (event === 'close') callback(0);
    })
  });

  const scanner = new ScannerService(mockSpawner);
  await scanner.runScan('192.168.1.1');

  expect(mockSpawner).toHaveBeenCalledWith('nmap', expect.any(Array));
});
```

**Sources:**
- [mock-spawn npm package](https://www.npmjs.com/package/mock-spawn)
- [Unit-testing Child Processes in Node.js](https://medium.com/@stephen.k.hess/unit-testing-child-processes-in-node-js-e855f866ae27)
- [Testing multiprocess code in Node](https://www.aha.io/engineering/articles/testing-multiprocess-code)

### Mocking UDP/TCP Sockets (Syslog Server)

#### Using Sinon for Socket Mocking

```javascript
const sinon = require('sinon');
const dgram = require('dgram');
const net = require('net');

describe("Syslog Server", () => {
  let udpSocket;
  let udpSocketStub;

  beforeEach(() => {
    udpSocket = dgram.createSocket('udp4');
    udpSocketStub = sinon.stub(dgram, 'createSocket').returns(udpSocket);
  });

  afterEach(() => {
    udpSocketStub.restore();
  });

  it("should receive syslog messages over UDP", (done) => {
    const syslogServer = new SyslogServer();

    syslogServer.on('message', (msg) => {
      expect(msg.facility).toBe(1);
      expect(msg.severity).toBe(6);
      done();
    });

    syslogServer.start();

    // Simulate incoming UDP message
    udpSocket.emit('message', Buffer.from('<14>Jan 01 12:00:00 testhost app: test message'), {
      address: '127.0.0.1',
      port: 12345
    });
  });
});
```

#### Integration Testing with Real Sockets

For more realistic testing, use actual UDP/TCP connections:

```javascript
const dgram = require('dgram');

describe("Syslog Server Integration", () => {
  let server;
  let client;

  beforeAll(async () => {
    server = new SyslogServer({ port: 0 }); // Random port
    await server.start();
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

  it("should receive and parse syslog messages", (done) => {
    const testMessage = '<134>Dec 09 20:36:20 webserver NGINX: test log entry';

    server.once('parsed', (log) => {
      expect(log.hostname).toBe('webserver');
      expect(log.app_name).toBe('NGINX');
      expect(log.message).toBe('test log entry');
      done();
    });

    const port = server.getPort();
    client.send(testMessage, port, '127.0.0.1');
  });
});
```

### Mocking File System (Log Shipper Testing)

#### Using mock-fs

```bash
npm install --save-dev mock-fs
```

```javascript
const mockFs = require('mock-fs');
const fs = require('fs');

describe("Log Shipper File Reading", () => {
  beforeEach(() => {
    mockFs({
      '/var/log': {
        'nginx': {
          'access.log': 'GET /page HTTP/1.1 200\n',
          'error.log': '[error] Connection refused\n'
        },
        'auth.log': 'Failed password for root\n'
      }
    });
  });

  afterEach(() => {
    mockFs.restore();
  });

  it("should read log files from configured paths", async () => {
    const shipper = new LogShipper({
      sources: ['/var/log/nginx/access.log']
    });

    const logs = await shipper.collectLogs();
    expect(logs).toHaveLength(1);
    expect(logs[0]).toContain('GET /page');
  });

  it("should watch for new log entries", (done) => {
    const shipper = new LogShipper({
      sources: ['/var/log/auth.log']
    });

    shipper.on('log', (entry) => {
      expect(entry).toContain('Failed password');
      done();
    });

    shipper.startWatching();

    // Simulate new log entry
    setTimeout(() => {
      fs.appendFileSync('/var/log/auth.log', 'Another failed attempt\n');
    }, 100);
  });
});
```

#### Alternative: memfs for Better Compatibility

```javascript
const { Volume } = require('memfs');

describe("Log Shipper with memfs", () => {
  let vol;

  beforeEach(() => {
    vol = Volume.fromJSON({
      '/logs/app.log': 'Initial log line\n'
    });
  });

  it("should read from in-memory filesystem", () => {
    const content = vol.readFileSync('/logs/app.log', 'utf8');
    expect(content).toContain('Initial log line');
  });
});
```

**Sources:**
- [mock-fs npm package](https://www.npmjs.com/package/mock-fs)
- [Testing Node.js fs with mock-fs](https://medium.com/nerd-for-tech/testing-in-node-js-easy-way-to-mock-filesystem-883b9f822ea4)
- [Unit testing Node.js fs with mock-fs](https://www.emgoto.com/nodejs-mock-fs/)

---

## Integration Test Patterns

### Test Lifecycle Best Practices

```javascript
describe("Full Integration Test Suite", () => {
  let container;
  let db;
  let app;

  // Setup once per test suite
  beforeAll(async () => {
    // Start database container
    container = await new PostgreSqlContainer("postgres:15")
      .withReuse() // Reuse across test runs if available
      .start();

    // Create database connection pool
    db = new Pool({
      connectionString: container.getConnectionUri()
    });

    // Run migrations
    await runMigrations(db);

    // Seed initial data
    await seedDatabase(db);

    // Create snapshot for fast restoration
    await container.snapshot("base");

    // Start application server
    app = await startTestServer(db);
  });

  // Reset state before each test
  beforeEach(async () => {
    await container.restoreSnapshot("base");
  });

  // Cleanup after each test (optional)
  afterEach(async () => {
    // Clear test-specific data if not using snapshots
  });

  // Cleanup once after all tests
  afterAll(async () => {
    await app.stop();
    await db.end();
    await container.stop();
  });

  it("test case 1", async () => {
    // Test logic
  });

  it("test case 2", async () => {
    // Test logic
  });
});
```

### Shared Test Utilities

```javascript
// test/helpers/testUtils.js
export class DatabaseTestHelper {
  constructor(db) {
    this.db = db;
  }

  async createUser(overrides = {}) {
    const user = {
      username: `user_${Date.now()}`,
      email: `test_${Date.now()}@example.com`,
      role: 'viewer',
      ...overrides
    };

    const result = await this.db.query(
      'INSERT INTO users (username, email, role) VALUES ($1, $2, $3) RETURNING *',
      [user.username, user.email, user.role]
    );

    return result.rows[0];
  }

  async createParser(overrides = {}) {
    const parser = {
      name: `parser_${Date.now()}`,
      pattern: '(?<message>.*)',
      priority: 50,
      enabled: true,
      ...overrides
    };

    const result = await this.db.query(
      'INSERT INTO parsers (name, pattern, priority, enabled) VALUES ($1, $2, $3, $4) RETURNING *',
      [parser.name, parser.pattern, parser.priority, parser.enabled]
    );

    return result.rows[0];
  }

  async clearTable(tableName) {
    await this.db.query(`TRUNCATE ${tableName} CASCADE`);
  }
}

// Usage in tests
let testHelper;

beforeAll(async () => {
  testHelper = new DatabaseTestHelper(db);
});

it("should create and query users", async () => {
  const user = await testHelper.createUser({ role: 'admin' });
  expect(user.role).toBe('admin');
});
```

### Parallel Test Execution with Database Isolation

#### Jest Configuration for Parallel Tests

```javascript
// jest.config.js
module.exports = {
  testEnvironment: 'node',
  maxWorkers: 4, // Number of parallel workers
  testTimeout: 30000,
  setupFilesAfterEnv: ['<rootDir>/test/setup.js']
};
```

#### Per-Worker Database Setup

```javascript
// test/setup.js
const { PostgreSqlContainer } = require('@testcontainers/postgresql');

let container;
let databaseUrl;

beforeAll(async () => {
  const workerId = process.env.JEST_WORKER_ID || '1';

  // Each worker gets its own database container
  container = await new PostgreSqlContainer("postgres:15")
    .withDatabase(`testdb_${workerId}`)
    .start();

  databaseUrl = container.getConnectionUri();
  process.env.DATABASE_URL = databaseUrl;

  // Run migrations for this worker's database
  await runMigrations(databaseUrl);
}, 60000);

afterAll(async () => {
  await container?.stop();
});

global.getDatabaseUrl = () => databaseUrl;
```

#### Vitest Configuration

```typescript
// vitest.config.ts
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    threads: true,
    maxThreads: 4,
    minThreads: 1,
    setupFiles: ['./test/setup.ts'],
    testTimeout: 30000,
    hookTimeout: 60000
  }
});
```

**Sources:**
- [Getting Started with Testcontainers for Node.js](https://testcontainers.com/guides/getting-started-with-testcontainers-for-nodejs/)
- [Jest CLI Options](https://jestjs.io/docs/cli)
- [How to Speed up Jest Test Runs](https://rathoreaparna678.medium.com/how-to-speed-up-jest-test-runs-by-splitting-and-parallelising-them-2c1557e196d5)

---

## Common Pitfalls and Solutions

### 1. Race Conditions in Async Tests

**Problem:**
```javascript
// BAD: Race condition with Promise.all
it("concurrent operations may fail", async () => {
  let counter = 0;

  await Promise.all([
    asyncIncrement(), // counter++
    asyncIncrement(), // counter++
    asyncIncrement()  // counter++
  ]);

  expect(counter).toBe(3); // May fail due to race condition
});
```

**Solution: Use Mutex Pattern**
```javascript
const { Mutex } = require('async-mutex');

it("use mutex for concurrent operations", async () => {
  const mutex = new Mutex();
  let counter = 0;

  async function safeIncrement() {
    const release = await mutex.acquire();
    try {
      counter++;
    } finally {
      release();
    }
  }

  await Promise.all([
    safeIncrement(),
    safeIncrement(),
    safeIncrement()
  ]);

  expect(counter).toBe(3); // Always passes
});
```

**Sources:**
- [Mastering Node.js Concurrency: Race Condition Detection](https://medium.com/@zuyufmanna/mastering-node-js-concurrency-race-condition-detection-and-prevention-3e0cfb3ccb07)
- [Node.js Race Conditions Guide](https://medium.com/@aliaghapour.developer/race-conditions-in-node-js-a-practical-guide-bcf13ee46b12)

### 2. Database Connection Leaks

**Problem:**
```javascript
// BAD: Client not released
it("will leak connection", async () => {
  const client = await pool.connect();
  const result = await client.query('SELECT * FROM users');
  // Missing client.release()
  expect(result.rows).toBeDefined();
});
```

**Solution 1: Always Release Clients**
```javascript
it("properly releases client", async () => {
  const client = await pool.connect();
  try {
    const result = await client.query('SELECT * FROM users');
    expect(result.rows).toBeDefined();
  } finally {
    client.release(); // Always release, even on error
  }
});
```

**Solution 2: Use Pool Query Method**
```javascript
it("use pool.query to avoid manual release", async () => {
  // Pool automatically manages client lifecycle
  const result = await pool.query('SELECT * FROM users');
  expect(result.rows).toBeDefined();
});
```

**Solution 3: Monitor Connection Pool**
```javascript
afterEach(() => {
  const { totalCount, idleCount, waitingCount } = pool;
  console.log(`Pool stats: total=${totalCount}, idle=${idleCount}, waiting=${waitingCount}`);

  if (waitingCount > 0) {
    throw new Error('Connection leak detected: clients waiting for pool');
  }
});
```

**Sources:**
- [node-postgres Pooling Documentation](https://node-postgres.com/features/pooling)
- [PG Pool leaking connections issue](https://github.com/brianc/node-postgres/issues/1882)

### 3. Port Conflicts in Parallel Tests

**Problem:**
```javascript
// BAD: Hard-coded ports cause conflicts
beforeAll(async () => {
  server = new SyslogServer({ port: 514 }); // Will fail if port in use
  await server.start();
});
```

**Solution 1: Use Dynamic Port Assignment**
```javascript
beforeAll(async () => {
  server = new SyslogServer({ port: 0 }); // OS assigns random available port
  await server.start();
  testPort = server.address().port;
});
```

**Solution 2: Testcontainers Automatic Port Mapping**
```javascript
// Testcontainers automatically maps to random host ports
const postgres = await new PostgreSqlContainer("postgres:15")
  .withExposedPorts(5432)
  .start();

const mappedPort = postgres.getMappedPort(5432); // Random available port
```

**Solution 3: Worker-Specific Ports**
```javascript
beforeAll(async () => {
  const workerId = parseInt(process.env.JEST_WORKER_ID || '1');
  const basePort = 10000;
  const workerPort = basePort + workerId;

  server = new SyslogServer({ port: workerPort });
  await server.start();
});
```

**Sources:**
- [Testcontainers Port Mapping](https://github.com/testcontainers/testcontainers-node/blob/main/docs/features/containers.md)
- [Jest Parallel Test Execution](https://jestjs.io/docs/cli)

### 4. Cleaning Up Test Data

**Problem:**
```javascript
// BAD: Tests leave data behind, affecting subsequent tests
it("creates user", async () => {
  await db.query("INSERT INTO users (username) VALUES ('testuser')");
  // No cleanup
});

it("expects empty database", async () => {
  const result = await db.query("SELECT * FROM users");
  expect(result.rows).toHaveLength(0); // FAILS: testuser still exists
});
```

**Solution 1: Snapshot Restore (Recommended)**
```javascript
beforeAll(async () => {
  await container.snapshot("clean");
});

beforeEach(async () => {
  await container.restoreSnapshot("clean");
});
```

**Solution 2: Transaction Rollback**
```javascript
beforeEach(async () => {
  await db.query("BEGIN");
});

afterEach(async () => {
  await db.query("ROLLBACK");
});
```

**Solution 3: Explicit Cleanup**
```javascript
afterEach(async () => {
  await db.query("TRUNCATE users, logs, parsers CASCADE");
  await seedDatabase(db); // Restore initial state
});
```

**Solution 4: Isolated Test Databases**
```javascript
// Each test suite gets its own database
beforeAll(async () => {
  const testId = Math.random().toString(36).substring(7);
  container = await new PostgreSqlContainer("postgres:15")
    .withDatabase(`test_${testId}`)
    .start();
});
```

### 5. Timeout Issues with Slow Container Startup

**Problem:**
```javascript
// BAD: Default timeout too short for container startup
beforeAll(async () => {
  container = await new PostgreSqlContainer("postgres:15").start();
  // Times out after 5 seconds
});
```

**Solution 1: Increase Timeout**
```javascript
beforeAll(async () => {
  container = await new PostgreSqlContainer("postgres:15").start();
}, 60000); // 60 second timeout
```

**Solution 2: Container Reuse**
```javascript
// Reuse containers across test runs
beforeAll(async () => {
  container = await new PostgreSqlContainer("postgres:15")
    .withReuse() // Reuses existing container if available
    .start();
}, 60000);
```

**Solution 3: Global Setup (Jest)**
```javascript
// globalSetup.js - runs once for all tests
module.exports = async () => {
  const container = await new PostgreSqlContainer("postgres:15").start();
  process.env.TEST_DATABASE_URL = container.getConnectionUri();
  global.__CONTAINER__ = container;
};

// globalTeardown.js
module.exports = async () => {
  await global.__CONTAINER__?.stop();
};
```

**Sources:**
- [Testcontainers Best Practices](https://www.docker.com/blog/testcontainers-best-practices/)
- [Initialization Strategies with Testcontainers](https://rieckpil.de/initialization-strategies-with-testcontainers-for-integration-tests/)

---

## Summary and Recommendations

### For SIEMBox Project

Based on the research, here are the recommended strategies for SIEMBox:

#### 1. Database Testing Strategy
- **Use Testcontainers** with PostgreSQL 15 for integration tests
- **Implement snapshot/restore** for fast test isolation
- **Run migrations** in `beforeAll`, then snapshot the clean state
- **Restore snapshot** in `beforeEach` for test isolation

#### 2. NMAP Integration Testing
- **Use mock-spawn** for unit tests of scan parsing logic
- **Use dependency injection** to make spawner testable
- **Create integration tests** that run actual nmap against test containers
- **Mock slow scans** in CI/CD, run real scans in nightly builds

#### 3. Syslog Server Testing
- **Use real UDP/TCP sockets** with dynamic port assignment
- **Test with actual syslog clients** for integration tests
- **Mock at application layer**, not transport layer
- **Validate RFC 3164 parsing** with comprehensive test cases

#### 4. Log Shipper Testing
- **Use mock-fs** for file system operations
- **Test file watching** with simulated file changes
- **Integration tests** with real Docker volume mounts
- **Validate API key authentication** and ghost shipper detection

#### 5. Parallel Testing
- **Configure Jest/Vitest** for 4 parallel workers
- **Use Testcontainers** with worker-specific databases
- **Leverage JEST_WORKER_ID** for isolation
- **Monitor connection pools** for leaks

#### 6. Test Data Management
- **Use Fishery factories** for TypeScript test data
- **Create test helpers** for common database operations
- **Seed realistic data** for end-to-end scenarios
- **Use snapshots** instead of manual cleanup

#### 7. Avoiding Pitfalls
- **Always release database clients** or use pool.query()
- **Use mutex patterns** for testing concurrent operations
- **Dynamic port assignment** for all network services
- **60-second timeouts** for container startup operations
- **Explicit cleanup** in afterAll hooks

### Example Test File Structure

```
/backend/test
├── setup.js                      # Global test configuration
├── helpers/
│   ├── testDatabase.js           # Database test utilities
│   ├── testServer.js             # Server test utilities
│   └── factories/                # Fishery factories
│       ├── user.factory.ts
│       ├── parser.factory.ts
│       └── log.factory.ts
├── integration/
│   ├── api/
│   │   ├── auth.test.js
│   │   ├── parsers.test.js
│   │   └── logs.test.js
│   ├── services/
│   │   ├── scanner.test.js       # NMAP integration
│   │   ├── syslog.test.js        # Syslog server
│   │   └── parser.test.js        # Parser engine
│   └── end-to-end/
│       └── logIngestion.test.js  # Full pipeline
└── unit/
    ├── parsers/
    └── validators/
```

### Additional Resources

- [Node.js Testing Best Practices (2025)](https://github.com/goldbergyoni/nodejs-testing-best-practices)
- [Testcontainers Documentation](https://testcontainers.com/guides/getting-started-with-testcontainers-for-nodejs/)
- [PostgreSQL Testing with Node.js](https://www.atdatabases.org/docs/pg-test)
- [Integration Testing Node.js Postgres with Vitest](https://nikolamilovic.com/posts/integration-testing-node-postgres-vitest-testcontainers/)

---

**Last Updated:** January 2026
**Researched for:** SIEMBox v0.x (Pre-v1.0)
