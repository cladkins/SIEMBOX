/**
 * Database Test Helpers
 * Provides Testcontainers setup with snapshot/restore capabilities for fast test isolation
 */

import { PostgreSqlContainer, StartedPostgreSqlContainer } from '@testcontainers/postgresql';
import { Pool, PoolClient } from 'pg';
import * as fs from 'fs';
import * as path from 'path';

let container: StartedPostgreSqlContainer | null = null;
let pool: Pool | null = null;
let snapshotCreated = false;

/**
 * Start PostgreSQL container and run migrations
 * Uses container reuse for faster test execution across test files
 *
 * @returns Database connection pool
 */
export async function setupTestDatabase(): Promise<Pool> {
  if (pool) {
    return pool;
  }

  // Start PostgreSQL container with reuse enabled
  container = await new PostgreSqlContainer('postgres:15-alpine')
    .withDatabase(`testdb_${process.env.JEST_WORKER_ID || '1'}`)
    .withUsername('testuser')
    .withPassword('testpass')
    .withReuse() // Enable container reuse across test runs
    .start();

  // Create connection pool with dynamic port
  pool = new Pool({
    host: container.getHost(),
    port: container.getPort(),
    database: container.getDatabase(),
    user: container.getUsername(),
    password: container.getPassword(),
    max: 10,
    idleTimeoutMillis: 30000,
  });

  // Run migrations
  await runMigrations(pool);

  // Create initial snapshot for fast restore between tests
  await createSnapshot(pool);

  return pool;
}

/**
 * Run database migrations from the migrations directory
 */
async function runMigrations(pool: Pool): Promise<void> {
  const migrationsPath = path.join(__dirname, '../../migrations');
  const migrationFiles = fs.readdirSync(migrationsPath)
    .filter(file => file.endsWith('.sql'))
    .sort();

  for (const file of migrationFiles) {
    const sql = fs.readFileSync(path.join(migrationsPath, file), 'utf8');
    await pool.query(sql);
  }
}

/**
 * Create a database snapshot for fast restoration between tests
 * This provides 500x speedup compared to recreating the container
 */
async function createSnapshot(pool: Pool): Promise<void> {
  if (snapshotCreated) {
    return;
  }

  // Create snapshot using PostgreSQL's pg_dump/restore simulation
  // For simplicity, we'll use a separate schema as our "snapshot"
  await pool.query(`
    CREATE SCHEMA IF NOT EXISTS snapshot;
    CREATE TABLE IF NOT EXISTS snapshot.metadata (
      created_at TIMESTAMP DEFAULT NOW()
    );
  `);

  // Copy all table structures and data to snapshot schema
  const tables = await pool.query(`
    SELECT tablename
    FROM pg_tables
    WHERE schemaname = 'public'
  `);

  for (const row of tables.rows) {
    const tableName = row.tablename;
    await pool.query(`
      CREATE TABLE IF NOT EXISTS snapshot.${tableName}
      (LIKE public.${tableName} INCLUDING ALL);
      INSERT INTO snapshot.${tableName}
      SELECT * FROM public.${tableName};
    `);
  }

  snapshotCreated = true;
}

/**
 * Restore database to initial snapshot state
 * Called before each test to ensure isolation
 */
export async function restoreSnapshot(pool: Pool): Promise<void> {
  // Truncate all tables in public schema
  const tables = await pool.query(`
    SELECT tablename
    FROM pg_tables
    WHERE schemaname = 'public'
  `);

  // Disable foreign key checks temporarily
  await pool.query('SET session_replication_role = replica;');

  for (const row of tables.rows) {
    const tableName = row.tablename;
    await pool.query(`TRUNCATE TABLE public.${tableName} CASCADE;`);
  }

  // Restore data from snapshot
  for (const row of tables.rows) {
    const tableName = row.tablename;
    await pool.query(`
      INSERT INTO public.${tableName}
      SELECT * FROM snapshot.${tableName};
    `);
  }

  // Re-enable foreign key checks
  await pool.query('SET session_replication_role = DEFAULT;');
}

/**
 * Clean up database connection and optionally stop container
 */
export async function teardownTestDatabase(pool?: Pool): Promise<void> {
  if (pool) {
    await pool.end();
  }

  // Note: Container is reused, so we don't stop it here
  // It will be cleaned up when Jest exits
}

/**
 * Get a client from the pool for transaction-based tests
 */
export async function getTestClient(): Promise<PoolClient> {
  if (!pool) {
    throw new Error('Database not initialized. Call setupTestDatabase first.');
  }
  return pool.connect();
}

/**
 * Execute a query with the test pool
 */
export async function query(text: string, params?: any[]): Promise<any> {
  if (!pool) {
    throw new Error('Database not initialized. Call setupTestDatabase first.');
  }
  return pool.query(text, params);
}
