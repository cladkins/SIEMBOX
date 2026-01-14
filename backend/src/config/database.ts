import { Pool } from 'pg';
import dotenv from 'dotenv';
import { logger } from '../utils/logger';

dotenv.config();

const pool = new Pool({
  host: process.env.DB_HOST || 'localhost',
  port: parseInt(process.env.DB_PORT || '5432'),
  database: process.env.DB_NAME || 'siembox',
  user: process.env.DB_USER || 'siembox',
  password: process.env.DB_PASSWORD || 'changeme',
  max: 20,
  idleTimeoutMillis: 30000,
  connectionTimeoutMillis: 2000,
});

pool.on('connect', () => {
  logger.info('Database connection established');
});

pool.on('error', (err) => {
  logger.error('Unexpected database error:', err);
  process.exit(-1);
});

export const query = async (text: string, params?: any[]) => {
  const start = Date.now();
  try {
    const res = await pool.query(text, params);
    const duration = Date.now() - start;
    logger.debug('Executed query', { text, duration, rows: res.rowCount });
    return res;
  } catch (error: any) {
    // Extract PostgreSQL error details for proper logging
    // Error properties exist on prototype chain and don't serialize with JSON.stringify
    const errorDetails = {
      message: error.message || 'Unknown error',
      code: error.code || 'UNKNOWN',
      detail: error.detail || null,
      hint: error.hint || null,
      position: error.position || null,
      where: error.where || null,
      schema: error.schema || null,
      table: error.table || null,
      column: error.column || null,
      dataType: error.dataType || null,
      constraint: error.constraint || null,
    };

    logger.error('Database query error:', {
      query: text,
      params: params ? JSON.stringify(params) : null,
      error: errorDetails,
      stack: error.stack,
    });

    throw error;
  }
};

export const getClient = () => {
  return pool.connect();
};

export default pool;
