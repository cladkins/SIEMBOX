import { logger } from './logger';

/**
 * Read an integer setting from the environment. Unset/blank gives `fallback`;
 * junk or a value below `min` also gives `fallback`, but says so -- a typo in
 * .env should be visible in the logs, not silently become NaN or 0.
 */
export function envInt(name: string, fallback: number, min: number): number {
  const raw = process.env[name];
  if (raw === undefined || raw.trim() === '') return fallback;
  const value = Number(raw);
  if (!Number.isInteger(value) || value < min) {
    logger.warn(`Ignoring ${name}="${raw}": expected an integer >= ${min}. Using ${fallback}.`);
    return fallback;
  }
  return value;
}
