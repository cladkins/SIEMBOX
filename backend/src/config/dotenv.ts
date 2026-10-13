import path from 'path';
import dotenv from 'dotenv';

/**
 * Load .env from the working directory into process.env, the way dotenv 16 did:
 * silently, and never overriding a variable that is already set.
 *
 * Every option is spelled out. Since dotenv 17, config() prints an
 * "injected env (N) from .env" line unless `quiet` is set, and since dotenv 18
 * it takes any option the call leaves out from DOTENV_* / DOTENV_CONFIG_*
 * environment variables (DOTENV_DEBUG would list key names, DOTENV_PATH would
 * load another file, DOTENV_OVERRIDE would let .env win), which dotenv 16
 * only honoured for `node -r dotenv/config`.
 */
export function loadDotenv(): void {
  dotenv.config({
    path: path.resolve(process.cwd(), '.env'),
    encoding: 'utf8',
    quiet: true,
    debug: false,
    override: false,
    fast: false,
  });
}
