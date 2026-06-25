/**
 * Server-delivered YARA rule packs for the EDR agent.
 *
 * Bundles live in `edr_yara_bundle` (one row per version). The server always
 * serves the HIGHEST version. The agent downloads it only when the
 * `yara_rules_version` in its AgentConfig increases.
 *
 * The re-pull trigger is handled in the EDR routes: the served `config_version`
 * is (agent.config_version + current yara version), so publishing a higher
 * bundle version automatically raises every agent's config_version → the agent
 * re-pulls config, sees the new yara_rules_version, and downloads the bundle.
 * Publishing therefore never has to touch agent rows.
 */
import crypto from 'crypto';
import { query } from '../../config/database';
import { logger } from '../../utils/logger';

export interface YaraBundle {
  version: number;
  rules: string;
  sha256: string;
  source: string | null;
  created_at: Date;
}

/**
 * How many bundle versions to retain. Server-side only — the agent always pulls
 * the highest version, so older rows exist purely for rollback/audit. Each row is
 * a full copy (~16.6MB on YARA-Forge Extended), so we cap the table. Always keep
 * at least 1 (the current bundle).
 */
const KEEP_VERSIONS = Math.max(1, parseInt(process.env.EDR_YARA_KEEP_VERSIONS || '10', 10) || 10);

/** Delete all but the newest KEEP_VERSIONS bundles (by version, gap-safe). */
async function pruneOldBundles(): Promise<void> {
  const result = await query(
    `DELETE FROM edr_yara_bundle
      WHERE version NOT IN (
        SELECT version FROM edr_yara_bundle ORDER BY version DESC LIMIT $1
      )`,
    [KEEP_VERSIONS]
  );
  if ((result.rowCount ?? 0) > 0) {
    logger.info(`[YARA] pruned ${result.rowCount} old bundle version(s), keeping latest ${KEEP_VERSIONS}`);
  }
}

/** Highest published bundle version, or 0 if none (agent then uses baseline only). */
export async function getCurrentYaraVersion(): Promise<number> {
  const result = await query('SELECT COALESCE(MAX(version), 0) AS v FROM edr_yara_bundle');
  return Number(result.rows[0]?.v ?? 0);
}

/** Highest-version bundle row, or null if nothing has been published. */
export async function getCurrentYaraBundle(): Promise<YaraBundle | null> {
  const result = await query(
    `SELECT version, rules, sha256, source, created_at
       FROM edr_yara_bundle
      ORDER BY version DESC
      LIMIT 1`
  );
  return result.rows[0] ?? null;
}

/** Bundle metadata (no rules body) for the admin UI / verification. */
export async function getYaraStatus(): Promise<{
  version: number;
  sha256: string | null;
  source: string | null;
  bytes: number;
  created_at: Date | null;
}> {
  const current = await getCurrentYaraBundle();
  return {
    version: current?.version ?? 0,
    sha256: current?.sha256 ?? null,
    source: current?.source ?? null,
    bytes: current ? Buffer.byteLength(current.rules, 'utf8') : 0,
    created_at: current?.created_at ?? null,
  };
}

/**
 * Publish a new bundle as max(version)+1, but ONLY if its content differs from
 * the current one (keyed on sha256). Returns the new version, or null if the
 * content is unchanged. Raising the version is what makes agents re-pull (see the
 * module note above), so callers don't touch agent rows.
 */
export async function publishYaraBundle(rules: string, source: string): Promise<number | null> {
  const sha256 = crypto.createHash('sha256').update(rules, 'utf8').digest('hex');
  const current = await getCurrentYaraBundle();
  if (current && current.sha256 === sha256) {
    logger.info(`[YARA] bundle unchanged (v${current.version}, sha256=${sha256.slice(0, 12)}…); skipping publish`);
    return null;
  }
  const nextVersion = (current?.version ?? 0) + 1;
  await query(
    `INSERT INTO edr_yara_bundle (version, rules, sha256, source) VALUES ($1, $2, $3, $4)`,
    [nextVersion, rules, sha256, source]
  );
  logger.info(
    `[YARA] published bundle v${nextVersion} (${Buffer.byteLength(rules, 'utf8')} bytes, ` +
      `sha256=${sha256.slice(0, 12)}…, source=${source})`
  );
  await pruneOldBundles();
  return nextVersion;
}
