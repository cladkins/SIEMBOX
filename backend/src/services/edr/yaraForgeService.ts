/**
 * YARA-Forge rule fetcher (optional, opt-in via EDR_YARA_FORGE_ENABLED).
 *
 * Downloads the latest YARA-Forge "Extended" rule pack and publishes it as a new
 * bundle. We use Extended (not Core + Extended) on purpose: YARA-Forge tiers are
 * cumulative — Extended already contains every Core rule — so concatenating both
 * would create duplicate rule identifiers and the agent's combined compile would
 * fail. Extended (a permissively-licensed superset of Core) gives the broadest
 * conflict-free coverage in a single file.
 *
 * Release assets are .zip archives, so we extract the .yar with a tiny built-in
 * zip reader (no new dependency) rather than pulling in an unzip library.
 *
 * https://github.com/YARAHQ/yara-forge/releases
 */
import zlib from 'zlib';
import { logger } from '../../utils/logger';
import { publishYaraBundle } from './yaraService';

// `/releases/latest/download/<asset>` always resolves to the latest release.
const EXTENDED_URL =
  'https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-extended.zip';
const CORE_URL =
  'https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip';

const FETCH_TIMEOUT_MS = 120_000;
const MAX_ASSET_BYTES = 128 * 1024 * 1024; // generous ceiling; Extended is well under this

async function download(url: string): Promise<Buffer> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      redirect: 'follow', // release assets 302 to objects.githubusercontent.com
      signal: controller.signal,
      headers: { 'User-Agent': 'SIEMBox-EDR', Accept: 'application/octet-stream' },
    });
    if (!res.ok) throw new Error(`HTTP ${res.status} ${res.statusText} for ${url}`);
    const buf = Buffer.from(await res.arrayBuffer());
    if (buf.byteLength > MAX_ASSET_BYTES) throw new Error(`asset too large (${buf.byteLength} bytes)`);
    if (buf.byteLength < 4 || buf.readUInt32LE(0) !== 0x04034b50) {
      throw new Error('downloaded asset is not a zip archive');
    }
    return buf;
  } finally {
    clearTimeout(timer);
  }
}

/**
 * Extract and concatenate every *.yar / *.yara entry from a zip archive.
 * Reads the central directory (authoritative sizes) and inflates each entry —
 * handles the stored (0) and deflate (8) methods that release zips use.
 */
function extractYaraFromZip(buf: Buffer): string {
  const EOCD_SIG = 0x06054b50;
  const CDH_SIG = 0x02014b50;
  const LFH_SIG = 0x04034b50;

  // Locate the End Of Central Directory record (scan back over its 22-byte fixed
  // part plus up to a 64KB trailing comment).
  let eocd = -1;
  const minEocd = Math.max(0, buf.length - 22 - 0xffff);
  for (let i = buf.length - 22; i >= minEocd; i--) {
    if (buf.readUInt32LE(i) === EOCD_SIG) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new Error('zip: end-of-central-directory not found');

  const entryCount = buf.readUInt16LE(eocd + 10);
  let p = buf.readUInt32LE(eocd + 16); // central directory offset

  const parts: string[] = [];
  for (let n = 0; n < entryCount; n++) {
    if (buf.readUInt32LE(p) !== CDH_SIG) throw new Error('zip: bad central directory header');
    const method = buf.readUInt16LE(p + 10);
    const compSize = buf.readUInt32LE(p + 20);
    const nameLen = buf.readUInt16LE(p + 28);
    const extraLen = buf.readUInt16LE(p + 30);
    const commentLen = buf.readUInt16LE(p + 32);
    const localOffset = buf.readUInt32LE(p + 42);
    const name = buf.toString('utf8', p + 46, p + 46 + nameLen);
    p += 46 + nameLen + extraLen + commentLen;

    const lower = name.toLowerCase();
    if (!lower.endsWith('.yar') && !lower.endsWith('.yara')) continue;

    // Local header name/extra lengths can differ from the central directory's, so
    // re-read them to find where the entry's data actually starts.
    if (buf.readUInt32LE(localOffset) !== LFH_SIG) throw new Error('zip: bad local file header');
    const lNameLen = buf.readUInt16LE(localOffset + 26);
    const lExtraLen = buf.readUInt16LE(localOffset + 28);
    const dataStart = localOffset + 30 + lNameLen + lExtraLen;
    const data = buf.subarray(dataStart, dataStart + compSize);

    let content: Buffer;
    if (method === 0) content = data; // stored
    else if (method === 8) content = zlib.inflateRawSync(data); // deflate
    else throw new Error(`zip: unsupported compression method ${method} for ${name}`);
    parts.push(content.toString('utf8'));
  }
  if (!parts.length) throw new Error('zip: no .yar entry found');
  return parts.join('\n');
}

/** Download the YARA-Forge bundle text (Extended, with a Core fallback). */
export async function fetchYaraForgeRules(): Promise<{ rules: string; tier: string }> {
  try {
    const zip = await download(EXTENDED_URL);
    return { rules: extractYaraFromZip(zip), tier: 'extended' };
  } catch (err) {
    logger.warn(
      '[YARA] YARA-Forge Extended fetch failed, falling back to Core:',
      err instanceof Error ? err.message : err
    );
    const zip = await download(CORE_URL);
    return { rules: extractYaraFromZip(zip), tier: 'core' };
  }
}

/**
 * Refresh from YARA-Forge: fetch, then publish if the content changed. Returns
 * the new bundle version, or null if unchanged (or on a non-fatal empty fetch).
 */
export async function refreshYaraForge(): Promise<number | null> {
  const { rules, tier } = await fetchYaraForgeRules();
  if (!rules.trim()) throw new Error('YARA-Forge returned an empty rule set');
  const header = `// SIEMBox: imported from YARA-Forge (${tier}) at version publish time\n`;
  return publishYaraBundle(header + rules, `yara-forge-${tier}`);
}
