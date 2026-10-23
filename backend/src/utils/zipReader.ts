/**
 * A strict, in-memory zip reader for archives SIEMBox downloads but did not
 * write (the SigmaHQ rule release). Nothing is written to disk and nothing in
 * the archive is ever executed: entries come back as Buffers for the caller to
 * parse as data.
 *
 * Caps (zip-bomb guards), all enforced before or while inflating:
 *  - the archive's own size (the caller's download cap applies first);
 *  - the number of entries in the central directory;
 *  - each entry's uncompressed size: inflate stops at the cap
 *    (zlib maxOutputLength), whatever the headers claim;
 *  - the total uncompressed size of the entries the caller asked for, summed as
 *    they are inflated (overlapping entries, the classic "zip of zips" bomb,
 *    count every time they are read).
 *
 * Refused outright (the whole archive): ZIP64, a multi-disk archive, an
 * encrypted entry, a compression method other than stored/deflate, a header
 * that points outside the buffer, an entry whose name is absolute, has a `..`
 * segment, a backslash, a NUL or another control character, a duplicate name,
 * and an entry whose inflated size or CRC-32 differs from the central directory.
 * Paths are never used to touch the filesystem; they are checked so an odd
 * archive is noticed instead of half-read.
 */
import zlib from 'zlib';

export interface ZipLimits {
  /** Largest archive accepted, in bytes. */
  maxArchiveBytes: number;
  /** Most central directory entries (files and directories). */
  maxEntries: number;
  /** Largest uncompressed entry, in bytes. */
  maxEntryBytes: number;
  /** Most uncompressed bytes read across all selected entries. */
  maxTotalBytes: number;
}

export interface ZipEntry {
  name: string;
  data: Buffer;
}

export class ZipError extends Error {}

const EOCD_SIG = 0x06054b50;
const ZIP64_LOCATOR_SIG = 0x07064b50;
const CDH_SIG = 0x02014b50;
const LFH_SIG = 0x04034b50;
const MAX_NAME_BYTES = 512;

/** Why an entry name is refused, or null. */
export function zipNameProblem(name: string): string | null {
  if (name.length === 0) return 'an empty name';
  if (Buffer.byteLength(name, 'utf8') > MAX_NAME_BYTES) return 'a name over 512 bytes';
  // Control characters (incl. NUL) and backslashes: no legitimate rule path has one.
  for (let i = 0; i < name.length; i++) {
    const c = name.charCodeAt(i);
    if (c < 0x20 || c === 0x7f) return 'a control character in its name';
  }
  if (name.includes('\\')) return 'a backslash in its name';
  if (name.startsWith('/')) return 'an absolute path';
  if (/^[A-Za-z]:/.test(name)) return 'a drive letter';
  const segments = name.split('/');
  if (segments.some((s) => s === '..' || s === '.')) return 'a "." or ".." path segment';
  if (segments.slice(0, -1).some((s) => s === '')) return 'an empty path segment';
  return null;
}

function u16(buf: Buffer, at: number): number {
  if (at < 0 || at + 2 > buf.length) throw new ZipError('zip: a header points outside the archive');
  return buf.readUInt16LE(at);
}

function u32(buf: Buffer, at: number): number {
  if (at < 0 || at + 4 > buf.length) throw new ZipError('zip: a header points outside the archive');
  return buf.readUInt32LE(at);
}

/**
 * Read the selected entries of a zip archive held in memory. `want` decides,
 * from the (already checked) name, whether an entry is inflated; directories
 * are never passed to it. Throws ZipError for anything outside the limits.
 */
export function readZip(buf: Buffer, limits: ZipLimits, want: (name: string) => boolean): ZipEntry[] {
  if (buf.length > limits.maxArchiveBytes) {
    throw new ZipError(`zip: the archive is ${buf.length} bytes; the limit is ${limits.maxArchiveBytes}`);
  }
  if (buf.length < 22 || buf.readUInt32LE(0) !== LFH_SIG) throw new ZipError('zip: not a zip archive');

  // End of central directory: its fixed 22 bytes plus at most a 64 KiB comment.
  let eocd = -1;
  const minEocd = Math.max(0, buf.length - 22 - 0xffff);
  for (let i = buf.length - 22; i >= minEocd; i--) {
    if (buf.readUInt32LE(i) === EOCD_SIG) {
      eocd = i;
      break;
    }
  }
  if (eocd < 0) throw new ZipError('zip: end of central directory not found');
  if (eocd >= 20 && buf.readUInt32LE(eocd - 20) === ZIP64_LOCATOR_SIG) throw new ZipError('zip: ZIP64 archives are not accepted');
  const disk = u16(buf, eocd + 4);
  const cdDisk = u16(buf, eocd + 6);
  const entriesOnDisk = u16(buf, eocd + 8);
  const entryCount = u16(buf, eocd + 10);
  const cdSize = u32(buf, eocd + 12);
  const cdOffset = u32(buf, eocd + 16);
  if (disk !== 0 || cdDisk !== 0 || entriesOnDisk !== entryCount) throw new ZipError('zip: multi-disk archives are not accepted');
  if (entryCount === 0xffff || cdOffset === 0xffffffff || cdSize === 0xffffffff) {
    throw new ZipError('zip: ZIP64 archives are not accepted');
  }
  if (entryCount > limits.maxEntries) {
    throw new ZipError(`zip: the archive has ${entryCount} entries; the limit is ${limits.maxEntries}`);
  }
  if (cdOffset + cdSize > eocd) throw new ZipError('zip: the central directory overlaps its end record');

  const seen = new Set<string>();
  const out: ZipEntry[] = [];
  let total = 0;
  let p = cdOffset;
  for (let n = 0; n < entryCount; n++) {
    if (u32(buf, p) !== CDH_SIG) throw new ZipError('zip: bad central directory header');
    const flags = u16(buf, p + 8);
    const method = u16(buf, p + 10);
    const crc = u32(buf, p + 16);
    const compSize = u32(buf, p + 20);
    const size = u32(buf, p + 24);
    const nameLen = u16(buf, p + 28);
    const extraLen = u16(buf, p + 30);
    const commentLen = u16(buf, p + 32);
    const localOffset = u32(buf, p + 42);
    if (p + 46 + nameLen > cdOffset + cdSize) throw new ZipError('zip: a central directory entry runs past the directory');
    const name = buf.toString('utf8', p + 46, p + 46 + nameLen);
    p += 46 + nameLen + extraLen + commentLen;

    const problem = zipNameProblem(name);
    if (problem) throw new ZipError(`zip: an entry has ${problem}`);
    if (seen.has(name)) throw new ZipError(`zip: duplicate entry "${name}"`);
    seen.add(name);
    if (flags & 0x1) throw new ZipError(`zip: entry "${name}" is encrypted`);
    if (compSize === 0xffffffff || size === 0xffffffff || localOffset === 0xffffffff) {
      throw new ZipError('zip: ZIP64 archives are not accepted');
    }
    if (name.endsWith('/')) continue; // a directory
    if (!want(name)) continue;
    if (method !== 0 && method !== 8) throw new ZipError(`zip: entry "${name}" uses compression method ${method}`);
    if (size > limits.maxEntryBytes) {
      throw new ZipError(`zip: entry "${name}" is ${size} bytes; the limit is ${limits.maxEntryBytes}`);
    }
    if (total + size > limits.maxTotalBytes) {
      throw new ZipError(`zip: the entries add up to more than ${limits.maxTotalBytes} bytes uncompressed`);
    }

    if (u32(buf, localOffset) !== LFH_SIG) throw new ZipError(`zip: bad local header for "${name}"`);
    const dataStart = localOffset + 30 + u16(buf, localOffset + 26) + u16(buf, localOffset + 28);
    if (dataStart + compSize > cdOffset) throw new ZipError(`zip: entry "${name}" runs into the central directory`);
    const raw = buf.subarray(dataStart, dataStart + compSize);

    let data: Buffer;
    if (method === 0) {
      data = Buffer.from(raw);
    } else {
      try {
        // Stops (throws) one byte past the declared size, whatever the stream holds.
        data = zlib.inflateRawSync(raw, { maxOutputLength: Math.max(1, size + 1) });
      } catch (e) {
        throw new ZipError(`zip: entry "${name}" does not inflate to its declared size (${e instanceof Error ? e.message : e})`);
      }
    }
    if (data.length !== size) throw new ZipError(`zip: entry "${name}" is not its declared size`);
    if (zlib.crc32(data) !== crc) throw new ZipError(`zip: entry "${name}" fails its CRC-32 check`);
    total += data.length;
    out.push({ name, data });
  }
  return out;
}
