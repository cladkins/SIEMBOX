/**
 * A tiny zip writer for tests (the SigmaHQ archive fixtures), with the knobs
 * the reader's guards need: a declared size that lies, a bad CRC, an
 * encryption flag, a compression method. Exported for the other test files;
 * its own test checks a plain archive round-trips through readZip.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import zlib from 'zlib';
import { readZip } from './zipReader';

export interface TestZipEntry {
  name: string;
  data: Buffer | string;
  /** Store instead of deflate. */
  stored?: boolean;
  /** Declared uncompressed size (default: the real one). */
  declaredSize?: number;
  crc?: number;
  flags?: number;
  method?: number;
}

export function makeZip(entries: TestZipEntry[], opts: { entryCount?: number } = {}): Buffer {
  const locals: Buffer[] = [];
  const centrals: Buffer[] = [];
  let offset = 0;
  for (const e of entries) {
    const data = Buffer.isBuffer(e.data) ? e.data : Buffer.from(e.data, 'utf8');
    const method = e.method ?? (e.stored ? 0 : 8);
    const body = method === 8 ? zlib.deflateRawSync(data) : data;
    const name = Buffer.from(e.name, 'utf8');
    const crc = e.crc ?? zlib.crc32(data);
    const size = e.declaredSize ?? data.length;
    const flags = (e.flags ?? 0) | 0x800; // UTF-8 names

    const local = Buffer.alloc(30);
    local.writeUInt32LE(0x04034b50, 0);
    local.writeUInt16LE(20, 4);
    local.writeUInt16LE(flags, 6);
    local.writeUInt16LE(method, 8);
    local.writeUInt32LE(crc >>> 0, 14);
    local.writeUInt32LE(body.length, 18);
    local.writeUInt32LE(size >>> 0, 22);
    local.writeUInt16LE(name.length, 26);
    locals.push(local, name, body);

    const central = Buffer.alloc(46);
    central.writeUInt32LE(0x02014b50, 0);
    central.writeUInt16LE(20, 4);
    central.writeUInt16LE(20, 6);
    central.writeUInt16LE(flags, 8);
    central.writeUInt16LE(method, 10);
    central.writeUInt32LE(crc >>> 0, 16);
    central.writeUInt32LE(body.length, 20);
    central.writeUInt32LE(size >>> 0, 24);
    central.writeUInt16LE(name.length, 28);
    central.writeUInt32LE(offset, 42);
    centrals.push(central, name);
    offset += 30 + name.length + body.length;
  }
  const cd = Buffer.concat(centrals);
  const eocd = Buffer.alloc(22);
  eocd.writeUInt32LE(0x06054b50, 0);
  const count = opts.entryCount ?? entries.length;
  eocd.writeUInt16LE(count, 8);
  eocd.writeUInt16LE(count, 10);
  eocd.writeUInt32LE(cd.length, 12);
  eocd.writeUInt32LE(offset, 16);
  return Buffer.concat([...locals, cd, eocd]);
}

test('makeZip output reads back with readZip (deflate and stored)', () => {
  const zip = makeZip([
    { name: 'rules/', data: '', stored: true },
    { name: 'rules/a.yml', data: 'title: a\n' },
    { name: 'rules/b.yml', data: 'title: b\n', stored: true },
  ]);
  const out = readZip(zip, { maxArchiveBytes: 1 << 20, maxEntries: 10, maxEntryBytes: 1024, maxTotalBytes: 4096 }, () => true);
  assert.deepEqual(
    out.map((e) => [e.name, e.data.toString()]),
    [
      ['rules/a.yml', 'title: a\n'],
      ['rules/b.yml', 'title: b\n'],
    ]
  );
});
