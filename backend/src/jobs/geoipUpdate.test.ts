/**
 * GeoIP database update job.
 *
 * The job exists because geo enrichment failed *silently*: no MMDB meant no
 * country_code in parsed_data, so none in alerts.matched_data, so the GeoIP map
 * and the Threat Intel country tables were permanently empty with nothing on
 * screen saying why. The only cure was noticing a shell script in the repo.
 *
 * These cover the parts that are easy to get wrong and impossible to notice:
 * the month walk across a year boundary, the staleness rule that decides
 * whether to touch the network at all, and the validity gate that stops a bad
 * download replacing a working database. Run with `npm test` (tsx --test).
 */
import { test, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import {
  monthStamp,
  needsUpdate,
  currentDbAgeMs,
  isValidMmdb,
  isAutoUpdateEnabled,
} from './geoipUpdate';

const DAY = 24 * 60 * 60 * 1000;
const tmpFiles: string[] = [];

function tmpFile(contents: Buffer | string, ageMs = 0): string {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'geoip-')), 'db.mmdb');
  fs.writeFileSync(file, contents);
  if (ageMs > 0) {
    const when = new Date(Date.now() - ageMs);
    fs.utimesSync(file, when, when);
  }
  tmpFiles.push(file);
  return file;
}

afterEach(() => {
  delete process.env.GEOIP_AUTO_UPDATE;
});

test('the month stamp matches the DB-IP file naming', () => {
  assert.equal(monthStamp(new Date('2026-07-28T12:00:00Z'), 0), '2026-07');
  assert.equal(monthStamp(new Date('2026-07-28T12:00:00Z'), 1), '2026-06');
});

test('the previous-month fallback crosses a year boundary', () => {
  // Every January this is the only path that finds a file, because the new
  // month is typically not published on the 1st.
  assert.equal(monthStamp(new Date('2026-01-03T00:00:00Z'), 1), '2025-12');
  assert.equal(monthStamp(new Date('2026-01-03T00:00:00Z'), 0), '2026-01');
});

test('the month stamp is UTC, not local', () => {
  // 23:30 on the 31st in UTC is already the next month in some zones; the file
  // name has to follow UTC or the first request of the month 404s.
  assert.equal(monthStamp(new Date('2026-03-31T23:30:00Z'), 0), '2026-03');
});

test('a missing database always needs an update', () => {
  assert.equal(needsUpdate(new Date(), '/nonexistent/path/db.mmdb'), true);
  assert.equal(currentDbAgeMs(new Date(), '/nonexistent/path/db.mmdb'), null);
});

test('an empty file counts as no database, not as a fresh one', () => {
  // A failed earlier install can leave a zero-byte file. Treating that as
  // current would wedge the job permanently.
  const file = tmpFile(Buffer.alloc(0));
  assert.equal(currentDbAgeMs(new Date(), file), null);
  assert.equal(needsUpdate(new Date(), file), true);
});

test('a recent database is left alone', () => {
  // The common cycle: no network access at all.
  const file = tmpFile(Buffer.from('not really an mmdb'), 3 * DAY);
  assert.equal(needsUpdate(new Date(), file), false);
});

test('a database older than a publishing cycle is refetched', () => {
  const file = tmpFile(Buffer.from('not really an mmdb'), 40 * DAY);
  assert.equal(needsUpdate(new Date(), file), true);
});

test('an HTML error page is not accepted as a database', () => {
  // The failure this guards: a captive portal or proxy returning 200 with HTML.
  // Installing that would replace a working database with a broken one.
  assert.equal(isValidMmdb(Buffer.from('<!DOCTYPE html><html>404</html>')), false);
});

test('truncated or empty bytes are not accepted as a database', () => {
  assert.equal(isValidMmdb(Buffer.alloc(0)), false);
  assert.equal(isValidMmdb(Buffer.from([0x00, 0x01, 0x02, 0x03])), false);
});

test('the real MMDB is accepted when one is present', (t) => {
  // Only meaningful on a host that has actually run the job or the script.
  const candidates = [
    process.env.GEOIP_DB_PATH,
    '/app/data/dbip-country-lite.mmdb',
    path.join(__dirname, '../../../data/geoip/dbip-country-lite.mmdb'),
  ].filter((p): p is string => !!p);

  const found = candidates.find((p) => {
    try {
      return fs.statSync(p).size > 0;
    } catch {
      return false;
    }
  });
  if (!found) return t.skip('no local MMDB to validate against');

  assert.equal(isValidMmdb(fs.readFileSync(found)), true);
});

test('auto-update is on by default and opt-out by env', () => {
  // Default-on is the point: the feature was invisible precisely because it
  // required a manual step. Air-gapped installs get an explicit switch.
  delete process.env.GEOIP_AUTO_UPDATE;
  assert.equal(isAutoUpdateEnabled(), true);

  process.env.GEOIP_AUTO_UPDATE = 'false';
  assert.equal(isAutoUpdateEnabled(), false);

  process.env.GEOIP_AUTO_UPDATE = 'FALSE';
  assert.equal(isAutoUpdateEnabled(), false, 'the switch should not be case-sensitive');

  process.env.GEOIP_AUTO_UPDATE = 'true';
  assert.equal(isAutoUpdateEnabled(), true);
});
