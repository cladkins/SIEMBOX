#!/usr/bin/env node
/**
 * End-to-end checks of the wall display page (docs/architecture/BIG-DISPLAY.md
 * §13, PR 4), with Playwright and Chromium from the environment (Playwright is
 * not a dependency of this package). Run against the Vite dev server or the
 * nginx image, plus a backend with some data:
 *
 *   BASE_URL=http://localhost:5173 API_URL=http://localhost:8421 \
 *   ADMIN_USER=admin ADMIN_PASSWORD=... OUT_DIR=/tmp/shots \
 *   PLAYWRIGHT_MODULE=/path/to/node_modules/playwright node scripts/verify-display.mjs
 *
 * NGINX=1 adds the checks only nginx can pass: the CSP header and no CSP
 * violations, and /display/ redirecting to /display with the fragment.
 *
 * It creates its own display links through the API and revokes them at the end.
 *
 * Checks:
 *  1. Session independence: with an admin signed in (tab A), opening a display
 *     link in the same browser (tab B) leaves the app's storage byte-identical,
 *     no display request carries Authorization or goes to /api/auth/me, the
 *     token never appears in a URL, and tab A's session still works.
 *  2. An expired (stale) session in storage: the display still works, storage
 *     is untouched, and it never navigates to /login.
 *  3. Rotation (server-timed, arrows, Space) and refresh (a request per refresh).
 *  4. Pause shows "Paused" and recovers by itself; rotate shows "isn't valid any
 *     more"; revoke shows "revoked" and stops polling. Never the login page.
 *  5. Backend unreachable: the lagging chip after 2 refreshes, the offline band
 *     and STALE panels after 5 minutes, recovery afterwards, no navigation.
 *  6. A new app_version reloads the page, right after a good snapshot.
 *  7. Readability at 1280×720, 1920×1080, 3840×2160 and portrait: no panel
 *     overflows and no text is under 2.2 vh (on portrait, 2.2 × 1.25vw: see
 *     board/theme.css). Screenshots go to OUT_DIR.
 *  8. Signing out in tab A leaves tab B updating.
 */
import { createRequire } from 'node:module';
import { mkdirSync } from 'node:fs';
import { join } from 'node:path';

const require = createRequire(import.meta.url);
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

const BASE = (process.env.BASE_URL || 'http://localhost:5173').replace(/\/$/, '');
const API = (process.env.API_URL || BASE).replace(/\/$/, '');
const OUT = process.env.OUT_DIR || '';
const NGINX = process.env.NGINX === '1';
const USER = process.env.ADMIN_USER || 'admin';
const PASSWORD = process.env.ADMIN_PASSWORD;
if (!PASSWORD) {
  console.error('ADMIN_PASSWORD is required');
  process.exit(2);
}
if (OUT) mkdirSync(OUT, { recursive: true });

const results = [];
let failed = 0;
async function check(name, fn) {
  const started = Date.now();
  try {
    await fn();
    results.push(`ok   ${name} (${((Date.now() - started) / 1000).toFixed(1)} s)`);
  } catch (error) {
    failed += 1;
    results.push(`FAIL ${name}: ${error.message}`);
  }
  console.log(results.at(-1));
}
function assert(cond, message) {
  if (!cond) throw new Error(message);
}

// --- API helpers (the admin's own session; never used by the display page) ------

async function api(method, path, token, body) {
  const res = await fetch(`${API}/api${path}`, {
    method,
    headers: { 'Content-Type': 'application/json', ...(token ? { Authorization: `Bearer ${token}` } : {}) },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const json = await res.json().catch(() => null);
  if (!res.ok) throw new Error(`${method} ${path}: ${res.status} ${JSON.stringify(json)}`);
  return json;
}

const login = await api('POST', '/auth/login', null, { username: USER, password: PASSWORD });
const adminToken = login.token;
const stamp = Date.now().toString(36);
const config = (refresh = 15) => ({
  privacy: 'operations',
  refresh_seconds: refresh,
  rotation: { enabled: true, seconds: 20 },
  timezone: null,
  clock: true,
  burn_in_shift: true,
  views: [
    {
      title: 'SOC overview',
      panels: [
        { id: 'open_alerts' },
        { id: 'alert_pulse' },
        { id: 'ingest' },
        { id: 'sources', silent_after_minutes: 15 },
        { id: 'shippers' },
        { id: 'recent_alerts', min_severity: 'high' },
      ],
    },
    {
      title: 'Threats',
      panels: [{ id: 'threat_map', window_days: 1 }, { id: 'top_sources' }, { id: 'top_rules', window_hours: 24 }, { id: 'open_alerts' }],
    },
  ],
});
const created = [];
async function createLink(name) {
  const r = await api('POST', '/display-links', adminToken, { name: `${name} ${stamp}`, config: config() });
  created.push(r.link.id);
  return { id: r.link.id, token: r.token };
}
const main = await createLink('verify main');
const lifecycle = await createLink('verify lifecycle');
const revokeMe = await createLink('verify revoke');
const displayUrl = (token, slash = '') => `${BASE}/display${slash}#k=${token}`;

// --- Browser ---------------------------------------------------------------------

const browser = await chromium.launch(process.env.CHROMIUM ? { executablePath: process.env.CHROMIUM } : {});
const context = await browser.newContext({ viewport: { width: 1920, height: 1080 } });
await context.addInitScript(() => {
  window.__csp = [];
  document.addEventListener('securitypolicyviolation', (e) => window.__csp.push(`${e.violatedDirective} ${e.blockedURI}`));
});

/** Every request a page makes, with its headers. */
function recordRequests(page) {
  const log = [];
  page.on('request', (req) => log.push({ url: req.url(), headers: req.headers() }));
  return log;
}
const snapshots = (log) => log.filter((r) => r.url.endsWith('/api/display/snapshot'));
const waitBoard = (page, timeout = 20_000) => page.waitForSelector('[data-panel]', { timeout });
async function waitRefusal(page, pattern, timeout) {
  await page.waitForFunction(
    (src) => new RegExp(src).test(document.querySelector('[data-testid="refusal"]')?.textContent ?? ''),
    pattern.source,
    { timeout }
  );
}
async function assertNotLogin(page) {
  const url = new URL(page.url());
  assert(url.pathname === '/display', `navigated to ${url.pathname}`);
  assert((await page.locator('input[type="password"]').count()) === 0, 'a password field is on the display page');
}
const APP_KEYS = ['token', 'user', 'siembox-dark-mode', 'siembox.recognizedBrowsers'];
const appStorage = (page) => page.evaluate((keys) => Object.fromEntries(keys.map((k) => [k, localStorage.getItem(k)])), APP_KEYS);

// Tab A: the signed-in app, with the session the app itself stores.
const tabA = await context.newPage();
await tabA.goto(`${BASE}/login`);
await tabA.evaluate(
  ({ token, user }) => {
    localStorage.setItem('token', token);
    localStorage.setItem('user', JSON.stringify(user));
    localStorage.setItem('siembox-dark-mode', 'true');
  },
  { token: adminToken, user: login.user }
);
await tabA.goto(`${BASE}/`);
await tabA.waitForLoadState('networkidle');
const before = await appStorage(tabA);
const meFromTabA = () =>
  tabA.evaluate(async () => (await fetch('/api/auth/me', { headers: { Authorization: `Bearer ${localStorage.getItem('token')}` } })).status);

const tabB = await context.newPage();
const tabBLog = recordRequests(tabB);

await check('1. a display link leaves the signed-in session alone', async () => {
  assert(before.token === adminToken, 'tab A is not signed in');
  assert(new URL(tabA.url()).pathname !== '/login', `tab A is on ${tabA.url()}`);
  await tabB.goto(displayUrl(main.token));
  await waitBoard(tabB);
  await tabB.waitForTimeout(1000);
  const after = await appStorage(tabA);
  assert(JSON.stringify(after) === JSON.stringify(before), `app storage changed: ${JSON.stringify(before)} -> ${JSON.stringify(after)}`);
  const sameOrigin = tabBLog.filter((r) => r.url.startsWith(BASE));
  assert(sameOrigin.every((r) => !('authorization' in r.headers)), 'a display request carried Authorization');
  assert(sameOrigin.every((r) => !r.url.includes('/api/auth/')), 'the display page called /api/auth');
  assert(tabBLog.every((r) => !r.url.includes('sbd1_')), 'the token appeared in a request URL');
  const snaps = snapshots(tabBLog);
  assert(snaps.length >= 1 && snaps.every((r) => r.headers['x-display-token'] === main.token), 'snapshot requests lack X-Display-Token');
  assert(sameOrigin.filter((r) => r.headers['x-display-token']).every((r) => r.url.endsWith('/api/display/snapshot')), 'token sent elsewhere');
  assert((await meFromTabA()) === 200, "tab A's session no longer works");
});

await check('2. an expired session in storage: display works, storage untouched, no /login', async () => {
  const stale = 'f'.repeat(64);
  await tabA.evaluate((t) => localStorage.setItem('token', t), stale);
  const staleStorage = await appStorage(tabA);
  const mark = tabBLog.length;
  await tabB.reload();
  await waitBoard(tabB);
  await tabB.waitForTimeout(1000);
  await assertNotLogin(tabB);
  assert(JSON.stringify(await appStorage(tabB)) === JSON.stringify(staleStorage), 'the display changed the stored session');
  const fresh = tabBLog.slice(mark);
  assert(fresh.every((r) => !('authorization' in r.headers) && !r.url.includes('/api/auth/')), 'a session call was made');
  await tabA.evaluate((t) => localStorage.setItem('token', t), adminToken);
});

if (NGINX) {
  await check('2b. /display/ (trailing slash) redirects to /display and keeps the link', async () => {
    const page = await context.newPage();
    await page.goto(displayUrl(main.token, '/'));
    await waitBoard(page);
    const url = new URL(page.url());
    assert(url.pathname === '/display' && url.hash === `#k=${main.token}`, `ended on ${page.url()}`);
    await page.close();
  });
  await check('2c. nginx: CSP on /display, /display.html not served', async () => {
    const res = await fetch(`${BASE}/display`);
    const csp = res.headers.get('content-security-policy') || '';
    assert(/script-src 'self'/.test(csp) && /default-src 'none'/.test(csp), `CSP: ${csp}`);
    assert(res.headers.get('referrer-policy') === 'no-referrer', 'no Referrer-Policy');
    assert((await fetch(`${BASE}/display.html`)).status === 404, '/display.html is served');
    const slash = await fetch(`${BASE}/display/`, { redirect: 'manual' });
    assert(slash.status === 301 && /\/display$/.test(slash.headers.get('location') || ''), `/display/ -> ${slash.status}`);
  });
}

await check('3. rotation and refresh', async () => {
  const counter = () => tabB.locator('.bd-strip-meta').innerText();
  const startCount = snapshots(tabBLog).length;
  const first = await counter();
  // Server-timed rotation: the view turns within one dwell (20 s).
  await tabB.waitForFunction((t) => document.querySelector('.bd-strip-meta')?.textContent !== t && /[12]\/2/.test(document.querySelector('.bd-strip-meta')?.textContent ?? ''), first, { timeout: 25_000 });
  // Refresh every 15 s (±10 %): another request within 17 s, and the chip says how fresh.
  for (let waited = 0; snapshots(tabBLog).length <= startCount && waited < 17_000; waited += 500) await tabB.waitForTimeout(500);
  assert(snapshots(tabBLog).length > startCount, 'no refresh request within one refresh');
  assert(/updated \d+ s ago/.test(await tabB.locator('[data-testid="freshness"]').innerText()), 'no freshness chip');
  const viewTitle = () => tabB.locator('.bd-strip-title').innerText();
  const t1 = await viewTitle();
  await tabB.keyboard.press('ArrowRight');
  await tabB.waitForFunction((t) => document.querySelector('.bd-strip-title')?.textContent !== t, t1, { timeout: 3000 });
  await tabB.keyboard.press(' ');
  await tabB.waitForFunction(() => /Paused/.test(document.querySelector('.bd-strip-meta')?.textContent ?? ''), null, { timeout: 3000 });
  assert((await tabB.locator('.bd-progress').count()) === 0, 'the rotation bar shows while paused');
  await tabB.keyboard.press(' ');
  await assertNotLogin(tabB);
});

await check('4. pause, resume, rotate and revoke show their states, never the login page', async () => {
  const page = await context.newPage();
  await page.clock.install();
  await page.goto(displayUrl(lifecycle.token));
  await waitBoard(page);
  await api('PUT', `/display-links/${lifecycle.id}`, adminToken, { enabled: false });
  await page.clock.fastForward(17_000); // within one refresh (15 s + 10 %)
  await waitRefusal(page, /Paused by an administrator/, 10_000);
  await assertNotLogin(page);
  await api('PUT', `/display-links/${lifecycle.id}`, adminToken, { enabled: true });
  await page.clock.fastForward(67_000); // the paused screen checks every 60 s (+10 %)
  await waitBoard(page, 10_000);
  await api('POST', `/display-links/${lifecycle.id}/rotate`, adminToken);
  await page.clock.fastForward(17_000);
  await waitRefusal(page, /isn't valid any more/, 10_000);
  await assertNotLogin(page);
  await page.close();

  const revoked = await context.newPage();
  const log = recordRequests(revoked);
  await revoked.clock.install();
  await revoked.goto(displayUrl(revokeMe.token));
  await waitBoard(revoked);
  await api('DELETE', `/display-links/${revokeMe.id}`, adminToken);
  await revoked.clock.fastForward(17_000);
  await waitRefusal(revoked, /was revoked/, 10_000);
  const n = snapshots(log).length;
  await revoked.clock.fastForward(30 * 60_000);
  await revoked.waitForTimeout(500);
  assert(snapshots(log).length === n, 'a revoked screen kept polling');
  await assertNotLogin(revoked);
  await revoked.close();

  const none = await context.newPage();
  await none.goto(`${BASE}/display`);
  await waitRefusal(none, /needs a display link/, 5000);
  assert((await none.locator('input').count()) === 0, 'an input box on the no-link screen');
  await none.close();
  assert((await meFromTabA()) === 200, 'tab A lost its session');
});

await check('5. backend unreachable: lagging, offline band, recovery, no navigation', async () => {
  const page = await context.newPage();
  await page.clock.install();
  await page.goto(displayUrl(main.token));
  await waitBoard(page);
  await page.route('**/api/display/snapshot', (route) => route.abort('connectionrefused'));
  await page.clock.fastForward(31_000); // past 2 × 15 s
  await page.clock.fastForward(1_000);
  const fresh = () => page.locator('[data-testid="freshness"]').innerText();
  assert(/reconnecting/.test(await fresh()), `freshness: ${await fresh()}`);
  for (let i = 0; i < 6; i += 1) await page.clock.fastForward(60_000);
  await page.waitForSelector('.bd-offline', { timeout: 5000 });
  assert(/NO CONNECTION TO SIEMBOX SINCE/.test(await page.locator('.bd-offline').innerText()), 'no offline band');
  assert((await page.locator('[data-panel] .bd-tag', { hasText: 'STALE' }).count()) > 0, 'panels not marked STALE');
  assert((await page.locator('[data-panel]').count()) > 0, 'the last data left the screen');
  await page.unroute('**/api/display/snapshot');
  await page.clock.fastForward(75_000); // the next retry (60 s + 20 %)
  await page.waitForFunction(() => !document.querySelector('.bd-offline'), null, { timeout: 10_000 });
  await page.waitForFunction(() => /updated/.test(document.querySelector('[data-testid="freshness"]')?.textContent ?? ''), null, { timeout: 5000 });
  await assertNotLogin(page);
  await page.close();
});

await check('6. a new backend version reloads the page after a good snapshot', async () => {
  const page = await context.newPage();
  let calls = 0;
  let loads = 0;
  page.on('load', () => (loads += 1));
  await page.route('**/api/display/snapshot', async (route) => {
    calls += 1;
    const res = await route.fetch();
    const body = await res.json();
    if (calls === 2) body.app_version = `${body.app_version}-next`;
    await route.fulfill({ response: res, json: body });
  });
  await page.goto(displayUrl(main.token));
  await waitBoard(page);
  assert(loads === 1, 'reloaded too early');
  await page.keyboard.press('r');
  await page.waitForFunction(() => document.readyState === 'complete', null, { timeout: 10_000 });
  await page.waitForTimeout(1500);
  assert(loads === 2, `expected one reload, saw ${loads - 1}`);
  await waitBoard(page);
  await page.close();
});

await check('7. readability: no overflow, no text under 2.2 vh, at four screen sizes', async () => {
  const sizes = [
    [1920, 1080],
    [1280, 720],
    [3840, 2160],
    [1080, 1920],
  ];
  for (const [width, height] of sizes) {
    const page = await context.newPage();
    await page.setViewportSize({ width, height });
    await page.goto(displayUrl(main.token));
    await waitBoard(page);
    await page.keyboard.press(' '); // hold the view while measuring
    for (let view = 0; view < 2; view += 1) {
      await page.waitForTimeout(1200); // the map draws, highlights settle
      const report = await page.evaluate(() => {
        // 2.2 vh, or 2.2 × 1.25vw on a portrait screen (theme.css --bd-u).
        const floor = Math.min(window.innerHeight, 1.25 * window.innerWidth) * 0.022 - 0.5;
        const small = [];
        const walker = document.createTreeWalker(document.querySelector('.bd-board'), NodeFilter.SHOW_TEXT);
        for (let n = walker.nextNode(); n; n = walker.nextNode()) {
          if (!n.textContent.trim()) continue;
          const el = n.parentElement;
          if (!el || el.closest('svg') || el.offsetParent === null) continue;
          const size = parseFloat(getComputedStyle(el).fontSize);
          if (size < floor) small.push(`${n.textContent.trim().slice(0, 30)} (${size}px)`);
        }
        const overflow = [...document.querySelectorAll('[data-panel]')]
          .filter((p) => {
            const body = p.querySelector('.bd-panel-body');
            if (body.scrollHeight > body.clientHeight + 1 || body.scrollWidth > body.clientWidth + 1) return true;
            // Text squeezed to nothing or pushed below the tile (the tile itself clips).
            const bottom = p.getBoundingClientRect().bottom + 1;
            return [...body.querySelectorAll('*')].some((el) => {
              if (el.children.length || !el.textContent.trim() || el.closest('svg')) return false;
              const r = el.getBoundingClientRect();
              return r.height < 1 || r.bottom > bottom;
            });
          })
          .map((p) => p.getAttribute('data-panel'));
        const page = document.documentElement;
        return { small, overflow, scroll: page.scrollWidth > window.innerWidth || page.scrollHeight > window.innerHeight };
      });
      assert(report.small.length === 0, `${width}×${height} view ${view + 1}: text under 2.2 vh: ${report.small.join(', ')}`);
      assert(report.overflow.length === 0, `${width}×${height} view ${view + 1}: overflowing panels: ${report.overflow.join(', ')}`);
      assert(!report.scroll, `${width}×${height}: the page scrolls`);
      if (OUT && (width === 1920 || width === 1280)) await page.screenshot({ path: join(OUT, `board-${width}x${height}-view${view + 1}.png`) });
      await page.keyboard.press('ArrowRight');
    }
    if (NGINX) {
      const csp = await page.evaluate(() => window.__csp);
      assert(csp.length === 0, `CSP violations: ${csp.join('; ')}`);
    }
    await page.close();
  }
});

await check('8. signing out in tab A leaves the display updating', async () => {
  await api('POST', '/auth/logout', adminToken);
  await tabA.evaluate(() => {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
  });
  await tabA.goto(`${BASE}/`);
  await tabA.waitForURL(/\/login/, { timeout: 10_000 });
  const n = snapshots(tabBLog).length;
  await tabB.waitForTimeout(18_000);
  assert(snapshots(tabBLog).length > n, 'tab B stopped refreshing');
  assert((await tabB.locator('[data-panel]').count()) > 0, 'tab B lost its board');
  await assertNotLogin(tabB);
  if (NGINX) {
    const csp = await tabB.evaluate(() => window.__csp);
    assert(csp.length === 0, `CSP violations: ${csp.join('; ')}`);
  }
});

await browser.close();
const cleanup = await api('POST', '/auth/login', null, { username: USER, password: PASSWORD });
for (const id of created) await api('DELETE', `/display-links/${id}`, cleanup.token).catch(() => undefined);

console.log(`\n${results.length - failed}/${results.length} checks passed against ${BASE}${NGINX ? ' (nginx)' : ''}`);
process.exit(failed ? 1 : 0);
