#!/usr/bin/env node
/**
 * The wall display (display.html -> src/display) must stay small and must not
 * carry the main app's session code (docs/architecture/BIG-DISPLAY.md §4.4,
 * §8.1). Run after `npm run build`. Starting from dist/display.html's module
 * script, modulepreload and stylesheet links, it follows every static import
 * between chunks (not the lazy `import()` of the map, which loads only on
 * views that show it) and fails when:
 *
 *   - an element-plus chunk is reachable (Vue must be in its own chunk:
 *     vite.config.ts codeSplitting group 'vue');
 *   - Pinia or Vue Router is reachable (their license headers are the marker);
 *   - the main app's entry chunk (index.html's) is reachable;
 *   - the gzipped total is over 100 kB (slow TV sticks and Raspberry Pis).
 */
import { existsSync, readFileSync } from 'node:fs';
import { join, posix } from 'node:path';
import { gzipSync } from 'node:zlib';

const dist = join(process.cwd(), 'dist');
const BUDGET = 100 * 1024;
const BANNED_MARKERS = { 'pinia v': 'Pinia', 'vue-router v': 'Vue Router' };

function fail(message) {
  console.error(`check-display-bundle: ${message}`);
  process.exit(1);
}

const page = join(dist, 'display.html');
if (!existsSync(page)) fail(`${page} not found; run the build first.`);
const html = readFileSync(page, 'utf8');

const attr = (tag, name) => new RegExp(`\\b${name}="([^"]+)"`, 'i').exec(tag)?.[1];
const roots = [];
for (const [tag] of html.matchAll(/<(script|link)\b[^>]*>/gi)) {
  if (tag.toLowerCase().startsWith('<script') && /type="module"/i.test(tag)) roots.push(attr(tag, 'src'));
  else if (/rel="(modulepreload|stylesheet)"/i.test(tag)) roots.push(attr(tag, 'href'));
}
if (!roots.some((r) => r?.endsWith('.js'))) fail('display.html has no module script.');

const mainEntry = /<script type="module"[^>]*src="([^"]+)"/i.exec(readFileSync(join(dist, 'index.html'), 'utf8'))?.[1];

// Static imports between chunks: `import{a}from"./vue-x.js"` and `import"./x.js"`; `import("./x.js")` is lazy.
const STATIC_IMPORT = /\b(?:import|export)\s*(?:[\w$*{}\s,]*?\bfrom\s*)?["'](\.{1,2}\/[^"']+\.js)["']/g;

const seen = new Map();
const queue = roots.filter(Boolean).map((r) => posix.normalize(r));
while (queue.length) {
  const url = queue.shift();
  if (seen.has(url)) continue;
  const file = join(dist, url.replace(/^\//, ''));
  if (!existsSync(file)) fail(`${url} (linked from display.html) is missing from dist.`);
  const code = readFileSync(file);
  seen.set(url, gzipSync(code, { level: 9 }).length);
  if (!url.endsWith('.js')) continue;
  for (const [, spec] of code.toString('utf8').matchAll(STATIC_IMPORT)) {
    queue.push(posix.join(posix.dirname(url), spec));
  }
}

const problems = [];
for (const url of seen.keys()) {
  const name = posix.basename(url);
  if (/^element-plus[-.]/.test(name)) problems.push(`${name} (Element Plus) is reachable from display.html.`);
  if (mainEntry && url === mainEntry) problems.push(`${name} (the main app's entry) is reachable from display.html.`);
  if (url.endsWith('.js')) {
    const code = readFileSync(join(dist, url.replace(/^\//, '')), 'utf8');
    for (const [marker, lib] of Object.entries(BANNED_MARKERS)) {
      if (code.includes(marker)) problems.push(`${name} bundles ${lib}.`);
    }
  }
}

const total = [...seen.values()].reduce((a, b) => a + b, 0);
if (total > BUDGET) problems.push(`gzipped total ${(total / 1024).toFixed(1)} kB is over the ${BUDGET / 1024} kB budget.`);

for (const [url, size] of seen) console.log(`  ${(size / 1024).toFixed(1).padStart(6)} kB  ${url}`);
if (problems.length) fail(problems.join('\n  '));
console.log(`check-display-bundle: ${seen.size} files, ${(total / 1024).toFixed(1)} kB gzipped (budget ${BUDGET / 1024} kB); no Element Plus, Pinia, Vue Router or app entry.`);
