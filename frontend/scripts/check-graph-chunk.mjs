#!/usr/bin/env node
/**
 * The Context Graph's canvas library (Cytoscape) must stay in its own lazy
 * chunk (vite.config.ts codeSplitting group 'graph', loaded by
 * components/graph/GraphCanvas.vue with `await import`), so no other page
 * downloads it. Run after `npm run build`: fails when the Cytoscape banner
 * (vite.config.ts postBanner) is missing from graph-*.js or appears in any
 * other chunk, the entry chunk included.
 */
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

const assets = join(process.cwd(), 'dist', 'assets');
const MARKER = '/*! cytoscape ';

if (!existsSync(assets)) {
  console.error(`check-graph-chunk: ${assets} not found; run the build first.`);
  process.exit(1);
}

const chunks = readdirSync(assets).filter((f) => f.endsWith('.js'));
const withMarker = chunks.filter((f) => readFileSync(join(assets, f), 'utf8').includes(MARKER));
const graph = withMarker.filter((f) => /^graph-[\w-]+\.js$/.test(f));
const elsewhere = withMarker.filter((f) => !graph.includes(f));

let failed = false;
if (graph.length !== 1) {
  console.error(`check-graph-chunk: expected one graph-*.js chunk carrying Cytoscape, found ${graph.length} (${graph.join(', ') || 'none'}).`);
  failed = true;
}
if (elsewhere.length > 0) {
  console.error(`check-graph-chunk: Cytoscape reached other chunks: ${elsewhere.join(', ')}.`);
  failed = true;
}
if (failed) process.exit(1);
console.log(`check-graph-chunk: Cytoscape is only in ${graph[0]}.`);
