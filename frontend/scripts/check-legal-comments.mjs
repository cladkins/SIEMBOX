// Fails when the production bundle has lost the license headers of the
// libraries it ships. Run after `npm run build` (CI does).
//
// Vite 8's minifier drops legal comments (/*! ... */, @license, @preserve)
// unless build.rolldownOptions.output.comments.legal is set; Vite 5 kept them.
// The MIT and Apache-2.0 code in dist/ must carry its copyright and license
// notice, so this checks a few libraries whose headers we know ship.
import { readFileSync, readdirSync, existsSync } from 'node:fs';
import { join } from 'node:path';

const root = join(import.meta.dirname, '..');
const assets = join(root, 'dist', 'assets');

// package (a dependency in package.json) -> text its license header contains
const EXPECTED = {
  vue: '@vue/runtime-core v',
  'vue-router': 'vue-router v',
  pinia: 'pinia v',
  'chart.js': 'Chart.js v',
  dompurify: '@license DOMPurify',
  'js-yaml': 'js-yaml',
  // vite.config.ts puts this header on the lazy graph chunk (postBanner).
  cytoscape: 'cytoscape ',
};

if (!existsSync(assets)) {
  console.error(`${assets} not found: run npm run build first.`);
  process.exit(1);
}

const { dependencies = {} } = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8'));

const legal = [];
for (const file of readdirSync(assets).filter((f) => f.endsWith('.js'))) {
  const code = readFileSync(join(assets, file), 'utf8');
  for (const [comment] of code.matchAll(/\/\*[\s\S]*?\*\//g)) {
    if (comment.startsWith('/*!') || /@license|@preserve/.test(comment)) legal.push(comment);
  }
}

const missing = Object.entries(EXPECTED).filter(
  ([pkg, marker]) => pkg in dependencies && !legal.some((c) => c.includes(marker)),
);

if (missing.length > 0) {
  console.error(
    `dist/assets has no license header for: ${missing.map(([pkg]) => pkg).join(', ')}.\n` +
      'The minifier is stripping legal comments: keep comments: { legal: true } in\n' +
      'build.rolldownOptions.output (vite.config.ts).',
  );
  process.exit(1);
}

console.log(`License headers present in dist/assets (${legal.length} legal comments).`);
