import { defineConfig, type Plugin } from 'vite';
import vue from '@vitejs/plugin-vue';
import { createRequire } from 'node:module';
import { readFileSync } from 'node:fs';
import path from 'path';

const require = createRequire(import.meta.url);
const { version: jsYamlVersion } = require('js-yaml/package.json');
// Cytoscape's package.json isn't in its "exports": read it from its folder.
const { version: cytoscapeVersion } = JSON.parse(
  readFileSync(path.join(path.dirname(require.resolve('cytoscape')), '..', 'package.json'), 'utf8')
);

/** Does this chunk bundle a module of `pkg` (node_modules/<pkg>/...)? */
const bundles = (chunk: { moduleIds: string[] }, pkg: string) =>
  chunk.moduleIds.some((id) => id.replace(/\\/g, '/').includes(`/node_modules/${pkg}/`));

/**
 * /display and /display/ serve display.html in development, as nginx's
 * `location = /display` does in production (nginx.conf.template). Without it
 * Vite's SPA fallback would answer with index.html, which runs the main app's
 * router guard and session handling on a display link (BIG-DISPLAY.md §4.4).
 */
const displayEntry: Plugin = {
  name: 'siembox-display-entry',
  configureServer(server) {
    server.middlewares.use((req, _res, next) => {
      const path = (req.url ?? '').split('?')[0];
      if (path === '/display' || path === '/display/') req.url = '/display.html';
      next();
    });
  },
  configurePreviewServer(server) {
    server.middlewares.use((req, _res, next) => {
      const path = (req.url ?? '').split('?')[0];
      if (path === '/display' || path === '/display/') req.url = '/display.html';
      next();
    });
  },
};

export default defineConfig({
  plugins: [vue(), displayEntry],
  resolve: {
    alias: {
      '@': path.resolve(import.meta.dirname, './src'),
    },
  },
  server: {
    host: '0.0.0.0',
    port: 5173,
    // The UI calls /api on its own origin and this proxies it to the backend,
    // as nginx does in production, so the API needs no CORS_ORIGIN for
    // development. API_PROXY_TARGET points it at another backend. Not
    // VITE_API_URL: that is the UI's own API base (src/services/api.ts), and an
    // absolute one makes the browser call the API cross-origin.
    proxy: {
      '/api': {
        target: process.env.API_PROXY_TARGET || 'http://localhost:8421',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
    // Vite 5's default target ('modules'), pinned so the build keeps running on
    // the same browsers: Vite 7 and 8 raised the default to Chrome/Edge 111,
    // Firefox 114 and Safari 16.4.
    target: ['es2020', 'edge88', 'firefox78', 'chrome87', 'safari14'],
    rolldownOptions: {
      // Two pages: the app, and the wall display (display.html -> src/display),
      // which shares none of the app's session code (BIG-DISPLAY.md §8.1).
      input: {
        main: path.resolve(import.meta.dirname, 'index.html'),
        display: path.resolve(import.meta.dirname, 'display.html'),
      },
      output: {
        // Keep the libraries' license and copyright headers (/*! ... */,
        // @license, @preserve) in the minified bundle, as Vite 5's esbuild
        // minifier did. Vite 8 strips them when minifying, and the MIT and
        // Apache-2.0 code we ship (Vue, Chart.js, DOMPurify, ...) must carry
        // its notice. scripts/check-legal-comments.mjs fails CI without them.
        comments: { legal: true },
        // Headers the libraries' own builds don't keep, put on the chunk that
        // bundles them (after minification, so nothing can strip them):
        // - js-yaml's v4-legacy releases (4.3.x) ship their ESM build without
        //   the license header 4.2.0 had;
        // - Cytoscape's ESM build opens with a plain /** Copyright ... */ block
        //   (MIT), which comments.legal doesn't count as a legal comment.
        postBanner: (chunk) =>
          [
            bundles(chunk, 'js-yaml') ? `/*! js-yaml ${jsYamlVersion} https://github.com/nodeca/js-yaml @license MIT */` : '',
            bundles(chunk, 'cytoscape')
              ? `/*! cytoscape ${cytoscapeVersion} | (c) The Cytoscape Consortium | https://js.cytoscape.org @license MIT */`
              : '',
          ]
            .filter(Boolean)
            .join('\n'),
        // The vendor chunks of Vite 5's manualChunks object, which Rolldown no
        // longer accepts. Like manualChunks, a group also takes in the
        // dependencies of the modules it matches (Vue, lodash-es, dayjs,
        // @kurkle/color, ...). Matching only .js/.mjs leaves Element Plus's
        // stylesheets, imported by main.ts, in index.css.
        codeSplitting: {
          groups: [
            // Oxc's helpers for lowering to the target above (_defineProperty
            // for class fields, ...), which esbuild used to inline. In a chunk
            // of their own, or the chart group takes them in and every chunk
            // needing one (markdown, which the layout loads) imports chart.js.
            { name: 'oxc-runtime', test: /^\0@oxc-project\+runtime@/, priority: 1 },
            // Vue in a chunk of its own: otherwise the element-plus group below
            // takes it in as a dependency, and every wall display would
            // download Element Plus (scripts/check-display-bundle.mjs).
            {
              name: 'vue',
              test: /[\\/]node_modules[\\/](vue|@vue[\\/](runtime-core|runtime-dom|reactivity|shared))[\\/].*\.m?js$/,
              priority: 2,
            },
            { name: 'element-plus', test: /[\\/]node_modules[\\/]element-plus[\\/].*\.m?js$/ },
            { name: 'chart', test: /[\\/]node_modules[\\/](chart\.js|vue-chartjs)[\\/].*\.m?js$/ },
            // The Context Graph's canvas library, loaded only when the graph
            // page draws (components/graph/GraphCanvas.vue imports it lazily);
            // scripts/check-graph-chunk.mjs fails CI if it reaches another chunk.
            { name: 'graph', test: /[\\/]node_modules[\\/]cytoscape[\\/].*\.m?js$/ },
          ],
        },
      },
    },
  },
});
