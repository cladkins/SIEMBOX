import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import { createRequire } from 'node:module';
import path from 'path';

const { version: jsYamlVersion } = createRequire(import.meta.url)('js-yaml/package.json');

export default defineConfig({
  plugins: [vue()],
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
      output: {
        // Keep the libraries' license and copyright headers (/*! ... */,
        // @license, @preserve) in the minified bundle, as Vite 5's esbuild
        // minifier did. Vite 8 strips them when minifying, and the MIT and
        // Apache-2.0 code we ship (Vue, Chart.js, DOMPurify, ...) must carry
        // its notice. scripts/check-legal-comments.mjs fails CI without them.
        comments: { legal: true },
        // js-yaml's v4-legacy releases (4.3.x) ship their ESM build without the
        // license header 4.2.0 had, so put the same header on the chunk that
        // bundles it (after minification, so nothing can strip it).
        postBanner: (chunk) =>
          chunk.moduleIds.some((id) => /[\\/]node_modules[\\/]js-yaml[\\/]/.test(id))
            ? `/*! js-yaml ${jsYamlVersion} https://github.com/nodeca/js-yaml @license MIT */`
            : '',
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
            { name: 'element-plus', test: /[\\/]node_modules[\\/]element-plus[\\/].*\.m?js$/ },
            { name: 'chart', test: /[\\/]node_modules[\\/](chart\.js|vue-chartjs)[\\/].*\.m?js$/ },
          ],
        },
      },
    },
  },
});
