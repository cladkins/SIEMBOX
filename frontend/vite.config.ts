import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import path from 'path';

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
    proxy: {
      '/api': {
        target: process.env.VITE_API_URL || 'http://localhost:8421',
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
