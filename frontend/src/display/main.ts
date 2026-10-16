/**
 * The wall display's own entry (display.html, served by nginx at /display):
 * BIG-DISPLAY.md §4.4, §8.1. It never loads the main app's main.ts, router,
 * Pinia, stores, axios client or Element Plus, and eslint.config.js keeps it
 * that way. A render error is logged and the screen keeps its last frame: it
 * never navigates away.
 */
import '../polyfills';
import { createApp } from 'vue';
import DisplayApp from './DisplayApp.vue';
import './board/theme.css';

const app = createApp(DisplayApp);
app.config.errorHandler = (error) => {
  console.error('[display]', error);
};
app.mount('#display');
