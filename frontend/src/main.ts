import { createApp } from 'vue';
import { createPinia } from 'pinia';
import ElementPlus from 'element-plus';
import 'element-plus/dist/index.css';
import 'element-plus/theme-chalk/dark/css-vars.css';
import * as ElementPlusIconsVue from '@element-plus/icons-vue';

import App from './App.vue';
import router from './router';

const app = createApp(App);

// Register Element Plus icons
for (const [key, component] of Object.entries(ElementPlusIconsVue)) {
  app.component(key, component);
}

app.use(createPinia());
app.use(router);
app.use(ElementPlus);

// Self-heal an already-open tab after a redeploy: if a lazy route chunk fails to load
// (its hashed filename no longer exists on the server), reload once to fetch the
// current index.html + chunks. Guarded via sessionStorage so it can't loop; the flag
// is cleared on the next successful navigation.
function reloadOnceForStaleChunk() {
  if (sessionStorage.getItem('siembox-chunk-reloaded')) return;
  sessionStorage.setItem('siembox-chunk-reloaded', '1');
  window.location.reload();
}
window.addEventListener('vite:preloadError', reloadOnceForStaleChunk);
router.onError((err) => {
  if (/dynamically imported module|module script failed|Failed to fetch/i.test(String((err as any)?.message || ''))) {
    reloadOnceForStaleChunk();
  }
});
router.afterEach(() => sessionStorage.removeItem('siembox-chunk-reloaded'));

app.mount('#app');
