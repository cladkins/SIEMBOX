<template>
  <el-config-provider :locale="locale">
    <router-view />
  </el-config-provider>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { ElConfigProvider } from 'element-plus';
import en from 'element-plus/es/locale/lang/en';
import { useThemeStore } from '@/stores/theme';

const locale = ref(en);

// Initialize theme store to apply saved preference
useThemeStore();
</script>

<style>
/* CSS Variables for light mode */
:root {
  --siembox-bg-color: #f5f7fa;
  --siembox-header-bg: #fff;
  --siembox-text-color: #303133;
  --siembox-text-secondary: #606266;
  --siembox-border-color: #dcdfe6;
  --siembox-sidebar-bg: #304156;
  --siembox-sidebar-header: #263445;
  --siembox-card-bg: #fff;
  --siembox-shadow: 0 1px 4px rgba(0, 21, 41, 0.08);
}

/* CSS Variables for dark mode */
html.dark {
  --siembox-bg-color: #141414;
  --siembox-header-bg: #1d1d1d;
  --siembox-text-color: #e5eaf3;
  --siembox-text-secondary: #a3a6ad;
  --siembox-border-color: #414243;
  --siembox-sidebar-bg: #1d1d1d;
  --siembox-sidebar-header: #141414;
  --siembox-card-bg: #1d1d1d;
  --siembox-shadow: 0 1px 4px rgba(0, 0, 0, 0.3);
}

* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

html,
body,
#app {
  height: 100%;
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial,
    sans-serif;
}

#app {
  background-color: var(--siembox-bg-color);
  color: var(--siembox-text-color);
  transition: background-color 0.3s, color 0.3s;
}
</style>
