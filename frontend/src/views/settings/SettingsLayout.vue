<template>
  <div class="settings-hub">
    <nav class="settings-nav" aria-label="Settings">
      <el-card class="settings-nav-card">
        <router-link
          v-for="area in visibleAreas"
          :key="area.key"
          :to="settingsAreaPath(area)"
          class="settings-nav-item"
          active-class="is-active"
        >
          <el-icon :size="16"><component :is="area.icon" /></el-icon>
          <span>{{ area.title }}</span>
        </router-link>
      </el-card>
    </nav>

    <section class="settings-content">
      <header v-if="activeArea" class="settings-header">
        <h2 class="settings-title">{{ activeArea.title }}</h2>
        <p class="settings-description">{{ activeArea.description }}</p>
      </header>
      <router-view />
    </section>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { useRoute } from 'vue-router';
import { useAuthStore } from '@/stores/auth';
import { settingsAreas, settingsAreaPath, settingsRouteName } from './areas';

const route = useRoute();
const authStore = useAuthStore();

// Admin-only areas are left out for everyone else; their routes also carry
// meta.requiresAdmin, so the router guard blocks a typed-in URL too.
const visibleAreas = computed(() =>
  settingsAreas.filter((area) => !area.adminOnly || authStore.isAdmin)
);

const activeArea = computed(() =>
  settingsAreas.find((area) => route.name === settingsRouteName(area))
);
</script>

<style scoped>
.settings-hub {
  display: flex;
  align-items: flex-start;
  gap: 20px;
}

/* Secondary nav: a sticky column beside the area's content. */
.settings-nav {
  flex: 0 0 200px;
  position: sticky;
  top: 0;
}

.settings-nav-card :deep(.el-card__body) {
  display: flex;
  flex-direction: column;
  gap: 2px;
  padding: 8px;
}

.settings-nav-item {
  display: flex;
  align-items: center;
  gap: 10px;
  padding: 9px 12px;
  border-radius: var(--el-border-radius-base);
  color: var(--el-text-color-regular);
  font-size: 14px;
  line-height: 20px;
  text-decoration: none;
  white-space: nowrap;
  transition: background-color 0.2s, color 0.2s;
}

.settings-nav-item:hover {
  background-color: var(--el-fill-color-light);
  color: var(--el-color-primary);
}

.settings-nav-item:focus-visible {
  outline: 2px solid var(--el-color-primary);
  outline-offset: -2px;
}

.settings-nav-item.is-active {
  background-color: var(--el-color-primary-light-9);
  color: var(--el-color-primary);
  font-weight: 500;
}

.settings-content {
  flex: 1 1 auto;
  min-width: 0;
}

.settings-header {
  margin-bottom: 16px;
}

.settings-title {
  font-size: 20px;
  font-weight: 600;
  line-height: 28px;
  color: var(--el-text-color-primary);
}

.settings-description {
  margin-top: 4px;
  font-size: 13px;
  color: var(--el-text-color-secondary);
}

/* Too narrow for the nav column beside the app sidebar: stack, and turn the
   nav into a horizontally scrolling strip above the content. */
@media (max-width: 1024px) {
  .settings-hub {
    flex-direction: column;
    align-items: stretch;
  }

  .settings-nav {
    flex: none;
    position: static;
  }

  .settings-nav-card :deep(.el-card__body) {
    flex-direction: row;
    overflow-x: auto;
  }

  .settings-nav-item {
    flex: 0 0 auto;
  }
}
</style>
