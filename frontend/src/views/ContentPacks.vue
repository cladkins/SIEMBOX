<template>
  <div class="content-packs">
    <el-card>
      <template #header>
        <div class="card-header">
          <div>
            <span>Content Packs</span>
            <div class="subtitle">
              One-click bundles of parsers + detections for a technology. Installing a pack pulls the
              referenced content from the catalog. Detections apply immediately; new parsers take effect
              after the next backend restart.
            </div>
          </div>
          <el-button size="small" :loading="loading" @click="load">
            <el-icon><Refresh /></el-icon> Refresh
          </el-button>
        </div>
      </template>

      <el-alert
        v-if="catalogUnavailable"
        type="warning"
        :closable="false"
        show-icon
        title="Detection catalog unavailable"
        description="Detection counts can't be shown right now (the catalog repo couldn't be reached). Parser counts are still accurate, and installing will retry the catalog."
        style="margin-bottom: 16px"
      />

      <div v-loading="loading" class="pack-grid">
        <el-card v-for="pack in packs" :key="pack.id" shadow="hover" class="pack-card">
          <div class="pack-head">
            <el-icon :size="22" class="pack-icon"><component :is="iconFor(pack.icon)" /></el-icon>
            <div class="pack-title">{{ pack.name }}</div>
            <el-tag :type="statusType(pack.status)" size="small" effect="light">
              {{ statusLabel(pack.status) }}
            </el-tag>
          </div>

          <p class="pack-desc">{{ pack.description }}</p>

          <div class="pack-counts">
            <span>
              <strong>{{ pack.parserInstalled }}/{{ pack.parserTotal }}</strong> parsers
            </span>
            <span v-if="!pack.catalogUnavailable">
              <strong>{{ pack.detectionInstalled }}/{{ pack.detectionTotal }}</strong> detections
            </span>
          </div>

          <el-collapse v-if="pack.setup?.length" class="pack-setup">
            <el-collapse-item title="Setup hints">
              <ul>
                <li v-for="(s, i) in pack.setup" :key="i">{{ s }}</li>
              </ul>
            </el-collapse-item>
          </el-collapse>

          <div class="pack-actions">
            <el-button
              type="primary"
              size="small"
              :loading="installing === pack.id"
              :disabled="!!installing"
              @click="install(pack)"
            >
              {{ pack.status === 'not_installed' ? 'Install' : 'Update / Reinstall' }}
            </el-button>
          </div>
        </el-card>
      </div>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { api } from '@/services/api';
import { ElMessage } from 'element-plus';
import {
  Refresh,
  Key,
  Connection,
  VideoPlay,
  Files,
  Share,
  House,
  Monitor,
  DataLine,
  Box,
} from '@element-plus/icons-vue';

// Map the backend icon name -> imported component (fallback to Box).
const ICON_MAP: Record<string, any> = {
  Key,
  Connection,
  VideoPlay,
  Files,
  Share,
  House,
  Monitor,
  DataLine,
  Box,
};
function iconFor(name: string) {
  return ICON_MAP[name] || Box;
}

const packs = ref<any[]>([]);
const loading = ref(false);
const installing = ref('');
const catalogUnavailable = ref(false);

function statusType(s: string) {
  return s === 'installed' ? 'success' : s === 'partial' ? 'warning' : 'info';
}
function statusLabel(s: string) {
  return s === 'installed' ? 'Installed' : s === 'partial' ? 'Partial' : 'Not installed';
}

async function load() {
  loading.value = true;
  try {
    const { data } = await api.getContentPacks();
    packs.value = data;
    catalogUnavailable.value = data.some((p: any) => p.catalogUnavailable);
  } catch (error: any) {
    ElMessage.error(error.response?.data?.message || 'Failed to load content packs');
  } finally {
    loading.value = false;
  }
}

async function install(pack: any) {
  installing.value = pack.id;
  try {
    const { data } = await api.installContentPack(pack.id);
    const p = data.parsers;
    const d = data.detections;
    const parts = [
      `parsers: ${p.installed} new, ${p.updated} updated`,
      `detections: ${d.installed} new, ${d.updated} updated`,
    ];
    const failed = (p.failed?.length || 0) + (d.failed?.length || 0);
    if (failed) parts.push(`${failed} skipped`);
    ElMessage.success(`${pack.name} — ${parts.join('; ')}`);
    await load();
  } catch (error: any) {
    ElMessage.error(error.response?.data?.message || 'Install failed');
  } finally {
    installing.value = '';
  }
}

onMounted(load);
</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
}
.subtitle {
  font-size: 13px;
  color: var(--el-text-color-secondary);
  margin-top: 4px;
  max-width: 720px;
}
.pack-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
  gap: 16px;
}
.pack-card {
  display: flex;
  flex-direction: column;
}
.pack-head {
  display: flex;
  align-items: center;
  gap: 10px;
}
.pack-icon {
  color: var(--el-color-primary);
}
.pack-title {
  font-weight: 600;
  flex: 1;
}
.pack-desc {
  font-size: 13px;
  color: var(--el-text-color-regular);
  margin: 10px 0;
  min-height: 38px;
}
.pack-counts {
  display: flex;
  gap: 16px;
  font-size: 13px;
  color: var(--el-text-color-secondary);
  margin-bottom: 6px;
}
.pack-setup :deep(.el-collapse-item__content) {
  font-size: 13px;
  color: var(--el-text-color-secondary);
  padding-bottom: 8px;
}
.pack-setup ul {
  margin: 0;
  padding-left: 18px;
}
.pack-actions {
  margin-top: 12px;
}
</style>
