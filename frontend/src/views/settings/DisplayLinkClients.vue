<template>
  <div class="clients" v-loading="loading">
    <p class="hint">
      The devices that used this link's current secret (at most 20, most recent first). For a link on one screen, more than one
      address is worth a look: rotate the link if you don't recognise one.
    </p>
    <el-table v-if="clients.length" :data="clients" size="small" data-testid="link-clients">
      <el-table-column prop="ip" label="Address" width="180" />
      <el-table-column label="Browser" min-width="180">
        <template #default="{ row }">
          <span :title="row.user_agent ?? ''">{{ shortBrowser(row.user_agent) }}</span>
        </template>
      </el-table-column>
      <el-table-column label="First seen" width="190">
        <template #default="{ row }">{{ formatDate(row.first_seen) }}</template>
      </el-table-column>
      <el-table-column label="Last seen" width="190">
        <template #default="{ row }">{{ formatDate(row.last_seen) }}</template>
      </el-table-column>
    </el-table>
    <p v-else-if="!loading" class="hint">No device has opened this link yet.</p>
  </div>
</template>

<script setup lang="ts">
/** Settings -> Display links: the devices seen for one link (BIG-DISPLAY.md §4.6). */
import { onMounted, ref } from 'vue';
import { api } from '@/services/api';
import { shortBrowser, type DisplayLinkClient } from '@/utils/displayLinks';
import { formatDate } from './format';

const props = defineProps<{ linkId: number }>();
const clients = ref<DisplayLinkClient[]>([]);
const loading = ref(false);

async function load() {
  loading.value = true;
  try {
    const { data } = await api.getDisplayLink(props.linkId);
    clients.value = data.link.clients ?? [];
  } finally {
    loading.value = false;
  }
}

defineExpose({ load });
onMounted(load);
</script>

<style scoped>
.clients {
  padding: 4px 16px 12px 48px;
}
.hint {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}
</style>
