<template>
  <el-table :data="sources" size="small">
    <el-table-column label="Host" min-width="160">
      <template #default="{ row }">
        <div>{{ row.hostname || row.ip }}</div>
        <div v-if="row.hostname" class="ip-sub">{{ row.ip }}</div>
      </template>
    </el-table-column>
    <el-table-column label="Match" min-width="160">
      <template #default="{ row }">{{ fingerprintName(row.matched_fingerprint_id) }}</template>
    </el-table-column>
    <el-table-column label="Confidence" width="140">
      <template #default="{ row }">
        <el-tag :type="row.is_guess ? 'warning' : 'success'" size="small">
          {{ row.confidence }}%{{ row.is_guess ? ' (guess)' : '' }}
        </el-tag>
      </template>
    </el-table-column>
    <el-table-column label="Why" min-width="220" prop="reason" />
    <el-table-column label="Status" min-width="240">
      <template #default="{ row }">
        <el-tag size="small">{{ row.status }}</el-tag>
        <el-tag
          v-if="row.poller?.configured && row.poller.enabled"
          size="small"
          :type="row.poller.last_status === 'error' ? 'danger' : 'success'"
          style="margin-left: 4px"
        >
          polling
        </el-tag>
        <el-tag v-else-if="row.poller?.configured" size="small" type="info" style="margin-left: 4px">paused</el-tag>
        <!-- What is polled (no token or query string) and why the last poll failed. -->
        <div v-if="row.poller?.configured && row.poller.effective_url" class="poll-url" :title="row.poller.effective_url">
          {{ row.poller.effective_url }}
        </div>
        <div v-if="row.poller?.configured && row.poller.last_status === 'error' && row.poller.last_error" class="poll-error">
          {{ row.poller.last_error }}
        </div>
      </template>
    </el-table-column>
    <el-table-column label="Actions" width="300">
      <template #default="{ row }">
        <el-button v-if="row.status === 'candidate'" link size="small" @click="$emit('confirm', row)">Confirm</el-button>
        <!-- Editing the poll target (address, port, HTTPS, endpoint) is admin-only in the API;
             the parent passes can-edit for admins only. Offered for polled sources and for
             manually added ones (which exist only to be polled). -->
        <el-button
          v-if="canEdit && (row.poller?.configured || row.evidence?.manual === true)"
          link
          size="small"
          type="primary"
          :icon="Edit"
          data-test="edit-source"
          @click="$emit('edit', row)"
        >
          Edit
        </el-button>
        <el-button
          v-if="row.matched_fingerprint_id && row.status !== 'ignored'"
          link
          size="small"
          type="primary"
          @click="$emit('onboard', row)"
        >
          Onboard
        </el-button>
        <el-button v-if="row.status !== 'ignored'" link size="small" @click="$emit('ignore', row)">Ignore</el-button>
        <!-- Only manually added sources are deletable here; a scan-discovered source is removed by
             re-scanning or ignoring, never by this button (the server also 403s a non-manual delete).
             Deleting is admin-only in the API, so the parent passes can-delete for admins only. -->
        <el-button
          v-if="canDelete && row.evidence?.manual === true"
          link
          size="small"
          type="danger"
          :icon="Delete"
          @click="$emit('delete', row)"
        >
          Delete
        </el-button>
      </template>
    </el-table-column>
  </el-table>
</template>

<script setup lang="ts">
import { Delete, Edit } from '@element-plus/icons-vue';
import type { RankedSource, FingerprintEntry } from '@/services/logDiscoveryService';

const props = defineProps<{
  sources: RankedSource[];
  fingerprints: FingerprintEntry[];
  /** Show Delete on manually added sources (admin-only in the API). Off unless passed. */
  canDelete?: boolean;
  /** Show Edit on API-polled and manually added sources (admin-only in the API). Off unless passed. */
  canEdit?: boolean;
}>();

defineEmits<{
  confirm: [source: RankedSource];
  ignore: [source: RankedSource];
  onboard: [source: RankedSource];
  delete: [source: RankedSource];
  edit: [source: RankedSource];
}>();

function fingerprintName(id: string | null): string {
  if (!id) return 'Unidentified host';
  return props.fingerprints.find((f) => f.id === id)?.name || id;
}
</script>

<style scoped>
.ip-sub {
  color: var(--el-text-color-secondary);
  font-size: 12px;
}
.poll-url {
  margin-top: 4px;
  font-family: monospace;
  font-size: 12px;
  color: var(--el-text-color-secondary);
  word-break: break-all;
}
.poll-error {
  margin-top: 2px;
  font-size: 12px;
  line-height: 1.4;
  color: var(--el-color-danger);
  white-space: normal;
  word-break: break-word;
}
</style>
