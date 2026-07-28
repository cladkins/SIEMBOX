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
    <el-table-column label="Status" width="110">
      <template #default="{ row }">
        <el-tag size="small">{{ row.status }}</el-tag>
      </template>
    </el-table-column>
    <el-table-column label="Actions" width="260">
      <template #default="{ row }">
        <el-button v-if="row.status === 'candidate'" link size="small" @click="$emit('confirm', row)">Confirm</el-button>
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
      </template>
    </el-table-column>
  </el-table>
</template>

<script setup lang="ts">
import type { RankedSource, FingerprintEntry } from '@/services/logDiscoveryService';

const props = defineProps<{
  sources: RankedSource[];
  fingerprints: FingerprintEntry[];
}>();

defineEmits<{
  confirm: [source: RankedSource];
  ignore: [source: RankedSource];
  onboard: [source: RankedSource];
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
</style>
