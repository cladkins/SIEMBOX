<template>
  <div class="shipper-scan-jobs" data-testid="shipper-scan-jobs">
    <div class="section-header">
      <h3>
        Scan Jobs
        <el-tag v-if="activeCount > 0" type="warning" size="small" effect="dark" class="count-tag">{{ activeCount }}</el-tag>
      </h3>
      <div>
        <el-text size="small" type="info">Queued jobs expire unrun after {{ expiryText }}</el-text>
        <el-button size="small" :icon="Refresh" circle style="margin-left: 8px" @click="load" />
      </div>
    </div>

    <el-alert
      v-if="queuedCount > 0 && shipperStatus !== 'online'"
      type="warning"
      :closable="false"
      show-icon
      style="margin-bottom: 10px"
      :title="`This shipper is ${shipperStatus || 'not online'}: its ${queuedCount} queued job${queuedCount === 1 ? '' : 's'} will run only if it comes back before ${queuedCount === 1 ? 'it expires' : 'they expire'}. Cancel any you no longer want.`"
    />

    <el-table
      :data="jobs"
      v-loading="loading"
      size="small"
      stripe
      :empty-text="loading ? 'Loading...' : 'No queued or running scan jobs'"
      style="margin-bottom: 20px"
    >
      <el-table-column label="Job" min-width="150">
        <template #default="{ row }">
          <div>{{ jobKindLabel(row.kind) }}</div>
          <el-text size="small" type="info">#{{ row.scanId }}<template v-if="row.scanType"> · {{ row.scanType }}</template></el-text>
        </template>
      </el-table-column>
      <el-table-column label="Status" width="135">
        <template #default="{ row }">
          <el-tooltip v-if="row.status === 'expired' && row.errorMessage" :content="row.errorMessage" placement="top">
            <el-tag :type="scanStatusTagType(row.status)" size="small" style="cursor: help">{{ scanStatusLabel(row.status) }}</el-tag>
          </el-tooltip>
          <el-tag v-else :type="scanStatusTagType(row.status)" size="small">{{ row.status }}</el-tag>
          <div v-if="row.status === 'queued' && row.expiresAt">
            <el-text size="small" type="info">expires {{ formatDate(row.expiresAt) }}</el-text>
          </div>
        </template>
      </el-table-column>
      <el-table-column label="Targets" min-width="150">
        <template #default="{ row }">
          <code class="targets">{{ row.targets.join(', ') || '—' }}</code>
          <el-tooltip
            v-if="publicOf(row).length > 0"
            placement="top"
            :content="`Public address space: ${publicOf(row).join(', ')}${row.publicTargetsConfirmed ? ' (confirmed when the scan was started)' : ''}`"
          >
            <el-tag type="danger" size="small" effect="plain" class="public-tag">public</el-tag>
          </el-tooltip>
        </template>
      </el-table-column>
      <el-table-column label="Created by" min-width="140">
        <template #default="{ row }">
          <div>{{ row.createdByUsername || 'System' }}</div>
          <el-text size="small" type="info">{{ jobOriginLabel(row.origin) }}</el-text>
        </template>
      </el-table-column>
      <el-table-column label="Created" width="120">
        <template #default="{ row }">
          <div>{{ formatDate(row.createdAt) }}</div>
          <el-text size="small" type="info">{{ formatAge(row.ageSeconds) }} ago</el-text>
        </template>
      </el-table-column>
      <el-table-column label="" width="84" align="center" fixed="right">
        <template #default="{ row }">
          <el-tooltip
            v-if="isActiveJob(row) && !canCancelJob(role, row.kind)"
            :content="`Cancelling a ${jobKindLabel(row.kind).toLowerCase()} needs the ${JOB_CANCEL_ROLE[row.kind as ShipperJobKind]} role or higher`"
            placement="top"
          >
            <span><el-button size="small" type="danger" plain disabled>Cancel</el-button></span>
          </el-tooltip>
          <el-button
            v-else-if="isActiveJob(row)"
            size="small"
            type="danger"
            plain
            :loading="cancelling === `${row.kind}:${row.scanId}`"
            @click="cancel(row)"
          >
            Cancel
          </el-button>
        </template>
      </el-table-column>
    </el-table>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue';
import { ElMessage, ElMessageBox } from 'element-plus';
import { Refresh } from '@element-plus/icons-vue';
import { format } from 'date-fns';
import { api } from '@/services/api';
import { useAuthStore } from '@/stores/auth';
import { findPublicTargets } from '@/utils/targetSafety';
import {
  JOB_CANCEL_ROLE,
  canCancelJob,
  formatAge,
  isActiveJob,
  jobKindLabel,
  jobOriginLabel,
  scanStatusLabel,
  scanStatusTagType,
  type ShipperJob,
  type ShipperJobKind,
} from '@/utils/shipperJobs';

// The scan jobs dispatched to one log shipper (GET /api/shippers/:id/jobs):
// queued, running, and expired in the last week, with Cancel for the roles
// that may stop that kind of scan.
const props = defineProps<{ shipperId: number; shipperStatus?: string }>();
const emit = defineEmits<{ (e: 'changed'): void }>();

const authStore = useAuthStore();
const role = computed(() => authStore.user?.role as string | undefined);

const jobs = ref<ShipperJob[]>([]);
const loading = ref(false);
const cancelling = ref<string | null>(null);

const activeCount = computed(() => jobs.value.filter(isActiveJob).length);
const queuedCount = computed(() => jobs.value.filter((j) => j.status === 'queued').length);
const expiryText = computed(() => {
  const queued = jobs.value.find((j) => j.status === 'queued' && j.expiresAt);
  if (!queued || !queued.expiresAt) return 'the configured window (Settings > Asset Discovery)';
  const hours = Math.round((new Date(queued.expiresAt).getTime() - new Date(queued.createdAt).getTime()) / 3600000);
  return `${hours} h`;
});

function publicOf(job: ShipperJob): string[] {
  return findPublicTargets(job.targets).publicTargets.map((t) => t.target);
}

function formatDate(value: string): string {
  return format(new Date(value), 'MMM d, HH:mm');
}

async function load() {
  loading.value = true;
  try {
    const { data } = await api.getShipperJobs(props.shipperId);
    jobs.value = data.jobs || [];
  } catch (error) {
    console.error('Failed to load shipper jobs', error);
    jobs.value = [];
  } finally {
    loading.value = false;
  }
}

async function cancel(job: ShipperJob) {
  try {
    await ElMessageBox.confirm(
      job.status === 'queued'
        ? `Cancel ${jobKindLabel(job.kind).toLowerCase()} #${job.scanId} of ${job.targets.join(', ')}? The shipper will never run it.`
        : `Cancel ${jobKindLabel(job.kind).toLowerCase()} #${job.scanId}? The shipper is already running it and can't be stopped from here; whatever it reports back will be ignored.`,
      'Cancel scan job',
      { type: 'warning', confirmButtonText: 'Cancel job', cancelButtonText: 'Keep' }
    );
  } catch {
    return;
  }
  cancelling.value = `${job.kind}:${job.scanId}`;
  try {
    const { data } = await api.cancelShipperJob(props.shipperId, job.kind, job.scanId);
    if (data.cancelled) ElMessage.success(`Job #${job.scanId} cancelled`);
    else ElMessage.info(`Job #${job.scanId} had already finished (${data.status})`);
    await load();
    emit('changed');
  } catch (error: any) {
    ElMessage.error(error.response?.data?.message || 'Failed to cancel job');
  } finally {
    cancelling.value = null;
  }
}

onMounted(load);
watch(() => props.shipperId, load);
defineExpose({ load });
</script>

<style scoped>
.section-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 10px;
}
.section-header h3 {
  margin: 0;
}
.count-tag {
  margin-left: 6px;
  vertical-align: 2px;
}
.targets {
  font-size: 12px;
  word-break: break-all;
}
.public-tag {
  margin-left: 6px;
}
</style>
