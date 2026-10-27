<template>
  <div class="endpoint-scan-policy" v-loading="loading" data-testid="endpoint-scan-policy">
    <template v-if="view">
      <el-alert
        v-if="!view.managed"
        type="warning"
        :closable="false"
        show-icon
        class="block"
        data-testid="policy-old-agent"
        :title="`Agent ${view.agent_version ? 'v' + view.agent_version : '(unknown version)'} does not follow scan policies — update it to v${view.min_agent_version} or later.`"
      >
        Until then it runs its own intervals: {{ describeLocalIntervals(view.local_intervals) }}. The schedule below applies once it is updated.
      </el-alert>

      <div class="policy-row">
        <span class="label">Policy</span>
        <el-select
          v-if="canEdit"
          :model-value="view.assigned_policy_id ?? defaultId"
          size="small"
          style="width: 260px"
          :loading="saving"
          data-testid="endpoint-policy-select"
          @change="assign"
        >
          <el-option v-for="p in policies" :key="p.id" :value="p.id" :label="p.is_default ? `${p.name} (default)` : p.name" />
        </el-select>
        <strong v-else>{{ view.policy.name }}</strong>
        <el-tag v-if="view.policy.is_default" size="small" type="info">default</el-tag>
        <span v-if="overrideCount" class="muted">{{ overrideCount }} scan(s) overridden on this endpoint</span>
      </div>

      <el-table :data="view.scans" size="small" stripe>
        <el-table-column label="Scan" width="150">
          <template #default="{ row }">{{ typeLabel(row.scan_type) }}</template>
        </el-table-column>
        <el-table-column label="From" width="100">
          <template #default="{ row }">
            <el-tag v-if="row.source === 'override'" size="small" type="warning">override</el-tag>
            <el-tag v-else size="small" type="info">policy</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="Schedule" min-width="200">
          <template #default="{ row }"><span :class="{ muted: !row.spec.enabled }">{{ describeSpec(row.spec) }}</span></template>
        </el-table-column>
        <el-table-column label="Next runs" min-width="200">
          <template #default="{ row }">
            <span v-if="!view.managed" class="muted">once the agent is updated</span>
            <template v-else-if="row.spec.enabled && row.next_runs.length">
              <div v-for="(r, i) in row.next_runs" :key="r" class="run" :class="{ muted: i > 0 }">
                {{ i === 0 && isNow(r) ? 'on the next heartbeat' : formatInZone(r, viewerZone) }}
              </div>
              <el-tag v-if="row.waiting === 'window'" size="small" type="info">due — waiting for its window</el-tag>
              <el-tag v-else-if="row.outstanding" size="small" type="info">a run is queued or running</el-tag>
            </template>
            <span v-else class="muted">—</span>
          </template>
        </el-table-column>
        <el-table-column label="Last policy run" width="170">
          <template #default="{ row }">
            <template v-if="row.last_run">
              <el-tag :type="scanStatusTag(row.last_run.status)" size="small">{{ row.last_run.status }}</el-tag>
              <div class="muted">{{ formatInZone(row.last_run.completed_at || row.last_run.requested_at, viewerZone) }}</div>
            </template>
            <span v-else class="muted">never</span>
          </template>
        </el-table-column>
        <el-table-column v-if="canEdit" label="" width="170" align="right">
          <template #default="{ row }">
            <el-button size="small" link type="primary" :data-testid="`override-${row.scan_type}`" @click="openOverride(row)">
              {{ row.source === 'override' ? 'Edit override' : 'Override' }}
            </el-button>
            <el-button v-if="row.source === 'override'" size="small" link type="danger" @click="clearOverride(row.scan_type)">Clear</el-button>
          </template>
        </el-table-column>
      </el-table>
      <p class="muted note">
        Times in your time zone ({{ viewerZone }}). The server issues each scan on a heartbeat when it is due; "Scan now"
        runs a scan regardless of the policy.
      </p>
    </template>

    <el-dialog v-model="override.open" :title="`Override ${typeLabel(override.type)} on this endpoint`" width="720px" top="6vh" append-to-body destroy-on-close>
      <p class="muted" style="margin-top: 0">Replaces the policy's {{ typeLabel(override.type).toLowerCase() }} settings for this endpoint only.</p>
      <el-form v-if="override.form" label-width="150px">
        <ScanSpecEditor v-model="override.form" :scan-type="override.type" :label="typeLabel(override.type)" />
      </el-form>
      <template #footer>
        <el-button @click="override.open = false">Cancel</el-button>
        <el-button type="primary" :loading="saving" data-testid="save-override" @click="saveOverride">Save override</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
/**
 * The Endpoints details pane's "Scan policy" tab: the endpoint's policy (and
 * changing it), its per-scan overrides, the effective schedule and next runs
 * per scan type, and a note for agents that predate scan policies.
 */
import { computed, reactive, ref, watch } from 'vue';
import { ElMessage } from 'element-plus';
import ScanSpecEditor from './ScanSpecEditor.vue';
import { api } from '@/services/api';
import { browserTimeZone, formatInZone } from '@/utils/scheduleTiming';
import { scanStatusTag } from '@/utils/endpointScans';
import {
  POLICY_SCAN_TYPES,
  describeLocalIntervals,
  describeSpec,
  specFormFromSpec,
  specFormProblem,
  specFromForm,
  type PolicyScanType,
  type ScanPolicy,
  type ScanSpec,
  type SpecForm,
} from '@/utils/scanPolicies';

interface ScanRowView {
  scan_type: PolicyScanType;
  source: 'policy' | 'override';
  spec: ScanSpec;
  next_runs: string[];
  waiting: 'window' | 'outstanding' | null;
  outstanding: boolean;
  last_run: { status: string; requested_at: string; completed_at: string | null } | null;
}
interface PolicyView {
  managed: boolean;
  min_agent_version: string;
  agent_version: string | null;
  policy: { id: number | null; name: string; is_default: boolean };
  assigned_policy_id: number | null;
  overrides: Partial<Record<PolicyScanType, ScanSpec>>;
  scans: ScanRowView[];
  local_intervals: { inventory_seconds: number; vuln_seconds: number; packages_seconds: number; yara: string } | null;
}

const props = defineProps<{ agentId: string; policies: ScanPolicy[]; canEdit: boolean }>();
const emit = defineEmits<{ changed: [] }>();

const viewerZone = browserTimeZone();
const view = ref<PolicyView | null>(null);
const loading = ref(false);
const saving = ref(false);
const defaultId = computed(() => props.policies.find((p) => p.is_default)?.id ?? null);
const overrideCount = computed(() => Object.keys(view.value?.overrides ?? {}).length);

const typeLabel = (t: string) => POLICY_SCAN_TYPES.find((x) => x.value === t)?.label ?? t;
const isNow = (iso: string) => Math.abs(new Date(iso).getTime() - Date.now()) < 90_000;

function errorMessage(e: unknown, fallback: string): string {
  const data = (e as { response?: { data?: { message?: string; error?: string } } })?.response?.data;
  return data?.message || data?.error || fallback;
}

async function load() {
  const id = props.agentId;
  loading.value = !view.value;
  try {
    const { data } = await api.getEndpointScanPolicy(id);
    if (id === props.agentId) view.value = data;
  } catch (e) {
    ElMessage.error(errorMessage(e, 'Failed to load the scan policy'));
  } finally {
    loading.value = false;
  }
}
watch(() => props.agentId, () => {
  view.value = null;
  void load();
}, { immediate: true });

async function put(body: { policy_id?: number | null; overrides?: unknown }, done: string) {
  saving.value = true;
  try {
    const { data } = await api.setEndpointScanPolicy(props.agentId, body);
    view.value = data;
    ElMessage.success(done);
    emit('changed');
    return true;
  } catch (e) {
    ElMessage.error(errorMessage(e, 'Failed to save'));
    return false;
  } finally {
    saving.value = false;
  }
}

async function assign(policyId: number) {
  const policy = props.policies.find((p) => p.id === policyId);
  await put({ policy_id: policy?.is_default ? null : policyId }, `This endpoint now follows ${policy?.name ?? 'the policy'}`);
}

const override = reactive<{ open: boolean; type: PolicyScanType; form: SpecForm | null }>({ open: false, type: 'vuln', form: null });

function openOverride(row: ScanRowView) {
  override.type = row.scan_type;
  override.form = specFormFromSpec(row.spec, viewerZone);
  override.open = true;
}

async function saveOverride() {
  if (!override.form || !view.value) return;
  const problem = override.form.enabled ? specFormProblem(override.form) : null;
  if (problem) {
    ElMessage.warning(problem);
    return;
  }
  const overrides = { ...view.value.overrides, [override.type]: specFromForm(override.form) };
  if (await put({ overrides }, `${typeLabel(override.type)} overridden on this endpoint`)) override.open = false;
}

async function clearOverride(type: PolicyScanType) {
  if (!view.value) return;
  const overrides = { ...view.value.overrides };
  delete overrides[type];
  await put({ overrides }, `${typeLabel(type)} follows the policy again`);
}

defineExpose({ reload: load });
</script>

<style scoped>
.block {
  margin-bottom: 12px;
}
.policy-row {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 10px;
  flex-wrap: wrap;
}
.label {
  font-weight: 600;
}
.muted {
  color: var(--el-text-color-secondary);
  font-size: 12px;
}
.run {
  font-variant-numeric: tabular-nums;
  line-height: 1.5;
}
.note {
  margin: 8px 0 0;
}
</style>
