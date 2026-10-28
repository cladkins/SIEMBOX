<template>
  <el-card class="scan-policies" data-testid="scan-policies">
    <template #header>
      <div class="card-header-row">
        <span>Scan policies</span>
        <el-button v-if="canEdit" size="small" type="primary" data-testid="new-policy" @click="openEditor(null)">
          <el-icon><Plus /></el-icon> New policy
        </el-button>
      </div>
    </template>
    <p class="muted intro">
      Which scans endpoints run and when. Every endpoint follows the <strong>Default</strong> policy unless it is assigned a
      named one (select endpoints above, then <strong>Assign policy</strong>); single scans can be overridden per endpoint in
      its details. The server issues each scan when it is due; an endpoint that was offline runs a missed scan once when
      it reconnects. Agents before v{{ MIN_POLICY_AGENT_VERSION }} keep their own intervals.
    </p>
    <el-table :data="policies" v-loading="loading" size="small" stripe row-key="id">
      <el-table-column label="Policy" min-width="170">
        <template #default="{ row }">
          <strong>{{ row.name }}</strong>
          <el-tag v-if="row.is_default" size="small" type="info" style="margin-left: 6px">default</el-tag>
          <div v-if="row.description" class="muted">{{ row.description }}</div>
        </template>
      </el-table-column>
      <el-table-column v-for="t in POLICY_SCAN_TYPES" :key="t.value" :label="t.label" min-width="150">
        <template #default="{ row }">
          <span :class="{ muted: !row.scans[t.value]?.enabled }">{{ describeSpec(row.scans[t.value]) }}</span>
        </template>
      </el-table-column>
      <el-table-column label="Performance" min-width="170">
        <template #default="{ row }">
          <span :class="{ muted: !row.performance?.metrics && row.performance }">{{ describePerformance(row.performance) }}</span>
        </template>
      </el-table-column>
      <el-table-column label="Endpoints" width="100" align="center">
        <template #default="{ row }">{{ row.endpoint_count ?? 0 }}</template>
      </el-table-column>
      <el-table-column v-if="canEdit" label="" width="150" align="right">
        <template #default="{ row }">
          <el-button size="small" :data-testid="`edit-policy-${row.id}`" @click="openEditor(row)">Edit</el-button>
          <el-button v-if="!row.is_default" size="small" type="danger" plain @click="remove(row)">Delete</el-button>
        </template>
      </el-table-column>
    </el-table>

    <el-dialog v-model="editor.open" :title="editor.id ? `Edit policy: ${editor.name}` : 'New scan policy'" width="760px" top="5vh" destroy-on-close>
      <el-form label-width="150px" size="default">
        <el-form-item label="Name" required>
          <el-input v-model="editor.name" maxlength="100" placeholder="e.g. Servers — nightly" data-testid="policy-name" />
        </el-form-item>
        <el-form-item label="Description">
          <el-input v-model="editor.description" maxlength="500" placeholder="Optional" />
        </el-form-item>
        <el-tabs v-model="editor.tab" class="spec-tabs">
          <el-tab-pane v-for="t in POLICY_SCAN_TYPES" :key="t.value" :name="t.value">
            <template #label>
              {{ t.label }}
              <el-tag v-if="!editor.specs[t.value].enabled" size="small" type="info" style="margin-left: 4px">off</el-tag>
              <el-tag v-else-if="specFormProblem(editor.specs[t.value])" size="small" type="warning" style="margin-left: 4px">!</el-tag>
            </template>
            <ScanSpecEditor v-model="editor.specs[t.value]" :scan-type="t.value" :label="t.label" :help="t.help" />
          </el-tab-pane>
          <el-tab-pane name="performance">
            <template #label>
              Performance
              <el-tag v-if="!editor.performance.metrics" size="small" type="info" style="margin-left: 4px">off</el-tag>
              <el-tag v-else-if="performanceProblem(editor.performance)" size="small" type="warning" style="margin-left: 4px">!</el-tag>
            </template>
            <PerfSettingsEditor v-model="editor.performance" />
          </el-tab-pane>
        </el-tabs>
      </el-form>
      <template #footer>
        <el-button @click="editor.open = false">Cancel</el-button>
        <el-button type="primary" :loading="editor.saving" data-testid="save-policy" @click="save">Save</el-button>
      </template>
    </el-dialog>
  </el-card>
</template>

<script setup lang="ts">
/**
 * The Endpoints page's "Scan policies" card: the default and named policies
 * with each scan type's timing, how many endpoints follow each, and the editor
 * (operators and admins). The parent loads the list and reloads on `changed`.
 */
import { reactive } from 'vue';
import { ElMessage, ElMessageBox } from 'element-plus';
import { Plus } from '@element-plus/icons-vue';
import ScanSpecEditor from './ScanSpecEditor.vue';
import PerfSettingsEditor from './PerfSettingsEditor.vue';
import { describePerformance, performanceForm, performanceProblem, type PolicyPerformance } from '@/utils/endpointPerformance';
import { api } from '@/services/api';
import { browserTimeZone } from '@/utils/scheduleTiming';
import {
  MIN_POLICY_AGENT_VERSION,
  POLICY_SCAN_TYPES,
  defaultPolicyScans,
  describeSpec,
  specFormFromSpec,
  specFormProblem,
  specFromForm,
  type PolicyScanType,
  type ScanPolicy,
  type SpecForm,
} from '@/utils/scanPolicies';

defineProps<{ policies: ScanPolicy[]; loading: boolean; canEdit: boolean }>();
const emit = defineEmits<{ changed: [] }>();

const zone = browserTimeZone();

function formsFor(scans: ScanPolicy['scans']): Record<PolicyScanType, SpecForm> {
  return Object.fromEntries(POLICY_SCAN_TYPES.map((t) => [t.value, specFormFromSpec(scans[t.value], zone)])) as Record<
    PolicyScanType,
    SpecForm
  >;
}

const editor = reactive<{
  open: boolean;
  id: number | null;
  name: string;
  description: string;
  tab: PolicyScanType | 'performance';
  specs: Record<PolicyScanType, SpecForm>;
  performance: PolicyPerformance;
  saving: boolean;
}>({
  open: false,
  id: null,
  name: '',
  description: '',
  tab: 'vuln',
  specs: formsFor(defaultPolicyScans()),
  performance: performanceForm(null),
  saving: false,
});

function openEditor(policy: ScanPolicy | null) {
  editor.id = policy?.id ?? null;
  editor.name = policy?.name ?? '';
  editor.description = policy?.description ?? '';
  editor.specs = formsFor(policy?.scans ?? defaultPolicyScans());
  editor.performance = performanceForm(policy?.performance);
  editor.tab = 'vuln';
  editor.open = true;
}

function errorMessage(e: unknown, fallback: string): string {
  const data = (e as { response?: { data?: { message?: string; error?: string } } })?.response?.data;
  return data?.message || data?.error || fallback;
}

async function save() {
  if (!editor.name.trim()) {
    ElMessage.warning('Name the policy');
    return;
  }
  for (const t of POLICY_SCAN_TYPES) {
    const problem = editor.specs[t.value].enabled ? specFormProblem(editor.specs[t.value]) : null;
    if (problem) {
      editor.tab = t.value;
      ElMessage.warning(`${t.label}: ${problem}`);
      return;
    }
  }
  const perfProblem = editor.performance.metrics ? performanceProblem(editor.performance) : null;
  if (perfProblem) {
    editor.tab = 'performance';
    ElMessage.warning(`Performance: ${perfProblem}`);
    return;
  }
  const scans = Object.fromEntries(POLICY_SCAN_TYPES.map((t) => [t.value, specFromForm(editor.specs[t.value])]));
  editor.saving = true;
  try {
    const body = { name: editor.name.trim(), description: editor.description.trim() || null, scans, performance: editor.performance };
    if (editor.id) await api.updateScanPolicy(editor.id, body);
    else await api.createScanPolicy(body);
    ElMessage.success(editor.id ? 'Policy saved; its endpoints pick it up on their next heartbeat' : 'Policy created');
    editor.open = false;
    emit('changed');
  } catch (e) {
    ElMessage.error(errorMessage(e, 'Failed to save the policy'));
  } finally {
    editor.saving = false;
  }
}

async function remove(policy: ScanPolicy) {
  try {
    await ElMessageBox.confirm(
      `Delete the policy "${policy.name}"? ${policy.endpoint_count ? `Its ${policy.endpoint_count} endpoint(s) go back to the Default policy.` : ''}`,
      'Delete policy',
      { type: 'warning', confirmButtonText: 'Delete', cancelButtonText: 'Cancel' }
    );
  } catch {
    return;
  }
  try {
    const { data } = await api.deleteScanPolicy(policy.id);
    ElMessage.success(data.endpoints ? `Policy deleted; ${data.endpoints} endpoint(s) now follow the Default policy` : 'Policy deleted');
    emit('changed');
  } catch (e) {
    ElMessage.error(errorMessage(e, 'Failed to delete the policy'));
  }
}
</script>

<style scoped>
.card-header-row {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.intro {
  margin: 0 0 10px;
  line-height: 1.5;
}
.muted {
  color: var(--el-text-color-secondary);
  font-size: 12px;
}
.spec-tabs {
  margin-top: 4px;
}
</style>
