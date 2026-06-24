<template>
  <div class="scheduled-scans">
    <div class="page-header">
      <h2>Scheduled Scans</h2>
      <p class="subtitle">
        Recurring asset discovery, vulnerability, and container image scans. Each
        schedule runs automatically on its interval, or trigger it now with "Run now".
      </p>
    </div>

    <el-card>
      <template #header>
        <div class="card-header">
          <span>Schedules</span>
          <el-button type="primary" size="small" @click="showCreateSchedule" :icon="Plus">
            New Schedule
          </el-button>
        </div>
      </template>

      <el-table :data="scheduledScans" v-loading="scheduledScansLoading" stripe>
        <el-table-column prop="name" label="Name" min-width="150" />

        <el-table-column label="Type" width="120">
          <template #default="{ row }">
            <el-tag :type="scanTypeTag(row.scan_type)" size="small">{{ row.scan_type }}</el-tag>
          </template>
        </el-table-column>

        <el-table-column label="Target" min-width="180">
          <template #default="{ row }">
            <el-text size="small">{{ formatScanTarget(row) }}</el-text>
          </template>
        </el-table-column>

        <el-table-column label="Interval" width="140">
          <template #default="{ row }">
            <el-text size="small">{{ formatInterval(row.interval_minutes) }}</el-text>
          </template>
        </el-table-column>

        <el-table-column label="Enabled" width="90" align="center">
          <template #default="{ row }">
            <el-switch
              v-model="row.enabled"
              :loading="scheduledScansSaving"
              @change="toggleScheduleEnabled(row)"
            />
          </template>
        </el-table-column>

        <el-table-column label="Last Run" width="180">
          <template #default="{ row }">
            <span v-if="row.last_run_at">{{ formatDate(row.last_run_at) }}</span>
            <el-text v-else type="info" size="small">Never</el-text>
          </template>
        </el-table-column>

        <el-table-column label="Next Run" width="180">
          <template #default="{ row }">
            <el-text size="small">{{ row.next_run_at ? formatDate(row.next_run_at) : '-' }}</el-text>
          </template>
        </el-table-column>

        <el-table-column label="Actions" width="240" align="center" fixed="right">
          <template #default="{ row }">
            <el-button size="small" type="success" @click="runScheduleNow(row)" :icon="VideoPlay">
              Run now
            </el-button>
            <el-button size="small" @click="editSchedule(row)" :icon="Edit">Edit</el-button>
            <el-button size="small" type="danger" @click="deleteScheduleConfirm(row)" :icon="Delete">
              Delete
            </el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- Schedule Dialog -->
    <el-dialog
      v-model="scheduledScanDialogVisible"
      :title="scheduledScanForm.id ? 'Edit Schedule' : 'New Schedule'"
      width="640px"
    >
      <el-form :model="scheduledScanForm" label-width="150px">
        <el-form-item label="Name" required>
          <el-input v-model="scheduledScanForm.name" placeholder="e.g., Nightly subnet scan" />
        </el-form-item>

        <el-form-item label="Scan Type" required>
          <el-select v-model="scheduledScanForm.scan_type" style="width: 100%">
            <el-option label="Asset" value="asset" />
            <el-option label="Vulnerability" value="vulnerability" />
            <el-option label="Container image (Trivy)" value="container" />
          </el-select>
        </el-form-item>

        <!-- Asset options -->
        <template v-if="scheduledScanForm.scan_type === 'asset'">
          <el-form-item label="Targets" required>
            <el-input
              v-model="scheduledScanForm.assetTargets"
              type="textarea"
              :rows="3"
              placeholder="192.168.1.0/24, 10.0.0.5&#10;One or more IPs/CIDRs, separated by comma, space, or newline"
            />
            <el-text size="small" type="info">
              IPs or CIDR ranges separated by comma, space, or newline.
            </el-text>
          </el-form-item>

          <el-form-item label="Asset Scan Type" required>
            <el-select v-model="scheduledScanForm.assetScanType" style="width: 100%">
              <el-option label="Ping" value="ping" />
              <el-option label="Port" value="port" />
              <el-option label="Service" value="service" />
              <el-option label="OS" value="os" />
            </el-select>
          </el-form-item>
        </template>

        <!-- Vulnerability options -->
        <template v-else-if="scheduledScanForm.scan_type === 'vulnerability'">
          <el-form-item label="Target" required>
            <el-input
              v-model="scheduledScanForm.vulnTarget"
              placeholder="IP address, CIDR range, or hostname (e.g., 192.168.1.1, example.com)"
            />
          </el-form-item>

          <el-form-item label="Template Selection" required>
            <el-radio-group v-model="scheduledScanForm.vulnTemplateMode">
              <el-radio-button value="all">All</el-radio-button>
              <el-radio-button value="cves">CVEs</el-radio-button>
              <el-radio-button value="category">By Category</el-radio-button>
              <el-radio-button value="tags">By Tags</el-radio-button>
              <el-radio-button value="custom">Custom</el-radio-button>
            </el-radio-group>
          </el-form-item>

          <el-form-item v-if="scheduledScanForm.vulnTemplateMode === 'category'" label="Categories">
            <el-checkbox-group v-model="scheduledScanForm.vulnCategories" v-loading="schedLoadingTemplates">
              <el-checkbox v-for="c in schedTemplateCategories" :key="c.id" :value="c.id">
                {{ c.name }}
                <el-tag size="small" type="info">{{ c.count.toLocaleString() }}</el-tag>
              </el-checkbox>
            </el-checkbox-group>
            <el-text v-if="schedTemplateCategories.length === 0" type="info" size="small">
              No templates available yet — download them on the Vulnerability Scanning page.
            </el-text>
          </el-form-item>

          <el-form-item v-if="scheduledScanForm.vulnTemplateMode === 'tags'" label="Tags">
            <el-select
              v-model="scheduledScanForm.vulnTags"
              multiple
              filterable
              placeholder="Select vulnerability tags (e.g. cve, rce, sqli)"
              style="width: 100%"
              :loading="schedLoadingTemplates"
            >
              <el-option
                v-for="t in schedTemplateTags"
                :key="t.name"
                :label="`${t.name} (${t.count})`"
                :value="t.name"
              />
            </el-select>
          </el-form-item>

          <el-form-item v-if="scheduledScanForm.vulnTemplateMode === 'custom'" label="Templates">
            <el-select
              v-model="scheduledScanForm.vulnTemplates"
              multiple
              filterable
              remote
              reserve-keyword
              placeholder="Search templates by name, CVE, or description..."
              style="width: 100%"
              :loading="schedLoadingTemplates"
              :remote-method="searchScheduledTemplates"
            >
              <el-option
                v-for="tmpl in schedTemplateOptions"
                :key="tmpl.id"
                :label="`${tmpl.name} (${tmpl.severity})`"
                :value="tmpl.id"
              />
            </el-select>
          </el-form-item>

          <el-form-item label="Severities">
            <el-select
              v-model="scheduledScanForm.vulnSeverities"
              multiple
              clearable
              placeholder="Optional - all severities if empty"
              style="width: 100%"
            >
              <el-option label="Critical" value="critical" />
              <el-option label="High" value="high" />
              <el-option label="Medium" value="medium" />
              <el-option label="Low" value="low" />
              <el-option label="Info" value="info" />
            </el-select>
          </el-form-item>
        </template>

        <!-- Container options -->
        <template v-else-if="scheduledScanForm.scan_type === 'container'">
          <el-form-item label="Image" required>
            <el-input
              v-model="scheduledScanForm.imageRef"
              placeholder="e.g. nginx:latest, ghcr.io/cladkins/siembox-backend:latest"
            />
            <el-text size="small" type="info">
              A container image reference. Trivy pulls and scans it on each run.
            </el-text>
          </el-form-item>
        </template>

        <el-form-item label="Interval" required>
          <el-select v-model="scheduledScanForm.interval_minutes" style="width: 100%">
            <el-option label="Every hour" :value="60" />
            <el-option label="Every 6 hours" :value="360" />
            <el-option label="Every 12 hours" :value="720" />
            <el-option label="Daily" :value="1440" />
            <el-option label="Weekly" :value="10080" />
          </el-select>
        </el-form-item>

        <el-form-item label="Enabled">
          <el-switch v-model="scheduledScanForm.enabled" />
        </el-form-item>
      </el-form>

      <template #footer>
        <el-button @click="scheduledScanDialogVisible = false">Cancel</el-button>
        <el-button type="primary" @click="saveSchedule" :loading="scheduledScansSaving">
          {{ scheduledScanForm.id ? 'Update' : 'Create' }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted } from 'vue';
import { ElMessage, ElMessageBox } from 'element-plus';
import { Plus, Edit, Delete, VideoPlay } from '@element-plus/icons-vue';
import { format } from 'date-fns';
import { api } from '@/services/api';
import vulnerabilityService, {
  type Template,
  type TemplateCategory,
  type TemplateTag,
} from '@/services/vulnerabilityService';

const scheduledScansLoading = ref(false);
const scheduledScansSaving = ref(false);
const scheduledScanDialogVisible = ref(false);
const scheduledScans = ref<any[]>([]);

const scheduledScanForm = reactive({
  id: null as number | null,
  name: '',
  scan_type: 'asset' as 'asset' | 'vulnerability' | 'container',
  enabled: true,
  interval_minutes: 1440,
  // asset
  assetTargets: '',
  assetScanType: 'ping' as 'ping' | 'port' | 'service' | 'os',
  // vulnerability
  vulnTarget: '',
  vulnTemplateMode: 'all' as 'all' | 'cves' | 'category' | 'tags' | 'custom',
  vulnCategories: ['http', 'network'] as string[],
  vulnTags: [] as string[],
  vulnTemplates: [] as string[],
  vulnSeverities: [] as string[],
  // container
  imageRef: '',
});

// Template data for the vuln-scan template selector (same source as the one-off
// scan form). Loaded lazily when the dialog opens.
const schedTemplateCategories = ref<TemplateCategory[]>([]);
const schedTemplateTags = ref<TemplateTag[]>([]);
const schedTemplateOptions = ref<Template[]>([]);
const schedLoadingTemplates = ref(false);

onMounted(() => {
  fetchScheduledScans();
});

async function fetchScheduledScans() {
  scheduledScansLoading.value = true;
  try {
    const response = await api.getScheduledScans();
    scheduledScans.value = response.data;
  } catch (error) {
    ElMessage.error('Failed to fetch scheduled scans');
  } finally {
    scheduledScansLoading.value = false;
  }
}

async function loadScanTemplateData() {
  if (schedTemplateCategories.value.length > 0 || schedLoadingTemplates.value) return;
  schedLoadingTemplates.value = true;
  try {
    const overview = await vulnerabilityService.getTemplatesOverview();
    schedTemplateCategories.value = overview.categories || [];
    schedTemplateTags.value = await vulnerabilityService.getTemplateTags();
  } catch (error: any) {
    if (error?.response?.status !== 404) {
      console.error('Failed to load scan templates:', error);
    }
  } finally {
    schedLoadingTemplates.value = false;
  }
}

async function searchScheduledTemplates(query: string) {
  if (!query || query.length < 2) {
    schedTemplateOptions.value = [];
    return;
  }
  schedLoadingTemplates.value = true;
  try {
    schedTemplateOptions.value = await vulnerabilityService.searchTemplates(query, 50);
  } catch (error) {
    console.error('Failed to search templates:', error);
  } finally {
    schedLoadingTemplates.value = false;
  }
}

function scanTypeTag(type: string): string {
  return { asset: 'primary', vulnerability: 'danger', container: 'warning' }[type] || 'info';
}

function formatInterval(minutes: number): string {
  const presets: Record<number, string> = {
    60: 'Every hour',
    360: 'Every 6 hours',
    720: 'Every 12 hours',
    1440: 'Daily',
    10080: 'Weekly',
  };
  if (presets[minutes]) return presets[minutes];
  if (minutes % 60 === 0) {
    const hours = minutes / 60;
    return `Every ${hours} hour${hours === 1 ? '' : 's'}`;
  }
  return `Every ${minutes} min`;
}

function formatScanTarget(scan: any): string {
  const options = scan.scan_options || {};
  if (scan.scan_type === 'asset') {
    return Array.isArray(options.targets) ? options.targets.join(', ') : '-';
  }
  if (scan.scan_type === 'container') {
    return options.image_ref || '-';
  }
  return options.target || '-';
}

function formatDate(date: string): string {
  return date ? format(new Date(date), 'MMM dd, yyyy HH:mm') : '-';
}

function resetScheduledScanForm() {
  scheduledScanForm.id = null;
  scheduledScanForm.name = '';
  scheduledScanForm.scan_type = 'asset';
  scheduledScanForm.enabled = true;
  scheduledScanForm.interval_minutes = 1440;
  scheduledScanForm.assetTargets = '';
  scheduledScanForm.assetScanType = 'ping';
  scheduledScanForm.vulnTarget = '';
  scheduledScanForm.vulnTemplateMode = 'all';
  scheduledScanForm.vulnCategories = ['http', 'network'];
  scheduledScanForm.vulnTags = [];
  scheduledScanForm.vulnTemplates = [];
  scheduledScanForm.vulnSeverities = [];
  scheduledScanForm.imageRef = '';
}

function showCreateSchedule() {
  resetScheduledScanForm();
  loadScanTemplateData();
  scheduledScanDialogVisible.value = true;
}

function editSchedule(scan: any) {
  resetScheduledScanForm();
  scheduledScanForm.id = scan.id;
  scheduledScanForm.name = scan.name;
  scheduledScanForm.scan_type = scan.scan_type;
  scheduledScanForm.enabled = scan.enabled;
  scheduledScanForm.interval_minutes = scan.interval_minutes;

  const options = scan.scan_options || {};
  if (scan.scan_type === 'asset') {
    scheduledScanForm.assetTargets = Array.isArray(options.targets) ? options.targets.join('\n') : '';
    scheduledScanForm.assetScanType = options.scanType || 'ping';
  } else if (scan.scan_type === 'container') {
    scheduledScanForm.imageRef = options.image_ref || '';
  } else if (scan.scan_type === 'vulnerability') {
    scheduledScanForm.vulnTarget = options.target || '';
    const sel = options.templateSelection || {};
    if (sel.all) {
      scheduledScanForm.vulnTemplateMode = 'all';
    } else if (sel.cves) {
      scheduledScanForm.vulnTemplateMode = 'cves';
    } else if (Array.isArray(sel.tags) && sel.tags.length > 0) {
      scheduledScanForm.vulnTemplateMode = 'tags';
      scheduledScanForm.vulnTags = [...sel.tags];
    } else if (Array.isArray(sel.templates) && sel.templates.length > 0) {
      if (sel.templates.every((t: string) => t.endsWith('/'))) {
        scheduledScanForm.vulnTemplateMode = 'category';
        scheduledScanForm.vulnCategories = sel.templates.map((t: string) => t.replace(/\/$/, ''));
      } else {
        scheduledScanForm.vulnTemplateMode = 'custom';
        scheduledScanForm.vulnTemplates = [...sel.templates];
      }
    }
    scheduledScanForm.vulnSeverities = Array.isArray(sel.severities) ? [...sel.severities] : [];
  }

  loadScanTemplateData();
  scheduledScanDialogVisible.value = true;
}

function parseTargets(raw: string): string[] {
  return raw
    .split(/[\s,]+/)
    .map((t) => t.trim())
    .filter((t) => t.length > 0);
}

function buildTemplateSelection(): any {
  let selection: any;
  switch (scheduledScanForm.vulnTemplateMode) {
    case 'all':
      selection = { all: true };
      break;
    case 'cves':
      selection = { cves: true };
      break;
    case 'category':
      selection = { templates: scheduledScanForm.vulnCategories.map((c) => `${c}/`) };
      break;
    case 'tags':
      selection = { tags: [...scheduledScanForm.vulnTags] };
      break;
    case 'custom':
      selection = { templates: [...scheduledScanForm.vulnTemplates] };
      break;
    default:
      selection = { all: true };
  }
  if (scheduledScanForm.vulnSeverities.length > 0) {
    selection.severities = [...scheduledScanForm.vulnSeverities];
  }
  return selection;
}

async function saveSchedule() {
  if (!scheduledScanForm.name.trim()) {
    ElMessage.warning('Please enter a name');
    return;
  }
  if (scheduledScanForm.interval_minutes < 5) {
    ElMessage.warning('Interval must be at least 5 minutes');
    return;
  }

  let scan_options: any;
  if (scheduledScanForm.scan_type === 'asset') {
    const targets = parseTargets(scheduledScanForm.assetTargets);
    if (targets.length === 0) {
      ElMessage.warning('Please enter at least one target');
      return;
    }
    scan_options = { targets, scanType: scheduledScanForm.assetScanType };
  } else if (scheduledScanForm.scan_type === 'container') {
    const imageRef = scheduledScanForm.imageRef.trim();
    if (!/^[a-zA-Z0-9][a-zA-Z0-9._:/@-]{0,510}$/.test(imageRef)) {
      ElMessage.warning('Please enter a valid container image reference');
      return;
    }
    scan_options = { image_ref: imageRef };
  } else {
    if (!scheduledScanForm.vulnTarget.trim()) {
      ElMessage.warning('Please enter a target');
      return;
    }
    scan_options = {
      target: scheduledScanForm.vulnTarget.trim(),
      templateSelection: buildTemplateSelection(),
    };
  }

  const payload = {
    name: scheduledScanForm.name.trim(),
    scan_type: scheduledScanForm.scan_type,
    scan_options,
    interval_minutes: scheduledScanForm.interval_minutes,
    enabled: scheduledScanForm.enabled,
  };

  scheduledScansSaving.value = true;
  try {
    if (scheduledScanForm.id) {
      await api.updateScheduledScan(scheduledScanForm.id, payload);
      ElMessage.success('Schedule updated successfully');
    } else {
      await api.createScheduledScan(payload);
      ElMessage.success('Schedule created successfully');
    }
    scheduledScanDialogVisible.value = false;
    fetchScheduledScans();
  } catch (error: any) {
    ElMessage.error(error.response?.data?.error || 'Failed to save schedule');
  } finally {
    scheduledScansSaving.value = false;
  }
}

async function toggleScheduleEnabled(scan: any) {
  scheduledScansSaving.value = true;
  try {
    await api.updateScheduledScan(scan.id, { enabled: scan.enabled });
    ElMessage.success(`Schedule ${scan.enabled ? 'enabled' : 'disabled'}`);
    fetchScheduledScans();
  } catch (error: any) {
    scan.enabled = !scan.enabled;
    ElMessage.error(error.response?.data?.error || 'Failed to update schedule');
  } finally {
    scheduledScansSaving.value = false;
  }
}

async function runScheduleNow(scan: any) {
  try {
    const response = await api.runScheduledScan(scan.id);
    ElMessage.success(response.data?.message || `Scan started (ID: ${response.data?.scanId})`);
    fetchScheduledScans();
  } catch (error: any) {
    ElMessage.error(error.response?.data?.error || 'Failed to run scan');
  }
}

async function deleteScheduleConfirm(scan: any) {
  try {
    await ElMessageBox.confirm(
      `Are you sure you want to delete the schedule "${scan.name}"?`,
      'Confirm Delete',
      { confirmButtonText: 'Delete', cancelButtonText: 'Cancel', type: 'warning' }
    );
    await api.deleteScheduledScan(scan.id);
    ElMessage.success('Schedule deleted successfully');
    fetchScheduledScans();
  } catch (error: any) {
    if (error !== 'cancel') {
      ElMessage.error('Failed to delete schedule');
    }
  }
}
</script>

<style scoped>
.scheduled-scans {
  padding: 0;
}
.page-header {
  margin-bottom: 16px;
}
.page-header h2 {
  margin: 0 0 4px;
}
.subtitle {
  margin: 0;
  color: var(--siembox-text-secondary, #909399);
  font-size: 14px;
}
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}
</style>
