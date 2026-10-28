<template>
  <div class="scheduled-scans">
    <div class="page-header">
      <h2>Scheduled Scans</h2>
      <p class="subtitle">
        Recurring asset discovery, vulnerability, container image and log discovery scans. Each
        schedule runs automatically at the times you choose, or trigger it now with "Run now".
        Start from a <el-link type="primary" :underline="false" @click="suggestionsOpen = true">suggested scan</el-link>
        to get sensible options and timing in one click.
      </p>
    </div>

    <el-card>
      <template #header>
        <div class="card-header">
          <span>Schedules</span>
          <span class="header-actions">
          <el-button
            v-if="convertible.length"
            size="small"
            data-testid="convert-legacy"
            @click="convertLegacySchedules"
          >Switch {{ convertible.length }} to set times</el-button>
          <el-button size="small" data-testid="open-suggestions" :icon="MagicStick" @click="suggestionsOpen = true">
            Suggested scans
          </el-button>
          <el-button type="primary" size="small" @click="showCreateSchedule" :icon="Plus">
            New Schedule
          </el-button>
          </span>
        </div>
      </template>

      <el-table :data="scheduledScans" v-loading="scheduledScansLoading" stripe>
        <el-table-column prop="name" label="Name" min-width="150" />

        <el-table-column label="Type" width="120">
          <template #default="{ row }">
            <el-tag :type="scanTypeTag(row.scan_type)" size="small">{{ scanTypeLabel(row.scan_type) }}</el-tag>
          </template>
        </el-table-column>

        <el-table-column label="Target" min-width="150">
          <template #default="{ row }">
            <el-tag v-if="row.missing_inputs?.length" type="warning" size="small" effect="plain" data-testid="needs-inputs">
              {{ missingInputsText(row.missing_inputs) }}
            </el-tag>
            <el-text v-else size="small">{{ formatScanTarget(row) }}</el-text>
            <el-tooltip
              v-if="row.public_targets?.length"
              placement="top"
              :content="`Public address space: ${row.public_targets.join(', ')}. This schedule keeps running; saving changes to it asks you to confirm you're authorized to scan these addresses.`"
            >
              <el-tag type="danger" size="small" effect="plain" class="public-badge" data-testid="public-target-badge">Public targets</el-tag>
            </el-tooltip>
          </template>
        </el-table-column>

        <el-table-column label="Run from" width="110">
          <template #default="{ row }">
            <el-text size="small">{{ formatRunFrom(row) }}</el-text>
          </template>
        </el-table-column>

        <el-table-column label="Schedule" min-width="250">
          <template #default="{ row }">
            <div class="schedule-cell">
              <el-text size="small" data-testid="schedule-summary">{{ describeSchedule(row) }}</el-text>
              <el-text v-if="!row.enabled" type="info" size="small">Disabled</el-text>
              <el-tooltip
                v-else-if="row.next_run_at && row.schedule?.timezone && row.schedule.timezone !== viewerZone"
                placement="top"
                :content="`${formatInZone(row.next_run_at, row.schedule.timezone)} (${row.schedule.timezone})`"
              >
                <el-text type="info" size="small" data-testid="schedule-next-run">Next: {{ formatInZone(row.next_run_at, viewerZone) }}</el-text>
              </el-tooltip>
              <el-text v-else-if="row.next_run_at" type="info" size="small" data-testid="schedule-next-run">
                Next: {{ formatInZone(row.next_run_at, viewerZone) }}
              </el-text>
            </div>
          </template>
        </el-table-column>

        <el-table-column label="Enabled" width="90" align="center">
          <template #default="{ row }">
            <el-tooltip :disabled="!(row.missing_inputs?.length && !row.enabled)" content="Fill in the targets (Edit) to enable it" placement="top">
              <el-switch
                v-model="row.enabled"
                :loading="scheduledScansSaving"
                :disabled="!!row.missing_inputs?.length && !row.enabled"
                @change="toggleScheduleEnabled(row)"
              />
            </el-tooltip>
          </template>
        </el-table-column>

        <el-table-column label="Last Run" width="150">
          <template #default="{ row }">
            <span v-if="row.last_run_at">{{ formatDate(row.last_run_at) }}</span>
            <el-text v-else type="info" size="small">Never</el-text>
          </template>
        </el-table-column>

        <el-table-column label="Actions" width="240" align="center" fixed="right">
          <template #default="{ row }">
            <el-button size="small" type="success" :disabled="!!row.missing_inputs?.length" @click="runScheduleNow(row)" :icon="VideoPlay">
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
            <el-option label="Log discovery" value="log_discovery" />
          </el-select>
        </el-form-item>

        <el-alert
          v-if="fromSuggestion"
          type="info"
          :closable="false"
          show-icon
          style="margin-bottom: 12px"
          data-testid="from-suggestion"
          :title="`Added from the suggested scan &quot;${fromSuggestion.name}&quot;. Fill in: ${fromSuggestion.inputs}, then switch Enabled on and save.`"
        />

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
            <PublicTargetWarning
              v-model="schedPublicConfirmed"
              :targets="schedTargetList"
              style="width: 100%"
              @use-suggestion="(from: string, to: string) => (scheduledScanForm.assetTargets = replaceTargetToken(scheduledScanForm.assetTargets, from, to))"
            />
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
            <PublicTargetWarning
              v-model="schedPublicConfirmed"
              :targets="schedTargetList"
              style="width: 100%"
              @use-suggestion="(_from: string, to: string) => (scheduledScanForm.vulnTarget = to)"
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

          <el-form-item label="Exclude tags">
            <el-select
              v-model="scheduledScanForm.vulnExcludeTags"
              multiple
              filterable
              allow-create
              default-first-option
              placeholder="e.g. intrusive, dos, fuzz"
              style="width: 100%"
              data-testid="vuln-exclude-tags"
            >
              <el-option v-for="t in ['intrusive', 'dos', 'fuzz']" :key="t" :label="t" :value="t" />
            </el-select>
            <el-text size="small" type="info">
              Templates with these tags are skipped. Excluding intrusive, dos and fuzz keeps the scan from logging in,
              sending payloads or stressing services.
            </el-text>
          </el-form-item>

          <el-form-item label="Rate limit">
            <el-input-number v-model="scheduledScanForm.vulnRateLimit" :min="1" :max="10000" :step="10" controls-position="right" />
            <el-text size="small" type="info" style="margin-left: 8px">requests per second (empty: Nuclei's default)</el-text>
          </el-form-item>
        </template>

        <!-- Container options -->
        <template v-else-if="scheduledScanForm.scan_type === 'container'">
          <el-form-item label="Images">
            <el-radio-group v-model="scheduledScanForm.containerAll">
              <el-radio :value="true">All discovered images</el-radio>
              <el-radio :value="false">One image</el-radio>
            </el-radio-group>
            <el-text v-if="scheduledScanForm.containerAll" size="small" type="info">
              Each run scans every image currently found on the SIEMBox host (Docker socket) and on every log
              shipper's host, as on the Container Scanning page — new containers are picked up automatically.
            </el-text>
          </el-form-item>
          <el-form-item v-if="!scheduledScanForm.containerAll" label="Image" required>
            <el-input
              v-model="scheduledScanForm.imageRef"
              placeholder="e.g. nginx:latest, ghcr.io/cladkins/siembox-backend:latest"
            />
            <el-text size="small" type="info">
              A container image reference. Trivy pulls and scans it on each run.
            </el-text>
          </el-form-item>
        </template>

        <!-- Log discovery options -->
        <template v-else-if="scheduledScanForm.scan_type === 'log_discovery'">
          <el-form-item label="Mode" required>
            <el-select v-model="scheduledScanForm.discoveryMode" style="width: 100%" data-testid="discovery-mode">
              <el-option label="Passive (listen only, no packets to hosts)" value="passive" />
              <el-option label="Active (probe hosts on fingerprinted ports and paths)" value="active" />
              <el-option label="Full (passive, then active)" value="full" />
            </el-select>
          </el-form-item>
          <el-form-item label="Subnets">
            <el-input
              v-model="scheduledScanForm.discoveryCidrs"
              type="textarea"
              :rows="2"
              placeholder="Leave empty to sweep the scope saved on the Log Discovery page"
            />
            <el-text size="small" type="info">
              CIDRs separated by comma, space or newline. Empty: each run sweeps the saved Log Discovery scope as it is then.
            </el-text>
            <PublicTargetWarning
              v-model="schedPublicConfirmed"
              :targets="schedTargetList"
              style="width: 100%"
              @use-suggestion="(from: string, to: string) => (scheduledScanForm.discoveryCidrs = replaceTargetToken(scheduledScanForm.discoveryCidrs, from, to))"
            />
          </el-form-item>
        </template>

        <!-- Run from (asset/vuln/log discovery; container = Trivy, no LAN scan) -->
        <el-form-item v-if="scheduledScanForm.scan_type !== 'container'" label="Run from">
          <el-select v-model="scheduledScanForm.assignedShipperId" placeholder="Select where to run the scan" style="width: 100%">
            <el-option :label="'SIEMBox backend (built-in)'" :value="null" />
            <el-option
              v-for="s in schedShippers"
              :key="s.id"
              :label="`${s.name}${s.status !== 'online' ? ` (${s.status})` : ''}`"
              :value="s.id"
              :disabled="s.status !== 'online'"
            />
          </el-select>
          <el-text size="small" type="info">
            Each run executes on the selected log shipper, out on its LAN. Leave as built-in to run on the SIEMBox backend.
          </el-text>
        </el-form-item>

        <el-alert
          v-if="convertedFrom && timing.frequency !== 'interval'"
          type="info"
          :closable="false"
          show-icon
          style="margin-bottom: 12px"
          data-testid="converted-note"
          :title="`This schedule ran ${convertedFrom.toLowerCase()} from when it was saved, so its time drifted. It's set below to run at the same time as its next run, at fixed times from now on. Choose Fixed interval to keep it as it was.`"
        />
        <el-form-item label="Frequency" required>
          <el-select v-model="timing.frequency" style="width: 100%" data-testid="schedule-frequency">
            <el-option label="Hourly" value="hourly" />
            <el-option label="Daily" value="daily" />
            <el-option label="Weekly" value="weekly" />
            <el-option label="Monthly" value="monthly" />
            <el-option label="Fixed interval (every N minutes from the last run)" value="interval" />
          </el-select>
        </el-form-item>

        <template v-if="timing.frequency === 'interval'">
          <el-form-item label="Interval" required>
            <el-select v-model="timing.interval_minutes" style="width: 100%">
              <el-option v-for="p in intervalOptions" :key="p.value" :label="p.label" :value="p.value" />
            </el-select>
            <el-text class="timing-help" size="small" type="info">
              Runs this long after it was saved or last ran, so the time of day drifts. Choose Hourly, Daily, Weekly or
              Monthly to run at set times instead.
            </el-text>
          </el-form-item>
        </template>

        <template v-else>
          <el-form-item v-if="timing.frequency === 'hourly'" label="Minute past the hour" required>
            <div class="timing-row">
              <el-input-number v-model="timing.minute" :min="0" :max="59" :step="5" controls-position="right" />
              <span class="timing-label">every</span>
              <el-select v-model="timing.every_hours" style="width: 130px">
                <el-option v-for="n in 12" :key="n" :label="n === 1 ? 'hour' : `${n} hours`" :value="n" />
              </el-select>
            </div>
            <el-text class="timing-help" v-if="timing.every_hours > 1" size="small" type="info">
              Counted from midnight in the schedule's time zone ({{ hourlySlots }}).
            </el-text>
          </el-form-item>

          <el-form-item v-if="timing.frequency === 'weekly'" label="Days" required>
            <el-checkbox-group v-model="timing.days" size="small" data-testid="schedule-days">
              <el-checkbox-button v-for="d in WEEKDAY_ORDER" :key="d" :value="d">{{ WEEKDAY_SHORT[d] }}</el-checkbox-button>
            </el-checkbox-group>
            <div class="day-shortcuts">
              <el-button link type="primary" size="small" @click="timing.days = [1, 2, 3, 4, 5]">Weekdays</el-button>
              <el-button link type="primary" size="small" @click="timing.days = [0, 6]">Weekends</el-button>
              <el-button link type="primary" size="small" @click="timing.days = [0, 1, 2, 3, 4, 5, 6]">Every day</el-button>
            </div>
          </el-form-item>

          <el-form-item v-if="timing.frequency === 'monthly'" label="Day of month" required>
            <el-input-number v-model="timing.day_of_month" :min="1" :max="31" controls-position="right" />
            <el-text class="timing-help" size="small" type="info">
              A month without this day (e.g. the 31st in April, or the 29th-31st in February) runs on its last day.
            </el-text>
          </el-form-item>

          <el-form-item v-if="timing.frequency !== 'hourly'" label="Time" required>
            <el-time-picker
              v-model="timing.time"
              format="HH:mm"
              value-format="HH:mm"
              :clearable="false"
              placeholder="HH:MM"
              style="width: 140px"
              data-testid="schedule-time"
            />
          </el-form-item>

          <el-form-item label="Time zone" required>
            <el-select v-model="timing.timezone" filterable style="width: 100%" data-testid="schedule-timezone">
              <el-option v-for="z in zoneOptions" :key="z" :label="z === viewerZone ? `${z} (your time zone)` : z" :value="z" />
            </el-select>
            <el-text class="timing-help" size="small" type="info">
              Times are wall-clock in this zone and follow daylight saving: a time skipped when clocks go forward runs
              when the clock jumps; a time repeated when they go back runs once.
            </el-text>
          </el-form-item>
        </template>

        <el-form-item label="Next runs">
          <div class="preview" data-testid="schedule-preview">
            <el-text v-if="timingProblem" type="warning" size="small">{{ timingProblem }}</el-text>
            <el-text v-else-if="previewError" type="danger" size="small">{{ previewError }}</el-text>
            <template v-else-if="previewRuns.length">
              <div v-for="run in previewRuns" :key="run" class="preview-run">
                <span>{{ formatInZone(run, previewZone) }}</span>
                <el-text v-if="previewZone !== viewerZone" type="info" size="small">
                  · {{ formatInZone(run, viewerZone) }} your time
                </el-text>
              </div>
              <el-text v-if="timing.frequency === 'interval' && !timingChanged && editingNextRun" class="timing-help" type="info" size="small">
                Unchanged: the next run stays {{ formatInZone(editingNextRun, viewerZone) }}.
              </el-text>
              <el-text v-else-if="timing.frequency === 'interval'" class="timing-help" type="info" size="small">If saved now.</el-text>
            </template>
            <el-text v-else type="info" size="small">…</el-text>
          </div>
        </el-form-item>

        <el-form-item label="Enabled">
          <el-switch v-model="scheduledScanForm.enabled" />
        </el-form-item>
      </el-form>

      <template #footer>
        <el-button @click="scheduledScanDialogVisible = false">Cancel</el-button>
        <el-button type="primary" @click="saveSchedule" :loading="scheduledScansSaving" :disabled="schedGate.blocked">
          {{ scheduledScanForm.id ? 'Update' : 'Create' }}
        </el-button>
      </template>
    </el-dialog>

    <ScanSuggestionsBrowser v-model="suggestionsOpen" @added="onSuggestionAdded" />
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, onMounted, computed, watch } from 'vue';
import { ElMessage, ElMessageBox } from 'element-plus';
import { Plus, Edit, Delete, VideoPlay, MagicStick } from '@element-plus/icons-vue';
import { useRouter } from 'vue-router';
import { format } from 'date-fns';
import { api } from '@/services/api';
import vulnerabilityService, {
  type Template,
  type TemplateCategory,
  type TemplateTag,
  type ShipperSummary,
} from '@/services/vulnerabilityService';
import PublicTargetWarning from '@/components/PublicTargetWarning.vue';
import ScanSuggestionsBrowser from '@/components/ScanSuggestionsBrowser.vue';
import { describeInputs, missingInputsText, type SuggestionInput } from '@/utils/scanSuggestions';
import { publicTargetGate, replaceTargetToken } from '@/utils/shipperJobs';
import {
  INTERVAL_PRESETS,
  WEEKDAY_ORDER,
  WEEKDAY_SHORT,
  browserTimeZone,
  defaultTimingForm,
  describeSchedule,
  formatInterval,
  formatInZone,
  timeZoneOptions,
  timingFormFromRow,
  calendarEquivalent,
  timingFormProblem,
  timingPayload,
  type TimingForm,
} from '@/utils/scheduleTiming';

const router = useRouter();
const scheduledScansLoading = ref(false);
// "Suggested scans" browser, and the suggestion the open dialog was added from.
const suggestionsOpen = ref(false);
const fromSuggestion = ref<{ name: string; inputs: string } | null>(null);
// Options the form has no field for (Nuclei timeout and template exclusions), kept on save.
let vulnPassThrough: Record<string, unknown> = {};
const scheduledScansSaving = ref(false);
const scheduledScanDialogVisible = ref(false);
const scheduledScans = ref<any[]>([]);

const scheduledScanForm = reactive({
  id: null as number | null,
  name: '',
  scan_type: 'asset' as 'asset' | 'vulnerability' | 'container' | 'log_discovery',
  enabled: true,
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
  vulnExcludeTags: [] as string[],
  vulnRateLimit: undefined as number | undefined,
  // container: every discovered image, or one image ref
  containerAll: true,
  imageRef: '',
  // log discovery: mode, and CIDRs (empty = the saved Log Discovery scope)
  discoveryMode: 'full' as 'passive' | 'active' | 'full',
  discoveryCidrs: '',
  // optional LAN-side dispatch (asset/vuln only); null = run on the backend
  assignedShipperId: null as number | null,
});

// When the schedule runs: a calendar frequency in a time zone, or the original
// fixed interval. New schedules default to daily at 02:00 in the viewer's zone.
const viewerZone = browserTimeZone();
const timing = reactive<TimingForm>(defaultTimingForm(viewerZone));
const zoneOptions = computed(() => timeZoneOptions(viewerZone, timing.timezone));
const timingProblem = computed(() => timingFormProblem(timing));
const intervalOptions = computed(() =>
  INTERVAL_PRESETS.some((p) => p.value === timing.interval_minutes)
    ? INTERVAL_PRESETS
    : [...INTERVAL_PRESETS, { label: formatInterval(timing.interval_minutes), value: timing.interval_minutes }]
);
const hourlySlots = computed(() => {
  const slots: string[] = [];
  for (let h = 0; h < 24; h += timing.every_hours) slots.push(`${String(h).padStart(2, '0')}:${String(timing.minute).padStart(2, '0')}`);
  return slots.join(', ');
});

// Live "Next runs" preview, computed by the server (the same rules it schedules with).
// Editing: the timing as loaded (an unchanged timing isn't sent, so saving a
// rename doesn't move the next run), the stored next run, and the interval a
// pre-converted fixed-interval schedule came from.
const loadedTiming = ref<string | null>(null);
const editingNextRun = ref<string | null>(null);
const convertedFrom = ref<string | null>(null);
const timingChanged = computed(() => loadedTiming.value === null || JSON.stringify(timingPayload(timing)) !== loadedTiming.value);

const previewRuns = ref<string[]>([]);
const previewError = ref('');
const previewZone = computed(() => (timing.frequency === 'interval' ? viewerZone : timing.timezone));
let previewTimer: ReturnType<typeof setTimeout> | null = null;
let previewSeq = 0;
watch(
  () => (scheduledScanDialogVisible.value ? JSON.stringify(timingPayload(timing)) : null),
  (payload) => {
    if (previewTimer) clearTimeout(previewTimer);
    if (!payload || timingProblem.value) {
      previewRuns.value = [];
      return;
    }
    previewTimer = setTimeout(async () => {
      const seq = ++previewSeq;
      try {
        const response = await api.previewScheduledScan({ ...JSON.parse(payload), count: 3 });
        if (seq !== previewSeq) return;
        previewRuns.value = response.data?.next_runs ?? [];
        previewError.value = '';
      } catch (error) {
        if (seq !== previewSeq) return;
        previewRuns.value = [];
        const data = (error as { response?: { data?: { message?: string; error?: string } } }).response?.data;
        previewError.value = data?.message || data?.error || 'Could not preview the next runs';
      }
    }, 250);
  },
  { immediate: true }
);

// Targets in public address space need the "I'm authorized" confirmation
// before a create or an edit can be saved (the API refuses them otherwise).
// A schedule saved before that check keeps running; its row shows a badge.
const schedPublicConfirmed = ref(false);
const schedTargetList = computed<string[]>(() => {
  if (scheduledScanForm.scan_type === 'asset') return parseTargets(scheduledScanForm.assetTargets);
  if (scheduledScanForm.scan_type === 'vulnerability') {
    const t = scheduledScanForm.vulnTarget.trim();
    return t ? [t] : [];
  }
  if (scheduledScanForm.scan_type === 'log_discovery') return parseTargets(scheduledScanForm.discoveryCidrs);
  return [];
});
const schedGate = computed(() => publicTargetGate(schedTargetList.value, schedPublicConfirmed.value));

// Log shippers available to run a scan from (for the "Run from" picker).
const schedShippers = ref<ShipperSummary[]>([]);
async function loadSchedShippers() {
  try {
    schedShippers.value = await vulnerabilityService.getShippers();
  } catch (error) {
    schedShippers.value = [];
    console.error('Failed to load shippers for scheduled-scan picker', error);
  }
}

// Render the "Run from" column for a schedule row: the shipper's name, or
// "Built-in" for asset/vuln on the backend, or "—" for container (Trivy).
function formatRunFrom(row: any): string {
  if (row?.scan_type === 'container') return '—';
  const id = row?.scan_options?.assignedShipperId;
  if (id == null) return 'Built-in';
  const match = schedShippers.value.find((s) => s.id === id);
  return match ? match.name : `shipper #${id}`;
}

// Template data for the vuln-scan template selector (same source as the one-off
// scan form). Loaded lazily when the dialog opens.
const schedTemplateCategories = ref<TemplateCategory[]>([]);
const schedTemplateTags = ref<TemplateTag[]>([]);
const schedTemplateOptions = ref<Template[]>([]);
const schedLoadingTemplates = ref(false);

onMounted(() => {
  fetchScheduledScans();
  loadSchedShippers();
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
  return { asset: 'primary', vulnerability: 'danger', container: 'warning', log_discovery: 'success' }[type] || 'info';
}

function scanTypeLabel(type: string): string {
  return type === 'log_discovery' ? 'log discovery' : type;
}

function formatScanTarget(scan: any): string {
  const options = scan.scan_options || {};
  if (scan.scan_type === 'asset') {
    return Array.isArray(options.targets) ? options.targets.join(', ') : '-';
  }
  if (scan.scan_type === 'container') {
    return options.all_images ? 'All discovered images' : options.image_ref || '-';
  }
  if (scan.scan_type === 'log_discovery') {
    const cidrs = Array.isArray(options.manual_cidrs) && options.manual_cidrs.length ? options.manual_cidrs.join(', ') : 'Saved Log Discovery scope';
    return `${options.mode || 'full'}: ${cidrs}`;
  }
  return options.target || '-';
}

function formatDate(date: string): string {
  return date ? format(new Date(date), 'MMM dd, yyyy HH:mm') : '-';
}

function resetScheduledScanForm() {
  loadedTiming.value = null;
  editingNextRun.value = null;
  convertedFrom.value = null;
  scheduledScanForm.id = null;
  scheduledScanForm.name = '';
  scheduledScanForm.scan_type = 'asset';
  scheduledScanForm.enabled = true;
  Object.assign(timing, defaultTimingForm(viewerZone));
  previewRuns.value = [];
  previewError.value = '';
  scheduledScanForm.assetTargets = '';
  scheduledScanForm.assetScanType = 'ping';
  scheduledScanForm.vulnTarget = '';
  scheduledScanForm.vulnTemplateMode = 'all';
  scheduledScanForm.vulnCategories = ['http', 'network'];
  scheduledScanForm.vulnTags = [];
  scheduledScanForm.vulnTemplates = [];
  scheduledScanForm.vulnSeverities = [];
  scheduledScanForm.vulnExcludeTags = [];
  scheduledScanForm.vulnRateLimit = undefined;
  vulnPassThrough = {};
  fromSuggestion.value = null;
  scheduledScanForm.discoveryMode = 'full';
  scheduledScanForm.discoveryCidrs = '';
  scheduledScanForm.imageRef = '';
  scheduledScanForm.containerAll = true;
  scheduledScanForm.assignedShipperId = null;
  schedPublicConfirmed.value = false;
}

// A suggestion was added: a disabled schedule (open it to fill in the targets),
// or an endpoint policy (open it on the Endpoints page).
async function onSuggestionAdded(result: { scheduled_scan?: any; policy?: { id: number }; inputs?: SuggestionInput[] }) {
  if (result.policy) {
    router.push({ path: '/endpoints', query: { policy: String(result.policy.id) } });
    return;
  }
  await fetchScheduledScans();
  const row = scheduledScans.value.find((r) => r.id === result.scheduled_scan?.id) ?? result.scheduled_scan;
  if (!row) return;
  editSchedule(row);
  fromSuggestion.value = {
    name: row.name,
    inputs: describeInputs({ inputs: result.inputs ?? [] } as Parameters<typeof describeInputs>[0]),
  };
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
  Object.assign(timing, timingFormFromRow(scan, viewerZone));
  loadedTiming.value = JSON.stringify(timingPayload(timing));
  editingNextRun.value = scan.next_run_at ?? null;
  // A fixed-interval schedule opens converted to set times at its next run's
  // time of day (the drift the interval caused stops once it's saved).
  const equivalent = scan.schedule ? null : calendarEquivalent(scan.interval_minutes, scan.next_run_at, viewerZone);
  if (equivalent) {
    Object.assign(timing, equivalent);
    convertedFrom.value = formatInterval(scan.interval_minutes);
  }

  const options = scan.scan_options || {};
  scheduledScanForm.assignedShipperId = options.assignedShipperId ?? null;
  if (scan.scan_type === 'asset') {
    scheduledScanForm.assetTargets = Array.isArray(options.targets) ? options.targets.join('\n') : '';
    scheduledScanForm.assetScanType = options.scanType || 'ping';
  } else if (scan.scan_type === 'container') {
    scheduledScanForm.imageRef = options.image_ref || '';
    scheduledScanForm.containerAll = options.all_images === true;
  } else if (scan.scan_type === 'log_discovery') {
    scheduledScanForm.discoveryMode = options.mode || 'full';
    scheduledScanForm.discoveryCidrs = Array.isArray(options.manual_cidrs) ? options.manual_cidrs.join('\n') : '';
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
    scheduledScanForm.vulnExcludeTags = Array.isArray(sel.excludeTags) ? [...sel.excludeTags] : [];
    scheduledScanForm.vulnRateLimit = Number.isInteger(options.rateLimit) ? options.rateLimit : undefined;
    vulnPassThrough = {
      ...(Array.isArray(sel.exclude) && sel.exclude.length ? { exclude: [...sel.exclude] } : {}),
      ...(Number.isInteger(options.timeout) ? { timeout: options.timeout } : {}),
    };
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
  if (scheduledScanForm.vulnExcludeTags.length > 0) {
    selection.excludeTags = [...scheduledScanForm.vulnExcludeTags];
  }
  if (Array.isArray(vulnPassThrough.exclude)) selection.exclude = [...(vulnPassThrough.exclude as string[])];
  return selection;
}

async function saveSchedule() {
  if (!scheduledScanForm.name.trim()) {
    ElMessage.warning('Please enter a name');
    return;
  }
  if (timingProblem.value) {
    ElMessage.warning(timingProblem.value);
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
  } else if (scheduledScanForm.scan_type === 'container' && scheduledScanForm.containerAll) {
    scan_options = { all_images: true };
  } else if (scheduledScanForm.scan_type === 'container') {
    const imageRef = scheduledScanForm.imageRef.trim();
    if (!/^[a-zA-Z0-9][a-zA-Z0-9._:/@-]{0,510}$/.test(imageRef)) {
      ElMessage.warning('Please enter a valid container image reference');
      return;
    }
    scan_options = { image_ref: imageRef };
  } else if (scheduledScanForm.scan_type === 'log_discovery') {
    const cidrs = parseTargets(scheduledScanForm.discoveryCidrs);
    scan_options = { mode: scheduledScanForm.discoveryMode, ...(cidrs.length ? { manual_cidrs: cidrs } : {}) };
  } else {
    if (!scheduledScanForm.vulnTarget.trim()) {
      ElMessage.warning('Please enter a target');
      return;
    }
    scan_options = {
      target: scheduledScanForm.vulnTarget.trim(),
      templateSelection: buildTemplateSelection(),
      ...(scheduledScanForm.vulnRateLimit ? { rateLimit: scheduledScanForm.vulnRateLimit } : {}),
      ...(typeof vulnPassThrough.timeout === 'number' ? { timeout: vulnPassThrough.timeout } : {}),
    };
  }

  // LAN-side dispatch (asset/vuln only). Stored inside scan_options, like the
  // other per-type options; omitted when running on the backend.
  if (scheduledScanForm.scan_type !== 'container' && scheduledScanForm.assignedShipperId) {
    scan_options.assignedShipperId = scheduledScanForm.assignedShipperId;
  }

  const payload: Record<string, unknown> = {
    name: scheduledScanForm.name.trim(),
    scan_type: scheduledScanForm.scan_type,
    scan_options,
    ...(timingChanged.value ? timingPayload(timing) : {}),
    enabled: scheduledScanForm.enabled,
  };
  if (schedGate.value.allowPublicTargets) payload.allow_public_targets = true;

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
    ElMessage.error(error.response?.data?.message || error.response?.data?.error || 'Failed to save schedule');
  } finally {
    scheduledScansSaving.value = false;
  }
}

// Fixed-interval schedules that have a set-times equivalent (see calendarEquivalent).
const convertible = computed(() =>
  scheduledScans.value
    .filter((row) => !row.schedule && row.interval_minutes)
    .map((row) => ({ row, equivalent: calendarEquivalent(row.interval_minutes, row.next_run_at, viewerZone) }))
    .filter((c): c is { row: any; equivalent: Partial<TimingForm> } => c.equivalent !== null)
);

async function convertLegacySchedules() {
  const plans = convertible.value.map(({ row, equivalent }) => {
    const form = { ...timingFormFromRow(row, viewerZone), ...equivalent };
    return { row, schedule: timingPayload(form).schedule };
  });
  const lines = plans.map((p) => `${p.row.name}: ${formatInterval(p.row.interval_minutes)} → ${describeSchedule({ schedule: p.schedule })}`);
  try {
    await ElMessageBox.confirm(
      `Each keeps the time of day of its next run, in ${viewerZone}, and stops drifting:\n\n${lines.join('\n')}`,
      `Switch ${plans.length} schedule${plans.length === 1 ? '' : 's'} to set times?`,
      { confirmButtonText: 'Switch', cancelButtonText: 'Cancel', type: 'info', customStyle: { whiteSpace: 'pre-line', maxWidth: '640px' } }
    );
  } catch {
    return;
  }
  scheduledScansSaving.value = true;
  let failed = 0;
  for (const p of plans) {
    try {
      await api.updateScheduledScan(p.row.id, { schedule: p.schedule });
    } catch {
      failed++;
    }
  }
  scheduledScansSaving.value = false;
  if (failed) ElMessage.error(`${failed} of ${plans.length} could not be switched`);
  else ElMessage.success(`Switched ${plans.length} schedule${plans.length === 1 ? '' : 's'} to set times`);
  fetchScheduledScans();
}

async function toggleScheduleEnabled(scan: any) {
  scheduledScansSaving.value = true;
  try {
    await api.updateScheduledScan(scan.id, { enabled: scan.enabled });
    ElMessage.success(`Schedule ${scan.enabled ? 'enabled' : 'disabled'}`);
    fetchScheduledScans();
  } catch (error: any) {
    scan.enabled = !scan.enabled;
    ElMessage.error(error.response?.data?.message || error.response?.data?.error || 'Failed to update schedule');
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

.header-actions {
  display: flex;
  gap: 8px;
}
.public-badge {
  margin-left: 6px;
}
.schedule-cell {
  text-align: left;
  line-height: 1.5;
}
.schedule-cell > * {
  display: block;
  text-align: left;
}
.timing-row {
  display: flex;
  align-items: center;
  gap: 8px;
}
.timing-label {
  color: var(--siembox-text-secondary, #909399);
}
.day-shortcuts {
  width: 100%;
}
.timing-help {
  display: block;
  width: 100%;
  line-height: 1.5;
  margin-top: 4px;
}
.preview {
  display: flex;
  flex-direction: column;
  line-height: 1.6;
}
.preview-run {
  font-variant-numeric: tabular-nums;
}
</style>
