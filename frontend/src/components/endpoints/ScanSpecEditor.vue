<template>
  <div class="scan-spec-editor" :data-testid="`spec-${scanType}`">
    <el-form-item :label="label">
      <el-switch v-model="form.enabled" active-text="Run" inactive-text="Off" :data-testid="`spec-${scanType}-enabled`" />
      <el-text v-if="help" class="spec-help" size="small" type="info">{{ help }}</el-text>
    </el-form-item>

    <template v-if="form.enabled">
      <ScheduleTimingFields v-model="form.timing" :interval-presets="POLICY_INTERVAL_PRESETS" :test-id="`spec-${scanType}`">
        <template #interval-help>Runs this long after the endpoint last ran it, so the time of day drifts.</template>
      </ScheduleTimingFields>

      <el-form-item label="Time window">
        <el-checkbox v-model="form.useWindow" :data-testid="`spec-${scanType}-window`">Only start between</el-checkbox>
        <template v-if="form.useWindow">
          <div class="window-row">
            <el-time-picker v-model="form.window.start" format="HH:mm" value-format="HH:mm" :clearable="false" style="width: 110px" />
            <span class="muted">and</span>
            <el-time-picker v-model="form.window.end" format="HH:mm" value-format="HH:mm" :clearable="false" style="width: 110px" />
            <el-select v-model="form.window.timezone" filterable style="width: 220px">
              <el-option v-for="z in zoneOptions" :key="z" :label="z" :value="z" />
            </el-select>
          </div>
          <el-text class="spec-help" size="small" type="info">
            A scan that comes due outside the window waits for it to open. An end earlier than the start runs overnight.
          </el-text>
          <el-text v-if="missesWindow" class="spec-help" size="small" type="warning">
            The scheduled time is outside this window, so each run waits for the next opening.
          </el-text>
        </template>
      </el-form-item>

      <el-form-item label="Next runs">
        <div class="preview" :data-testid="`spec-${scanType}-preview`">
          <el-text v-if="problem" type="warning" size="small">{{ problem }}</el-text>
          <el-text v-else-if="previewError" type="danger" size="small">{{ previewError }}</el-text>
          <template v-else-if="previewRuns.length">
            <div v-for="run in previewRuns" :key="run" class="preview-run">{{ formatInZone(run, previewZone) }}</div>
            <el-text class="spec-help" type="info" size="small">
              For an endpoint that already ran it; an endpoint new to the policy runs it once right away.
            </el-text>
          </template>
          <el-text v-else type="info" size="small">…</el-text>
        </div>
      </el-form-item>
    </template>
  </div>
</template>

<script setup lang="ts">
/**
 * Editor for one scan type's entry in a scan policy or an endpoint override:
 * on/off, timing (ScheduleTimingFields), an optional time window, and the
 * next runs the server computes for it. Bound to a SpecForm with v-model.
 */
import { computed, onBeforeUnmount, ref, watch } from 'vue';
import ScheduleTimingFields from '@/components/ScheduleTimingFields.vue';
import { api } from '@/services/api';
import { browserTimeZone, formatInZone, timeZoneOptions } from '@/utils/scheduleTiming';
import {
  POLICY_INTERVAL_PRESETS,
  specFormProblem,
  specFromForm,
  windowMissesSchedule,
  type SpecForm,
} from '@/utils/scanPolicies';

const props = defineProps<{ scanType: string; label: string; help?: string }>();
const form = defineModel<SpecForm>({ required: true });

const viewerZone = browserTimeZone();
const zoneOptions = computed(() => timeZoneOptions(viewerZone, form.value.window.timezone, form.value.timing.timezone));
const problem = computed(() => specFormProblem(form.value));
const missesWindow = computed(() => !problem.value && windowMissesSchedule(specFromForm(form.value)));
const previewZone = computed(() =>
  form.value.timing.frequency === 'interval' ? (form.value.useWindow ? form.value.window.timezone : viewerZone) : form.value.timing.timezone
);

const previewRuns = ref<string[]>([]);
const previewError = ref('');
let timer: ReturnType<typeof setTimeout> | null = null;
let seq = 0;
watch(
  () => (form.value.enabled ? JSON.stringify(specFromForm(form.value)) : null),
  (payload) => {
    if (timer) clearTimeout(timer);
    if (!payload || problem.value) {
      previewRuns.value = [];
      return;
    }
    timer = setTimeout(async () => {
      const mine = ++seq;
      try {
        const { data } = await api.previewScanPolicySpec(JSON.parse(payload), 3);
        if (mine !== seq) return;
        previewRuns.value = data?.next_runs ?? [];
        previewError.value = '';
      } catch (error) {
        if (mine !== seq) return;
        previewRuns.value = [];
        const data = (error as { response?: { data?: { message?: string; error?: string } } }).response?.data;
        previewError.value = data?.message || data?.error || `Could not preview the next ${props.label.toLowerCase()} runs`;
      }
    }, 250);
  },
  { immediate: true }
);
onBeforeUnmount(() => {
  if (timer) clearTimeout(timer);
});
</script>

<style scoped>
.spec-help {
  display: block;
  width: 100%;
  line-height: 1.5;
  margin-top: 4px;
}
.window-row {
  display: flex;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
  margin-top: 6px;
  width: 100%;
}
.muted {
  color: var(--el-text-color-secondary);
  font-size: 12px;
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
