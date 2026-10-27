<template>
  <div class="schedule-timing-fields">
    <el-form-item label="Frequency" required>
      <el-select v-model="timing.frequency" style="width: 100%" :data-testid="`${testId}-frequency`">
        <el-option label="Hourly" value="hourly" />
        <el-option label="Daily" value="daily" />
        <el-option label="Weekly" value="weekly" />
        <el-option label="Monthly" value="monthly" />
        <el-option label="Fixed interval (every N minutes from the last run)" value="interval" />
      </el-select>
    </el-form-item>

    <el-form-item v-if="timing.frequency === 'interval'" label="Interval" required>
      <el-select v-model="timing.interval_minutes" style="width: 100%">
        <el-option v-for="p in intervalOptions" :key="p.value" :label="p.label" :value="p.value" />
      </el-select>
      <el-text class="timing-help" size="small" type="info">
        <slot name="interval-help">Runs this long after it last ran, so the time of day drifts.</slot>
      </el-text>
    </el-form-item>

    <template v-else>
      <el-form-item v-if="timing.frequency === 'hourly'" label="Minute past the hour" required>
        <div class="timing-row">
          <el-input-number v-model="timing.minute" :min="0" :max="59" :step="5" controls-position="right" />
          <span class="timing-label">every</span>
          <el-select v-model="timing.every_hours" style="width: 130px">
            <el-option v-for="n in 12" :key="n" :label="n === 1 ? 'hour' : `${n} hours`" :value="n" />
          </el-select>
        </div>
        <el-text v-if="timing.every_hours > 1" class="timing-help" size="small" type="info">
          Counted from midnight in the schedule's time zone ({{ hourlySlots }}).
        </el-text>
      </el-form-item>

      <el-form-item v-if="timing.frequency === 'weekly'" label="Days" required>
        <el-checkbox-group v-model="timing.days" size="small" :data-testid="`${testId}-days`">
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
          A month without this day (e.g. the 31st in April) runs on its last day.
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
          :data-testid="`${testId}-time`"
        />
      </el-form-item>

      <el-form-item label="Time zone" required>
        <el-select v-model="timing.timezone" filterable style="width: 100%" :data-testid="`${testId}-timezone`">
          <el-option v-for="z in zoneOptions" :key="z" :label="z === viewerZone ? `${z} (your time zone)` : z" :value="z" />
        </el-select>
        <el-text class="timing-help" size="small" type="info">
          Wall-clock times in this zone, following daylight saving.
        </el-text>
      </el-form-item>
    </template>
  </div>
</template>

<script setup lang="ts">
/**
 * The timing fields of a schedule form (frequency, interval or calendar times,
 * time zone), bound to a TimingForm (utils/scheduleTiming.ts) with v-model.
 * Used by the endpoint scan policy editor; the fields match Scheduled Scans'.
 * Render it inside an <el-form>.
 */
import { computed } from 'vue';
import {
  WEEKDAY_ORDER,
  WEEKDAY_SHORT,
  browserTimeZone,
  formatInterval,
  timeZoneOptions,
  type TimingForm,
} from '@/utils/scheduleTiming';

const props = withDefaults(
  defineProps<{
    /** Interval choices; the current value is added when it isn't one. */
    intervalPresets: Array<{ label: string; value: number }>;
    /** Prefix for data-testid attributes. */
    testId?: string;
  }>(),
  { testId: 'schedule' }
);

const timing = defineModel<TimingForm>({ required: true });

const viewerZone = browserTimeZone();
const zoneOptions = computed(() => timeZoneOptions(viewerZone, timing.value.timezone));
const intervalOptions = computed(() =>
  props.intervalPresets.some((p) => p.value === timing.value.interval_minutes)
    ? props.intervalPresets
    : [...props.intervalPresets, { label: formatInterval(timing.value.interval_minutes), value: timing.value.interval_minutes }]
);
const hourlySlots = computed(() => {
  const slots: string[] = [];
  for (let h = 0; h < 24; h += timing.value.every_hours) {
    slots.push(`${String(h).padStart(2, '0')}:${String(timing.value.minute).padStart(2, '0')}`);
  }
  return slots.join(', ');
});
</script>

<style scoped>
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
</style>
