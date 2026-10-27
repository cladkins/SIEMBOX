<template>
  <div v-if="report.publicTargets.length > 0 || report.hostnames.length > 0" class="public-target-warning">
    <el-alert
      v-if="report.publicTargets.length > 0"
      type="error"
      :closable="false"
      show-icon
      title="Public address space"
      data-testid="public-target-warning"
    >
      <p class="ptw-lead">
        {{ report.publicTargets.length === 1 ? 'This target is' : 'These targets are' }} outside private and reserved
        ranges (192.168/16, 10/8, 172.16/12, 100.64/10, loopback, link-local, fc00::/7), so
        {{ report.publicTargets.length === 1 ? 'it belongs' : 'they belong' }} to someone else unless you own
        {{ report.publicTargets.length === 1 ? 'it' : 'them' }}:
      </p>
      <ul class="ptw-list">
        <li v-for="t in report.publicTargets" :key="t.target">
          <code>{{ t.target }}</code>
          <span v-if="t.partlyPrivate" class="ptw-note"> (reaches into public space)</span>
          <template v-if="t.suggestion">
            — did you mean <code>{{ t.suggestion }}</code>?
            <el-button
              v-if="allowFix"
              link
              type="primary"
              size="small"
              @click="emit('use-suggestion', t.target, t.suggestion)"
            >
              Use {{ t.suggestion }}
            </el-button>
          </template>
        </li>
      </ul>
      <el-checkbox
        v-if="confirmable"
        :model-value="modelValue"
        data-testid="public-target-confirm"
        @update:model-value="(v: unknown) => emit('update:modelValue', v === true)"
      >
        I'm authorized to scan these public addresses
      </el-checkbox>
      <p v-else class="ptw-lead">A scan of {{ report.publicTargets.length === 1 ? 'it' : 'them' }} will ask you to confirm you're authorized.</p>
    </el-alert>
    <el-alert
      v-if="report.hostnames.length > 0"
      type="info"
      :closable="false"
      show-icon
      class="ptw-hostnames"
      :title="`Hostnames aren't checked: make sure ${report.hostnames.join(', ')} resolve${report.hostnames.length === 1 ? 's' : ''} to addresses you're authorized to scan.`"
    />
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { findPublicTargets } from '@/utils/targetSafety';

// The scan dialogs' public-target warning. Lists the targets in public address
// space (with a "did you mean" hint for a likely typo of a private range) and
// asks for the confirmation the API requires (allow_public_targets: true).
const props = withDefaults(
  defineProps<{
    targets: string[];
    modelValue?: boolean;
    /** Offer a "Use <suggestion>" button (emits use-suggestion). */
    allowFix?: boolean;
    /** Show the "I'm authorized" checkbox (off where nothing is scanned yet, e.g. editing a scope). */
    confirmable?: boolean;
  }>(),
  { modelValue: false, allowFix: true, confirmable: true }
);

const emit = defineEmits<{
  (e: 'update:modelValue', value: boolean): void;
  (e: 'use-suggestion', from: string, to: string): void;
}>();

const report = computed(() => findPublicTargets(props.targets));
</script>

<style scoped>
.public-target-warning {
  margin: 4px 0 12px;
}
.ptw-lead {
  margin: 0 0 6px;
}
.ptw-list {
  margin: 0 0 8px;
  padding-left: 18px;
}
.ptw-list code {
  font-weight: 600;
}
.ptw-note {
  color: var(--el-text-color-secondary);
}
.ptw-hostnames {
  margin-top: 8px;
}
</style>
