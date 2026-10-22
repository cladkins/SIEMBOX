<template>
  <span class="alert-ref" @click.stop>
    <router-link v-if="link" :to="alertRefPath(id)" class="alert-ref-text" @click="emit('navigate')">{{ refText }}</router-link>
    <span v-else class="alert-ref-text">{{ refText }}</span>
    <el-tooltip :content="copied ? 'Copied' : `Copy ${refText}`" placement="top" :hide-after="0">
      <button type="button" class="alert-ref-copy" :aria-label="`Copy ${refText}`" @click="copy">
        <el-icon><CopyDocument /></el-icon>
      </button>
    </el-tooltip>
  </span>
</template>

<script setup lang="ts">
/**
 * An alert's ALR-#### reference: monospace, click the icon to copy it.
 * With `link`, the reference itself opens the alert on the Alerts page.
 */
import { computed, ref } from 'vue';
import { ElMessage } from 'element-plus';
import { CopyDocument } from '@element-plus/icons-vue';
import { alertRefPath, formatAlertRef } from '@/utils/alertRef';

const props = withDefaults(defineProps<{ id: number; link?: boolean }>(), { link: false });
const emit = defineEmits<{ navigate: [] }>();

const refText = computed(() => formatAlertRef(props.id));
const copied = ref(false);

async function copy() {
  try {
    await navigator.clipboard.writeText(refText.value);
    copied.value = true;
    window.setTimeout(() => (copied.value = false), 1500);
  } catch {
    ElMessage.warning(`Could not copy ${refText.value}`);
  }
}
</script>

<style scoped>
.alert-ref {
  display: inline-flex;
  align-items: center;
  gap: 2px;
  white-space: nowrap;
}
.alert-ref-text {
  font-family: var(--el-font-family-mono, ui-monospace, SFMono-Regular, Menlo, Consolas, monospace);
  font-size: 0.92em;
  color: inherit;
  text-decoration: none;
}
a.alert-ref-text {
  color: var(--el-color-primary);
}
a.alert-ref-text:hover {
  text-decoration: underline;
}
.alert-ref-copy {
  display: inline-flex;
  align-items: center;
  border: 0;
  background: transparent;
  padding: 2px;
  cursor: pointer;
  color: var(--el-text-color-secondary);
  font-size: 13px;
}
.alert-ref-copy:hover {
  color: var(--el-color-primary);
}
</style>
