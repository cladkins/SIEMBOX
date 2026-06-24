<template>
  <span class="explain-with-ai">
    <el-button :size="size" :type="type" :plain="plain" @click="open">
      <el-icon class="explain-icon"><MagicStick /></el-icon>
      {{ label }}
    </el-button>

    <el-dialog
      v-model="visible"
      :title="`Explain this ${kind}`"
      width="640px"
      append-to-body
      @open="run"
    >
      <div v-loading="loading" class="explain-body">
        <el-alert
          v-if="error"
          :title="error"
          type="warning"
          :closable="false"
          show-icon
        >
          <template v-if="notConfigured" #default>
            {{ error }}
            <router-link to="/settings">Configure it in Settings → AI Builder.</router-link>
          </template>
        </el-alert>

        <!-- LLM output is rendered as plain pre-wrapped text (not HTML) so a
             model response can never inject markup. -->
        <pre v-if="explanation" class="explain-text">{{ explanation }}</pre>

        <div v-if="!loading && !explanation && !error" class="explain-empty">
          No explanation returned.
        </div>
      </div>

      <template #footer>
        <el-button @click="visible = false">Close</el-button>
        <el-button type="primary" :loading="loading" @click="run">Regenerate</el-button>
      </template>
    </el-dialog>
  </span>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import { MagicStick } from '@element-plus/icons-vue';
import { api } from '@/services/api';

const props = withDefaults(
  defineProps<{
    /** Artifact type, e.g. 'alert' | 'vulnerability' | 'log'. */
    kind: string;
    /** The artifact to explain (object or string). */
    data: unknown;
    /** Optional focusing question. */
    question?: string;
    label?: string;
    size?: 'small' | 'default' | 'large';
    type?: 'primary' | 'success' | 'info' | 'warning' | 'danger' | 'default';
    plain?: boolean;
  }>(),
  { label: 'Explain with AI', size: 'small', type: 'primary', plain: true }
);

const visible = ref(false);
const loading = ref(false);
const explanation = ref('');
const error = ref('');
const notConfigured = ref(false);

function open() {
  visible.value = true;
}

async function run() {
  loading.value = true;
  error.value = '';
  notConfigured.value = false;
  explanation.value = '';
  try {
    const res = await api.explainWithAI(props.kind, props.data, props.question);
    explanation.value = res.data?.explanation || '';
  } catch (e: any) {
    const msg =
      e?.response?.data?.error ||
      e?.response?.data?.message ||
      e?.message ||
      'Failed to generate explanation';
    // Surface the "no provider/key configured" case with a route to Settings.
    notConfigured.value = /api key|configured|provider|ollama|reach/i.test(String(msg));
    error.value = notConfigured.value
      ? 'AI is not configured (or unreachable).'
      : msg;
  } finally {
    loading.value = false;
  }
}
</script>

<style scoped>
.explain-icon {
  margin-right: 4px;
}
.explain-body {
  min-height: 120px;
}
.explain-text {
  white-space: pre-wrap;
  word-break: break-word;
  font-family: inherit;
  font-size: 14px;
  line-height: 1.55;
  margin: 0;
}
.explain-empty {
  color: var(--siembox-text-secondary, #909399);
  text-align: center;
  padding: 24px 0;
}
</style>
