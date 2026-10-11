<template>
  <div class="ai-settings">
    <el-card>
      <template #header>
        <span>AI Builder <HelpTip text="Powers parser and detection generation from a sample log line. Bring your own API key (stored encrypted at rest); generated artifacts run a generate → validate → auto-refine loop against the real engine before you can save them." /></span>
      </template>

      <el-form :model="aiForm" label-width="200px" v-loading="aiLoading">
        <el-form-item label="Provider">
          <el-select v-model="aiForm.provider" style="width: 220px">
            <el-option label="Anthropic (Claude)" value="anthropic" />
            <el-option label="OpenAI" value="openai" />
            <el-option label="Ollama (local)" value="ollama" />
          </el-select>
        </el-form-item>

        <el-form-item label="Model">
          <el-input v-model="aiForm.model" style="width: 320px" :placeholder="aiModelPlaceholder" />
        </el-form-item>

        <el-form-item v-if="aiForm.provider !== 'anthropic'" label="Base URL">
          <el-input
            v-model="aiForm.baseUrl"
            style="width: 320px"
            :placeholder="aiForm.provider === 'ollama' ? 'http://localhost:11434' : 'https://api.openai.com/v1'"
          />
        </el-form-item>

        <el-form-item v-if="aiForm.provider !== 'ollama'" label="API Key">
          <el-input
            v-model="aiForm.apiKey"
            type="password"
            show-password
            style="width: 320px"
            :placeholder="aiKeyPlaceholder"
          />
          <el-text size="small" :type="aiConfigured ? 'success' : 'warning'" style="margin-left: 10px">
            {{ aiKeyStatus }}
          </el-text>
        </el-form-item>

        <el-form-item>
          <el-button type="primary" @click="saveAiSettings" :loading="aiSaving">
            <el-icon><Check /></el-icon> Save AI Settings
          </el-button>
        </el-form-item>
        <el-text size="small" type="info">
          Powers "Generate with AI" on the Parsers and Detection Rules pages. The API key is stored
          encrypted at rest; you can instead set ANTHROPIC_API_KEY / OPENAI_API_KEY as environment variables.
          Leave the key blank to keep the existing one.
        </el-text>
      </el-form>
    </el-card>

    <el-card style="margin-top: 20px">
      <template #header>
        <span>AI Analyst (chat) <HelpTip text="The conversational SOC analyst (Ask AI). Read-only by design — it can query alerts, assets, and vulnerabilities but can never change anything. Configured separately from the AI Builder so you can use a cheaper or local model here." /></span>
      </template>

      <el-form :model="chatForm" label-width="200px" v-loading="chatLoading">
        <el-form-item label="Provider">
          <el-select v-model="chatForm.provider" style="width: 260px">
            <el-option label="Inherit main AI config" value="" />
            <el-option label="Anthropic (Claude)" value="anthropic" />
            <el-option label="OpenAI" value="openai" />
            <el-option label="Ollama (local)" value="ollama" />
          </el-select>
        </el-form-item>

        <template v-if="chatForm.provider">
          <el-form-item label="Model">
            <el-input v-model="chatForm.model" style="width: 320px" :placeholder="chatModelPlaceholder" />
          </el-form-item>

          <el-form-item v-if="chatForm.provider !== 'anthropic'" label="Base URL">
            <el-input
              v-model="chatForm.baseUrl"
              style="width: 320px"
              :placeholder="chatForm.provider === 'ollama' ? 'http://localhost:11434' : 'https://api.openai.com/v1'"
            />
          </el-form-item>

          <el-form-item v-if="chatForm.provider !== 'ollama'" label="API Key">
            <el-input
              v-model="chatForm.apiKey"
              type="password"
              show-password
              style="width: 320px"
              :placeholder="chatKeyPlaceholder"
            />
            <el-text size="small" :type="chatConfigured ? 'success' : 'warning'" style="margin-left: 10px">
              {{ chatKeyStatus }}
            </el-text>
          </el-form-item>
        </template>

        <el-form-item>
          <el-button type="primary" @click="saveChatSettings" :loading="chatSaving">
            <el-icon><Check /></el-icon> Save Analyst Settings
          </el-button>
        </el-form-item>
        <el-text size="small" type="info">
          Powers the conversational AI Analyst. Leave the provider on "Inherit main AI config" to reuse the
          AI Builder model above, or choose a separate model (e.g. a larger one, or a local Ollama instruct
          model like Qwen2.5 / Llama 3.1) just for the analyst — the tool loop works best with a strong
          instruction-following model. Key stored encrypted at rest; leave blank to keep the existing one.
          <span v-if="chatInheritsFrom === 'main'"> Currently inheriting the main AI config.</span>
        </el-text>
      </el-form>
    </el-card>

    <el-card style="margin-top: 20px">
      <template #header>
        <span>AI Triage (automatic alert analysis) <HelpTip text="Runs the AI Analyst's read-only tool loop automatically on new alerts to produce a risk score, verdict, evidence, and a PROPOSED remediation plan — nothing is ever auto-executed; a human still applies status changes manually. Off by default." /></span>
      </template>

      <el-form :model="triageForm" label-width="200px" v-loading="triageLoading">
        <el-form-item label="Enabled">
          <el-switch v-model="triageForm.enabled" />
          <el-text size="small" type="info" style="margin-left: 10px">
            Automatically analyze new alerts at or above the minimum severity below
          </el-text>
        </el-form-item>

        <el-form-item label="Minimum severity">
          <el-select v-model="triageForm.minSeverity" style="width: 160px">
            <el-option label="Low" value="low" />
            <el-option label="Medium" value="medium" />
            <el-option label="High" value="high" />
            <el-option label="Critical" value="critical" />
          </el-select>
        </el-form-item>

        <el-form-item label="Daily cap">
          <el-input-number v-model="triageForm.dailyCap" :min="0" :max="10000" style="width: 160px" />
          <el-text size="small" type="info" style="margin-left: 10px">max analyses per 24h</el-text>
        </el-form-item>

        <el-form-item label="Max concurrent">
          <el-input-number v-model="triageForm.maxConcurrent" :min="1" :max="10" style="width: 160px" />
        </el-form-item>

        <el-form-item label="Max tool calls">
          <el-input-number v-model="triageForm.maxToolCalls" :min="1" :max="12" style="width: 160px" />
          <el-text size="small" type="info" style="margin-left: 10px">
            per-alert depth cap — more calls dig deeper but cost more and take longer
          </el-text>
        </el-form-item>

        <el-form-item label="Time budget">
          <el-input-number v-model="triageForm.wallBudgetSeconds" :min="20" :max="280" :step="10" style="width: 160px" />
          <el-text size="small" type="info" style="margin-left: 10px">
            seconds per alert before the agent must wrap up with what it has gathered so far
          </el-text>
        </el-form-item>

        <el-divider />

        <el-form-item label="Provider">
          <el-select v-model="triageForm.provider" style="width: 260px">
            <el-option label="Inherit AI Analyst config" value="" />
            <el-option label="Anthropic (Claude)" value="anthropic" />
            <el-option label="OpenAI" value="openai" />
            <el-option label="Ollama (local)" value="ollama" />
          </el-select>
        </el-form-item>

        <template v-if="triageForm.provider">
          <el-form-item label="Model">
            <el-input v-model="triageForm.model" style="width: 320px" :placeholder="triageModelPlaceholder" />
          </el-form-item>

          <el-form-item v-if="triageForm.provider !== 'anthropic'" label="Base URL">
            <el-input
              v-model="triageForm.baseUrl"
              style="width: 320px"
              :placeholder="triageForm.provider === 'ollama' ? 'http://localhost:11434' : 'https://api.openai.com/v1'"
            />
          </el-form-item>

          <el-form-item v-if="triageForm.provider !== 'ollama'" label="API Key">
            <el-input
              v-model="triageForm.apiKey"
              type="password"
              show-password
              style="width: 320px"
              :placeholder="triageKeyPlaceholder"
            />
            <el-text size="small" :type="triageConfigured ? 'success' : 'warning'" style="margin-left: 10px">
              {{ triageKeyStatus }}
            </el-text>
          </el-form-item>
        </template>

        <el-form-item>
          <el-button type="primary" @click="saveTriageSettings" :loading="triageSaving">
            <el-icon><Check /></el-icon> Save Triage Settings
          </el-button>
        </el-form-item>
        <el-text size="small" type="info">
          Read-only, same as the AI Analyst — no create/update/delete tools. Costs roughly one LLM call per
          analyzed alert, so a strong instruction-following model works best; the tool loop works on local
          Ollama models too. Key stored encrypted at rest; leave blank to keep the existing one.
          <span v-if="triageInheritsFrom === 'chat'"> Currently inheriting the AI Analyst config.</span>
        </el-text>
      </el-form>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, reactive, computed } from 'vue';
import { api } from '@/services/api';
import { ElMessage } from 'element-plus';
import { Check } from '@element-plus/icons-vue';
import HelpTip from '@/components/HelpTip.vue';

// AI builder settings
const aiLoading = ref(false);
const aiSaving = ref(false);
const aiConfigured = ref(false);
const aiKeySource = ref<'stored' | 'env' | 'none'>('none');
const aiForm = reactive({ provider: 'anthropic', model: '', baseUrl: '', apiKey: '' });

const aiModelPlaceholder = computed(() =>
  ({ anthropic: 'claude-sonnet-4-6', openai: 'gpt-4o', ollama: 'llama3.1' } as Record<string, string>)[aiForm.provider] || ''
);
const aiKeyPlaceholder = computed(() =>
  aiKeySource.value === 'stored' ? '•••••••• (saved — leave blank to keep)'
  : aiKeySource.value === 'env' ? 'set via environment variable'
  : 'paste your API key'
);
const aiKeyStatus = computed(() =>
  aiConfigured.value
    ? aiKeySource.value === 'env' ? 'Configured via environment variable' : 'Key configured'
    : 'No API key configured'
);

async function fetchAiSettings() {
  aiLoading.value = true;
  try {
    const { data } = await api.getAiSettings();
    aiForm.provider = data.provider || 'anthropic';
    aiForm.model = data.model || '';
    aiForm.baseUrl = data.baseUrl || '';
    aiForm.apiKey = '';
    aiConfigured.value = !!data.configured;
    aiKeySource.value = data.keySource || 'none';
  } catch (error) {
    // non-admins / not configured — leave defaults
  } finally {
    aiLoading.value = false;
  }
}

async function saveAiSettings() {
  aiSaving.value = true;
  try {
    const payload: any = { provider: aiForm.provider, model: aiForm.model, baseUrl: aiForm.baseUrl };
    if (aiForm.apiKey) payload.apiKey = aiForm.apiKey; // only send when changing
    await api.updateAiSettings(payload);
    ElMessage.success('AI settings saved');
    await fetchAiSettings();
  } catch (error: any) {
    ElMessage.error(error.response?.data?.message || 'Failed to save AI settings');
  } finally {
    aiSaving.value = false;
  }
}

// AI Analyst (chat) settings — a separate model config that may inherit the main one.
const chatLoading = ref(false);
const chatSaving = ref(false);
const chatConfigured = ref(false);
const chatKeySource = ref<'stored' | 'env' | 'none'>('none');
const chatInheritsFrom = ref<'chat' | 'main'>('main');
const chatForm = reactive({ provider: '', model: '', baseUrl: '', apiKey: '' });

const chatModelPlaceholder = computed(() =>
  ({ anthropic: 'claude-sonnet-4-6', openai: 'gpt-4o', ollama: 'llama3.1' } as Record<string, string>)[
    chatForm.provider
  ] || 'inherits main config'
);
const chatKeyPlaceholder = computed(() =>
  chatKeySource.value === 'stored'
    ? '•••••••• (saved — leave blank to keep)'
    : chatKeySource.value === 'env'
    ? 'set via environment variable'
    : 'paste your API key'
);
const chatKeyStatus = computed(() =>
  chatConfigured.value
    ? chatKeySource.value === 'env'
      ? 'Configured via environment variable'
      : 'Key configured'
    : 'No API key configured'
);

async function fetchChatSettings() {
  chatLoading.value = true;
  try {
    const { data } = await api.getChatAiSettings();
    chatInheritsFrom.value = data.inheritsFrom || 'main';
    const own = data.inheritsFrom === 'chat';
    chatForm.provider = own ? data.provider || '' : '';
    chatForm.model = own ? data.model || '' : '';
    chatForm.baseUrl = own ? data.baseUrl || '' : '';
    chatForm.apiKey = '';
    chatConfigured.value = !!data.configured;
    chatKeySource.value = data.keySource || 'none';
  } catch (error) {
    // non-admins / not configured — leave defaults
  } finally {
    chatLoading.value = false;
  }
}

async function saveChatSettings() {
  chatSaving.value = true;
  try {
    const payload: any = { provider: chatForm.provider };
    if (chatForm.provider) {
      payload.model = chatForm.model;
      payload.baseUrl = chatForm.baseUrl;
      if (chatForm.apiKey) payload.apiKey = chatForm.apiKey; // only send when changing
    }
    await api.updateChatAiSettings(payload);
    ElMessage.success('AI Analyst settings saved');
    await fetchChatSettings();
  } catch (error: any) {
    ElMessage.error(error.response?.data?.message || 'Failed to save analyst settings');
  } finally {
    chatSaving.value = false;
  }
}

// AI Triage settings — automatic per-alert analysis, inherits the AI Analyst
// (chat) config when its own provider is unset.
const triageLoading = ref(false);
const triageSaving = ref(false);
const triageConfigured = ref(false);
const triageKeySource = ref<'stored' | 'env' | 'none'>('none');
const triageInheritsFrom = ref<'triage' | 'chat'>('chat');
const triageForm = reactive({
  provider: '',
  model: '',
  baseUrl: '',
  apiKey: '',
  enabled: false,
  minSeverity: 'medium',
  dailyCap: 200,
  maxConcurrent: 2,
  maxToolCalls: 6,
  wallBudgetSeconds: 110,
});

const triageModelPlaceholder = computed(() =>
  ({ anthropic: 'claude-sonnet-4-6', openai: 'gpt-4o', ollama: 'llama3.1' } as Record<string, string>)[
    triageForm.provider
  ] || 'inherits AI Analyst config'
);
const triageKeyPlaceholder = computed(() =>
  triageKeySource.value === 'stored'
    ? '•••••••• (saved — leave blank to keep)'
    : triageKeySource.value === 'env'
    ? 'set via environment variable'
    : 'paste your API key'
);
const triageKeyStatus = computed(() =>
  triageConfigured.value
    ? triageKeySource.value === 'env'
      ? 'Configured via environment variable'
      : 'Key configured'
    : 'No API key configured'
);

async function fetchTriageSettings() {
  triageLoading.value = true;
  try {
    const { data } = await api.getTriageAiSettings();
    triageInheritsFrom.value = data.inheritsFrom || 'chat';
    const own = data.inheritsFrom === 'triage';
    triageForm.provider = own ? data.provider || '' : '';
    triageForm.model = own ? data.model || '' : '';
    triageForm.baseUrl = own ? data.baseUrl || '' : '';
    triageForm.apiKey = '';
    triageConfigured.value = !!data.configured;
    triageKeySource.value = data.keySource || 'none';
    triageForm.enabled = !!data.enabled;
    triageForm.minSeverity = data.minSeverity || 'medium';
    triageForm.dailyCap = data.dailyCap ?? 200;
    triageForm.maxConcurrent = data.maxConcurrent ?? 2;
    triageForm.maxToolCalls = data.maxToolCalls ?? 6;
    triageForm.wallBudgetSeconds = data.wallBudgetSeconds ?? 110;
  } catch (error) {
    // non-admins — leave defaults
  } finally {
    triageLoading.value = false;
  }
}

async function saveTriageSettings() {
  triageSaving.value = true;
  try {
    const payload: any = {
      provider: triageForm.provider,
      enabled: triageForm.enabled,
      minSeverity: triageForm.minSeverity,
      dailyCap: triageForm.dailyCap,
      maxConcurrent: triageForm.maxConcurrent,
      maxToolCalls: triageForm.maxToolCalls,
      wallBudgetSeconds: triageForm.wallBudgetSeconds,
    };
    if (triageForm.provider) {
      payload.model = triageForm.model;
      payload.baseUrl = triageForm.baseUrl;
      if (triageForm.apiKey) payload.apiKey = triageForm.apiKey; // only send when changing
    }
    await api.updateTriageAiSettings(payload);
    ElMessage.success('AI Triage settings saved');
    await fetchTriageSettings();
  } catch (error: any) {
    ElMessage.error(error.response?.data?.message || 'Failed to save triage settings');
  } finally {
    triageSaving.value = false;
  }
}

onMounted(() => {
  fetchAiSettings();
  fetchChatSettings();
  fetchTriageSettings();
});
</script>
