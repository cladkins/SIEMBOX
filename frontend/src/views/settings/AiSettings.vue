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

        <el-form-item v-if="aiForm.provider !== 'ollama'" label="API Key" :required="aiKeyNeeded && !aiForm.removeKey">
          <el-input
            v-model="aiForm.apiKey"
            type="password"
            show-password
            style="width: 320px"
            :placeholder="aiKeyNeeded ? NEW_KEY_PLACEHOLDER : aiKeyPlaceholder"
            :disabled="aiKeyNeeded && aiForm.removeKey"
          />
          <el-text v-if="!aiKeyNeeded" size="small" :type="aiKeyStatusType" style="margin-left: 10px">
            {{ aiKeyStatus }}
          </el-text>
          <div v-if="aiKeyNeeded" class="key-needed" data-test="ai-key-needed">
            <el-text size="small" type="warning">{{ KEY_NEEDED_TEXT }}</el-text>
            <el-checkbox v-model="aiForm.removeKey" size="small">
              Remove the saved key instead<template v-if="ENV_KEY_VARS[aiForm.provider]">
                (the {{ ENV_KEY_VARS[aiForm.provider] }} environment variable is used, if set)</template>
            </el-checkbox>
          </div>
        </el-form-item>
        <el-form-item v-else-if="aiKeyNeeded" label="API Key">
          <el-text size="small" type="info">{{ OLLAMA_REMOVES_KEY_TEXT }}</el-text>
        </el-form-item>

        <el-form-item>
          <el-button type="primary" @click="saveAiSettings" :loading="aiSaving">
            <el-icon><Check /></el-icon> Save AI Settings
          </el-button>
        </el-form-item>
        <el-text size="small" type="info">
          Powers "Generate with AI" on the Parsers and Detection Rules pages. The API key is stored
          encrypted at rest; you can instead set ANTHROPIC_API_KEY / OPENAI_API_KEY as environment variables.
          Leave the key blank to keep the existing one. A saved key is only sent to the provider and base URL
          it was saved for, so changing either asks for the key again.
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
              :placeholder="blankBaseUrl(chatForm.provider, aiSaved)"
            />
          </el-form-item>

          <el-form-item
            v-if="chatForm.provider !== 'ollama'"
            label="API Key"
            :required="chatKeyNeeded && !chatForm.removeKey"
          >
            <el-input
              v-model="chatForm.apiKey"
              type="password"
              show-password
              style="width: 320px"
              :placeholder="chatKeyNeeded ? NEW_KEY_PLACEHOLDER : chatKeyPlaceholder"
              :disabled="chatKeyNeeded && chatForm.removeKey"
            />
            <el-text v-if="!chatKeyNeeded" size="small" :type="chatKeyStatusType" style="margin-left: 10px">
              {{ chatKeyStatus }}
            </el-text>
            <div v-if="chatKeyNeeded" class="key-needed" data-test="chat-key-needed">
              <el-text size="small" type="warning">{{ KEY_NEEDED_TEXT }}</el-text>
              <el-checkbox v-model="chatForm.removeKey" size="small">
                Remove the saved key instead (the AI Builder's key is used where the AI Builder sends it, else
                the environment variable, if set)
              </el-checkbox>
            </div>
          </el-form-item>
          <el-form-item v-else-if="chatKeyNeeded" label="API Key">
            <el-text size="small" type="info">{{ OLLAMA_REMOVES_KEY_TEXT }}</el-text>
          </el-form-item>
        </template>
        <el-form-item v-else-if="chatKeySaved" label="API Key">
          <el-text size="small" type="info">{{ INHERIT_REMOVES_KEY_TEXT }}</el-text>
        </el-form-item>

        <el-form-item>
          <el-button type="primary" @click="saveChatSettings" :loading="chatSaving">
            <el-icon><Check /></el-icon> Save Analyst Settings
          </el-button>
        </el-form-item>
        <el-text size="small" type="info">
          Powers the conversational AI Analyst. Leave the provider on "Inherit main AI config" to reuse the
          AI Builder model above, or choose a separate model (e.g. a larger one, or a local Ollama instruct
          model like Qwen2.5 / Llama 3.1) just for the analyst — the tool loop works best with a strong
          instruction-following model. Key stored encrypted at rest; leave blank to keep the existing one. A
          saved key is only sent to the provider and base URL it was saved for, so changing either asks for
          the key again; the AI Builder's key is only used where the AI Builder sends it.
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

        <el-form-item label="Lookups, time, length">
          <el-text size="small" type="info">
            Per-alert data lookups, time budget and output lengths are under AI budgets below.
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
              :placeholder="blankBaseUrl(triageForm.provider, chatSaved)"
            />
          </el-form-item>

          <el-form-item
            v-if="triageForm.provider !== 'ollama'"
            label="API Key"
            :required="triageKeyNeeded && !triageForm.removeKey"
          >
            <el-input
              v-model="triageForm.apiKey"
              type="password"
              show-password
              style="width: 320px"
              :placeholder="triageKeyNeeded ? NEW_KEY_PLACEHOLDER : triageKeyPlaceholder"
              :disabled="triageKeyNeeded && triageForm.removeKey"
            />
            <el-text v-if="!triageKeyNeeded" size="small" :type="triageKeyStatusType" style="margin-left: 10px">
              {{ triageKeyStatus }}
            </el-text>
            <div v-if="triageKeyNeeded" class="key-needed" data-test="triage-key-needed">
              <el-text size="small" type="warning">{{ KEY_NEEDED_TEXT }}</el-text>
              <el-checkbox v-model="triageForm.removeKey" size="small">
                Remove the saved key instead (the AI Analyst's key is used where the AI Analyst sends it, else
                the environment variable, if set)
              </el-checkbox>
            </div>
          </el-form-item>
          <el-form-item v-else-if="triageKeyNeeded" label="API Key">
            <el-text size="small" type="info">{{ OLLAMA_REMOVES_KEY_TEXT }}</el-text>
          </el-form-item>
        </template>
        <el-form-item v-else-if="triageKeySaved" label="API Key">
          <el-text size="small" type="info">{{ INHERIT_REMOVES_KEY_TEXT }}</el-text>
        </el-form-item>

        <el-form-item>
          <el-button type="primary" @click="saveTriageSettings" :loading="triageSaving">
            <el-icon><Check /></el-icon> Save Triage Settings
          </el-button>
        </el-form-item>
        <el-text size="small" type="info">
          Read-only, same as the AI Analyst — no create/update/delete tools. Costs roughly one LLM call per
          analyzed alert, so a strong instruction-following model works best; the tool loop works on local
          Ollama models too. Key stored encrypted at rest; leave blank to keep the existing one. A saved key
          is only sent to the provider and base URL it was saved for, so changing either asks for the key again.
          <span v-if="triageInheritsFrom === 'chat'"> Currently inheriting the AI Analyst config.</span>
        </el-text>
      </el-form>
    </el-card>

    <el-card style="margin-top: 20px" data-test="ai-budgets">
      <template #header>
        <span>AI budgets <HelpTip text="How much each AI feature may write and how long it may work. Longer limits give more complete answers but take longer and, with a paid provider, cost more per answer. The model's own output limit still applies: a value above it is cut at the model's limit." /></span>
      </template>

      <el-form :model="budgetForm" label-width="200px" v-loading="budgetLoading">
        <el-text size="small" type="info" tag="p" class="budget-intro">
          When an answer hits one of these limits it says so and names the setting to raise. Output lengths are
          in tokens (a token is roughly ¾ of a word). Higher limits give more complete answers, but they are
          slower, and paid providers bill for every output token. The model's own maximum output still applies.
        </el-text>

        <el-divider content-position="left">AI Analyst (chat)</el-divider>
        <el-form-item label="Answer length">
          <el-input-number v-model="budgetForm.analyst.answerMaxTokens" v-bind="tokenInput('analyst', 'answerMaxTokens')" />
          <el-text size="small" type="info" class="budget-hint">
            tokens for the written answer {{ defaultHint('analyst', 'answerMaxTokens') }}
          </el-text>
        </el-form-item>
        <el-form-item label="Working-step length">
          <el-input-number v-model="budgetForm.analyst.stepMaxTokens" v-bind="tokenInput('analyst', 'stepMaxTokens')" />
          <el-text size="small" type="info" class="budget-hint">
            tokens for each step that picks a lookup (a short answer can come back in one) {{ defaultHint('analyst', 'stepMaxTokens') }}
          </el-text>
        </el-form-item>
        <el-form-item label="Max data lookups">
          <el-input-number v-model="budgetForm.analyst.maxToolCalls" v-bind="numInput('analyst', 'maxToolCalls', 1)" />
          <el-text size="small" type="info" class="budget-hint">
            read-only queries per question; more dig deeper, and each is another model call {{ defaultHint('analyst', 'maxToolCalls') }}
          </el-text>
        </el-form-item>
        <el-form-item label="Time budget">
          <el-input-number v-model="budgetForm.analyst.wallBudgetSeconds" v-bind="numInput('analyst', 'wallBudgetSeconds', 10)" />
          <el-text size="small" type="info" class="budget-hint">
            seconds of gathering before it must answer with what it has; writing the answer may take up to 2 more
            minutes {{ defaultHint('analyst', 'wallBudgetSeconds') }}
          </el-text>
        </el-form-item>

        <el-divider content-position="left">AI Triage (per alert)</el-divider>
        <el-form-item label="Verdict length">
          <el-input-number v-model="budgetForm.triage.answerMaxTokens" v-bind="tokenInput('triage', 'answerMaxTokens')" />
          <el-text size="small" type="info" class="budget-hint">
            tokens for the verdict, reasoning and remediation plan {{ defaultHint('triage', 'answerMaxTokens') }}
          </el-text>
        </el-form-item>
        <el-form-item label="Working-step length">
          <el-input-number v-model="budgetForm.triage.stepMaxTokens" v-bind="tokenInput('triage', 'stepMaxTokens')" />
          <el-text size="small" type="info" class="budget-hint">
            tokens for each step that picks a lookup {{ defaultHint('triage', 'stepMaxTokens') }}
          </el-text>
        </el-form-item>
        <el-form-item label="Max data lookups">
          <el-input-number v-model="budgetForm.triage.maxToolCalls" v-bind="numInput('triage', 'maxToolCalls', 1)" />
          <el-text size="small" type="info" class="budget-hint">
            per-alert depth; triage runs on every qualifying alert, so this multiplies cost {{ defaultHint('triage', 'maxToolCalls') }}
          </el-text>
        </el-form-item>
        <el-form-item label="Time budget">
          <el-input-number v-model="budgetForm.triage.wallBudgetSeconds" v-bind="numInput('triage', 'wallBudgetSeconds', 10)" />
          <el-text size="small" type="info" class="budget-hint">
            seconds per alert before it must wrap up with what it has gathered {{ defaultHint('triage', 'wallBudgetSeconds') }}
          </el-text>
        </el-form-item>

        <el-divider content-position="left">AI builders and Explain</el-divider>
        <el-form-item label="Builder output length">
          <el-input-number v-model="budgetForm.builder.maxTokens" v-bind="tokenInput('builder', 'maxTokens')" />
          <el-text size="small" type="info" class="budget-hint">
            tokens for a generated parser or detection rule (many sample lines need more) {{ defaultHint('builder', 'maxTokens') }}
          </el-text>
        </el-form-item>
        <el-form-item label="Explain answer length">
          <el-input-number v-model="budgetForm.explain.maxTokens" v-bind="tokenInput('explain', 'maxTokens')" />
          <el-text size="small" type="info" class="budget-hint">
            tokens for an "Explain with AI" answer {{ defaultHint('explain', 'maxTokens') }}
          </el-text>
        </el-form-item>

        <el-form-item>
          <el-button type="primary" @click="saveBudgets" :loading="budgetSaving" data-test="save-ai-budgets">
            <el-icon><Check /></el-icon> Save AI Budgets
          </el-button>
          <el-button @click="restoreBudgetDefaults">Restore defaults</el-button>
        </el-form-item>
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
import { ENV_KEY_VARS, blankBaseUrl, keyNeeded, type AiEndpoint } from './aiKeyTarget';

// A saved key is only sent to the provider and base URL it was saved for (the
// API answers 400 to a change of either without apiKey), so each form asks for
// the key again when an edit changes where its key would go, unless it goes
// back to where the key was saved for (keySavedFor).
const NEW_KEY_PLACEHOLDER = 'API key for the new provider or base URL';
const KEY_NEEDED_TEXT =
  'You changed the provider or base URL. The saved key is only sent to the provider and base URL it was ' +
  'saved for, so enter the key for this one.';
const OLLAMA_REMOVES_KEY_TEXT = 'Ollama uses no API key: saving removes the saved key.';
const INHERIT_REMOVES_KEY_TEXT =
  'This config has a key of its own saved; inheriting removes it, along with its own model and base URL.';
const MISMATCH_STATUS = 'Saved key not used: it was saved for another provider or base URL';
const PROVIDER_LABELS: Record<string, string> = { anthropic: 'Anthropic', openai: 'OpenAI', ollama: 'Ollama' };
const ENTER_KEY_WARNING = 'Enter the API key for the new provider or base URL, or choose to remove the saved key.';

type KeySource = 'stored' | 'env' | 'none';

function keyStatus(configured: boolean, source: KeySource, mismatch: boolean, savedFor: AiEndpoint | null): string {
  if (mismatch && savedFor) {
    // Say where, so the form can be pointed back there (that needs no key).
    const label = PROVIDER_LABELS[savedFor.provider] || savedFor.provider;
    return `Saved key not used: it was saved for ${savedFor.provider === 'anthropic' ? label : `${label} at ${savedFor.baseUrl}`}`;
  }
  if (mismatch) return MISMATCH_STATUS;
  if (!configured) return 'No API key configured';
  return source === 'env' ? 'Configured via environment variable' : 'Key configured';
}

function keyPlaceholder(source: KeySource, mismatch: boolean): string {
  if (mismatch) return 'paste your API key';
  if (source === 'stored') return '•••••••• (saved — leave blank to keep)';
  if (source === 'env') return 'set via environment variable';
  return 'paste your API key';
}

// AI builder settings
const aiLoading = ref(false);
const aiSaving = ref(false);
const aiConfigured = ref(false);
const aiKeySource = ref<KeySource>('none');
const aiKeySaved = ref(false);
const aiKeyMismatch = ref(false);
/** Where its saved key was saved for (keySavedFor); null when none can be read. */
const aiKeySavedFor = ref<AiEndpoint | null>(null);
/** The saved config: where its key goes now. The analyst inherits from it. */
const aiSaved = reactive<AiEndpoint>({ provider: 'anthropic', baseUrl: '' });
const aiForm = reactive({ provider: 'anthropic', model: '', baseUrl: '', apiKey: '', removeKey: false });

const aiModelPlaceholder = computed(() =>
  ({ anthropic: 'claude-sonnet-4-6', openai: 'gpt-4o', ollama: 'llama3.1' } as Record<string, string>)[aiForm.provider] || ''
);
const aiKeyPlaceholder = computed(() => keyPlaceholder(aiKeySource.value, aiKeyMismatch.value));
const aiKeyStatus = computed(() =>
  keyStatus(aiConfigured.value, aiKeySource.value, aiKeyMismatch.value, aiKeySavedFor.value)
);
const aiKeyStatusType = computed(() => (aiConfigured.value && !aiKeyMismatch.value ? 'success' : 'warning'));
/** The edit moves the saved key's provider or base URL, not back to its own: a new key (or removing it) is needed. */
const aiKeyNeeded = computed(() =>
  keyNeeded(aiForm, aiSaved, { keySaved: aiKeySaved.value, keySavedFor: aiKeySavedFor.value })
);

async function fetchAiSettings() {
  aiLoading.value = true;
  try {
    const { data } = await api.getAiSettings();
    aiForm.provider = data.provider || 'anthropic';
    aiForm.model = data.model || '';
    aiForm.baseUrl = data.baseUrl || '';
    aiForm.apiKey = '';
    aiForm.removeKey = false;
    aiSaved.provider = aiForm.provider;
    aiSaved.baseUrl = aiForm.baseUrl;
    aiConfigured.value = !!data.configured;
    aiKeySource.value = data.keySource || 'none';
    aiKeySaved.value = !!data.keySaved;
    aiKeyMismatch.value = !!data.keyMismatch;
    aiKeySavedFor.value = data.keySavedFor ?? null;
  } catch (error) {
    // non-admins / not configured — leave defaults
  } finally {
    aiLoading.value = false;
  }
}

async function saveAiSettings() {
  if (aiKeyNeeded.value && aiForm.provider !== 'ollama' && !aiForm.apiKey && !aiForm.removeKey) {
    ElMessage.warning(ENTER_KEY_WARNING);
    return;
  }
  aiSaving.value = true;
  try {
    const payload: any = { provider: aiForm.provider, model: aiForm.model, baseUrl: aiForm.baseUrl };
    if (aiKeyNeeded.value && (aiForm.provider === 'ollama' || aiForm.removeKey)) payload.apiKey = '';
    else if (aiForm.apiKey) payload.apiKey = aiForm.apiKey; // only send when changing
    await api.updateAiSettings(payload);
    ElMessage.success('AI settings saved');
    await fetchAiSettings();
    // The analyst and triage inherit from here: refresh what they report, not their forms.
    await fetchChatSettings(false);
    await fetchTriageSettings(false);
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
const chatKeySource = ref<KeySource>('none');
const chatKeySaved = ref(false);
const chatKeyMismatch = ref(false);
const chatKeySavedFor = ref<AiEndpoint | null>(null);
const chatInheritsFrom = ref<'chat' | 'main'>('main');
/** Where the analyst sends requests now (inherited or its own). Triage inherits from it. */
const chatSaved = reactive<AiEndpoint>({ provider: '', baseUrl: '' });
const chatForm = reactive({ provider: '', model: '', baseUrl: '', apiKey: '', removeKey: false });

const chatModelPlaceholder = computed(() =>
  ({ anthropic: 'claude-sonnet-4-6', openai: 'gpt-4o', ollama: 'llama3.1' } as Record<string, string>)[
    chatForm.provider
  ] || 'inherits main config'
);
const chatKeyPlaceholder = computed(() => keyPlaceholder(chatKeySource.value, chatKeyMismatch.value));
const chatKeyStatus = computed(() =>
  keyStatus(chatConfigured.value, chatKeySource.value, chatKeyMismatch.value, chatKeySavedFor.value)
);
const chatKeyStatusType = computed(() => (chatConfigured.value && !chatKeyMismatch.value ? 'success' : 'warning'));
const chatKeyNeeded = computed(() =>
  keyNeeded(chatForm, chatSaved, { keySaved: chatKeySaved.value, keySavedFor: chatKeySavedFor.value }, aiSaved)
);

/**
 * Load the analyst config; `resetForm` false keeps the form's edits and refreshes only what it reports.
 * The form holds the analyst's own base URL setting (ownBaseUrl), not the one it resolves to: a blank
 * one stays blank and keeps following the AI Builder, and an untouched form still points where the
 * analyst does after the AI Builder moves (keyNeeded resolves it against aiSaved).
 */
async function fetchChatSettings(resetForm = true) {
  chatLoading.value = true;
  try {
    const { data } = await api.getChatAiSettings();
    chatInheritsFrom.value = data.inheritsFrom || 'main';
    if (resetForm) {
      const own = data.inheritsFrom === 'chat';
      chatForm.provider = own ? data.provider || '' : '';
      chatForm.model = own ? data.model || '' : '';
      chatForm.baseUrl = own ? data.ownBaseUrl || '' : '';
      chatForm.apiKey = '';
      chatForm.removeKey = false;
    }
    chatSaved.provider = data.provider || '';
    chatSaved.baseUrl = data.baseUrl || '';
    chatConfigured.value = !!data.configured;
    chatKeySource.value = data.keySource || 'none';
    chatKeySaved.value = !!data.keySaved;
    chatKeyMismatch.value = !!data.keyMismatch;
    chatKeySavedFor.value = data.keySavedFor ?? null;
  } catch (error) {
    // non-admins / not configured — leave defaults
  } finally {
    chatLoading.value = false;
  }
}

async function saveChatSettings() {
  const own = !!chatForm.provider;
  if (own && chatKeyNeeded.value && chatForm.provider !== 'ollama' && !chatForm.apiKey && !chatForm.removeKey) {
    ElMessage.warning(ENTER_KEY_WARNING);
    return;
  }
  chatSaving.value = true;
  try {
    const payload: any = { provider: chatForm.provider };
    if (own) {
      payload.model = chatForm.model;
      payload.baseUrl = chatForm.baseUrl;
      if (chatKeyNeeded.value && (chatForm.provider === 'ollama' || chatForm.removeKey)) payload.apiKey = '';
      else if (chatForm.apiKey) payload.apiKey = chatForm.apiKey; // only send when changing
    } else {
      // Inherit everything: drop this config's own model, base URL and key.
      payload.model = '';
      payload.baseUrl = '';
      if (chatKeySaved.value) payload.apiKey = '';
    }
    await api.updateChatAiSettings(payload);
    ElMessage.success('AI Analyst settings saved');
    await fetchChatSettings();
    await fetchTriageSettings(false);
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
const triageKeySource = ref<KeySource>('none');
const triageKeySaved = ref(false);
const triageKeyMismatch = ref(false);
const triageKeySavedFor = ref<AiEndpoint | null>(null);
const triageInheritsFrom = ref<'triage' | 'chat'>('chat');
const triageSaved = reactive<AiEndpoint>({ provider: '', baseUrl: '' });
const triageForm = reactive({
  provider: '',
  model: '',
  baseUrl: '',
  apiKey: '',
  removeKey: false,
  enabled: false,
  minSeverity: 'medium',
  dailyCap: 200,
  maxConcurrent: 2,
});

const triageModelPlaceholder = computed(() =>
  ({ anthropic: 'claude-sonnet-4-6', openai: 'gpt-4o', ollama: 'llama3.1' } as Record<string, string>)[
    triageForm.provider
  ] || 'inherits AI Analyst config'
);
const triageKeyPlaceholder = computed(() => keyPlaceholder(triageKeySource.value, triageKeyMismatch.value));
const triageKeyStatus = computed(() =>
  keyStatus(triageConfigured.value, triageKeySource.value, triageKeyMismatch.value, triageKeySavedFor.value)
);
const triageKeyStatusType = computed(() =>
  triageConfigured.value && !triageKeyMismatch.value ? 'success' : 'warning'
);
const triageKeyNeeded = computed(() =>
  keyNeeded(
    triageForm,
    triageSaved,
    { keySaved: triageKeySaved.value, keySavedFor: triageKeySavedFor.value },
    chatSaved
  )
);

/**
 * Load the triage config; `resetForm` false keeps the form's edits and refreshes only what it reports.
 * As for the analyst, the form holds triage's own base URL setting (ownBaseUrl), resolved against chatSaved.
 */
async function fetchTriageSettings(resetForm = true) {
  triageLoading.value = true;
  try {
    const { data } = await api.getTriageAiSettings();
    triageInheritsFrom.value = data.inheritsFrom || 'chat';
    if (resetForm) {
      const own = data.inheritsFrom === 'triage';
      triageForm.provider = own ? data.provider || '' : '';
      triageForm.model = own ? data.model || '' : '';
      triageForm.baseUrl = own ? data.ownBaseUrl || '' : '';
      triageForm.apiKey = '';
      triageForm.removeKey = false;
      triageForm.enabled = !!data.enabled;
      triageForm.minSeverity = data.minSeverity || 'medium';
      triageForm.dailyCap = data.dailyCap ?? 200;
      triageForm.maxConcurrent = data.maxConcurrent ?? 2;
    }
    triageSaved.provider = data.provider || '';
    triageSaved.baseUrl = data.baseUrl || '';
    triageConfigured.value = !!data.configured;
    triageKeySource.value = data.keySource || 'none';
    triageKeySaved.value = !!data.keySaved;
    triageKeyMismatch.value = !!data.keyMismatch;
    triageKeySavedFor.value = data.keySavedFor ?? null;
  } catch (error) {
    // non-admins — leave defaults
  } finally {
    triageLoading.value = false;
  }
}

async function saveTriageSettings() {
  const own = !!triageForm.provider;
  if (own && triageKeyNeeded.value && triageForm.provider !== 'ollama' && !triageForm.apiKey && !triageForm.removeKey) {
    ElMessage.warning(ENTER_KEY_WARNING);
    return;
  }
  triageSaving.value = true;
  try {
    const payload: any = {
      provider: triageForm.provider,
      enabled: triageForm.enabled,
      minSeverity: triageForm.minSeverity,
      dailyCap: triageForm.dailyCap,
      maxConcurrent: triageForm.maxConcurrent,
      // Lookups and time budget are saved with the AI budgets card (PUT /settings/ai-budgets).
    };
    if (own) {
      payload.model = triageForm.model;
      payload.baseUrl = triageForm.baseUrl;
      if (triageKeyNeeded.value && (triageForm.provider === 'ollama' || triageForm.removeKey)) payload.apiKey = '';
      else if (triageForm.apiKey) payload.apiKey = triageForm.apiKey; // only send when changing
    } else {
      // Inherit everything: drop this config's own model, base URL and key.
      payload.model = '';
      payload.baseUrl = '';
      if (triageKeySaved.value) payload.apiKey = '';
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

// AI budgets — output lengths, data lookups and time budgets per feature
// (GET/PUT /settings/ai-budgets). The server validates every value against the
// bounds it reports; the inputs use the same bounds.
type BudgetSection = 'analyst' | 'triage' | 'builder' | 'explain';
interface Bound {
  min: number;
  max: number;
  default: number;
}
const BUDGET_DEFAULTS = {
  analyst: { answerMaxTokens: 4000, stepMaxTokens: 1500, maxToolCalls: 10, wallBudgetSeconds: 180 },
  triage: { answerMaxTokens: 3000, stepMaxTokens: 1500, maxToolCalls: 6, wallBudgetSeconds: 110 },
  builder: { maxTokens: 8000 },
  explain: { maxTokens: 3000 },
};
const budgetLoading = ref(false);
const budgetSaving = ref(false);
const budgetForm = reactive(JSON.parse(JSON.stringify(BUDGET_DEFAULTS)) as typeof BUDGET_DEFAULTS);
const budgetBounds = ref<Record<string, Record<string, Bound>>>({});

function boundOf(section: BudgetSection, field: string): Bound {
  const b = budgetBounds.value[section]?.[field];
  if (b) return b;
  const def = (BUDGET_DEFAULTS[section] as Record<string, number>)[field];
  return /Tokens$/.test(field) ? { min: 256, max: 32000, default: def } : { min: 1, max: 1000, default: def };
}
function numInput(section: BudgetSection, field: string, step: number) {
  const b = boundOf(section, field);
  return { min: b.min, max: b.max, step, precision: 0, style: 'width: 160px' };
}
function tokenInput(section: BudgetSection, field: string) {
  return numInput(section, field, 250);
}
function defaultHint(section: BudgetSection, field: string): string {
  const b = boundOf(section, field);
  return `(${b.min}–${b.max}, default ${b.default})`;
}

function applyBudgets(data: any) {
  if (data?.bounds) budgetBounds.value = data.bounds;
  for (const section of Object.keys(BUDGET_DEFAULTS) as BudgetSection[]) {
    Object.assign(budgetForm[section], data?.budgets?.[section] ?? {});
  }
}

async function fetchBudgets() {
  budgetLoading.value = true;
  try {
    const { data } = await api.getAiBudgets();
    applyBudgets(data);
  } catch (error) {
    // non-admins — leave defaults
  } finally {
    budgetLoading.value = false;
  }
}

async function saveBudgets() {
  budgetSaving.value = true;
  try {
    const { data } = await api.updateAiBudgets(JSON.parse(JSON.stringify(budgetForm)));
    applyBudgets(data);
    ElMessage.success('AI budgets saved');
  } catch (error: any) {
    ElMessage.error(error.response?.data?.message || 'Failed to save AI budgets');
  } finally {
    budgetSaving.value = false;
  }
}

/** Put the defaults in the form (saved with Save AI Budgets). */
function restoreBudgetDefaults() {
  for (const section of Object.keys(BUDGET_DEFAULTS) as BudgetSection[]) {
    for (const field of Object.keys(budgetForm[section])) {
      (budgetForm[section] as Record<string, number>)[field] = boundOf(section, field).default;
    }
  }
}

onMounted(() => {
  fetchAiSettings();
  fetchChatSettings();
  fetchTriageSettings();
  fetchBudgets();
});
</script>

<style scoped>
.budget-intro {
  margin: 0 0 8px;
  line-height: 1.5;
}
.budget-hint {
  margin-left: 10px;
}
.key-needed {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
  gap: 2px;
  width: 100%;
  margin-top: 6px;
  line-height: 1.4;
}
</style>
