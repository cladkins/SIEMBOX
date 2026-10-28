<template>
  <el-dialog
    :model-value="modelValue"
    :title="title"
    width="980px"
    top="4vh"
    class="signature-editor"
    destroy-on-close
    @update:model-value="emit('update:modelValue', $event)"
    @closed="reset"
  >
    <el-alert v-if="origin === 'catalog'" type="info" :closable="false" show-icon class="block" data-test="override-note"
      title="A catalog signature. Saving makes a local copy with the same id that overrides the catalog's here." />
    <el-alert v-else-if="origin === 'override'" type="warning" :closable="false" show-icon class="block"
      title="This local signature overrides the catalog's signature with the same id." />

    <div class="toolbar">
      <el-radio-group v-model="mode" size="small" @change="switchMode">
        <el-radio-button value="form">Form</el-radio-button>
        <el-radio-button value="yaml">YAML</el-radio-button>
      </el-radio-group>
      <div class="toolbar-right">
        <el-tooltip v-if="canAi" :content="aiAvailable ? 'Ask the AI Builder model to draft the signature from the selected values' : 'No AI provider is configured (Settings -> AI)'" placement="top">
          <span>
            <el-button size="small" :disabled="!aiAvailable || !gapItems.length" :loading="drafting" data-test="ai-draft" @click="aiDraft">
              <el-icon><MagicStick /></el-icon> Draft with AI
            </el-button>
          </span>
        </el-tooltip>
        <el-button size="small" :loading="testing" data-test="test-evidence" @click="runTest">
          <el-icon><Search /></el-icon> Test against my evidence
        </el-button>
      </div>
    </div>
    <el-input v-if="canAi && aiAvailable && gapItems.length" v-model="aiHints" size="small" class="block" placeholder="Hints for the AI draft (optional): what the software is, its vendor..." />

    <div class="editor-body">
      <div class="editor-main">
        <el-form v-if="mode === 'form'" label-position="top" size="small" class="sig-form">
          <div class="row">
            <el-form-item label="Name" class="grow">
              <el-input v-model="form.name" placeholder="Plex Media Server" @input="nameChanged" />
            </el-form-item>
            <el-form-item label="Id (file name)" class="grow">
              <el-input v-model="form.id" :disabled="!!lockedId" placeholder="plex" @input="idTouched = true" />
            </el-form-item>
          </div>
          <div class="row">
            <el-form-item label="Vendor" class="grow"><el-input v-model="form.vendor" placeholder="Plex" /></el-form-item>
            <el-form-item label="Category" class="grow">
              <el-select v-model="form.category" placeholder="Choose" filterable @change="changed">
                <el-option v-for="c in APP_CATEGORIES" :key="c" :label="categoryLabel(c)" :value="c" />
              </el-select>
            </el-form-item>
          </div>
          <el-form-item label="Description"><el-input v-model="form.description" placeholder="What it is, in one sentence." /></el-form-item>
          <div class="row">
            <el-form-item label="Website" class="grow"><el-input v-model="form.website" placeholder="https://..." /></el-form-item>
            <el-form-item label="CPE vendor (optional)"><el-input v-model="form.cpeVendor" placeholder="plex" /></el-form-item>
            <el-form-item label="CPE product"><el-input v-model="form.cpeProduct" placeholder="media_server" /></el-form-item>
          </div>

          <h4 class="section">Matchers <span class="muted">(one per line)</span></h4>
          <div class="matchers">
            <el-form-item v-for="m in LIST_MATCHERS" :key="m.key" :label="MATCH_KIND_LABELS[m.kind].label + (m.suffix ?? '')">
              <template #label>
                <span>{{ MATCH_KIND_LABELS[m.kind].label }}{{ m.suffix ?? '' }}</span>
                <el-tooltip :content="m.hint ?? MATCH_KIND_LABELS[m.kind].hint" placement="top"><el-icon class="hint"><InfoFilled /></el-icon></el-tooltip>
              </template>
              <el-input
                type="textarea"
                :autosize="{ minRows: 1, maxRows: 6 }"
                :model-value="listToLines(form[m.key] as string[])"
                :placeholder="m.placeholder"
                :class="{ mono: m.regex }"
                @update:model-value="(v: string) => setList(m.key, v)"
              />
            </el-form-item>
            <el-form-item label="Endpoint OS">
              <div class="row tight">
                <el-select v-model="form.osFamily" clearable placeholder="family" class="os-family" @change="changed">
                  <el-option v-for="f in ['linux', 'windows', 'darwin', 'freebsd']" :key="f" :label="f" :value="f" />
                </el-select>
                <el-input v-model="form.osPrettyName" class="mono grow" :disabled="!form.osFamily" placeholder="^Ubuntu (\d+\.\d+)" />
              </div>
            </el-form-item>
          </div>

          <h4 class="section">
            Tests
            <span v-if="missingTests.length" class="muted warn-text">— add a matching test for: {{ missingTests.map((k) => MATCH_KIND_LABELS[k].label).join(', ') }}</span>
          </h4>
          <div v-for="(t, i) in form.tests" :key="i" class="test-row">
            <el-select v-model="t.source" class="t-source" @change="changed">
              <el-option v-for="k in MATCH_KINDS" :key="k" :label="MATCH_KIND_LABELS[k].label" :value="k" />
            </el-select>
            <template v-if="t.source === 'service'">
              <el-input v-model="t.name" placeholder="service name" class="t-small" />
              <el-input v-model="t.serviceVersion" placeholder="nmap version string" class="grow" />
              <el-input v-model="t.banner" placeholder="banner" class="t-small" />
            </template>
            <template v-else-if="t.source === 'os'">
              <el-select v-model="t.family" class="t-small" @change="changed">
                <el-option v-for="f in ['linux', 'windows', 'darwin', 'freebsd']" :key="f" :label="f" :value="f" />
              </el-select>
              <el-input v-model="t.prettyName" placeholder="Ubuntu 22.04.4 LTS" class="grow" />
            </template>
            <el-input v-else v-model="t.input" placeholder="a real value from your evidence" class="grow" />
            <el-input v-model="t.version" placeholder="version" class="t-version" title="Expected version; 'none' = none; empty = not checked" />
            <el-tooltip :content="t.shouldMatch ? 'Must match' : 'Must NOT match'" placement="top">
              <el-switch v-model="t.shouldMatch" inline-prompt active-text="match" inactive-text="not" @change="changed" />
            </el-tooltip>
            <el-button :icon="Delete" circle size="small" text @click="removeTest(i)" />
          </div>
          <el-button size="small" text type="primary" @click="addTest"><el-icon><Plus /></el-icon> Add test</el-button>
        </el-form>

        <div v-else>
          <el-input v-model="yamlText" type="textarea" :rows="26" class="mono yaml-input" data-test="yaml" @input="changed" />
          <div v-if="yamlError" class="err-text">YAML: {{ yamlError }}</div>
        </div>
      </div>

      <div class="editor-side">
        <h4 class="section">Checks</h4>
        <div v-if="checking" class="muted">Checking…</div>
        <template v-else-if="check">
          <el-tag :type="check.ok ? (check.ready ? 'success' : 'warning') : 'danger'" size="small" data-test="check-state">
            {{ check.ok ? (check.ready ? 'Valid · ready to contribute' : 'Valid · can be saved') : 'Not valid yet' }}
          </el-tag>
          <div v-if="check.tests.total" class="muted small">Tests: {{ check.tests.total - check.tests.failures.length }}/{{ check.tests.total }} pass</div>
          <div v-if="check.catalog?.exists" class="muted small">
            The catalog has <code>{{ check.signature?.id }}</code>
            <el-tag size="small" :type="CATALOG_STATUS[check.catalog.status as CatalogStatus]?.type ?? 'info'">{{ CATALOG_STATUS[check.catalog.status as CatalogStatus]?.label }}</el-tag>
          </div>
          <ul v-if="check.errors.length" class="issues error" data-test="errors">
            <li v-for="(e, i) in check.errors" :key="'e' + i">{{ e }}</li>
          </ul>
          <template v-if="check.contribute_errors.length">
            <div class="muted small">Needed before contributing:</div>
            <ul class="issues warn"><li v-for="(e, i) in check.contribute_errors" :key="'c' + i">{{ e }}</li></ul>
          </template>
          <ul v-if="check.warnings.length" class="issues info"><li v-for="(w, i) in check.warnings" :key="'w' + i">{{ w }}</li></ul>
        </template>
        <div v-else class="muted small">Edit the signature: it is checked with the validator the catalog's CI runs.</div>

        <template v-if="testResult">
          <h4 class="section">In your evidence now</h4>
          <div class="small" data-test="test-summary">
            <strong>{{ testResult.total }}</strong> match(es) at {{ testResult.locations }} location(s)
            <template v-if="testResult.versions.length"> · versions {{ testResult.versions.slice(0, 6).join(', ') }}</template>
            <div v-if="testResult.resolves_unmatched" class="muted">{{ testResult.resolves_unmatched }} would leave the Not identified list</div>
          </div>
          <div class="muted small hits-intro">Saving this signature identifies:</div>
          <el-table :data="testResult.hits.slice(0, 50)" size="small" max-height="320" empty-text="Nothing in the current evidence matches" class="hits" table-layout="auto">
            <el-table-column label="Evidence">
              <template #default="{ row }">
                <div class="muted">{{ hitKind(row.kind) }}<template v-if="row.version"> · v{{ row.version }}</template></div>
                <code class="wrap">{{ row.value }}</code>
                <div class="muted small wrap">{{ row.location_label ?? row.location ?? '—' }}</div>
              </template>
            </el-table-column>
            <el-table-column label="Today" width="118">
              <template #default="{ row }">
                <el-tooltip v-if="row.identified_as.length" :content="`Also identified as ${row.identified_as.join(', ')}`" placement="top">
                  <el-tag size="small" type="info" class="now-tag">also {{ row.identified_as[0] }}</el-tag>
                </el-tooltip>
                <el-tag v-else size="small" type="success" class="now-tag">newly identified</el-tag>
              </template>
            </el-table-column>
          </el-table>
        </template>
      </div>
    </div>

    <template #footer>
      <span class="muted small footer-note">Saved signatures apply on the next inventory run (started at once), including evidence already collected.</span>
      <el-button @click="emit('update:modelValue', false)">Cancel</el-button>
      <el-button type="primary" :loading="saving" :disabled="!check?.ok" data-test="save" @click="save">{{ editingId ? 'Save changes' : 'Save signature' }}</el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
import { computed, ref, watch } from 'vue';
import { ElMessage } from 'element-plus';
import { Delete, InfoFilled, MagicStick, Plus, Search } from '@element-plus/icons-vue';
import { api } from '@/services/api';
import { categoryLabel } from '@/utils/applications';
import {
  APP_CATEGORIES,
  CATALOG_STATUS,
  MATCH_KINDS,
  MATCH_KIND_LABELS,
  docToForm,
  docToYaml,
  emptyForm,
  emptyTest,
  formToDoc,
  idFromName,
  kindsWithoutTests,
  linesToList,
  listToLines,
  unmatchedKindLabel,
  yamlToDoc,
  type CatalogStatus,
  type MatchKind,
  type SignatureForm,
} from '@/utils/applicationSignatures';

export interface GapItem {
  source: string;
  value: string;
  sample?: string | null;
  detail?: Record<string, unknown> | null;
}

const props = defineProps<{
  modelValue: boolean;
  /** A document to start from (a draft, a catalog signature, a saved one). */
  initialDoc?: Record<string, unknown> | null;
  /** The saved text, when editing (kept as written). */
  initialYaml?: string | null;
  /** Editing this local signature (PUT) instead of creating one. */
  editingId?: string | null;
  origin?: 'local' | 'override' | 'catalog' | null;
  /** The Not identified values it was opened from (for the AI draft). */
  gapItems?: GapItem[];
  canAi?: boolean;
  aiAvailable?: boolean;
}>();
const emit = defineEmits<{ (e: 'update:modelValue', v: boolean): void; (e: 'saved', id: string): void }>();

type ListKey = 'syslog_program' | 'parser' | 'serviceNames' | 'serviceBanner' | 'container_image' | 'package' | 'user_agent' | 'dns';
const LIST_MATCHERS: Array<{ key: ListKey; kind: MatchKind; suffix?: string; hint?: string; placeholder: string; regex?: boolean }> = [
  { key: 'syslog_program', kind: 'syslog_program', placeholder: 'plexmediaserver' },
  { key: 'package', kind: 'package', placeholder: 'plexmediaserver' },
  { key: 'container_image', kind: 'container_image', placeholder: 'plexinc/pms-docker\n*/linuxserver/plex' },
  { key: 'serviceNames', kind: 'service', suffix: ' names', hint: 'nmap service names, exact.', placeholder: 'plexmediaserver' },
  { key: 'serviceBanner', kind: 'service', suffix: ' banner regex', hint: "Regexes on nmap's product/version or the banner; group 1 = version.", placeholder: '^Plex Media Server (\\d[\\w.-]*)', regex: true },
  { key: 'user_agent', kind: 'user_agent', suffix: ' regex', placeholder: '^PlexMediaServer/(\\d+(?:\\.\\d+)+)', regex: true },
  { key: 'dns', kind: 'dns', placeholder: 'plex.tv\n*.plex.direct' },
  { key: 'parser', kind: 'parser', placeholder: 'plex' },
];

const mode = ref<'form' | 'yaml'>('form');
const form = ref<SignatureForm>(emptyForm());
const yamlText = ref('');
const yamlError = ref<string | null>(null);
const idTouched = ref(false);
const check = ref<any>(null);
const checking = ref(false);
const testing = ref(false);
const testResult = ref<any>(null);
const saving = ref(false);
const drafting = ref(false);
const aiHints = ref('');
let timer: ReturnType<typeof setTimeout> | null = null;
let seq = 0;
const lockedId = computed(() => props.editingId ?? (props.origin === 'catalog' ? String(props.initialDoc?.id ?? '') : null));
const gapItems = computed(() => props.gapItems ?? []);
const missingTests = computed(() => kindsWithoutTests(form.value));
const title = computed(() => (props.editingId ? `Edit signature: ${props.editingId}` : props.origin === 'catalog' ? 'Override a catalog signature' : 'New application signature'));

function load(doc: Record<string, unknown> | null | undefined, text?: string | null) {
  form.value = docToForm(doc ?? {});
  yamlText.value = text ?? docToYaml(formToDoc(form.value));
  yamlError.value = null;
  idTouched.value = !!form.value.id && !!props.editingId;
  check.value = null;
  testResult.value = null;
  scheduleCheck(0);
}

watch(
  () => props.modelValue,
  (open) => {
    if (open) {
      mode.value = 'form';
      load(props.initialDoc, props.initialYaml);
    }
  },
  { immediate: true }
);

function reset() {
  check.value = null;
  testResult.value = null;
  aiHints.value = '';
}

/** The YAML the server checks and saves: the text in YAML mode, the form's document otherwise. */
function currentYaml(): string {
  return mode.value === 'yaml' ? yamlText.value : docToYaml(formToDoc(form.value));
}

function switchMode(next: string | number | boolean | undefined) {
  if (next === 'yaml') {
    yamlText.value = docToYaml(formToDoc(form.value));
  } else {
    const { doc, error } = yamlToDoc(yamlText.value);
    if (error) {
      ElMessage.warning(`Fix the YAML first: ${error}`);
      mode.value = 'yaml';
      return;
    }
    form.value = docToForm(doc);
  }
  scheduleCheck(0);
}

function setList(key: ListKey, text: string) {
  form.value[key] = linesToList(text);
  changed();
}

function nameChanged() {
  if (!idTouched.value && !lockedId.value) form.value.id = idFromName(form.value.name);
  changed();
}

function addTest() {
  form.value.tests.push(emptyTest(missingTests.value[0] ?? 'syslog_program'));
  changed();
}
function removeTest(i: number) {
  form.value.tests.splice(i, 1);
  changed();
}

// Any edit in the form is checked again (debounced).
watch(
  form,
  () => {
    if (mode.value === 'form') scheduleCheck(600);
  },
  { deep: true }
);

function changed() {
  if (mode.value === 'yaml') yamlError.value = yamlToDoc(yamlText.value).error;
  scheduleCheck(600);
}
function scheduleCheck(ms: number) {
  if (timer) clearTimeout(timer);
  timer = setTimeout(runCheck, ms);
}

async function runCheck() {
  const text = currentYaml();
  if (mode.value === 'yaml' && yamlToDoc(text).error) return;
  const mine = ++seq;
  checking.value = true;
  try {
    const { data } = await api.validateApplicationSignature(text, props.editingId ?? undefined);
    if (mine === seq) check.value = data;
  } catch (err: any) {
    if (mine === seq) check.value = { ok: false, ready: false, errors: [err?.response?.data?.message ?? 'Could not check the signature'], warnings: [], contribute_errors: [], tests: { total: 0, failures: [] } };
  } finally {
    if (mine === seq) checking.value = false;
  }
}

async function runTest() {
  testing.value = true;
  try {
    const { data } = await api.testApplicationSignature(currentYaml());
    testResult.value = data.result;
    check.value = { ...data.check, catalog: check.value?.catalog };
  } catch (err: any) {
    const d = err?.response?.data;
    if (d?.errors) check.value = { ...d, catalog: check.value?.catalog };
    ElMessage.warning(d?.message ?? 'Could not test the signature');
  } finally {
    testing.value = false;
  }
}

async function aiDraft() {
  drafting.value = true;
  try {
    const { data } = await api.draftApplicationSignatureAI(gapItems.value, aiHints.value || undefined);
    if (!data.signature) {
      ElMessage.warning(data.error ?? 'The AI returned no signature');
      return;
    }
    const keepId = lockedId.value;
    load(data.signature);
    if (keepId) form.value.id = keepId;
    yamlText.value = docToYaml(formToDoc(form.value));
    if (data.ok) ElMessage.success(`Drafted in ${data.attempts} attempt(s): review it, then Test and Save.`);
    else ElMessage.warning(`The draft still has problems after ${data.attempts} attempt(s): see Checks.`);
  } catch (err: any) {
    ElMessage.error(err?.response?.data?.message ?? 'AI draft failed');
  } finally {
    drafting.value = false;
  }
}

async function save() {
  saving.value = true;
  try {
    const text = currentYaml();
    const { data } = props.editingId ? await api.updateApplicationSignature(props.editingId, { yaml: text }) : await api.createApplicationSignature(text);
    ElMessage.success('Signature saved: the inventory is being updated, including evidence already collected.');
    emit('saved', data.signature.id);
    emit('update:modelValue', false);
  } catch (err: any) {
    const d = err?.response?.data;
    if (d?.errors) check.value = { ...d, catalog: check.value?.catalog };
    ElMessage.error(d?.message ?? 'Could not save the signature');
  } finally {
    saving.value = false;
  }
}

function hitKind(kind: string): string {
  return MATCH_KIND_LABELS[kind as MatchKind]?.label ?? unmatchedKindLabel(kind);
}
</script>

<style scoped>
.hits-intro {
  margin: 6px 0 4px;
}
.hits :deep(.wrap) {
  white-space: normal;
  overflow-wrap: anywhere;
  word-break: break-word;
}
.now-tag {
  max-width: 100%;
  overflow: hidden;
  text-overflow: ellipsis;
}
.block {
  margin-bottom: 10px;
}
.toolbar {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 10px;
  gap: 8px;
  flex-wrap: wrap;
}
.toolbar-right {
  display: flex;
  gap: 8px;
}
.editor-body {
  display: grid;
  grid-template-columns: minmax(0, 3fr) minmax(0, 2fr);
  gap: 16px;
}
@media (max-width: 900px) {
  .editor-body {
    grid-template-columns: 1fr;
  }
}
.editor-main {
  max-height: 68vh;
  overflow-y: auto;
  padding-right: 6px;
}
.editor-side {
  max-height: 68vh;
  overflow-y: auto;
  border-left: 1px solid var(--el-border-color-lighter);
  padding-left: 12px;
}
.row {
  display: flex;
  gap: 10px;
  flex-wrap: wrap;
}
.row.tight {
  width: 100%;
  flex-wrap: nowrap;
}
.grow {
  flex: 1 1 200px;
}
.os-family {
  width: 120px;
}
.section {
  margin: 12px 0 6px;
  font-size: 13px;
}
.matchers {
  display: grid;
  grid-template-columns: 1fr 1fr;
  column-gap: 10px;
}
.hint {
  margin-left: 4px;
  vertical-align: middle;
  color: var(--el-text-color-secondary);
}
.test-row {
  display: flex;
  gap: 6px;
  align-items: center;
  margin-bottom: 6px;
}
.t-source {
  width: 140px;
  flex: none;
}
.t-small {
  width: 120px;
  flex: none;
}
.t-version {
  width: 90px;
  flex: none;
}
.mono :deep(textarea),
.mono :deep(input) {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px;
}
.yaml-input :deep(textarea) {
  font-family: ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size: 12px;
}
.muted {
  color: var(--el-text-color-secondary);
}
.small {
  font-size: 12px;
  margin: 6px 0;
}
.warn-text {
  color: var(--el-color-warning);
  font-weight: normal;
}
.err-text {
  color: var(--el-color-danger);
  font-size: 12px;
  margin-top: 4px;
}
.issues {
  margin: 6px 0;
  padding-left: 18px;
  font-size: 12px;
  word-break: break-word;
}
.issues.error {
  color: var(--el-color-danger);
}
.issues.warn {
  color: var(--el-color-warning);
}
.issues.info {
  color: var(--el-text-color-secondary);
}
.wrap {
  word-break: break-all;
  font-size: 11px;
}
.footer-note {
  float: left;
  margin-top: 8px;
}
</style>
