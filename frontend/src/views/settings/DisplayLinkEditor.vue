<template>
  <el-dialog
    :model-value="modelValue"
    :title="linkId === null ? 'New display link' : `Edit ${initial?.name ?? 'display link'}`"
    width="min(1400px, 96vw)"
    top="3vh"
    :close-on-click-modal="false"
    destroy-on-close
    class="display-link-editor"
    @update:model-value="emit('update:modelValue', $event)"
    @open="onOpened"
    @closed="onClosed"
  >
    <el-alert v-if="topError" type="error" :title="topError" show-icon :closable="false" class="block" />

    <div class="editor">
      <!-- Form -->
      <el-form label-position="top" class="editor-form" @submit.prevent>
        <h4>General</h4>
        <el-form-item label="Name" :error="errorFor('name')">
          <el-input v-model="name" maxlength="80" placeholder="NOC wall left" data-testid="link-name" />
        </el-form-item>

        <el-form-item label="Privacy" :error="errorFor('config.privacy')">
          <el-radio-group v-model="config.privacy" class="privacy">
            <el-radio value="operations" data-testid="privacy-operations">Operations room: rule names, shipper and host names, IPs</el-radio>
            <el-radio value="public" data-testid="privacy-public">Public area: counts only</el-radio>
          </el-radio-group>
          <div class="hint">Alert titles, usernames and email addresses are never shown on a display.</div>
        </el-form-item>
        <el-alert v-if="conflicts.length" type="warning" show-icon :closable="false" class="block" title="Not on a public-area display">
          <template #default>
            <div v-for="c in conflicts" :key="c">{{ c }}</div>
            <el-button size="small" class="mt" @click="removeConflicts">Remove them</el-button>
          </template>
        </el-alert>

        <el-form-item label="Expires" :error="errorFor('expires_at')">
          <el-select v-model="expiry" style="width: 180px">
            <el-option label="Never" value="never" />
            <el-option v-if="originalExpiry" :label="`Keep (${dayMonth(originalExpiry)})`" value="keep" />
            <el-option label="In 30 days" value="30" />
            <el-option label="In 90 days" value="90" />
            <el-option label="On a date" value="date" />
          </el-select>
          <el-date-picker v-if="expiry === 'date'" v-model="expiryDate" type="datetime" :disabled-date="isPast" class="ml" />
        </el-form-item>

        <el-form-item label="Allowed networks (optional)" :error="errorFor('allowed_cidrs')">
          <el-input
            v-model="cidrsText"
            type="textarea"
            :rows="2"
            placeholder="Any network. Or one per line: 10.20.0.0/16, 192.168.1.40"
            data-testid="link-cidrs"
          />
          <div class="hint">
            <template v-if="clientAddress">Your address as SIEMBox sees it: <code>{{ clientAddress }}</code>. </template>
            Screens outside these networks are refused.
          </div>
          <el-alert
            v-for="w in addressWarnings"
            :key="w"
            type="warning"
            :closable="false"
            show-icon
            class="mt"
            :title="w"
            description="If SIEMBox sees every client as one proxy address, a network list can't tell screens apart (DEPLOYMENT.md, 'Client addresses and reverse proxies')."
          />
        </el-form-item>

        <h4>Views</h4>
        <div class="row">
          <el-select v-model="presetChoice" placeholder="Start from a preset" style="width: 240px" @change="applyPreset">
            <el-option label="SOC overview, Threats, Health" value="default" />
            <el-option v-for="p in PRESETS" :key="p.key" :label="p.label" :value="p.key" />
          </el-select>
          <el-button :disabled="config.views.length >= MAX_VIEWS" @click="addView">Add view</el-button>
        </div>
        <div v-if="errorFor('config.views', true)" class="field-error">{{ errorFor('config.views', true) }}</div>

        <el-card v-for="(view, v) in config.views" :key="v" shadow="never" class="view-card">
          <div class="row">
            <el-input v-model="view.title" maxlength="40" placeholder="View title" class="view-title" />
            <el-button-group>
              <el-button size="small" :disabled="v === 0" aria-label="Move view up" @click="moveView(v, -1)">↑</el-button>
              <el-button size="small" :disabled="v === config.views.length - 1" aria-label="Move view down" @click="moveView(v, 1)">↓</el-button>
            </el-button-group>
            <el-button size="small" type="danger" plain :disabled="config.views.length <= 1" @click="config.views.splice(v, 1)">Remove</el-button>
          </div>
          <div v-if="errorFor(`config.views[${v}]`)" class="field-error">{{ errorFor(`config.views[${v}]`) }}</div>

          <div v-for="(panel, p) in view.panels" :key="p" class="panel-row">
            <el-select :model-value="panel.id" style="width: 210px" size="small" @update:model-value="setPanelKind(v, p, $event)">
              <el-option
                v-for="info in PANEL_CATALOGUE"
                :key="info.id"
                :label="info.label"
                :value="info.id"
                :disabled="config.privacy === 'public' && !info.publicAllowed"
              >
                <span>{{ info.label }}</span>
                <span v-if="config.privacy === 'public' && !info.publicAllowed" class="option-reason">{{ PUBLIC_REFUSED_REASON }}</span>
              </el-option>
            </el-select>
            <el-select
              v-if="panelInfo(panel.id).param"
              :model-value="paramValue(panel)"
              size="small"
              style="width: 150px"
              @update:model-value="setParam(v, p, $event)"
            >
              <el-option
                v-for="o in panelInfo(panel.id).param!.options"
                :key="o.value"
                :label="`${panelInfo(panel.id).param!.label}: ${o.label}`"
                :value="o.value"
              />
            </el-select>
            <el-button-group>
              <el-button size="small" :disabled="p === 0" aria-label="Move panel up" @click="movePanel(v, p, -1)">↑</el-button>
              <el-button size="small" :disabled="p === view.panels.length - 1" aria-label="Move panel down" @click="movePanel(v, p, 1)">↓</el-button>
            </el-button-group>
            <el-button size="small" link type="danger" @click="view.panels.splice(p, 1)">Remove</el-button>
            <div class="what">{{ panelInfo(panel.id).what }}</div>
          </div>
          <el-button size="small" :disabled="view.panels.length >= MAX_PANELS_PER_VIEW" class="mt" @click="addPanel(v)">Add panel</el-button>
        </el-card>

        <h4>Behaviour</h4>
        <div class="behaviour">
          <el-form-item label="Rotate views" :error="errorFor('config.rotation')">
            <el-switch v-model="config.rotation.enabled" :disabled="config.views.length <= 1" />
            <span class="ml">every</span>
            <el-input-number
              v-model="config.rotation.seconds"
              :min="ROTATION_SECONDS.min"
              :max="ROTATION_SECONDS.max"
              :disabled="!config.rotation.enabled || config.views.length <= 1"
              size="small"
              class="ml"
            />
            <span class="ml">s</span>
          </el-form-item>
          <el-form-item label="Refresh" :error="errorFor('config.refresh_seconds')">
            <el-select v-model="config.refresh_seconds" style="width: 110px">
              <el-option v-for="s in REFRESH_OPTIONS" :key="s" :label="`${s} s`" :value="s" />
            </el-select>
          </el-form-item>
          <el-form-item label="Time zone" :error="errorFor('config.timezone')">
            <el-select v-model="timezone" filterable style="width: 230px">
              <el-option label="The screen's own" value="" />
              <el-option v-for="z in zones" :key="z" :label="z" :value="z" />
            </el-select>
          </el-form-item>
          <el-form-item label="Clock">
            <el-switch v-model="config.clock" />
          </el-form-item>
          <el-form-item label="Burn-in protection">
            <el-switch v-model="config.burn_in_shift" />
          </el-form-item>
        </div>
      </el-form>

      <!-- Live preview -->
      <div class="editor-preview">
        <div class="preview-head">
          <h4>Preview</h4>
          <span v-if="preview.loading.value" class="hint">updating…</span>
        </div>
        <el-alert v-if="previewError" type="warning" :title="previewError" show-icon :closable="false" class="block" />
        <BoardPreview
          v-if="preview.snapshot.value"
          :snapshot="preview.snapshot.value"
          :status="preview.status.value"
          :view-index="preview.currentView.value"
        />
        <div v-else class="preview-empty">Loading the preview…</div>
        <div class="hint mt">The board as a screen with this layout shows it now, with this install's data. It rotates as the screen would.</div>
      </div>
    </div>

    <template #footer>
      <el-button @click="emit('update:modelValue', false)">Cancel</el-button>
      <el-button type="primary" :loading="saving" :disabled="conflicts.length > 0" data-testid="link-save" @click="save">
        {{ linkId === null ? 'Create link' : 'Save' }}
      </el-button>
    </template>
  </el-dialog>
</template>

<script setup lang="ts">
/**
 * Settings -> Display links: the editor for a new or saved link
 * (BIG-DISPLAY.md §8.3). The form is on the left and a live preview on the
 * right, built by POST /api/display-links/preview from the unsaved layout a
 * second after each change, and at the layout's refresh interval. 400s are
 * shown next to their field, 409s (the limit, a name in use) at the top.
 */
import { computed, nextTick, reactive, ref, watch } from 'vue';
import { api } from '@/services/api';
import { apiErrorMessage, apiErrorStatus } from '@/utils/exposure';
import BoardPreview from '@/components/BoardPreview.vue';
import { useBoardRunner } from '@/composables/useBoardRunner';
import {
  MAX_PANELS_PER_VIEW,
  MAX_VIEWS,
  PANEL_CATALOGUE,
  PRESETS,
  PUBLIC_REFUSED_REASON,
  REFRESH_OPTIONS,
  ROTATION_SECONDS,
  dayMonth,
  defaultConfig,
  expiresAtFor,
  moveItem,
  newPanel,
  panelInfo,
  parseCidrList,
  presetViews,
  publicConflicts,
  type DisplayConfig,
  type DisplayLinkDetail,
  type DisplayLinkSecret,
  type EditorInitial,
  type PanelId,
  type PanelSpec,
} from '@/utils/displayLinks';

const props = defineProps<{
  modelValue: boolean;
  /** null: a new link (created from `initial` when given, a duplicate). */
  linkId: number | null;
  initial: EditorInitial | null;
}>();
const emit = defineEmits<{
  'update:modelValue': [value: boolean];
  created: [secret: DisplayLinkSecret];
  updated: [link: DisplayLinkDetail];
}>();

const clone = <T,>(value: T): T => JSON.parse(JSON.stringify(value)) as T;

const name = ref('');
const config = reactive<DisplayConfig>(defaultConfig());
const timezone = ref('');
const expiry = ref<'never' | 'keep' | '30' | '90' | 'date'>('never');
const expiryDate = ref<Date | null>(null);
const originalExpiry = ref<string | null>(null);
const cidrsText = ref('');
const presetChoice = ref<string>('');
const saving = ref(false);
const topError = ref('');
const fieldError = ref<{ field: string; message: string } | null>(null);
const clientAddress = ref<string | null>(null);
const addressWarnings = ref<string[]>([]);

const zones: string[] = (() => {
  try {
    return (Intl as unknown as { supportedValuesOf: (k: string) => string[] }).supportedValuesOf('timeZone');
  } catch {
    return ['UTC'];
  }
})();

function fill() {
  const initial = props.initial;
  name.value = initial?.name ?? '';
  Object.assign(config, clone(initial?.config ?? defaultConfig()));
  timezone.value = config.timezone ?? '';
  originalExpiry.value = props.linkId !== null ? (initial?.expires_at ?? null) : null;
  expiry.value = originalExpiry.value ? 'keep' : 'never';
  expiryDate.value = null;
  cidrsText.value = (initial?.allowed_cidrs ?? []).join('\n');
  presetChoice.value = '';
  topError.value = '';
  fieldError.value = null;
}

/** The layout as the API takes it. */
function currentConfig(): DisplayConfig {
  return { ...clone(config), timezone: timezone.value || null };
}

const conflicts = computed(() => publicConflicts(config));

/** The 400's message when its field is `prefix` or inside it; `exact` leaves out deeper fields. */
function errorFor(prefix: string, exact = false): string {
  const e = fieldError.value;
  if (!e) return '';
  if (e.field === prefix) return e.message;
  if (exact) return '';
  return e.field.startsWith(`${prefix}.`) || e.field.startsWith(`${prefix}[`) ? e.message : '';
}

// --- Views and panels ----------------------------------------------------------

function applyPreset(key: string) {
  if (key === 'default') {
    const fresh = defaultConfig();
    config.views = fresh.views;
    config.privacy = 'operations';
  } else {
    const preset = presetViews(key);
    if (!preset) return;
    config.views = preset.views;
    config.privacy = preset.privacy;
  }
  presetChoice.value = '';
}

function addView() {
  config.views.push({ title: `View ${config.views.length + 1}`, panels: [newPanel('open_alerts')] });
}
function moveView(v: number, direction: -1 | 1) {
  config.views = moveItem(config.views, v, direction);
}
function addPanel(v: number) {
  const used = new Set(config.views[v].panels.map((p) => p.id));
  const kind = PANEL_CATALOGUE.find((p) => !used.has(p.id) && (config.privacy !== 'public' || p.publicAllowed)) ?? PANEL_CATALOGUE[0];
  config.views[v].panels.push(newPanel(kind.id));
}
function movePanel(v: number, p: number, direction: -1 | 1) {
  config.views[v].panels = moveItem(config.views[v].panels, p, direction);
}
function setPanelKind(v: number, p: number, id: PanelId) {
  config.views[v].panels[p] = newPanel(id);
}
function paramValue(panel: PanelSpec): string | number {
  const param = panelInfo(panel.id).param!;
  return (panel as unknown as Record<string, string | number>)[param.name] ?? param.default;
}
function setParam(v: number, p: number, value: string | number) {
  const panel = config.views[v].panels[p];
  const param = panelInfo(panel.id).param!;
  config.views[v].panels[p] = { ...panel, [param.name]: value } as PanelSpec;
}
function removeConflicts() {
  for (const view of config.views) view.panels = view.panels.filter((p) => panelInfo(p.id).publicAllowed);
}

const isPast = (date: Date) => date.getTime() < Date.now() - 86_400_000;

// --- Preview -------------------------------------------------------------------

const preview = useBoardRunner((signal) => api.previewDisplayLink(currentConfig(), signal).then((r) => r.data), { autoStart: false });
const previewError = computed(() => {
  const e = preview.error.value;
  if (!e) return '';
  return apiErrorStatus(e) === 400
    ? `The preview can't show this layout yet: ${apiErrorMessage(e, 'it is not valid')}`
    : apiErrorMessage(e, "Couldn't load the preview. It retries by itself.");
});

let debounce: ReturnType<typeof setTimeout> | null = null;
let open = false;
watch(
  [() => JSON.stringify(config), timezone],
  () => {
    if (!open) return;
    if (debounce) clearTimeout(debounce);
    debounce = setTimeout(() => void preview.refresh(), 1000);
  },
  { flush: 'post' }
);

async function onOpened() {
  fill();
  await nextTick(); // the watcher above sees fill() before `open`: the refresh below is the first
  open = true;
  preview.reset();
  void preview.refresh();
  try {
    const { data } = await api.getClientAddress();
    clientAddress.value = data?.you?.address ?? null;
    addressWarnings.value = Array.isArray(data?.warnings) ? data.warnings : [];
  } catch {
    clientAddress.value = null;
  }
}

function onClosed() {
  open = false;
  if (debounce) clearTimeout(debounce);
  preview.stop();
}

// --- Save ----------------------------------------------------------------------

async function save() {
  topError.value = '';
  fieldError.value = null;
  if (expiry.value === 'date' && !expiryDate.value) {
    fieldError.value = { field: 'expires_at', message: 'Pick a date, or choose Never.' };
    return;
  }
  const body = {
    name: name.value,
    config: currentConfig(),
    allowed_cidrs: parseCidrList(cidrsText.value),
  };
  const expiresAt = expiry.value === 'keep' ? undefined : expiresAtFor(expiry.value, expiryDate.value, Date.now());
  saving.value = true;
  try {
    if (props.linkId === null) {
      const { data } = await api.createDisplayLink({ ...body, expires_at: expiresAt ?? null });
      emit('created', data);
    } else {
      const { data } = await api.updateDisplayLink(props.linkId, expiresAt === undefined ? body : { ...body, expires_at: expiresAt });
      emit('updated', data.link);
    }
    emit('update:modelValue', false);
  } catch (error) {
    const status = apiErrorStatus(error);
    const data = (error as { response?: { data?: { field?: unknown } } }).response?.data;
    const message = apiErrorMessage(error, "Couldn't save the display link.");
    if (status === 400 && typeof data?.field === 'string') {
      const field = data.field.replace(/^allowed_cidrs\[\d+\]$/, 'allowed_cidrs');
      fieldError.value = { field, message };
      if (!['name', 'expires_at', 'allowed_cidrs'].includes(field) && !field.startsWith('config')) topError.value = message;
    } else {
      topError.value = message;
    }
  } finally {
    saving.value = false;
  }
}
</script>

<style scoped>
.editor {
  display: grid;
  grid-template-columns: minmax(380px, 5fr) minmax(320px, 6fr);
  gap: 24px;
  align-items: start;
}
@media (max-width: 1000px) {
  .editor {
    grid-template-columns: 1fr;
  }
}
.editor-form {
  max-height: 76vh;
  overflow-y: auto;
  padding-right: 8px;
}
.editor-form h4,
.editor-preview h4 {
  margin: 8px 0 12px;
}
.editor-preview {
  position: sticky;
  top: 0;
}
.preview-head {
  display: flex;
  align-items: baseline;
  gap: 12px;
}
.preview-empty {
  aspect-ratio: 16 / 9;
  display: flex;
  align-items: center;
  justify-content: center;
  background: #0b0f14;
  color: #a9b6c6;
  border-radius: 6px;
}
.privacy {
  display: flex;
  flex-direction: column;
  align-items: flex-start;
}
.hint {
  font-size: 12px;
  color: var(--el-text-color-secondary);
  line-height: 1.5;
}
.field-error {
  color: var(--el-color-danger);
  font-size: 12px;
  margin: 4px 0;
}
.row {
  display: flex;
  gap: 8px;
  align-items: center;
  flex-wrap: wrap;
  margin-bottom: 8px;
}
.view-card {
  margin-bottom: 12px;
}
.view-title {
  flex: 1 1 200px;
}
.panel-row {
  display: flex;
  flex-wrap: wrap;
  gap: 6px;
  align-items: center;
  padding: 6px 0;
  border-top: 1px solid var(--el-border-color-lighter);
}
.what {
  flex: 1 0 100%;
  font-size: 12px;
  color: var(--el-text-color-secondary);
}
.option-reason {
  margin-left: 8px;
  font-size: 11px;
  color: var(--el-text-color-secondary);
}
.behaviour {
  display: flex;
  flex-wrap: wrap;
  column-gap: 24px;
}
.block {
  margin-bottom: 12px;
}
.mt {
  margin-top: 8px;
}
.ml {
  margin-left: 8px;
}
</style>
