<template>
  <div class="display-links" v-loading="loading && !loaded">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>Display links</span>
          <div class="actions">
            <el-switch v-model="showRevoked" active-text="Show revoked" @change="load" />
            <el-button :icon="Refresh" :loading="loading" @click="load">Refresh</el-button>
            <el-button type="primary" :icon="Plus" :disabled="atLimit" data-testid="new-link" @click="openCreate">New display link</el-button>
          </div>
        </div>
      </template>

      <p class="intro">
        Display links let a wall screen or TV show a read-only Big Display without anyone signing in. Each keeps working until you
        pause, rotate or revoke it. Use one link per screen.
      </p>
      <p v-if="atLimit" class="intro warn">There are already {{ limit }} display links. Revoke one you no longer use first.</p>

      <el-empty v-if="loaded && links.length === 0" description="No display links yet. Create one for each wall screen.">
        <el-button type="primary" :icon="Plus" @click="openCreate">New display link</el-button>
      </el-empty>

      <el-table v-else :data="links" row-key="id" data-testid="links-table">
        <el-table-column type="expand">
          <template #default="{ row }">
            <DisplayLinkClients v-if="!row.revoked_at" :key="`${row.id}-${row.token_rotated_at}`" :link-id="row.id" />
            <p v-else class="hint revoked-note">Revoked {{ formatDate(row.revoked_at) }}.</p>
          </template>
        </el-table-column>
        <el-table-column label="Name" min-width="160">
          <template #default="{ row }">
            <div class="name">{{ row.name }}</div>
            <div class="hint">…{{ row.token_hint }} · by {{ row.created_by ? row.created_by.username : 'deleted user' }}</div>
          </template>
        </el-table-column>
        <el-table-column label="Status" min-width="190">
          <template #default="{ row }">
            <el-tag :type="statusText(row, now).tone" effect="light" data-testid="link-status">{{ statusText(row, now).text }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="Privacy" width="125">
          <template #default="{ row }">{{ row.privacy === 'public' ? 'Public area' : 'Operations room' }}</template>
        </el-table-column>
        <el-table-column label="Views" width="64" align="center">
          <template #default="{ row }">{{ row.view_count }}</template>
        </el-table-column>
        <el-table-column label="Seen from" min-width="170">
          <template #default="{ row }">
            <template v-if="row.last_client">
              <div>{{ row.last_client.ip }} · {{ shortBrowser(row.last_client.user_agent) }}</div>
              <div v-if="row.clients_24h > 1" class="amber">+{{ row.clients_24h - 1 }} more in 24 h</div>
            </template>
            <span v-else class="hint">—</span>
          </template>
        </el-table-column>
        <el-table-column label="Networks" min-width="100">
          <template #default="{ row }">
            <span v-if="row.allowed_cidrs.length === 0" class="hint">Any</span>
            <div v-for="c in row.allowed_cidrs.slice(0, 3)" :key="c">{{ c }}</div>
            <div v-if="row.allowed_cidrs.length > 3" class="hint">+{{ row.allowed_cidrs.length - 3 }} more</div>
          </template>
        </el-table-column>
        <el-table-column label="Actions" min-width="220">
          <template #default="{ row }">
            <template v-if="!row.revoked_at">
              <el-button link type="primary" @click="preview(row)">Preview</el-button>
              <el-button link type="primary" data-testid="link-edit" @click="openEdit(row)">Edit</el-button>
              <el-button link type="primary" :data-testid="row.enabled ? 'link-pause' : 'link-resume'" @click="setEnabled(row, !row.enabled)">
                {{ row.enabled ? 'Pause' : 'Resume' }}
              </el-button>
              <el-dropdown trigger="click" class="more" @command="(c: string) => onMore(row, c)">
                <el-button link type="primary" data-testid="link-more">More<el-icon class="el-icon--right"><ArrowDown /></el-icon></el-button>
                <template #dropdown>
                  <el-dropdown-menu>
                    <el-dropdown-item command="rotate" data-testid="link-rotate">Rotate…</el-dropdown-item>
                    <el-dropdown-item command="duplicate" :disabled="atLimit">Duplicate</el-dropdown-item>
                    <el-dropdown-item command="revoke" divided data-testid="link-revoke">Revoke…</el-dropdown-item>
                  </el-dropdown-menu>
                </template>
              </el-dropdown>
            </template>
            <span v-else class="hint">Revoked</span>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <DisplayLinkEditor v-model="editorOpen" :link-id="editingId" :initial="editorInitial" @created="onCreated" @updated="load" />
    <DisplayLinkCreatedDialog :secret="secret" :rotated="secretRotated" @close="secret = null" />
  </div>
</template>

<script setup lang="ts">
/**
 * Settings -> Display links (admin only; BIG-DISPLAY.md §8.3): the read-only
 * links wall screens use, with when and from where each was last used.
 * Create, edit, pause, rotate, duplicate and revoke; a link's secret is shown
 * once, after create and rotate, by DisplayLinkCreatedDialog.
 */
import { computed, onBeforeUnmount, onMounted, ref } from 'vue';
import { useRouter } from 'vue-router';
import { ElMessage, ElMessageBox } from 'element-plus';
import { ArrowDown, Plus, Refresh } from '@element-plus/icons-vue';
import { api } from '@/services/api';
import { defaultConfig, shortBrowser, statusText, type DisplayLinkSecret, type DisplayLinkSummary, type EditorInitial } from '@/utils/displayLinks';
import { formatDate } from './format';
import DisplayLinkEditor from './DisplayLinkEditor.vue';
import DisplayLinkCreatedDialog from './DisplayLinkCreatedDialog.vue';
import DisplayLinkClients from './DisplayLinkClients.vue';

const router = useRouter();
const links = ref<DisplayLinkSummary[]>([]);
const limit = ref(50);
const loading = ref(false);
const loaded = ref(false);
const showRevoked = ref(false);
const now = ref(Date.now());

const editorOpen = ref(false);
const editingId = ref<number | null>(null);
const editorInitial = ref<EditorInitial | null>(null);
const secret = ref<DisplayLinkSecret | null>(null);
const secretRotated = ref(false);

const atLimit = computed(() => links.value.filter((l) => !l.revoked_at).length >= limit.value);

let refreshTimer: ReturnType<typeof setInterval> | null = null;
let clockTimer: ReturnType<typeof setInterval> | null = null;

async function load() {
  loading.value = true;
  try {
    const { data } = await api.listDisplayLinks(showRevoked.value);
    links.value = data.links;
    limit.value = data.limit;
    now.value = Date.now();
    loaded.value = true;
  } finally {
    loading.value = false;
  }
}

function openCreate() {
  editingId.value = null;
  editorInitial.value = null;
  editorOpen.value = true;
}

async function detailOf(row: DisplayLinkSummary): Promise<EditorInitial> {
  const { data } = await api.getDisplayLink(row.id);
  if (!data.link.config) {
    ElMessage.error("This link's saved layout is no longer valid: starting from the default layout.");
  }
  return {
    name: data.link.name,
    config: data.link.config ?? defaultConfig(),
    expires_at: data.link.expires_at,
    allowed_cidrs: data.link.allowed_cidrs,
  };
}

async function openEdit(row: DisplayLinkSummary) {
  const initial = await detailOf(row);
  editingId.value = row.id;
  editorInitial.value = initial;
  editorOpen.value = true;
}

async function duplicate(row: DisplayLinkSummary) {
  const initial = await detailOf(row);
  editingId.value = null;
  editorInitial.value = { ...initial, name: `${initial.name} (copy)`.slice(0, 80), expires_at: null };
  editorOpen.value = true;
}

function onCreated(created: DisplayLinkSecret) {
  secretRotated.value = false;
  secret.value = created;
  void load();
}

function onMore(row: DisplayLinkSummary, command: string) {
  if (command === 'rotate') void rotate(row);
  else if (command === 'duplicate') void duplicate(row);
  else if (command === 'revoke') void revoke(row);
}

function preview(row: DisplayLinkSummary) {
  const href = router.resolve({ path: '/big-display', query: { link: String(row.id) } }).href;
  window.open(href, '_blank', 'noopener');
}

async function setEnabled(row: DisplayLinkSummary, enabled: boolean) {
  try {
    await api.updateDisplayLink(row.id, { enabled });
    ElMessage.success(enabled ? `${row.name} resumed` : `${row.name} paused: its screens show "Paused" at their next refresh`);
  } catch (error) {
    ElMessage.error((error as { response?: { data?: { message?: string } } }).response?.data?.message ?? "Couldn't change the link");
  }
  await load();
}

async function rotate(row: DisplayLinkSummary) {
  try {
    await ElMessageBox.confirm(
      "The screen using the current link shows 'not valid any more' at its next refresh. Put the new link on that screen.",
      `Rotate ${row.name}?`,
      { confirmButtonText: 'Rotate', cancelButtonText: 'Cancel', type: 'warning' }
    );
  } catch {
    return;
  }
  const { data } = await api.rotateDisplayLink(row.id);
  secretRotated.value = true;
  secret.value = data;
  await load();
}

async function revoke(row: DisplayLinkSummary) {
  try {
    await ElMessageBox.confirm("Screens using this link show 'revoked' at their next refresh. This can't be undone.", `Revoke ${row.name}?`, {
      confirmButtonText: 'Revoke',
      cancelButtonText: 'Cancel',
      type: 'error',
      confirmButtonClass: 'el-button--danger',
    });
  } catch {
    return;
  }
  await api.revokeDisplayLink(row.id);
  ElMessage.success(`${row.name} revoked`);
  await load();
}

onMounted(() => {
  void load();
  // Keeps "refreshed 12 s ago" and the statuses current.
  refreshTimer = setInterval(() => {
    if (!editorOpen.value && !secret.value) void load();
  }, 30_000);
  clockTimer = setInterval(() => (now.value = Date.now()), 5_000);
});
onBeforeUnmount(() => {
  if (refreshTimer) clearInterval(refreshTimer);
  if (clockTimer) clearInterval(clockTimer);
});
</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  flex-wrap: wrap;
  gap: 8px;
}
.actions {
  display: flex;
  gap: 12px;
  align-items: center;
}
.intro {
  margin: 0 0 12px;
  color: var(--el-text-color-regular);
}
.warn,
.amber {
  color: var(--el-color-warning);
}
.name {
  font-weight: 600;
}
.hint {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}
.more {
  margin-left: 12px;
  vertical-align: middle;
}
.revoked-note {
  padding: 4px 48px;
}
</style>
