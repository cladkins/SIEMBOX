<template>
  <el-card style="margin-top: 20px" data-test="ai-mcp">
    <template #header>
      <div class="mcp-header">
        <span>MCP servers <HelpTip text="Connect remote MCP (Model Context Protocol) servers so the AI Analyst can use their tools next to its built-in ones: a ticket system, a threat intelligence service, your own tooling. Only tools you switch on are offered to the model." /></span>
        <el-button type="primary" size="small" @click="openAdd" :disabled="servers.length >= MAX_SERVERS" data-test="add-mcp-server">
          <el-icon><Plus /></el-icon> Add server
        </el-button>
      </div>
    </template>

    <div v-loading="loading">
      <el-text size="small" type="info" tag="p" class="mcp-intro">
        The built-in analyst tools only read SIEMBox data. An MCP tool does whatever its server does, and its
        results are sent to your AI provider. Tools a server marks read-only start switched on. All others
        start off: switch one on only if you want the analyst to use it when you ask. Servers are reached from
        the SIEMBox backend over HTTP (Streamable HTTP transport).
      </el-text>

      <el-empty v-if="!loading && servers.length === 0" description="No MCP servers connected" :image-size="60" />

      <div v-for="s in servers" :key="s.id" class="mcp-server" :data-test="`mcp-server-${s.name}`">
        <div class="mcp-server-head">
          <div class="mcp-server-title">
            <strong>{{ s.name }}</strong>
            <el-text size="small" type="info" class="mcp-url">{{ s.url }}</el-text>
            <el-tag v-if="s.hasAuthValue" size="small" type="info">{{ s.authHeader }} saved</el-tag>
          </div>
          <div class="mcp-server-actions">
            <el-button size="small" @click="sync(s)" :loading="busy === `sync-${s.id}`">Sync tools</el-button>
            <el-button size="small" @click="openEdit(s)">Edit</el-button>
            <el-popconfirm :title="`Remove MCP server ${s.name}?`" @confirm="remove(s)">
              <template #reference>
                <el-button size="small" type="danger" plain>Remove</el-button>
              </template>
            </el-popconfirm>
          </div>
        </div>

        <el-alert v-if="s.lastError" type="error" :closable="false" show-icon class="mcp-error">
          Last sync failed: {{ s.lastError }}
        </el-alert>

        <div class="mcp-switches">
          <span>
            <el-switch :model-value="s.enabled" @change="(v: any) => patch(s, { enabled: !!v })" />
            <el-text size="small" class="mcp-switch-label">Use in AI Analyst chat</el-text>
          </span>
          <span>
            <el-switch :model-value="s.triageEnabled" :disabled="!s.enabled" @change="(v: any) => patch(s, { triageEnabled: !!v })" />
            <el-text size="small" class="mcp-switch-label">
              Use in AI Triage
              <HelpTip text="Triage runs unattended on alert content an attacker can influence, so it only ever gets this server's tools marked read-only. Each lookup sends alert details to this server." />
            </el-text>
          </span>
          <el-text size="small" type="info">
            {{ s.lastSyncAt ? `Synced ${new Date(s.lastSyncAt).toLocaleString()}` : 'Never synced' }}
          </el-text>
        </div>

        <el-table v-if="s.tools.length" :data="s.tools" size="small" class="mcp-tools">
          <el-table-column label="On" width="70">
            <template #default="{ row }">
              <el-switch size="small" :model-value="row.enabled" @change="(v: any) => toggleTool(s, row, !!v)" />
            </template>
          </el-table-column>
          <el-table-column label="Tool" min-width="180">
            <template #default="{ row }">
              <code>{{ row.name }}</code>
            </template>
          </el-table-column>
          <el-table-column label="Kind" width="130">
            <template #default="{ row }">
              <el-tag v-if="row.readOnly" size="small" type="success">read-only</el-tag>
              <el-tag v-else size="small" type="warning">may change data</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="Description" prop="description" min-width="320" show-overflow-tooltip />
        </el-table>
        <el-text v-else-if="!s.lastError" size="small" type="info">No tools yet. Use Sync tools.</el-text>
      </div>
    </div>

    <el-dialog v-model="dialogOpen" :title="editing ? `Edit ${editing.name}` : 'Add MCP server'" width="560px">
      <el-form :model="form" label-width="130px" @submit.prevent>
        <el-form-item label="Name">
          <el-input v-model="form.name" :disabled="!!editing" placeholder="threat_intel" maxlength="24" data-test="mcp-name" />
          <el-text size="small" type="info">
            Lowercase letters, digits and underscores. Tools appear to the analyst as mcp__{{ form.name || 'name' }}__tool.
          </el-text>
        </el-form-item>
        <el-form-item label="URL">
          <el-input v-model="form.url" placeholder="https://mcp.example.com/mcp" data-test="mcp-url" />
        </el-form-item>
        <el-form-item label="Auth header">
          <el-input v-model="form.authHeader" placeholder="Authorization" />
          <el-text size="small" type="info">Leave empty for a server without authentication.</el-text>
        </el-form-item>
        <el-form-item label="Header value">
          <el-input
            v-model="form.authValue"
            type="password"
            show-password
            autocomplete="off"
            :placeholder="editing?.hasAuthValue ? 'Saved. Leave empty to keep it.' : 'Bearer <token>'"
          />
          <el-text v-if="needsAuthAgain" size="small" type="warning">
            The saved value belongs to the previous URL. Enter it again for the new URL.
          </el-text>
          <el-checkbox v-if="editing?.hasAuthValue" v-model="form.clearAuth">Remove the saved value</el-checkbox>
        </el-form-item>
      </el-form>
      <template #footer>
        <el-button @click="dialogOpen = false">Cancel</el-button>
        <el-button type="primary" @click="save" :loading="busy === 'save'" data-test="save-mcp-server">
          {{ editing ? 'Save' : 'Add and sync' }}
        </el-button>
      </template>
    </el-dialog>
  </el-card>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue';
import { ElMessage } from 'element-plus';
import { Plus } from '@element-plus/icons-vue';
import { api } from '@/services/api';
import HelpTip from '@/components/HelpTip.vue';

interface McpTool {
  name: string;
  description: string;
  readOnly: boolean;
  enabled: boolean;
}
interface McpServer {
  id: number;
  name: string;
  url: string;
  authHeader: string | null;
  hasAuthValue: boolean;
  enabled: boolean;
  triageEnabled: boolean;
  tools: McpTool[];
  lastSyncAt: string | null;
  lastError: string | null;
}

const MAX_SERVERS = 10;
const servers = ref<McpServer[]>([]);
const loading = ref(false);
const busy = ref('');
const dialogOpen = ref(false);
const editing = ref<McpServer | null>(null);
const form = reactive({ name: '', url: '', authHeader: '', authValue: '', clearAuth: false });

const needsAuthAgain = computed(
  () =>
    !!editing.value?.hasAuthValue &&
    !form.clearAuth &&
    !form.authValue &&
    form.url.trim() !== editing.value.url
);

function failed(error: any, fallback: string) {
  ElMessage.error(error?.response?.data?.message || fallback);
}

function replace(server: McpServer) {
  const i = servers.value.findIndex((s) => s.id === server.id);
  if (i === -1) servers.value.push(server);
  else servers.value[i] = server;
}

async function load() {
  loading.value = true;
  try {
    const { data } = await api.getMcpServers();
    servers.value = data.servers || [];
  } catch (error) {
    failed(error, 'Failed to load MCP servers');
  } finally {
    loading.value = false;
  }
}

function openAdd() {
  editing.value = null;
  Object.assign(form, { name: '', url: '', authHeader: '', authValue: '', clearAuth: false });
  dialogOpen.value = true;
}

function openEdit(s: McpServer) {
  editing.value = s;
  Object.assign(form, { name: s.name, url: s.url, authHeader: s.authHeader || '', authValue: '', clearAuth: false });
  dialogOpen.value = true;
}

async function save() {
  if (needsAuthAgain.value) {
    ElMessage.warning('Enter the header value again for the new URL, or remove the saved value.');
    return;
  }
  busy.value = 'save';
  try {
    const body: Record<string, unknown> = { url: form.url.trim(), authHeader: form.authHeader.trim() };
    if (form.clearAuth) body.authValue = '';
    else if (form.authValue) body.authValue = form.authValue;
    if (editing.value) {
      const urlChanged = body.url !== editing.value.url;
      let { data } = await api.updateMcpServer(editing.value.id, body);
      if (urlChanged) data = (await api.syncMcpServer(editing.value.id)).data;
      replace(data);
      ElMessage.success('MCP server saved');
    } else {
      const { data } = await api.createMcpServer({ ...body, name: form.name.trim() });
      replace(data);
      if (data.lastError) ElMessage.warning(`Server saved, but its tools could not be fetched: ${data.lastError}`);
      else ElMessage.success(`Server added with ${data.tools.length} tool(s). Review which are switched on.`);
    }
    dialogOpen.value = false;
  } catch (error) {
    failed(error, 'Failed to save the MCP server');
  } finally {
    busy.value = '';
  }
}

async function patch(s: McpServer, body: Record<string, unknown>) {
  try {
    const { data } = await api.updateMcpServer(s.id, body);
    replace(data);
  } catch (error) {
    failed(error, 'Failed to update the MCP server');
  }
}

function toggleTool(s: McpServer, tool: McpTool, enabled: boolean) {
  return patch(s, { tools: [{ name: tool.name, enabled }] });
}

async function sync(s: McpServer) {
  busy.value = `sync-${s.id}`;
  try {
    const { data } = await api.syncMcpServer(s.id);
    replace(data);
    if (data.lastError) ElMessage.error(`Sync failed: ${data.lastError}`);
    else ElMessage.success(`Synced ${data.tools.length} tool(s)`);
  } catch (error) {
    failed(error, 'Failed to sync the MCP server');
  } finally {
    busy.value = '';
  }
}

async function remove(s: McpServer) {
  try {
    await api.deleteMcpServer(s.id);
    servers.value = servers.value.filter((x) => x.id !== s.id);
    ElMessage.success('MCP server removed');
  } catch (error) {
    failed(error, 'Failed to remove the MCP server');
  }
}

onMounted(load);
</script>

<style scoped>
.mcp-header,
.mcp-server-head {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 12px;
  flex-wrap: wrap;
}
.mcp-intro {
  margin: 0 0 12px;
  line-height: 1.5;
}
.mcp-server {
  padding: 14px 0;
  border-top: 1px solid var(--el-border-color-lighter);
}
.mcp-server-title {
  display: flex;
  align-items: center;
  gap: 10px;
  flex-wrap: wrap;
  min-width: 0;
}
.mcp-url {
  word-break: break-all;
}
.mcp-error {
  margin-top: 10px;
}
.mcp-switches {
  display: flex;
  align-items: center;
  gap: 24px;
  flex-wrap: wrap;
  margin: 12px 0;
}
.mcp-switch-label {
  margin-left: 8px;
}
.mcp-tools {
  width: 100%;
}
</style>
