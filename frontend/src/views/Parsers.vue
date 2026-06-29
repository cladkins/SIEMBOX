<template>
  <div class="parsers">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>Log Parsers</span>
          <div class="header-actions">
            <el-button size="small" @click="openAiBuilder">
              <el-icon><MagicStick /></el-icon> Generate with AI
            </el-button>
            <el-button size="small" @click="openCatalog">
              <el-icon><Shop /></el-icon> Browse Catalog
            </el-button>
            <el-button size="small" @click="triggerImport">
              <el-icon><Upload /></el-icon> Import
            </el-button>
            <el-button type="primary" size="small" @click="showCreateDialog">
              <el-icon><Plus /></el-icon> Add Parser
            </el-button>
            <input
              ref="importFileInput"
              type="file"
              accept=".json"
              style="display: none"
              @change="onImportFileChange"
            />
          </div>
        </div>
      </template>

      <el-table :data="parsers" v-loading="loading" stripe>
        <el-table-column prop="name" label="Name" min-width="200" />
        <el-table-column prop="parser_type" label="Type" width="120">
          <template #default="{ row }">
            <el-tag>{{ row.parser_type.toUpperCase() }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="priority" label="Priority" width="100" sortable />
        <el-table-column prop="enabled" label="Status" width="120">
          <template #default="{ row }">
            <el-switch
              v-model="row.enabled"
              @change="toggleParser(row)"
              :disabled="updating"
            />
          </template>
        </el-table-column>
        <el-table-column prop="description" label="Description" min-width="300" show-overflow-tooltip />
        <el-table-column label="Actions" width="420" fixed="right">
          <template #default="{ row }">
            <el-button size="small" @click="testParser(row)">Test</el-button>
            <el-button size="small" @click="editParser(row)">Edit</el-button>
            <el-button size="small" @click="exportParser(row)">Export</el-button>
            <el-button size="small" @click="contributeParser(row)">Contribute</el-button>
            <el-button type="danger" size="small" @click="deleteParser(row)">Delete</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- Create/Edit Parser Dialog -->
    <el-dialog
      v-model="dialogVisible"
      :title="editMode ? 'Edit Parser' : 'Create Parser'"
      width="900px"
      @close="resetForm"
    >
      <el-form :model="parserForm" :rules="rules" ref="formRef" label-width="120px">
        <el-form-item label="Name" prop="name">
          <el-input v-model="parserForm.name" placeholder="e.g., SSH Authentication" />
        </el-form-item>

        <el-form-item label="Description" prop="description">
          <el-input
            v-model="parserForm.description"
            type="textarea"
            :rows="2"
            placeholder="What does this parser do?"
          />
        </el-form-item>

        <el-row :gutter="20">
          <el-col :span="12">
            <el-form-item label="Parser Type" prop="parser_type">
              <el-select v-model="parserForm.parser_type" @change="onTypeChange">
                <el-option label="Regex" value="regex" />
                <el-option label="Grok" value="grok" />
                <el-option label="JSON" value="json" />
              </el-select>
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item label="Priority" prop="priority">
              <el-input-number v-model="parserForm.priority" :min="1" :max="1000" />
              <el-text size="small" type="info">Lower = Higher Priority</el-text>
            </el-form-item>
          </el-col>
        </el-row>

        <el-form-item label="Event Type">
          <el-input
            v-model="parserForm.event_type"
            placeholder="e.g., ssh_auth, http_request, dns_query (optional)"
            clearable
          />
          <el-text size="small" type="info">
            Categorizes parsed logs in the UI. Leave blank for auto-detection based on parser name.
          </el-text>
        </el-form-item>

        <el-form-item label="Pattern" prop="pattern">
          <el-input
            v-model="parserForm.pattern"
            type="textarea"
            :rows="4"
            :placeholder="getPatternPlaceholder()"
          />
          <el-text size="small" type="info">{{ getPatternHelp() }}</el-text>
        </el-form-item>

        <el-form-item label="Field Mappings">
          <div class="field-mappings">
            <div v-for="(_value, _key, index) in parserForm.field_mappings" :key="index" class="mapping-row">
              <el-input v-model="mappingKeys[index]" placeholder="Group name/number" style="width: 200px" />
              <el-icon><Right /></el-icon>
              <el-input v-model="parserForm.field_mappings[mappingKeys[index]]" placeholder="Field name" style="width: 200px" />
              <el-button type="danger" size="small" @click="removeMapping(index)" :icon="Delete" circle />
            </div>
            <el-button size="small" @click="addMapping" :icon="Plus">Add Field Mapping</el-button>
          </div>
        </el-form-item>

        <el-form-item label="Test Sample">
          <el-input
            v-model="testSample"
            type="textarea"
            :rows="3"
            placeholder="Paste a sample log line to test your parser"
          />
          <el-button type="primary" size="small" @click="testCurrentParser" style="margin-top: 10px">
            <el-icon><CircleCheck /></el-icon> Test Parser
          </el-button>
        </el-form-item>

        <el-form-item v-if="testResult" label="Test Result">
          <el-alert
            :title="testResult.matched ? 'Parser Matched!' : 'Parser Did Not Match'"
            :type="testResult.matched ? 'success' : 'warning'"
            :closable="false"
          >
            <pre v-if="testResult.matched">{{ JSON.stringify(testResult.fields, null, 2) }}</pre>
            <div v-else>No match found. Check your pattern and try again.</div>
          </el-alert>
        </el-form-item>
      </el-form>

      <template #footer>
        <el-button @click="dialogVisible = false">Cancel</el-button>
        <el-button type="primary" @click="saveParser" :loading="saving">
          {{ editMode ? 'Update' : 'Create' }} Parser
        </el-button>
      </template>
    </el-dialog>

    <!-- Test Parser Dialog -->
    <el-dialog v-model="testDialogVisible" title="Test Parser" width="700px">
      <el-form label-width="100px">
        <el-form-item label="Parser">
          <el-text>{{ selectedParser?.name }}</el-text>
        </el-form-item>
        <el-form-item label="Sample Log">
          <el-input v-model="testInput" type="textarea" :rows="4" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="runTest" :loading="testing">Test</el-button>
        </el-form-item>
        <el-form-item v-if="testResult" label="Result">
          <el-alert
            :title="testResult.matched ? 'Matched!' : 'No Match'"
            :type="testResult.matched ? 'success' : 'warning'"
            :closable="false"
          >
            <pre v-if="testResult.matched">{{ JSON.stringify(testResult.fields, null, 2) }}</pre>
          </el-alert>
        </el-form-item>
      </el-form>
    </el-dialog>

    <!-- Import Parser Dialog -->
    <el-dialog v-model="importDialogVisible" title="Import Parser" width="700px">
      <template v-if="importParserData">
        <p class="import-name">
          <strong>{{ importParserData.name || '(unnamed)' }}</strong>
          <el-tag v-if="importParserData.parser_type" size="small">{{ importParserData.parser_type.toUpperCase() }}</el-tag>
        </p>
        <p v-if="importParserData.description" class="import-desc">{{ importParserData.description }}</p>

        <el-alert
          v-if="importValidation && !importValidation.ok"
          type="error"
          :closable="false"
          title="Validation errors — fix these before importing"
          style="margin-bottom: 10px"
        >
          <ul><li v-for="(e, i) in importValidation.errors" :key="i">{{ e }}</li></ul>
        </el-alert>

        <el-alert
          v-if="importValidation && importValidation.warnings && importValidation.warnings.length"
          type="warning"
          :closable="false"
          title="Warnings"
          style="margin-bottom: 10px"
        >
          <ul><li v-for="(w, i) in importValidation.warnings" :key="i">{{ w }}</li></ul>
        </el-alert>

        <el-alert
          v-if="importSelfTest"
          :type="importSelfTest.ok ? 'success' : 'warning'"
          :closable="false"
          :title="`Self-tests: ${importSelfTest.passed}/${importSelfTest.total} passed`"
        >
          <div v-for="(f, i) in importSelfTest.failures" :key="i" class="selftest-failure">
            sample[{{ f.index }}]<span v-if="f.description"> "{{ f.description }}"</span><span v-if="!f.matched"> — parser did not match</span>
            <ul><li v-for="(m, j) in f.mismatches" :key="j">{{ m.field }}: expected {{ JSON.stringify(m.expected) }}, got {{ JSON.stringify(m.actual) }}</li></ul>
          </div>
        </el-alert>
      </template>

      <template #footer>
        <el-button @click="importDialogVisible = false">Cancel</el-button>
        <el-button
          type="primary"
          :disabled="!importValidation || !importValidation.ok"
          :loading="importing"
          @click="doImport"
        >
          Import{{ importSelfTest && !importSelfTest.ok ? ' anyway' : '' }}
        </el-button>
      </template>
    </el-dialog>

    <!-- Parser Catalog Dialog -->
    <el-dialog v-model="catalogDialogVisible" title="Parser Catalog" width="900px">
      <div class="catalog-toolbar">
        <el-input
          v-model="catalogSearch"
          placeholder="Search name, tag, description…"
          clearable
          size="small"
          style="width: 240px"
        />
        <el-select v-model="catalogStatusFilter" size="small" style="width: 160px">
          <el-option label="All statuses" value="all" />
          <el-option label="Available" value="available" />
          <el-option label="Installed" value="installed" />
          <el-option label="Update available" value="update" />
          <el-option label="Invalid" value="invalid" />
        </el-select>
        <div style="flex: 1" />
        <span class="catalog-count">{{ filteredParserCatalog.length }} / {{ catalog.length }}</span>
        <el-button
          size="small"
          type="primary"
          :loading="installingAll"
          :disabled="catalogLoading || catalog.length === 0"
          @click="installAll"
        >
          <el-icon><Download /></el-icon> Install all
        </el-button>
        <el-button size="small" :loading="catalogLoading" @click="loadCatalog(true)">
          <el-icon><Refresh /></el-icon> Refresh
        </el-button>
      </div>
      <div v-if="catalogSource" class="catalog-source catalog-source-line">
        Source: <code>{{ catalogSource.repo }}@{{ catalogSource.ref }}/{{ catalogSource.path }}</code>
      </div>

      <el-alert
        v-if="catalogError"
        type="error"
        :closable="false"
        :title="catalogError"
        style="margin-bottom: 12px"
      />

      <el-table :data="filteredParserCatalog" v-loading="catalogLoading" stripe max-height="460" :default-sort="{ prop: 'name', order: 'ascending' }">
        <el-table-column prop="name" label="Name" min-width="150" sortable>
          <template #default="{ row }">
            <strong>{{ row.name }}</strong>
            <div v-if="row.log_source" class="catalog-sub">{{ row.log_source }}</div>
          </template>
        </el-table-column>
        <el-table-column prop="description" label="Description" min-width="240" show-overflow-tooltip />
        <el-table-column label="Tags" width="160">
          <template #default="{ row }">
            <el-tag v-for="t in row.tags" :key="t" size="small" class="catalog-tag">{{ t }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="Status" width="130">
          <template #default="{ row }">
            <el-tag v-if="!row.valid" type="danger" size="small">Invalid</el-tag>
            <el-tag v-else-if="row.update_available" type="warning" size="small">Update</el-tag>
            <el-tag v-else-if="row.installed" type="success" size="small">Installed</el-tag>
            <el-tag v-else type="info" size="small" effect="plain">Available</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="Action" width="140" fixed="right">
          <template #default="{ row }">
            <el-tooltip
              v-if="!row.valid"
              :content="(row.errors && row.errors[0]) || 'Failed self-tests'"
              placement="top"
            >
              <el-button size="small" disabled>Invalid</el-button>
            </el-tooltip>
            <el-button
              v-else-if="row.update_available"
              size="small"
              type="warning"
              :loading="installing === row.name"
              @click="install(row)"
            >Update</el-button>
            <el-button
              v-else-if="row.installed"
              size="small"
              :loading="installing === row.name"
              @click="install(row)"
            >Reinstall</el-button>
            <el-button
              v-else
              size="small"
              type="primary"
              :loading="installing === row.name"
              @click="install(row)"
            >Install</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-dialog>

    <!-- AI Parser Builder Dialog -->
    <el-dialog v-model="aiDialogVisible" title="Generate Parser with AI" width="760px">
      <el-form label-position="top">
        <el-form-item label="Paste a log line (or a few)">
          <el-input
            v-model="aiSample"
            type="textarea"
            :rows="4"
            placeholder="e.g. Jan 1 12:00:00 host myapp: login failed from 203.0.113.5"
          />
        </el-form-item>
        <el-form-item label="Hints (optional)">
          <el-input v-model="aiHints" placeholder="e.g. this is MyApp's auth log; the IP is the attacker" />
        </el-form-item>
        <el-button type="primary" :loading="aiGenerating" @click="runAiGenerate">
          <el-icon><MagicStick /></el-icon> {{ aiResult ? 'Regenerate' : 'Generate' }}
        </el-button>
      </el-form>

      <template v-if="aiError">
        <el-divider />
        <el-alert type="error" :closable="false" :title="aiError" />
      </template>

      <template v-if="aiResult">
        <el-divider />
        <el-alert
          :type="aiResult.ok ? 'success' : 'warning'"
          :closable="false"
          style="margin-bottom: 10px"
          :title="aiResult.ok
            ? `Valid parser (${aiResult.self_test ? aiResult.self_test.passed + '/' + aiResult.self_test.total + ' self-tests' : 'no self-tests'}, ${aiResult.attempts} attempt(s))`
            : `Not fully valid after ${aiResult.attempts} attempt(s) — review or regenerate with a hint`"
        >
          <div v-if="aiResult.parser">
            <strong>{{ aiResult.parser.name }}</strong>
            <el-tag size="small">{{ aiResult.parser.parser_type }}</el-tag>
          </div>
          <ul v-if="aiResult.validation && aiResult.validation.errors.length">
            <li v-for="(e, i) in aiResult.validation.errors" :key="i">{{ e }}</li>
          </ul>
          <div v-for="(f, i) in (aiResult.self_test && aiResult.self_test.failures) || []" :key="'f' + i" class="selftest-failure">
            sample[{{ f.index }}]<span v-if="!f.matched"> — did not match</span>
            <ul><li v-for="(m, j) in f.mismatches" :key="j">{{ m.field }}: expected {{ JSON.stringify(m.expected) }}, got {{ JSON.stringify(m.actual) }}</li></ul>
          </div>
        </el-alert>
        <p v-if="!aiResult.ok && aiResult.parser" class="ai-hint">
          Close, but not fully verified. You can tweak the <strong>Hints</strong> above and Regenerate, edit
          the JSON below, or <strong>Save anyway</strong> and refine it with the Test/Edit tools.
        </p>
        <pre v-if="aiResult.parser" class="ai-preview">{{ JSON.stringify(aiResult.parser, null, 2) }}</pre>
      </template>

      <template #footer>
        <el-button @click="aiDialogVisible = false">Close</el-button>
        <el-button
          v-if="aiResult && aiResult.parser && !aiResult.ok"
          type="warning"
          plain
          :loading="aiSaving"
          @click="saveAiParser(true)"
        >
          Save anyway
        </el-button>
        <el-button type="primary" :disabled="!aiResult || !aiResult.ok" :loading="aiSaving" @click="saveAiParser(false)">
          Save Parser
        </el-button>
      </template>
    </el-dialog>

    <!-- Contribute to the community catalog (browser hand-off — no token needed) -->
    <el-dialog v-model="contributeDialogVisible" title="Contribute to the community catalog" width="640px">
      <div v-loading="contributeLoading" style="min-height: 60px">
        <template v-if="contributeData">
          <el-alert
            v-if="contributeData.ready"
            type="success" :closable="false" show-icon
            title="Validated + self-tests passed — ready to propose."
            style="margin-bottom: 12px"
          />
          <el-alert
            v-else
            type="error" :closable="false" show-icon
            title="Not ready — fix the issues below, then try again."
            style="margin-bottom: 12px"
          />

          <p style="margin: 0 0 10px; color: var(--el-text-color-secondary); font-size: 13px">
            This opens GitHub's pre-filled <strong>“propose new file”</strong> page for
            <code>{{ contributeData.path }}</code>. You finish the fork + pull request in your browser,
            signed in as you — SIEMBox never touches your GitHub credentials. A maintainer reviews it and
            the catalog's CI re-runs these same checks before it can merge.
          </p>

          <div v-if="contributeData.self_test" style="margin: 6px 0">
            Self-tests:
            <el-tag :type="contributeData.self_test.ok ? 'success' : 'danger'" size="small">
              {{ contributeData.self_test.passed }}/{{ contributeData.self_test.total }} passed
            </el-tag>
          </div>

          <ul v-if="contributeData.errors && contributeData.errors.length" class="contrib-issues error">
            <li v-for="(e, i) in contributeData.errors" :key="'e' + i">{{ e }}</li>
          </ul>
          <ul v-if="contributeData.warnings && contributeData.warnings.length" class="contrib-issues warn">
            <li v-for="(w, i) in contributeData.warnings" :key="'w' + i">{{ w }}</li>
          </ul>
        </template>
      </div>
      <template #footer>
        <el-button @click="contributeDialogVisible = false">Close</el-button>
        <el-button v-if="contributeData" @click="copyContributeContent">Copy JSON</el-button>
        <el-button type="primary" :disabled="!contributeData || !contributeData.ready" @click="openContributeUrl">
          Open GitHub PR
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, reactive, computed } from 'vue';
import { api } from '@/services/api';
import { ElMessage, ElMessageBox, FormInstance, FormRules } from 'element-plus';
import { Plus, Delete, Right, CircleCheck, Upload, Shop, Refresh, MagicStick, Download } from '@element-plus/icons-vue';

const parsers = ref<any[]>([]);
const loading = ref(false);
const updating = ref(false);
const saving = ref(false);
const testing = ref(false);

const dialogVisible = ref(false);
const testDialogVisible = ref(false);
const editMode = ref(false);
const selectedParser = ref<any>(null);

const formRef = ref<FormInstance>();
const parserForm = reactive({
  name: '',
  description: '',
  parser_type: 'regex',
  priority: 100,
  pattern: '',
  field_mappings: {} as Record<string, string>,
  event_type: '',
  enabled: true,
});

const mappingKeys = ref<string[]>([]);
const testSample = ref('');
const testInput = ref('');
const testResult = ref<any>(null);

// Portable parser import/export
const importFileInput = ref<HTMLInputElement>();
const importDialogVisible = ref(false);
const importParserData = ref<any>(null);
const importValidation = ref<any>(null);
const importSelfTest = ref<any>(null);
const importing = ref(false);

// Parser catalog (browse/install from GitHub)
const catalogDialogVisible = ref(false);
const catalogLoading = ref(false);
const catalog = ref<any[]>([]);
const catalogSource = ref<any>(null);
const catalogError = ref('');
const installing = ref('');
const installingAll = ref(false);
const catalogSearch = ref('');
const catalogStatusFilter = ref('all');

function entryStatus(r: any) {
  return !r.valid ? 'invalid' : r.update_available ? 'update' : r.installed ? 'installed' : 'available';
}

const filteredParserCatalog = computed(() => {
  const q = catalogSearch.value.trim().toLowerCase();
  const sf = catalogStatusFilter.value;
  return catalog.value.filter((r) => {
    if (sf !== 'all' && entryStatus(r) !== sf) return false;
    if (q) {
      const hay = [r.name, r.description, r.log_source, ...(r.tags || [])].join(' ').toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
});

// AI parser builder
const aiDialogVisible = ref(false);
const aiSample = ref('');
const aiHints = ref('');
const aiGenerating = ref(false);
const aiResult = ref<any>(null);
const aiError = ref('');
const aiSaving = ref(false);

function openAiBuilder() {
  aiResult.value = null;
  aiError.value = '';
  aiDialogVisible.value = true;
}

async function runAiGenerate() {
  if (!aiSample.value.trim()) {
    ElMessage.warning('Paste a log sample first');
    return;
  }
  aiGenerating.value = true;
  aiError.value = '';
  aiResult.value = null;
  try {
    const res = await api.generateParserAI(aiSample.value, aiHints.value || undefined);
    aiResult.value = res.data;
    if (res.data.error) aiError.value = res.data.error;
  } catch (error: any) {
    aiError.value =
      error.response?.data?.message ||
      (error.code === 'ECONNABORTED' ? 'Timed out waiting for the model — try again or simplify the sample' : error.message) ||
      'Generation failed';
  } finally {
    aiGenerating.value = false;
  }
}

async function saveAiParser(force = false) {
  if (!aiResult.value?.parser) return;
  // A not-fully-valid parser can still be a useful starting point — let the user
  // save it (force) and refine it with the Test/Edit tools, rather than dead-ending.
  if (force) {
    try {
      await ElMessageBox.confirm(
        "This parser didn't pass all of its self-tests, so it may not extract every field correctly yet. You can save it now and refine it with the Test and Edit tools. Save anyway?",
        'Save unverified parser?',
        { confirmButtonText: 'Save anyway', cancelButtonText: 'Cancel', type: 'warning' }
      );
    } catch {
      return; // user cancelled
    }
  }
  aiSaving.value = true;
  try {
    const res = await api.importParser(aiResult.value.parser, force);
    ElMessage.success(`Parser "${res.data.parser?.name}" ${res.data.action}`);
    aiDialogVisible.value = false;
    fetchParsers();
  } catch (error: any) {
    ElMessage.error(error.response?.data?.message || 'Failed to save parser');
  } finally {
    aiSaving.value = false;
  }
}

const rules: FormRules = {
  name: [{ required: true, message: 'Name is required', trigger: 'blur' }],
  parser_type: [{ required: true, message: 'Type is required', trigger: 'change' }],
  pattern: [{ required: true, message: 'Pattern is required', trigger: 'blur' }],
  priority: [{ required: true, message: 'Priority is required', trigger: 'blur' }],
};

onMounted(fetchParsers);

async function fetchParsers() {
  loading.value = true;
  try {
    const response = await api.getParsers();
    parsers.value = response.data;
  } catch (error) {
    ElMessage.error('Failed to fetch parsers');
  } finally {
    loading.value = false;
  }
}

function showCreateDialog() {
  editMode.value = false;
  resetForm();
  dialogVisible.value = true;
}

function editParser(parser: any) {
  editMode.value = true;
  selectedParser.value = parser;

  Object.assign(parserForm, {
    name: parser.name,
    description: parser.description,
    parser_type: parser.parser_type,
    priority: parser.priority,
    pattern: parser.pattern,
    field_mappings: { ...parser.field_mappings },
    event_type: parser.event_type || '',
    enabled: parser.enabled,
  });

  mappingKeys.value = Object.keys(parser.field_mappings);
  dialogVisible.value = true;
}

function resetForm() {
  Object.assign(parserForm, {
    name: '',
    description: '',
    parser_type: 'regex',
    priority: 100,
    pattern: '',
    field_mappings: {},
    event_type: '',
    enabled: true,
  });
  mappingKeys.value = [];
  testSample.value = '';
  testResult.value = null;
  formRef.value?.clearValidate();
}

function onTypeChange() {
  parserForm.pattern = '';
  parserForm.field_mappings = {};
  mappingKeys.value = [];
}

function addMapping() {
  const key = `group${mappingKeys.value.length}`;
  mappingKeys.value.push(key);
  parserForm.field_mappings[key] = '';
}

function removeMapping(index: number) {
  const key = mappingKeys.value[index];
  delete parserForm.field_mappings[key];
  mappingKeys.value.splice(index, 1);
}

function getPatternPlaceholder() {
  if (parserForm.parser_type === 'regex') {
    return 'e.g., ^(?<timestamp>\\S+\\s+\\d+\\s+\\d+:\\d+:\\d+)\\s+(?<hostname>\\S+)\\s+(?<message>.+)$';
  } else if (parserForm.parser_type === 'grok') {
    return 'e.g., %{SYSLOGTIMESTAMP:timestamp} %{SYSLOGHOST:hostname} %{GREEDYDATA:message}';
  } else {
    return 'JSON logs are parsed automatically';
  }
}

function getPatternHelp() {
  if (parserForm.parser_type === 'regex') {
    return 'Use named groups (?<name>pattern) for field extraction';
  } else if (parserForm.parser_type === 'grok') {
    return 'Use grok patterns like %{PATTERN:fieldname}';
  } else {
    return 'No pattern needed for JSON logs';
  }
}

async function testCurrentParser() {
  if (!testSample.value) {
    ElMessage.warning('Please enter a test sample');
    return;
  }

  // Build field mappings from current state
  const mappings: Record<string, string> = {};
  mappingKeys.value.forEach((key) => {
    if (parserForm.field_mappings[key]) {
      mappings[key] = parserForm.field_mappings[key];
    }
  });

  testing.value = true;
  try {
    // Test parser configuration without saving
    const response = await api.testParserConfig(
      parserForm.parser_type,
      parserForm.pattern,
      mappings,
      testSample.value
    );
    testResult.value = response.data;
  } catch (error) {
    ElMessage.error('Test failed');
  } finally {
    testing.value = false;
  }
}

async function saveParser() {
  if (!formRef.value) return;

  await formRef.value.validate(async (valid) => {
    if (!valid) return;

    // Build final field mappings
    const mappings: Record<string, string> = {};
    mappingKeys.value.forEach((key) => {
      if (parserForm.field_mappings[key]) {
        mappings[key] = parserForm.field_mappings[key];
      }
    });

    const data = {
      ...parserForm,
      field_mappings: mappings,
    };

    saving.value = true;
    try {
      if (editMode.value && selectedParser.value) {
        await api.updateParser(selectedParser.value.id, data);
        ElMessage.success('Parser updated successfully');
      } else {
        await api.createParser(data);
        ElMessage.success('Parser created successfully');
      }

      dialogVisible.value = false;
      fetchParsers();
    } catch (error: any) {
      ElMessage.error(error.response?.data?.message || 'Failed to save parser');
    } finally {
      saving.value = false;
    }
  });
}

async function toggleParser(parser: any) {
  updating.value = true;
  try {
    await api.updateParser(parser.id, { enabled: parser.enabled });
    ElMessage.success(`Parser ${parser.enabled ? 'enabled' : 'disabled'}`);
  } catch (error) {
    parser.enabled = !parser.enabled; // Revert on error
    ElMessage.error('Failed to update parser');
  } finally {
    updating.value = false;
  }
}

function testParser(parser: any) {
  selectedParser.value = parser;
  testInput.value = '';
  testResult.value = null;
  testDialogVisible.value = true;
}

async function runTest() {
  if (!testInput.value) {
    ElMessage.warning('Please enter a sample log');
    return;
  }

  testing.value = true;
  try {
    const response = await api.testParser(selectedParser.value.id, testInput.value);
    testResult.value = response.data;
  } catch (error) {
    ElMessage.error('Test failed');
  } finally {
    testing.value = false;
  }
}

async function exportParser(parser: any) {
  try {
    const res = await api.exportParser(parser.id);
    const url = URL.createObjectURL(new Blob([res.data], { type: 'application/json' }));
    const a = document.createElement('a');
    a.href = url;
    a.download = `${parser.name}.parser.json`;
    a.click();
    URL.revokeObjectURL(url);
  } catch (error) {
    ElMessage.error('Failed to export parser');
  }
}

// --- Contribute to the community catalog (browser hand-off; no token needed) ---
const contributeDialogVisible = ref(false);
const contributeLoading = ref(false);
const contributeData = ref<any>(null);

async function contributeParser(parser: any) {
  contributeData.value = null;
  contributeLoading.value = true;
  contributeDialogVisible.value = true;
  try {
    const { data } = await api.getParserContribution(parser.id);
    contributeData.value = data;
  } catch (error) {
    ElMessage.error('Failed to prepare contribution');
    contributeDialogVisible.value = false;
  } finally {
    contributeLoading.value = false;
  }
}

function openContributeUrl() {
  if (contributeData.value?.contribute_url) {
    window.open(contributeData.value.contribute_url, '_blank', 'noopener');
  }
}

async function copyContributeContent() {
  if (!contributeData.value?.content) return;
  try {
    await navigator.clipboard.writeText(contributeData.value.content);
    ElMessage.success('Copied parser JSON — you can paste it into GitHub manually');
  } catch {
    ElMessage.warning('Copy failed');
  }
}

function triggerImport() {
  importFileInput.value?.click();
}

async function onImportFileChange(e: Event) {
  const input = e.target as HTMLInputElement;
  const file = input.files?.[0];
  if (!file) return;

  let parsed: any;
  try {
    parsed = JSON.parse(await file.text());
  } catch {
    ElMessage.error('Selected file is not valid JSON');
    input.value = '';
    return;
  }
  input.value = ''; // allow re-selecting the same file later

  importParserData.value = parsed;
  importValidation.value = null;
  importSelfTest.value = null;
  try {
    const res = await api.validatePortableParser(parsed);
    importValidation.value = res.data.validation;
    importSelfTest.value = res.data.self_test;
  } catch {
    ElMessage.error('Failed to validate parser');
  }
  importDialogVisible.value = true;
}

async function doImport() {
  if (!importParserData.value) return;
  const force = !!(importSelfTest.value && !importSelfTest.value.ok);
  importing.value = true;
  try {
    const res = await api.importParser(importParserData.value, force);
    ElMessage.success(`Parser ${res.data.action} successfully`);
    importDialogVisible.value = false;
    importParserData.value = null;
    fetchParsers();
  } catch (error: any) {
    ElMessage.error(error.response?.data?.message || 'Failed to import parser');
  } finally {
    importing.value = false;
  }
}

function openCatalog() {
  catalogDialogVisible.value = true;
  if (catalog.value.length === 0) loadCatalog(false);
}

async function loadCatalog(refresh: boolean) {
  catalogLoading.value = true;
  catalogError.value = '';
  try {
    const res = await api.getCatalog(refresh);
    catalog.value = res.data.parsers || [];
    catalogSource.value = res.data.source || null;
  } catch (error: any) {
    catalogError.value = error.response?.data?.message || 'Failed to load catalog';
  } finally {
    catalogLoading.value = false;
  }
}

async function install(row: any) {
  installing.value = row.name;
  try {
    const res = await api.installCatalogParser(row.name);
    ElMessage.success(`Parser "${row.name}" ${res.data.action}`);
    await Promise.all([fetchParsers(), loadCatalog(false)]);
  } catch (error: any) {
    ElMessage.error(error.response?.data?.message || `Failed to install "${row.name}"`);
  } finally {
    installing.value = '';
  }
}

async function installAll() {
  installingAll.value = true;
  try {
    const { data } = await api.installAllCatalogParsers();
    const msg = `Parsers: ${data.installed} installed, ${data.updated} updated` +
      (data.failed?.length ? `, ${data.failed.length} failed` : '');
    if (data.failed?.length) ElMessage.warning(msg);
    else ElMessage.success(msg);
    await Promise.all([fetchParsers(), loadCatalog(false)]);
  } catch (error: any) {
    ElMessage.error(error.response?.data?.message || 'Failed to install catalog');
  } finally {
    installingAll.value = false;
  }
}

async function deleteParser(parser: any) {
  try {
    await ElMessageBox.confirm(
      `Are you sure you want to delete parser "${parser.name}"?`,
      'Confirm Delete',
      {
        confirmButtonText: 'Delete',
        cancelButtonText: 'Cancel',
        type: 'warning',
      }
    );

    await api.deleteParser(parser.id);
    ElMessage.success('Parser deleted');
    fetchParsers();
  } catch (error: any) {
    if (error !== 'cancel') {
      ElMessage.error('Failed to delete parser');
    }
  }
}
</script>

<style scoped>
.parsers {
  padding: 0;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.header-actions {
  display: flex;
  gap: 10px;
  align-items: center;
}

.import-name {
  display: flex;
  align-items: center;
  gap: 8px;
  margin: 0 0 6px;
}

.import-desc {
  color: var(--el-text-color-secondary);
  margin: 0 0 12px;
}

.selftest-failure {
  margin-top: 6px;
  font-size: 13px;
  word-break: break-word;
  overflow-wrap: anywhere;
}

.ai-hint {
  margin: 8px 0 0;
  font-size: 13px;
  color: var(--el-text-color-secondary);
}

.catalog-toolbar {
  display: flex;
  gap: 10px;
  align-items: center;
  margin-bottom: 8px;
}

.catalog-count {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

.catalog-source-line {
  margin-bottom: 12px;
}

.catalog-source {
  font-size: 13px;
  color: var(--el-text-color-secondary);
}

.catalog-sub {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

.catalog-tag {
  margin: 0 4px 4px 0;
}

.ai-preview {
  background: var(--siembox-bg-color);
  padding: 12px;
  border-radius: 4px;
  max-height: 280px;
  overflow: auto;
  font-size: 12px;
}

.field-mappings {
  width: 100%;
}

.mapping-row {
  display: flex;
  align-items: center;
  gap: 10px;
  margin-bottom: 10px;
}

pre {
  background: var(--siembox-bg-color);
  padding: 15px;
  border-radius: 4px;
  overflow-x: auto;
  font-size: 12px;
}
.contrib-issues {
  margin: 6px 0 0;
  padding-left: 18px;
  font-size: 13px;
}
.contrib-issues.error { color: var(--el-color-danger); }
.contrib-issues.warn { color: var(--el-color-warning); }
</style>
