<template>
  <div class="parsers">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>Log Parsers</span>
          <el-button type="primary" size="small" @click="showCreateDialog">
            <el-icon><Plus /></el-icon> Add Parser
          </el-button>
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
        <el-table-column label="Actions" width="250" fixed="right">
          <template #default="{ row }">
            <el-button size="small" @click="testParser(row)">Test</el-button>
            <el-button size="small" @click="editParser(row)">Edit</el-button>
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
            <div v-for="(value, key, index) in parserForm.field_mappings" :key="index" class="mapping-row">
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
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, reactive } from 'vue';
import { api } from '@/services/api';
import { ElMessage, ElMessageBox, FormInstance, FormRules } from 'element-plus';
import { Plus, Delete, Right, CircleCheck } from '@element-plus/icons-vue';

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
  background: #f5f7fa;
  padding: 15px;
  border-radius: 4px;
  overflow-x: auto;
  font-size: 12px;
}
</style>
