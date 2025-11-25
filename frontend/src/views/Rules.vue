<template>
  <div class="rules">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>Detection Rules</span>
          <el-button type="primary" size="small" @click="showCreateDialog">
            <el-icon><Plus /></el-icon> Add Rule
          </el-button>
        </div>
      </template>

      <el-table :data="rules" v-loading="loading" stripe>
        <el-table-column prop="name" label="Name" min-width="250" />
        <el-table-column prop="severity" label="Severity" width="120" sortable>
          <template #default="{ row }">
            <el-tag :type="getSeverityType(row.severity)">
              {{ row.severity.toUpperCase() }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="enabled" label="Status" width="120">
          <template #default="{ row }">
            <el-switch
              v-model="row.enabled"
              @change="toggleRule(row)"
              :disabled="updating"
            />
          </template>
        </el-table-column>
        <el-table-column prop="tags" label="Tags" min-width="200">
          <template #default="{ row }">
            <el-tag v-for="tag in row.tags" :key="tag" size="small" style="margin-right: 5px">
              {{ tag }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="description" label="Description" min-width="300" show-overflow-tooltip />
        <el-table-column label="Actions" width="200" fixed="right">
          <template #default="{ row }">
            <el-button size="small" @click="editRule(row)">Edit</el-button>
            <el-button type="danger" size="small" @click="deleteRule(row)">Delete</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- Create/Edit Rule Dialog -->
    <el-dialog
      v-model="dialogVisible"
      :title="editMode ? 'Edit Detection Rule' : 'Create Detection Rule'"
      width="1000px"
      @close="resetForm"
    >
      <el-form :model="ruleForm" :rules="formRules" ref="formRef" label-width="120px">
        <el-form-item label="Name" prop="name">
          <el-input v-model="ruleForm.name" placeholder="e.g., SSH Brute Force Detection" />
        </el-form-item>

        <el-form-item label="Description" prop="description">
          <el-input
            v-model="ruleForm.description"
            type="textarea"
            :rows="2"
            placeholder="What does this rule detect?"
          />
        </el-form-item>

        <el-row :gutter="20">
          <el-col :span="12">
            <el-form-item label="Severity" prop="severity">
              <el-select v-model="ruleForm.severity" style="width: 100%">
                <el-option label="Critical" value="critical">
                  <el-tag type="danger">CRITICAL</el-tag>
                </el-option>
                <el-option label="High" value="high">
                  <el-tag type="warning">HIGH</el-tag>
                </el-option>
                <el-option label="Medium" value="medium">
                  <el-tag type="primary">MEDIUM</el-tag>
                </el-option>
                <el-option label="Low" value="low">
                  <el-tag type="success">LOW</el-tag>
                </el-option>
              </el-select>
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item label="Template">
              <el-select v-model="selectedTemplate" placeholder="Use a template" @change="applyTemplate" clearable>
                <el-option label="SSH Brute Force" value="ssh_brute" />
                <el-option label="Failed Authentication" value="failed_auth" />
                <el-option label="Root Login" value="root_login" />
                <el-option label="Web Scanning" value="web_scan" />
                <el-option label="Privilege Escalation" value="priv_esc" />
                <el-option label="Custom (Blank)" value="custom" />
              </el-select>
            </el-form-item>
          </el-col>
        </el-row>

        <el-form-item label="Tags" prop="tags">
          <el-select v-model="ruleForm.tags" multiple placeholder="Add tags" allow-create filterable style="width: 100%">
            <el-option label="authentication" value="authentication" />
            <el-option label="ssh" value="ssh" />
            <el-option label="web" value="web" />
            <el-option label="privilege" value="privilege" />
            <el-option label="brute-force" value="brute-force" />
            <el-option label="security" value="security" />
          </el-select>
        </el-form-item>

        <el-form-item label="Rule YAML" prop="rule_yaml">
          <div class="yaml-editor-container">
            <el-input
              v-model="ruleForm.rule_yaml"
              type="textarea"
              :rows="15"
              placeholder="Enter YAML rule definition..."
              class="yaml-editor"
            />
            <div class="yaml-help">
              <el-text size="small" type="info">
                <strong>YAML Rule Format:</strong><br>
                conditions: List of field conditions to match<br>
                aggregation: Count events over timeframe (optional)<br>
                actions: Define alert title and description with variables
              </el-text>
            </div>
          </div>
          <el-button type="info" size="small" @click="validateYaml" style="margin-top: 10px">
            <el-icon><CircleCheck /></el-icon> Validate YAML
          </el-button>
        </el-form-item>

        <el-alert v-if="yamlError" type="error" :title="yamlError" :closable="false" style="margin-bottom: 20px" />
        <el-alert v-if="yamlValid" type="success" title="YAML is valid!" :closable="false" style="margin-bottom: 20px" />
      </el-form>

      <template #footer>
        <el-button @click="dialogVisible = false">Cancel</el-button>
        <el-button type="primary" @click="saveRule" :loading="saving">
          {{ editMode ? 'Update' : 'Create' }} Rule
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, reactive } from 'vue';
import { api } from '@/services/api';
import { ElMessage, ElMessageBox, FormInstance, FormRules } from 'element-plus';
import { Plus, CircleCheck } from '@element-plus/icons-vue';
import yaml from 'js-yaml';

const rules = ref<any[]>([]);
const loading = ref(false);
const updating = ref(false);
const saving = ref(false);

const dialogVisible = ref(false);
const editMode = ref(false);
const selectedRule = ref<any>(null);
const selectedTemplate = ref('');

const formRef = ref<FormInstance>();
const ruleForm = reactive({
  name: '',
  description: '',
  severity: 'medium',
  rule_yaml: '',
  tags: [] as string[],
  enabled: true,
});

const yamlError = ref('');
const yamlValid = ref(false);

const formRules: FormRules = {
  name: [{ required: true, message: 'Name is required', trigger: 'blur' }],
  severity: [{ required: true, message: 'Severity is required', trigger: 'change' }],
  rule_yaml: [{ required: true, message: 'Rule YAML is required', trigger: 'blur' }],
};

const ruleTemplates = {
  ssh_brute: {
    name: 'SSH Brute Force Detection',
    description: 'Detects multiple failed SSH authentication attempts from the same source',
    severity: 'high',
    tags: ['ssh', 'authentication', 'brute-force'],
    rule_yaml: `conditions:
  - field: event_type
    operator: equals
    value: ssh_auth
  - field: status
    operator: equals
    value: failed

aggregation:
  field: source_ip
  timeframe: 5m
  threshold: 5

actions:
  alert:
    title: "SSH Brute Force Attack Detected"
    description: "Multiple failed SSH login attempts from {{source_ip}} ({{count}} attempts in 5 minutes)"`,
  },
  failed_auth: {
    name: 'Failed Authentication Alert',
    description: 'Detects failed authentication attempts',
    severity: 'medium',
    tags: ['authentication', 'security'],
    rule_yaml: `conditions:
  - field: event_type
    operator: contains
    value: auth
  - field: status
    operator: equals
    value: failed

actions:
  alert:
    title: "Failed Authentication Attempt"
    description: "Failed authentication from {{source_ip}} for user {{username}}"`,
  },
  root_login: {
    name: 'Root Login Detection',
    description: 'Alerts on successful root or administrator logins',
    severity: 'critical',
    tags: ['authentication', 'privilege'],
    rule_yaml: `conditions:
  - field: event_type
    operator: equals
    value: ssh_auth
  - field: username
    operator: equals
    value: root
  - field: status
    operator: equals
    value: success

actions:
  alert:
    title: "Root Login Detected"
    description: "Root login from {{source_ip}} at {{timestamp}}"`,
  },
  web_scan: {
    name: 'Web Vulnerability Scanning',
    description: 'Detects potential web vulnerability scanning activity',
    severity: 'high',
    tags: ['web', 'security', 'scanning'],
    rule_yaml: `conditions:
  - field: event_type
    operator: equals
    value: http_request
  - field: status_code
    operator: equals
    value: 404

aggregation:
  field: source_ip
  timeframe: 1m
  threshold: 20

actions:
  alert:
    title: "Web Scanning Detected"
    description: "Potential web scan from {{source_ip}} ({{count}} 404 errors in 1 minute)"`,
  },
  priv_esc: {
    name: 'Privilege Escalation Detection',
    description: 'Detects sudo or privilege escalation attempts',
    severity: 'critical',
    tags: ['privilege', 'security'],
    rule_yaml: `conditions:
  - field: event_type
    operator: equals
    value: sudo
  - field: command
    operator: contains
    value: root

actions:
  alert:
    title: "Privilege Escalation Detected"
    description: "User {{username}} executed sudo command: {{command}}"`,
  },
  custom: {
    name: '',
    description: '',
    severity: 'medium',
    tags: [],
    rule_yaml: `conditions:
  - field:
    operator: equals
    value:

actions:
  alert:
    title: ""
    description: ""`,
  },
};

onMounted(fetchRules);

async function fetchRules() {
  loading.value = true;
  try {
    const response = await api.getRules();
    rules.value = response.data;
  } catch (error) {
    ElMessage.error('Failed to fetch rules');
  } finally {
    loading.value = false;
  }
}

function showCreateDialog() {
  editMode.value = false;
  resetForm();
  dialogVisible.value = true;
}

function editRule(rule: any) {
  editMode.value = true;
  selectedRule.value = rule;

  Object.assign(ruleForm, {
    name: rule.name,
    description: rule.description,
    severity: rule.severity,
    rule_yaml: rule.rule_yaml,
    tags: rule.tags || [],
    enabled: rule.enabled,
  });

  dialogVisible.value = true;
}

function resetForm() {
  Object.assign(ruleForm, {
    name: '',
    description: '',
    severity: 'medium',
    rule_yaml: '',
    tags: [],
    enabled: true,
  });
  selectedTemplate.value = '';
  yamlError.value = '';
  yamlValid.value = false;
  formRef.value?.clearValidate();
}

function applyTemplate() {
  if (!selectedTemplate.value) return;

  const template = ruleTemplates[selectedTemplate.value as keyof typeof ruleTemplates];
  if (template) {
    ruleForm.name = template.name;
    ruleForm.description = template.description;
    ruleForm.severity = template.severity;
    ruleForm.rule_yaml = template.rule_yaml;
    ruleForm.tags = [...template.tags];
    yamlError.value = '';
    yamlValid.value = false;
  }
}

function validateYaml() {
  yamlError.value = '';
  yamlValid.value = false;

  if (!ruleForm.rule_yaml) {
    yamlError.value = 'YAML cannot be empty';
    return;
  }

  try {
    const parsed = yaml.load(ruleForm.rule_yaml) as any;

    // Validate structure
    if (!parsed.conditions || !Array.isArray(parsed.conditions)) {
      yamlError.value = 'YAML must contain a "conditions" array';
      return;
    }

    if (!parsed.actions || !parsed.actions.alert) {
      yamlError.value = 'YAML must contain "actions.alert" with title and description';
      return;
    }

    // Validate conditions
    for (const condition of parsed.conditions) {
      if (!condition.field || !condition.operator || condition.value === undefined) {
        yamlError.value = 'Each condition must have field, operator, and value';
        return;
      }
    }

    // Validate aggregation if present
    if (parsed.aggregation) {
      if (!parsed.aggregation.field || !parsed.aggregation.timeframe || !parsed.aggregation.threshold) {
        yamlError.value = 'Aggregation must have field, timeframe, and threshold';
        return;
      }
    }

    yamlValid.value = true;
    ElMessage.success('YAML validation passed!');
  } catch (error: any) {
    yamlError.value = `YAML parsing error: ${error.message}`;
  }
}

async function saveRule() {
  if (!formRef.value) return;

  await formRef.value.validate(async (valid) => {
    if (!valid) return;

    // Validate YAML before saving
    yamlError.value = '';
    try {
      yaml.load(ruleForm.rule_yaml);
    } catch (error: any) {
      yamlError.value = `Invalid YAML: ${error.message}`;
      ElMessage.error('Please fix YAML errors before saving');
      return;
    }

    const data = {
      name: ruleForm.name,
      description: ruleForm.description,
      severity: ruleForm.severity,
      rule_yaml: ruleForm.rule_yaml,
      tags: ruleForm.tags,
      enabled: ruleForm.enabled,
    };

    saving.value = true;
    try {
      if (editMode.value && selectedRule.value) {
        await api.updateRule(selectedRule.value.id, data);
        ElMessage.success('Rule updated successfully');
      } else {
        await api.createRule(data);
        ElMessage.success('Rule created successfully');
      }

      dialogVisible.value = false;
      fetchRules();
    } catch (error: any) {
      ElMessage.error(error.response?.data?.message || 'Failed to save rule');
    } finally {
      saving.value = false;
    }
  });
}

async function toggleRule(rule: any) {
  updating.value = true;
  try {
    await api.updateRule(rule.id, { enabled: rule.enabled });
    ElMessage.success(`Rule ${rule.enabled ? 'enabled' : 'disabled'}`);
  } catch (error) {
    rule.enabled = !rule.enabled; // Revert on error
    ElMessage.error('Failed to update rule');
  } finally {
    updating.value = false;
  }
}

async function deleteRule(rule: any) {
  try {
    await ElMessageBox.confirm(
      `Are you sure you want to delete rule "${rule.name}"?`,
      'Confirm Delete',
      {
        confirmButtonText: 'Delete',
        cancelButtonText: 'Cancel',
        type: 'warning',
      }
    );

    await api.deleteRule(rule.id);
    ElMessage.success('Rule deleted');
    fetchRules();
  } catch (error: any) {
    if (error !== 'cancel') {
      ElMessage.error('Failed to delete rule');
    }
  }
}

const getSeverityType = (severity: string) => {
  const types: Record<string, any> = {
    critical: 'danger',
    high: 'warning',
    medium: 'primary',
    low: 'success',
  };
  return types[severity] || 'info';
};
</script>

<style scoped>
.rules {
  padding: 0;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.yaml-editor-container {
  width: 100%;
}

.yaml-editor {
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', monospace;
  font-size: 13px;
}

.yaml-editor :deep(textarea) {
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', monospace;
  font-size: 13px;
  line-height: 1.5;
}

.yaml-help {
  margin-top: 10px;
  padding: 10px;
  background: #f5f7fa;
  border-radius: 4px;
  font-size: 12px;
}
</style>
