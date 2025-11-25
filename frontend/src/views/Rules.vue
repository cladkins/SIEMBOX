<template>
  <div class="rules">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>Detection Rules</span>
          <el-button type="primary" size="small">Add Rule</el-button>
        </div>
      </template>

      <el-table :data="rules" v-loading="loading" stripe>
        <el-table-column prop="name" label="Name" min-width="250" />
        <el-table-column prop="severity" label="Severity" width="120">
          <template #default="{ row }">
            <el-tag :type="getSeverityType(row.severity)">
              {{ row.severity.toUpperCase() }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="enabled" label="Status" width="120">
          <template #default="{ row }">
            <el-tag :type="row.enabled ? 'success' : 'info'">
              {{ row.enabled ? 'Enabled' : 'Disabled' }}
            </el-tag>
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
        <el-table-column label="Actions" width="200">
          <template #default="{ row }">
            <el-button size="small">Edit</el-button>
            <el-button type="danger" size="small">Delete</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { api } from '@/services/api';

const rules = ref([]);
const loading = ref(false);

onMounted(async () => {
  loading.value = true;
  try {
    const response = await api.getRules();
    rules.value = response.data;
  } catch (error) {
    console.error('Failed to fetch rules:', error);
  } finally {
    loading.value = false;
  }
});

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
</style>
