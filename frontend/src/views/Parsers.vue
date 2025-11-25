<template>
  <div class="parsers">
    <el-card>
      <template #header>
        <div class="card-header">
          <span>Log Parsers</span>
          <el-button type="primary" size="small">Add Parser</el-button>
        </div>
      </template>

      <el-table :data="parsers" v-loading="loading" stripe>
        <el-table-column prop="name" label="Name" min-width="200" />
        <el-table-column prop="parser_type" label="Type" width="120" />
        <el-table-column prop="priority" label="Priority" width="100" sortable />
        <el-table-column prop="enabled" label="Status" width="120">
          <template #default="{ row }">
            <el-tag :type="row.enabled ? 'success' : 'info'">
              {{ row.enabled ? 'Enabled' : 'Disabled' }}
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

const parsers = ref([]);
const loading = ref(false);

onMounted(async () => {
  loading.value = true;
  try {
    const response = await api.getParsers();
    parsers.value = response.data;
  } catch (error) {
    console.error('Failed to fetch parsers:', error);
  } finally {
    loading.value = false;
  }
});
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
</style>
