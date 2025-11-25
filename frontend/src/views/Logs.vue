<template>
  <div class="logs">
    <el-tabs v-model="activeTab">
      <el-tab-pane label="Parsed Logs" name="parsed">
        <el-card>
          <el-table :data="parsedLogs" v-loading="loading" stripe max-height="600">
            <el-table-column prop="timestamp" label="Timestamp" width="180">
              <template #default="{ row }">
                {{ formatDate(row.timestamp) }}
              </template>
            </el-table-column>
            <el-table-column prop="source_ip" label="Source IP" width="150" />
            <el-table-column prop="event_type" label="Event Type" width="180" />
            <el-table-column label="Parsed Data">
              <template #default="{ row }">
                <el-popover placement="left" width="500" trigger="click">
                  <template #reference>
                    <el-button size="small">View Data</el-button>
                  </template>
                  <pre class="json-data">{{ JSON.stringify(row.parsed_data, null, 2) }}</pre>
                </el-popover>
              </template>
            </el-table-column>
          </el-table>

          <el-pagination
            v-model:current-page="parsedPage"
            v-model:page-size="pageSize"
            :total="parsedTotal"
            layout="total, prev, pager, next"
            @current-change="fetchParsedLogs"
            class="pagination"
          />
        </el-card>
      </el-tab-pane>

      <el-tab-pane label="Raw Logs" name="raw">
        <el-card>
          <el-table :data="rawLogs" v-loading="loading" stripe max-height="600">
            <el-table-column prop="timestamp" label="Timestamp" width="180">
              <template #default="{ row }">
                {{ formatDate(row.timestamp) }}
              </template>
            </el-table-column>
            <el-table-column prop="source_ip" label="Source IP" width="150" />
            <el-table-column prop="hostname" label="Hostname" width="180" />
            <el-table-column prop="raw_message" label="Message" min-width="400" show-overflow-tooltip />
          </el-table>

          <el-pagination
            v-model:current-page="rawPage"
            v-model:page-size="pageSize"
            :total="rawTotal"
            layout="total, prev, pager, next"
            @current-change="fetchRawLogs"
            class="pagination"
          />
        </el-card>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue';
import { api } from '@/services/api';
import { format } from 'date-fns';

const activeTab = ref('parsed');
const loading = ref(false);

const rawLogs = ref([]);
const parsedLogs = ref([]);
const rawPage = ref(1);
const parsedPage = ref(1);
const pageSize = ref(20);
const rawTotal = ref(0);
const parsedTotal = ref(0);

onMounted(() => {
  fetchParsedLogs();
});

const fetchRawLogs = async () => {
  loading.value = true;
  try {
    const response = await api.getRawLogs({
      limit: pageSize.value,
      offset: (rawPage.value - 1) * pageSize.value,
    });
    rawLogs.value = response.data.logs;
    rawTotal.value = response.data.total;
  } catch (error) {
    console.error('Failed to fetch raw logs:', error);
  } finally {
    loading.value = false;
  }
};

const fetchParsedLogs = async () => {
  loading.value = true;
  try {
    const response = await api.getParsedLogs({
      limit: pageSize.value,
      offset: (parsedPage.value - 1) * pageSize.value,
    });
    parsedLogs.value = response.data.logs;
    parsedTotal.value = response.data.total;
  } catch (error) {
    console.error('Failed to fetch parsed logs:', error);
  } finally {
    loading.value = false;
  }
};

const formatDate = (date: string) => {
  return format(new Date(date), 'MMM dd, yyyy HH:mm:ss');
};
</script>

<style scoped>
.logs {
  padding: 0;
}

.pagination {
  margin-top: 20px;
  display: flex;
  justify-content: flex-end;
}

.json-data {
  background: #f5f7fa;
  padding: 15px;
  border-radius: 4px;
  overflow-x: auto;
  font-size: 12px;
  max-height: 400px;
  overflow-y: auto;
}
</style>
