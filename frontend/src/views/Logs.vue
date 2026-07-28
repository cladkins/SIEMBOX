<template>
  <div class="logs">
    <el-card class="filter-card">
      <el-form :inline="true" :model="filters" class="filter-form">
        <el-form-item label="Search">
          <el-input
            v-model="filters.search"
            placeholder="Search in logs..."
            clearable
            style="width: 300px"
            @keyup.enter="applyFilters"
          >
            <template #prefix>
              <el-icon><Search /></el-icon>
            </template>
          </el-input>
        </el-form-item>

        <el-form-item label="Source IP">
          <el-input
            v-model="filters.source_ip"
            placeholder="e.g., 192.168.1.1"
            clearable
            style="width: 180px"
          />
        </el-form-item>

        <el-form-item label="Event Type" v-if="activeTab === 'parsed'">
          <el-input
            v-model="filters.event_type"
            placeholder="e.g., ssh_auth"
            clearable
            style="width: 180px"
          />
        </el-form-item>

        <el-form-item label="Source">
          <el-input
            v-model="filters.app_name"
            placeholder="e.g., sshd, nginx"
            clearable
            style="width: 180px"
          />
        </el-form-item>

        <el-form-item label="Parser" v-if="activeTab === 'parsed'">
          <el-select
            v-model="filters.parser_id"
            placeholder="All Parsers"
            clearable
            filterable
            style="width: 200px"
            @change="applyFilters"
          >
            <el-option v-for="p in parsers" :key="p.id" :label="p.name" :value="p.id" />
          </el-select>
        </el-form-item>

        <!-- Unparsed logs live in parsed_logs too (generic fallback record, no
             parser, no detections) — this is how you separate the two. -->
        <el-form-item label="Parse Status" v-if="activeTab === 'parsed'">
          <el-select
            v-model="filters.parse_status"
            placeholder="All"
            clearable
            style="width: 160px"
            @change="applyFilters"
          >
            <el-option label="Parsed only" value="parsed" />
            <el-option label="Unparsed only" value="unparsed" />
          </el-select>
        </el-form-item>

        <!-- Syslog PRI severity only exists on the raw record. -->
        <el-form-item label="Severity" v-if="activeTab === 'raw'">
          <el-select
            v-model="filters.severity"
            placeholder="All Severities"
            clearable
            style="width: 160px"
          >
            <el-option label="Emergency" :value="0" />
            <el-option label="Alert" :value="1" />
            <el-option label="Critical" :value="2" />
            <el-option label="Error" :value="3" />
            <el-option label="Warning" :value="4" />
            <el-option label="Notice" :value="5" />
            <el-option label="Info" :value="6" />
            <el-option label="Debug" :value="7" />
          </el-select>
        </el-form-item>

        <el-form-item label="Date Range">
          <el-date-picker
            v-model="dateRange"
            type="datetimerange"
            range-separator="to"
            start-placeholder="Start date"
            end-placeholder="End date"
            style="width: 380px"
            @change="applyFilters"
          />
        </el-form-item>

        <el-form-item>
          <el-button type="primary" @click="applyFilters">
            <el-icon><Search /></el-icon> Search
          </el-button>
          <el-button @click="resetFilters">Reset</el-button>
          <el-button @click="exportLogs" :loading="exporting">
            <el-icon><Download /></el-icon> Export
          </el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-tabs v-model="activeTab" @tab-change="handleTabChange">
      <el-tab-pane label="Parsed Logs" name="parsed">
        <el-card>
          <el-table :data="parsedLogs" v-loading="loading" stripe max-height="600">
            <el-table-column prop="timestamp" label="Timestamp" width="180" sortable>
              <template #default="{ row }">
                {{ formatDate(row.timestamp) }}
              </template>
            </el-table-column>
            <el-table-column prop="source_ip" label="Source IP" width="150" />
            <el-table-column prop="app_name" label="Source" width="150">
              <template #default="{ row }">
                <el-tooltip
                  v-if="row.app_name"
                  content="Syslog tag (program) of the originating raw log"
                  placement="top"
                >
                  <el-tag type="success" size="small">{{ row.app_name }}</el-tag>
                </el-tooltip>
                <el-text v-else type="info" size="small">N/A</el-text>
              </template>
            </el-table-column>
            <el-table-column prop="event_type" label="Event Type" width="180">
              <template #default="{ row }">
                <el-tag v-if="row.event_type" :type="row.event_type === 'unparsed' ? 'info' : undefined" size="small">
                  {{ row.event_type }}
                </el-tag>
                <el-text v-else type="info" size="small">N/A</el-text>
              </template>
            </el-table-column>
            <!-- parser_id IS NULL means no parser matched — a known state, not
                 an unknown one, so "Unknown" read as a bug. (Deleting a parser
                 also lands rows here: the FK is ON DELETE SET NULL, so its
                 historical logs become unparsed rather than orphaned.) -->
            <el-table-column prop="parser_name" label="Parser" width="180">
              <template #default="{ row }">
                <el-tag v-if="row.parser_name" type="warning" size="small" effect="plain">{{ row.parser_name }}</el-tag>
                <el-tooltip
                  v-else
                  content="No parser matched — or the parser that matched was deleted. Stored so the log stays searchable, but detection rules do not run on it."
                  placement="top"
                >
                  <el-tag type="info" size="small" effect="plain">Unparsed</el-tag>
                </el-tooltip>
              </template>
            </el-table-column>
            <el-table-column label="Parsed Data">
              <template #default="{ row }">
                <el-popover placement="left" width="600" trigger="click">
                  <template #reference>
                    <el-button size="small">View Data</el-button>
                  </template>
                  <div class="json-viewer">
                    <pre class="json-data">{{ JSON.stringify(row.parsed_data, null, 2) }}</pre>
                  </div>
                </el-popover>
              </template>
            </el-table-column>
          </el-table>

          <el-pagination
            v-model:current-page="parsedPage"
            v-model:page-size="pageSize"
            :page-sizes="[20, 50, 100, 200]"
            :total="parsedTotal"
            layout="total, sizes, prev, pager, next"
            @current-change="fetchParsedLogs"
            @size-change="fetchParsedLogs"
            class="pagination"
          />
        </el-card>
      </el-tab-pane>

      <el-tab-pane label="Raw Logs" name="raw">
        <el-card>
          <el-table :data="rawLogs" v-loading="loading" stripe max-height="600">
            <el-table-column prop="timestamp" label="Timestamp" width="180" sortable>
              <template #default="{ row }">
                {{ formatDate(row.timestamp) }}
              </template>
            </el-table-column>
            <el-table-column prop="source_ip" label="Source IP" width="150" />
            <el-table-column prop="hostname" label="Hostname" width="180" />
            <!-- Same field the Parsed Logs tab shows as "Source": the syslog tag
                 parsed off the header. Parsed Logs reads it via a join on
                 raw_log_id, so both tabs label the identical value. -->
            <el-table-column prop="app_name" label="Source" width="150">
              <template #default="{ row }">
                <el-tag v-if="row.app_name" type="success" size="small">{{ row.app_name }}</el-tag>
                <el-text v-else type="info" size="small">N/A</el-text>
              </template>
            </el-table-column>
            <el-table-column prop="facility" label="Facility" width="100">
              <template #default="{ row }">
                <el-tag v-if="row.facility !== null" size="small">
                  {{ getFacilityName(row.facility) }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="severity" label="Severity" width="100">
              <template #default="{ row }">
                <el-tag v-if="row.severity !== null" :type="getSeverityColor(row.severity)" size="small">
                  {{ getSeverityName(row.severity) }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="raw_message" label="Message" min-width="400" show-overflow-tooltip />
          </el-table>

          <el-pagination
            v-model:current-page="rawPage"
            v-model:page-size="pageSize"
            :page-sizes="[20, 50, 100, 200]"
            :total="rawTotal"
            layout="total, sizes, prev, pager, next"
            @current-change="fetchRawLogs"
            @size-change="fetchRawLogs"
            class="pagination"
          />
        </el-card>
      </el-tab-pane>
    </el-tabs>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, reactive } from 'vue';
import { api } from '@/services/api';
import { ElMessage } from 'element-plus';
import { format } from 'date-fns';
import { Search, Download } from '@element-plus/icons-vue';

const activeTab = ref('parsed');
const loading = ref(false);
const exporting = ref(false);

const rawLogs = ref([]);
const parsedLogs = ref([]);
const rawPage = ref(1);
const parsedPage = ref(1);
const pageSize = ref(20);
const rawTotal = ref(0);
const parsedTotal = ref(0);

const filters = reactive({
  search: '',
  source_ip: '',
  event_type: '',
  app_name: '',
  parser_id: null as number | null,
  parse_status: '' as '' | 'parsed' | 'unparsed',
  severity: null as number | null,
});

const dateRange = ref<[Date, Date] | null>(null);

// Parser list powers the "Parser" filter dropdown.
const parsers = ref<{ id: number; name: string }[]>([]);

const loadParsers = async () => {
  try {
    const res = await api.getParsers();
    parsers.value = (res.data || []).map((p: any) => ({ id: p.id, name: p.name }));
  } catch {
    // Non-fatal: the filter just stays empty if parsers can't be loaded.
  }
};

onMounted(() => {
  fetchParsedLogs();
  loadParsers();
});

// Only send the filters the active tab's endpoint actually supports. Both tabs
// share one filter bar, so sending e.g. severity to /logs/parsed (which has no
// severity) would look like a filter that silently does nothing.
const buildQueryParams = () => {
  const isRaw = activeTab.value === 'raw';

  const params: any = {
    limit: pageSize.value,
    offset: ((isRaw ? rawPage.value : parsedPage.value) - 1) * pageSize.value,
  };

  if (filters.search) {
    params.search = filters.search;
  }

  if (filters.source_ip) {
    params.source_ip = filters.source_ip;
  }

  // app_name is the "Source" on both tabs (raw_logs.app_name, joined into the
  // parsed rows), so it is the one field that filters identically on each.
  if (filters.app_name) {
    params.app_name = filters.app_name;
  }

  if (isRaw) {
    if (filters.severity !== null && filters.severity !== undefined) {
      params.severity = filters.severity;
    }
  } else {
    if (filters.event_type) {
      params.event_type = filters.event_type;
    }

    if (filters.parser_id !== null && filters.parser_id !== undefined) {
      params.parser_id = filters.parser_id;
    }

    if (filters.parse_status) {
      params.parse_status = filters.parse_status;
    }
  }

  if (dateRange.value && dateRange.value.length === 2) {
    params.start_date = dateRange.value[0].toISOString();
    params.end_date = dateRange.value[1].toISOString();
  }

  return params;
};

const fetchRawLogs = async () => {
  loading.value = true;
  try {
    const params = buildQueryParams();
    const response = await api.getRawLogs(params);
    rawLogs.value = response.data.logs;
    rawTotal.value = response.data.total;
  } catch (error) {
    ElMessage.error('Failed to fetch raw logs');
  } finally {
    loading.value = false;
  }
};

const fetchParsedLogs = async () => {
  loading.value = true;
  try {
    const params = buildQueryParams();
    const response = await api.getParsedLogs(params);
    parsedLogs.value = response.data.logs;
    parsedTotal.value = response.data.total;
  } catch (error) {
    ElMessage.error('Failed to fetch parsed logs');
  } finally {
    loading.value = false;
  }
};

const applyFilters = () => {
  // Reset to first page when applying filters
  rawPage.value = 1;
  parsedPage.value = 1;

  if (activeTab.value === 'raw') {
    fetchRawLogs();
  } else {
    fetchParsedLogs();
  }
};

const resetFilters = () => {
  filters.search = '';
  filters.source_ip = '';
  filters.event_type = '';
  filters.app_name = '';
  filters.parser_id = null;
  filters.parse_status = '';
  filters.severity = null;
  dateRange.value = null;
  applyFilters();
};

// Re-query on tab change: the two endpoints take different filters, so a cached
// page from before a filter changed would show a stale, unfiltered result.
const handleTabChange = () => {
  if (activeTab.value === 'raw') {
    fetchRawLogs();
  } else {
    fetchParsedLogs();
  }
};

const exportLogs = async () => {
  exporting.value = true;
  try {
    const params = buildQueryParams();
    params.limit = 10000; // Export up to 10k logs
    params.offset = 0;

    const response =
      activeTab.value === 'raw'
        ? await api.getRawLogs(params)
        : await api.getParsedLogs(params);

    const logs = response.data.logs;

    if (logs.length === 0) {
      ElMessage.warning('No logs to export');
      return;
    }

    // Convert to CSV
    const csv = convertToCSV(logs, activeTab.value);
    const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    const url = URL.createObjectURL(blob);

    link.setAttribute('href', url);
    link.setAttribute('download', `${activeTab.value}_logs_${Date.now()}.csv`);
    link.style.visibility = 'hidden';

    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);

    ElMessage.success(`Exported ${logs.length} logs`);
  } catch (error) {
    ElMessage.error('Failed to export logs');
  } finally {
    exporting.value = false;
  }
};

const convertToCSV = (logs: any[], type: string): string => {
  if (logs.length === 0) return '';

  if (type === 'raw') {
    const headers = ['Timestamp', 'Source IP', 'Hostname', 'Source', 'Facility', 'Severity', 'Raw Message'];
    const rows = logs.map((log) => [
      log.timestamp,
      log.source_ip || '',
      log.hostname || '',
      log.app_name || '',
      log.facility !== null ? getFacilityName(log.facility) : '',
      log.severity !== null ? getSeverityName(log.severity) : '',
      `"${(log.raw_message || '').replace(/"/g, '""')}"`,
    ]);

    return [headers.join(','), ...rows.map((row) => row.join(','))].join('\n');
  } else {
    const headers = ['Timestamp', 'Source IP', 'Source', 'Parser', 'Event Type', 'Parsed Data'];
    const rows = logs.map((log) => [
      log.timestamp,
      log.source_ip || '',
      log.app_name || '',
      log.parser_name || 'Unparsed',
      log.event_type || '',
      `"${JSON.stringify(log.parsed_data || {}).replace(/"/g, '""')}"`,
    ]);

    return [headers.join(','), ...rows.map((row) => row.join(','))].join('\n');
  }
};

const formatDate = (date: string) => {
  return format(new Date(date), 'MMM dd, yyyy HH:mm:ss');
};

const getFacilityName = (facility: number): string => {
  const facilities = [
    'kern', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news',
    'uucp', 'cron', 'authpriv', 'ftp', 'ntp', 'security', 'console', 'solaris-cron',
    'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7',
  ];
  return facilities[facility] || `facility${facility}`;
};

const getSeverityName = (severity: number): string => {
  const severities = ['Emergency', 'Alert', 'Critical', 'Error', 'Warning', 'Notice', 'Info', 'Debug'];
  return severities[severity] || `sev${severity}`;
};

const getSeverityColor = (severity: number): string => {
  if (severity <= 2) return 'danger';
  if (severity <= 4) return 'warning';
  if (severity <= 5) return 'primary';
  return 'info';
};
</script>

<style scoped>
.logs {
  padding: 0;
}

.filter-card {
  margin-bottom: 20px;
}

.filter-form {
  margin: 0;
}

.pagination {
  margin-top: 20px;
  display: flex;
  justify-content: flex-end;
}

.json-viewer {
  max-height: 500px;
  overflow-y: auto;
}

.json-data {
  background: var(--siembox-bg-color);
  padding: 15px;
  border-radius: 4px;
  overflow-x: auto;
  font-size: 12px;
  margin: 0;
}
</style>
