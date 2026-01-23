<template>
  <div class="templates-container">
    <!-- Stats Overview -->
    <el-row :gutter="20" class="stats-row">
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-value">{{ stats.totalTemplates.toLocaleString() }}</div>
          <div class="stat-label">Total Templates</div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-value">{{ stats.categories }}</div>
          <div class="stat-label">Categories</div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card">
          <div class="stat-value">{{ stats.tags }}</div>
          <div class="stat-label">Unique Tags</div>
        </el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="hover" class="stat-card severity-card">
          <div class="severity-breakdown">
            <span class="severity critical">{{ stats.severityCounts.critical }}</span>
            <span class="severity high">{{ stats.severityCounts.high }}</span>
            <span class="severity medium">{{ stats.severityCounts.medium }}</span>
            <span class="severity low">{{ stats.severityCounts.low }}</span>
            <span class="severity info">{{ stats.severityCounts.info }}</span>
          </div>
          <div class="stat-label">By Severity</div>
        </el-card>
      </el-col>
    </el-row>

    <!-- Search and Filters -->
    <el-card class="filter-card">
      <el-row :gutter="20" align="middle">
        <el-col :span="8">
          <el-input
            v-model="searchQuery"
            placeholder="Search templates by name, CVE, description..."
            clearable
            @input="debouncedSearch"
          >
            <template #prefix>
              <el-icon><Search /></el-icon>
            </template>
          </el-input>
        </el-col>
        <el-col :span="6">
          <el-select v-model="selectedCategory" placeholder="Filter by Category" clearable @change="handleCategoryChange">
            <el-option
              v-for="cat in categories"
              :key="cat.id"
              :label="`${cat.name} (${cat.count})`"
              :value="cat.id"
            />
          </el-select>
        </el-col>
        <el-col :span="6">
          <el-select v-model="selectedSeverity" placeholder="Filter by Severity" clearable @change="handleSeverityChange">
            <el-option label="Critical" value="critical" />
            <el-option label="High" value="high" />
            <el-option label="Medium" value="medium" />
            <el-option label="Low" value="low" />
            <el-option label="Info" value="info" />
          </el-select>
        </el-col>
        <el-col :span="4">
          <el-button @click="refreshTemplates" :loading="loading">
            <el-icon><Refresh /></el-icon>
            Refresh
          </el-button>
        </el-col>
      </el-row>
    </el-card>

    <!-- Categories Grid (when no search/filter active) -->
    <div v-if="!searchQuery && !selectedCategory && !selectedSeverity" class="categories-section">
      <h3>Browse by Category</h3>
      <el-row :gutter="20">
        <el-col :span="6" v-for="cat in categories" :key="cat.id">
          <el-card
            shadow="hover"
            class="category-card"
            @click="selectedCategory = cat.id"
          >
            <div class="category-icon">
              <el-icon :size="32"><Folder /></el-icon>
            </div>
            <div class="category-name">{{ cat.name }}</div>
            <div class="category-count">{{ cat.count.toLocaleString() }} templates</div>
            <div class="category-description">{{ cat.description }}</div>
          </el-card>
        </el-col>
      </el-row>
    </div>

    <!-- Popular Tags -->
    <div v-if="!searchQuery && !selectedCategory && !selectedSeverity" class="tags-section">
      <h3>Popular Tags</h3>
      <div class="tags-cloud">
        <el-tag
          v-for="tag in topTags"
          :key="tag.name"
          class="tag-item"
          :type="getTagType(tag.name)"
          effect="plain"
          @click="searchByTag(tag.name)"
        >
          {{ tag.name }} ({{ tag.count }})
        </el-tag>
      </div>
    </div>

    <!-- Templates Table -->
    <el-card v-if="searchQuery || selectedCategory || selectedSeverity" class="templates-table-card">
      <template #header>
        <div class="card-header">
          <span>
            {{ filteredTemplates.length }} Templates
            <span v-if="selectedCategory"> in {{ getCategoryName(selectedCategory) }}</span>
            <span v-if="selectedSeverity"> with {{ selectedSeverity }} severity</span>
            <span v-if="searchQuery"> matching "{{ searchQuery }}"</span>
          </span>
          <el-button text @click="clearFilters">Clear Filters</el-button>
        </div>
      </template>

      <el-table
        :data="paginatedTemplates"
        v-loading="loading"
        style="width: 100%"
        @row-click="showTemplateDetails"
        row-class-name="clickable-row"
      >
        <el-table-column prop="id" label="Template ID" width="280">
          <template #default="{ row }">
            <div class="template-id">
              <el-icon><Document /></el-icon>
              {{ row.id }}
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="name" label="Name" min-width="200">
          <template #default="{ row }">
            <div class="template-name">{{ row.name }}</div>
            <div class="template-description" v-if="row.description">
              {{ truncate(row.description, 80) }}
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="severity" label="Severity" width="100">
          <template #default="{ row }">
            <el-tag :type="getSeverityType(row.severity)" size="small">
              {{ row.severity }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="category" label="Category" width="140" />
        <el-table-column prop="tags" label="Tags" min-width="200">
          <template #default="{ row }">
            <div class="tags-cell">
              <el-tag
                v-for="tag in row.tags.slice(0, 3)"
                :key="tag"
                size="small"
                type="info"
                class="tag-mini"
              >
                {{ tag }}
              </el-tag>
              <span v-if="row.tags.length > 3" class="more-tags">
                +{{ row.tags.length - 3 }}
              </span>
            </div>
          </template>
        </el-table-column>
        <el-table-column prop="author" label="Author" width="120" />
      </el-table>

      <!-- Pagination -->
      <div class="pagination-container">
        <el-pagination
          v-model:current-page="currentPage"
          v-model:page-size="pageSize"
          :page-sizes="[25, 50, 100, 200]"
          :total="filteredTemplates.length"
          layout="total, sizes, prev, pager, next, jumper"
          @size-change="handlePageSizeChange"
          @current-change="handlePageChange"
        />
      </div>
    </el-card>

    <!-- Template Details Dialog -->
    <el-dialog
      v-model="detailsDialogVisible"
      :title="selectedTemplate?.name || 'Template Details'"
      width="700px"
    >
      <div v-if="selectedTemplate" class="template-details">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="Template ID" :span="2">
            <code>{{ selectedTemplate.id }}</code>
          </el-descriptions-item>
          <el-descriptions-item label="Name" :span="2">
            {{ selectedTemplate.name }}
          </el-descriptions-item>
          <el-descriptions-item label="Severity">
            <el-tag :type="getSeverityType(selectedTemplate.severity)">
              {{ selectedTemplate.severity }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="Category">
            {{ selectedTemplate.category }}
          </el-descriptions-item>
          <el-descriptions-item label="Author" :span="2">
            {{ selectedTemplate.author || 'Unknown' }}
          </el-descriptions-item>
          <el-descriptions-item label="Description" :span="2">
            {{ selectedTemplate.description || 'No description available' }}
          </el-descriptions-item>
          <el-descriptions-item label="CVE ID" :span="2" v-if="selectedTemplate.cveId">
            <el-link
              :href="`https://nvd.nist.gov/vuln/detail/${selectedTemplate.cveId}`"
              target="_blank"
              type="primary"
            >
              {{ selectedTemplate.cveId }}
            </el-link>
          </el-descriptions-item>
          <el-descriptions-item label="CVSS Score" v-if="selectedTemplate.cvssScore">
            <el-tag :type="getCvssType(selectedTemplate.cvssScore)">
              {{ selectedTemplate.cvssScore }}
            </el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="Tags" :span="2">
            <div class="details-tags">
              <el-tag
                v-for="tag in selectedTemplate.tags"
                :key="tag"
                size="small"
                type="info"
                class="tag-mini"
              >
                {{ tag }}
              </el-tag>
            </div>
          </el-descriptions-item>
          <el-descriptions-item label="References" :span="2" v-if="selectedTemplate.reference?.length">
            <div class="references">
              <el-link
                v-for="(ref, idx) in selectedTemplate.reference"
                :key="idx"
                :href="ref"
                target="_blank"
                type="primary"
              >
                {{ truncate(ref, 60) }}
              </el-link>
            </div>
          </el-descriptions-item>
          <el-descriptions-item label="File Path" :span="2">
            <code class="file-path">{{ selectedTemplate.filePath }}</code>
          </el-descriptions-item>
        </el-descriptions>
      </div>
      <template #footer>
        <el-button @click="detailsDialogVisible = false">Close</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted } from 'vue';
import { ElMessage } from 'element-plus';
import { Search, Refresh, Folder, Document } from '@element-plus/icons-vue';
import api from '@/services/api';

interface TemplateInfo {
  id: string;
  name: string;
  author?: string;
  severity: string;
  description?: string;
  tags: string[];
  reference?: string[];
  cveId?: string;
  cvssScore?: number;
  filePath: string;
  category: string;
}

interface TemplateCategory {
  id: string;
  name: string;
  description: string;
  count: number;
}

interface TagInfo {
  name: string;
  count: number;
}

interface Stats {
  totalTemplates: number;
  categories: number;
  tags: number;
  severityCounts: Record<string, number>;
}

// State
const loading = ref(false);
const searchQuery = ref('');
const selectedCategory = ref('');
const selectedSeverity = ref('');
const categories = ref<TemplateCategory[]>([]);
const tags = ref<TagInfo[]>([]);
const templates = ref<TemplateInfo[]>([]);
const stats = ref<Stats>({
  totalTemplates: 0,
  categories: 0,
  tags: 0,
  severityCounts: { critical: 0, high: 0, medium: 0, low: 0, info: 0, unknown: 0 }
});

// Pagination
const currentPage = ref(1);
const pageSize = ref(50);

// Dialog
const detailsDialogVisible = ref(false);
const selectedTemplate = ref<TemplateInfo | null>(null);

// Computed
const topTags = computed(() => tags.value.slice(0, 30));

const filteredTemplates = computed(() => {
  return templates.value;
});

const paginatedTemplates = computed(() => {
  const start = (currentPage.value - 1) * pageSize.value;
  const end = start + pageSize.value;
  return filteredTemplates.value.slice(start, end);
});

// Debounce search
let searchTimeout: ReturnType<typeof setTimeout>;
const debouncedSearch = () => {
  clearTimeout(searchTimeout);
  searchTimeout = setTimeout(() => {
    if (searchQuery.value.length >= 2) {
      searchTemplates();
    } else if (searchQuery.value.length === 0) {
      templates.value = [];
    }
  }, 300);
};

// Methods
async function loadOverview() {
  try {
    const response = await api.get('/api/vulnerabilities/templates');
    categories.value = response.data.categories || [];
    stats.value = response.data.stats || stats.value;
  } catch (error: any) {
    ElMessage.error('Failed to load templates overview');
  }
}

async function loadTags() {
  try {
    const response = await api.get('/api/vulnerabilities/templates/tags');
    tags.value = response.data.tags || [];
  } catch (error: any) {
    console.error('Failed to load tags:', error);
  }
}

async function searchTemplates() {
  loading.value = true;
  try {
    const response = await api.get('/api/vulnerabilities/templates/search', {
      params: { q: searchQuery.value, limit: 500 }
    });
    templates.value = response.data.templates || [];
    currentPage.value = 1;
  } catch (error: any) {
    ElMessage.error('Failed to search templates');
  } finally {
    loading.value = false;
  }
}

async function handleCategoryChange() {
  if (!selectedCategory.value) {
    templates.value = [];
    return;
  }

  loading.value = true;
  try {
    const response = await api.get(`/api/vulnerabilities/templates/category/${selectedCategory.value}`, {
      params: { limit: 500 }
    });
    templates.value = response.data.templates || [];
    currentPage.value = 1;
  } catch (error: any) {
    ElMessage.error('Failed to load category templates');
  } finally {
    loading.value = false;
  }
}

async function handleSeverityChange() {
  if (!selectedSeverity.value) {
    templates.value = [];
    return;
  }

  loading.value = true;
  try {
    // Use search with severity filter
    const response = await api.get('/api/vulnerabilities/templates/search', {
      params: { q: selectedSeverity.value, limit: 500 }
    });
    // Filter by severity since API search is text-based
    templates.value = (response.data.templates || []).filter(
      (t: TemplateInfo) => t.severity.toLowerCase() === selectedSeverity.value.toLowerCase()
    );
    currentPage.value = 1;
  } catch (error: any) {
    ElMessage.error('Failed to load templates by severity');
  } finally {
    loading.value = false;
  }
}

function searchByTag(tag: string) {
  searchQuery.value = tag;
  searchTemplates();
}

async function refreshTemplates() {
  loading.value = true;
  try {
    await api.post('/api/vulnerabilities/templates/refresh');
    await loadOverview();
    await loadTags();
    ElMessage.success('Templates refreshed');
  } catch (error: any) {
    ElMessage.error('Failed to refresh templates');
  } finally {
    loading.value = false;
  }
}

function clearFilters() {
  searchQuery.value = '';
  selectedCategory.value = '';
  selectedSeverity.value = '';
  templates.value = [];
}

function showTemplateDetails(row: TemplateInfo) {
  selectedTemplate.value = row;
  detailsDialogVisible.value = true;
}

function getCategoryName(categoryId: string): string {
  const cat = categories.value.find(c => c.id === categoryId);
  return cat?.name || categoryId;
}

function getSeverityType(severity: string): 'danger' | 'warning' | 'info' | 'success' | '' {
  const map: Record<string, 'danger' | 'warning' | 'info' | 'success' | ''> = {
    critical: 'danger',
    high: 'warning',
    medium: 'info',
    low: '',
    info: 'success'
  };
  return map[severity?.toLowerCase()] || '';
}

function getCvssType(score: number): 'danger' | 'warning' | 'info' | 'success' {
  if (score >= 9) return 'danger';
  if (score >= 7) return 'warning';
  if (score >= 4) return 'info';
  return 'success';
}

function getTagType(tag: string): 'danger' | 'warning' | 'info' | 'success' | '' {
  const dangerTags = ['rce', 'sqli', 'xss', 'lfi', 'ssrf', 'xxe'];
  const warningTags = ['auth-bypass', 'default-login', 'cve'];
  if (dangerTags.includes(tag.toLowerCase())) return 'danger';
  if (warningTags.includes(tag.toLowerCase())) return 'warning';
  return 'info';
}

function truncate(text: string, length: number): string {
  if (!text) return '';
  return text.length > length ? text.substring(0, length) + '...' : text;
}

function handlePageSizeChange() {
  currentPage.value = 1;
}

function handlePageChange() {
  // Page already updated via v-model
}

// Lifecycle
onMounted(async () => {
  await Promise.all([loadOverview(), loadTags()]);
});
</script>

<style scoped>
.templates-container {
  padding: 0;
}

.stats-row {
  margin-bottom: 20px;
}

.stat-card {
  text-align: center;
  padding: 20px;
}

.stat-value {
  font-size: 32px;
  font-weight: bold;
  color: #409EFF;
}

.stat-label {
  color: #909399;
  font-size: 14px;
  margin-top: 8px;
}

.severity-card .severity-breakdown {
  display: flex;
  justify-content: center;
  gap: 8px;
}

.severity-breakdown .severity {
  padding: 4px 8px;
  border-radius: 4px;
  font-size: 12px;
  font-weight: bold;
}

.severity.critical { background: #F56C6C; color: white; }
.severity.high { background: #E6A23C; color: white; }
.severity.medium { background: #909399; color: white; }
.severity.low { background: #C0C4CC; color: white; }
.severity.info { background: #67C23A; color: white; }

.filter-card {
  margin-bottom: 20px;
}

.categories-section,
.tags-section {
  margin-bottom: 30px;
}

.categories-section h3,
.tags-section h3 {
  margin-bottom: 15px;
  color: #303133;
}

.category-card {
  cursor: pointer;
  text-align: center;
  margin-bottom: 20px;
  transition: transform 0.2s, box-shadow 0.2s;
}

.category-card:hover {
  transform: translateY(-4px);
  box-shadow: 0 4px 12px rgba(0, 0, 0, 0.1);
}

.category-icon {
  color: #409EFF;
  margin-bottom: 10px;
}

.category-name {
  font-size: 16px;
  font-weight: bold;
  color: #303133;
}

.category-count {
  color: #409EFF;
  font-size: 14px;
  margin: 5px 0;
}

.category-description {
  color: #909399;
  font-size: 12px;
  line-height: 1.4;
}

.tags-cloud {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
}

.tag-item {
  cursor: pointer;
  transition: transform 0.2s;
}

.tag-item:hover {
  transform: scale(1.05);
}

.templates-table-card .card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.clickable-row {
  cursor: pointer;
}

.template-id {
  display: flex;
  align-items: center;
  gap: 8px;
  font-family: monospace;
  font-size: 12px;
}

.template-name {
  font-weight: 500;
}

.template-description {
  color: #909399;
  font-size: 12px;
  margin-top: 4px;
}

.tags-cell {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
  align-items: center;
}

.tag-mini {
  margin: 2px;
}

.more-tags {
  color: #909399;
  font-size: 12px;
}

.pagination-container {
  margin-top: 20px;
  display: flex;
  justify-content: flex-end;
}

.template-details .details-tags {
  display: flex;
  flex-wrap: wrap;
  gap: 4px;
}

.template-details .references {
  display: flex;
  flex-direction: column;
  gap: 4px;
}

.file-path {
  font-size: 12px;
  word-break: break-all;
}
</style>
