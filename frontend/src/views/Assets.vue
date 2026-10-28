<template>
  <div class="assets-container">
    <el-card>
      <template #header>
        <div class="card-header">
          <span class="title">Asset Inventory</span>
          <div class="header-actions">
            <el-button type="primary" @click="openScanDialog" v-if="canTriggerScans">
              <el-icon><Search /></el-icon>
              Trigger Scan
            </el-button>
            <el-tooltip
              v-if="canMerge"
              :content="selectedRows.length >= 2 ? 'Merge the selected assets into one' : 'Select two or more assets (the same machine) to merge them'"
              placement="bottom"
            >
              <span>
                <el-button :disabled="selectedRows.length < 2" @click="openMergeDialog(selectedRows)" data-test="merge-into">
                  <el-icon><Files /></el-icon>
                  Merge into…
                </el-button>
              </span>
            </el-tooltip>
            <el-button @click="refreshAll">
              <el-icon><Refresh /></el-icon>
              Refresh
            </el-button>
          </div>
        </div>
      </template>

      <!-- Scan Status Section - Always visible -->
      <div class="recent-scans">
        <div class="scans-header">
          <h3>Asset Discovery Scans</h3>
          <el-tag v-if="activeScans.length > 0" type="warning" effect="dark">
            {{ activeScans.length }} Active
          </el-tag>
        </div>

        <!-- Active Scans (with progress indicator) -->
        <div v-if="activeScans.length > 0" class="active-scans">
          <el-alert type="warning" :closable="false" style="margin-bottom: 10px">
            <strong>{{ activeScans.length }} scan(s) in progress...</strong>
          </el-alert>

          <el-table :data="activeScans" style="width: 100%; margin-bottom: 20px">
            <el-table-column prop="id" label="Scan ID" width="80" />
            <el-table-column prop="target" label="Target" width="200" />
            <el-table-column prop="scan_type" label="Type" width="120" />
            <el-table-column label="Run from" width="140">
              <template #default="{ row }">
                <el-tag size="small" :type="row.assigned_shipper_name ? 'info' : undefined">
                  {{ row.assigned_shipper_name || 'Built-in' }}
                </el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="status" label="Status" width="100">
              <template #default="{ row }">
                <el-tag type="warning">{{ row.status }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="started_at" label="Started" width="180">
              <template #default="{ row }">
                {{ formatDate(row.started_at) }}
              </template>
            </el-table-column>
          </el-table>
        </div>

        <!-- No Scans Message -->
        <div v-if="activeScans.length === 0 && recentScans.length === 0" class="no-scans">
          <el-empty description="No scans yet">
            <template #default>
              <el-text type="info">
                Trigger a scan using the button above to discover network assets
              </el-text>
            </template>
          </el-empty>
        </div>

        <!-- Recent Completed Scans -->
        <el-collapse v-if="recentScans.length > 0">
          <el-collapse-item title="View Recent Scans" name="scans">
            <el-table :data="recentScans" style="width: 100%">
              <el-table-column prop="id" label="ID" width="70" />
              <el-table-column prop="target" label="Target" width="150" />
              <el-table-column label="Run from" width="140">
                <template #default="{ row }">
                  <el-tag size="small" :type="row.assigned_shipper_name ? 'info' : undefined">
                    {{ row.assigned_shipper_name || 'Built-in' }}
                  </el-tag>
                </template>
              </el-table-column>
              <el-table-column prop="status" label="Status" width="100">
                <template #default="{ row }">
                  <el-tooltip v-if="row.status === 'expired' && row.error_message" :content="row.error_message" placement="top">
                    <el-tag :type="getScanStatusColor(row.status)">{{ scanStatusLabel(row.status) }}</el-tag>
                  </el-tooltip>
                  <el-tag v-else :type="getScanStatusColor(row.status)">{{ scanStatusLabel(row.status) }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column prop="assets_discovered" label="Assets Found" width="120" />
              <el-table-column prop="duration_seconds" label="Duration" width="100">
                <template #default="{ row }">
                  {{ row.duration_seconds ? `${row.duration_seconds}s` : '-' }}
                </template>
              </el-table-column>
              <el-table-column prop="completed_at" label="Completed" width="180">
                <template #default="{ row }">
                  {{ row.completed_at ? formatDate(row.completed_at) : '-' }}
                </template>
              </el-table-column>
              <el-table-column label="Actions" width="100">
                <template #default="{ row }">
                  <el-button link size="small" @click="showScanDetails(row)">Details</el-button>
                </template>
              </el-table-column>
            </el-table>
          </el-collapse-item>
        </el-collapse>
      </div>

      <!-- Filters -->
      <div class="filters">
        <el-input
          v-model="filters.search"
          placeholder="Search IP or hostname..."
          clearable
          @change="loadAssets"
          style="width: 300px"
        >
          <template #prefix>
            <el-icon><Search /></el-icon>
          </template>
        </el-input>

        <el-select v-model="filters.status" placeholder="Status" clearable @change="loadAssets" style="width: 150px">
          <el-option label="Active" value="active" />
          <el-option label="Inactive" value="inactive" />
          <el-option label="Offline" value="offline" />
        </el-select>

        <el-select v-model="filters.criticality" placeholder="Criticality" clearable @change="loadAssets" style="width: 150px">
          <el-option label="Critical" value="critical" />
          <el-option label="High" value="high" />
          <el-option label="Medium" value="medium" />
          <el-option label="Low" value="low" />
        </el-select>
      </div>

      <!-- Assets Table -->
      <el-table
        :data="assets"
        v-loading="loading"
        row-key="id"
        @row-click="onRowClick"
        @selection-change="onSelectionChange"
        style="width: 100%; margin-top: 20px"
        :default-sort="{ prop: 'last_seen', order: 'descending' }"
      >
        <el-table-column v-if="canMerge" type="selection" width="44" />
        <el-table-column prop="ip_address" label="IP Address" width="150" sortable />
        <el-table-column prop="hostname" label="Hostname" width="200" sortable />
        <el-table-column prop="os_type" label="OS" width="120" />
        <el-table-column prop="asset_type" label="Type" width="120">
          <template #default="{ row }">
            <el-tag :type="getAssetTypeColor(row.asset_type)">{{ row.asset_type }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="criticality" label="Criticality" width="120">
          <template #default="{ row }">
            <el-tag :type="getCriticalityColor(row.criticality)">{{ row.criticality }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="status" label="Status" width="100">
          <template #default="{ row }">
            <el-tag :type="getStatusColor(row.status)">{{ row.status }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="last_seen" label="Last Seen" width="180" sortable>
          <template #default="{ row }">
            {{ formatDate(row.last_seen) }}
          </template>
        </el-table-column>
        <el-table-column label="Actions" width="150" fixed="right">
          <template #default="{ row }">
            <el-button link type="primary" size="small" @click.stop="showAssetDetails(row)">Details</el-button>
            <el-button link type="danger" size="small" @click.stop="confirmDelete(row)">Delete</el-button>
          </template>
        </el-table-column>
      </el-table>

      <!-- Pagination -->
      <div class="pagination">
        <el-pagination
          v-model:current-page="currentPage"
          v-model:page-size="pageSize"
          :total="total"
          :page-sizes="[25, 50, 100]"
          layout="total, sizes, prev, pager, next"
          @current-change="loadAssets"
          @size-change="loadAssets"
        />
      </div>
    </el-card>

    <!-- Asset Details Dialog -->
    <el-dialog v-model="showDetailsDialog" title="Asset Details" width="800px">
      <div v-if="selectedAsset" v-loading="loadingDetails">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="IP Address">{{ selectedAsset.ip_address }}</el-descriptions-item>
          <el-descriptions-item label="Hostname">{{ selectedAsset.hostname || 'N/A' }}</el-descriptions-item>
          <el-descriptions-item label="MAC Address">{{ selectedAsset.mac_address || 'N/A' }}</el-descriptions-item>
          <el-descriptions-item label="OS">{{ selectedAsset.os_type }} {{ selectedAsset.os_version }}</el-descriptions-item>
          <el-descriptions-item label="Type">
            <el-tag :type="getAssetTypeColor(selectedAsset.asset_type)">{{ selectedAsset.asset_type }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="Criticality">
            <el-tag :type="getCriticalityColor(selectedAsset.criticality)">{{ selectedAsset.criticality }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="Status">
            <el-tag :type="getStatusColor(selectedAsset.status)">{{ selectedAsset.status }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="Discovery Method">{{ selectedAsset.discovery_method }}</el-descriptions-item>
          <el-descriptions-item label="First Seen">{{ formatDate(selectedAsset.first_seen) }}</el-descriptions-item>
          <el-descriptions-item label="Last Seen">{{ formatDate(selectedAsset.last_seen) }}</el-descriptions-item>
          <el-descriptions-item v-if="selectedAsset.metadata?.current_ip" label="Current IP">
            {{ selectedAsset.metadata.current_ip }}
            <span class="field-hint">(reported by its agent; another asset holds this address)</span>
          </el-descriptions-item>
          <el-descriptions-item label="Location">
            <template v-if="related?.geo">
              {{ related.geo.country_name }} ({{ related.geo.country_code }})
            </template>
            <span v-else style="color: var(--el-text-color-secondary)">N/A</span>
          </el-descriptions-item>
        </el-descriptions>

        <!-- Linked entities: Endpoint agent, log shipper, exposure counts -->
        <div class="graph-entry">
          <OpenInGraphButton type="asset" :value="selectedAsset.id" window="7d" size="small" @navigate="showDetailsDialog = false" />
        </div>
        <div class="related-summary" v-loading="loadingRelated">
          <div class="related-card">
            <div class="related-label">
              <el-icon><Cpu /></el-icon> Endpoint Agent
            </div>
            <template v-if="related?.agent">
              <el-tag :type="related.agent.online ? 'success' : 'info'" size="small">
                {{ related.agent.online ? 'Online' : 'Offline' }}
              </el-tag>
              <div class="related-meta">
                {{ related.agent.hostname || related.agent.agent_id.slice(0, 8) }}
                <span v-if="related.agent.agent_version">· v{{ related.agent.agent_version }}</span>
              </div>
              <div class="related-meta" v-if="related.agent.last_seen">
                Last seen {{ formatDate(related.agent.last_seen) }}
              </div>
            </template>
            <div class="related-meta muted" v-else>No agent enrolled</div>
          </div>

          <div class="related-card">
            <div class="related-label">
              <el-icon><Connection /></el-icon> Log Shipper
            </div>
            <template v-if="related?.shipper">
              <el-tag :type="related.shipper.status === 'online' ? 'success' : 'info'" size="small">
                {{ related.shipper.status }}
              </el-tag>
              <div class="related-meta">
                {{ related.shipper.name }}
                <span v-if="related.shipper.version">· v{{ related.shipper.version }}</span>
              </div>
            </template>
            <div class="related-meta muted" v-else>No shipper linked</div>
          </div>

          <div class="related-card">
            <div class="related-label">
              <el-icon><Warning /></el-icon> Exposure
            </div>
            <div class="related-counts">
              <el-tag :type="openVulnCount > 0 ? 'danger' : 'success'" size="small" effect="plain">
                {{ openVulnCount }} open vuln{{ openVulnCount === 1 ? '' : 's' }}
              </el-tag>
              <el-tag :type="(related?.alerts?.length || 0) > 0 ? 'warning' : 'info'" size="small" effect="plain">
                {{ related?.alerts?.length || 0 }} alert{{ (related?.alerts?.length || 0) === 1 ? '' : 's' }}
              </el-tag>
            </div>
          </div>
        </div>

        <!-- Possible duplicates: hints only, merged only when someone chooses to -->
        <div v-if="duplicates.length" class="duplicate-hints" data-test="duplicate-hints">
          <div class="duplicate-hints-header">
            <span class="related-label"><el-icon><Files /></el-icon> Possible duplicates</span>
            <el-button
              v-if="canMerge"
              size="small"
              type="primary"
              plain
              :disabled="duplicateSelection.length === 0"
              @click="mergeDuplicatesIntoSelected"
            >
              Merge selected into this asset
            </el-button>
          </div>
          <div class="field-hint">
            Other assets that look like the same machine. Nothing is merged unless you choose to.
          </div>
          <el-table
            :data="duplicates"
            size="small"
            style="width: 100%; margin-top: 6px"
            max-height="220"
            @selection-change="(rows: DuplicateHint[]) => (duplicateSelection = rows)"
          >
            <el-table-column v-if="canMerge" type="selection" width="40" />
            <el-table-column label="Asset" min-width="220">
              <template #default="{ row }">
                <el-button link type="primary" size="small" @click="openAssetById(row.id)">{{ assetLabel(row) }}</el-button>
              </template>
            </el-table-column>
            <el-table-column label="Why" min-width="200">
              <template #default="{ row }">
                <el-tag v-for="r in row.reasons" :key="r" size="small" effect="plain" class="reason-tag">{{ duplicateReasonLabel(r) }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column prop="discovery_method" label="Found by" width="110" />
            <el-table-column label="Open vulns" width="100">
              <template #default="{ row }">{{ row.open_vulnerabilities }}</template>
            </el-table-column>
          </el-table>
        </div>

        <!-- Detail tabs: vulns + alerts (correlation) then services + metadata -->
        <el-tabs v-model="activeTab" style="margin-top: 20px">
          <el-tab-pane name="vulnerabilities">
            <template #label>
              Vulnerabilities
              <el-badge
                v-if="related && related.vulnerabilities.length"
                :value="related.vulnerabilities.length"
                type="danger"
                class="tab-badge"
              />
            </template>
            <el-table :data="related?.vulnerabilities || []" v-loading="loadingRelated" style="width: 100%" max-height="360">
              <el-table-column label="Severity" width="110">
                <template #default="{ row }">
                  <el-tag :type="getSeverityColor(row.vulnerability?.severity)" size="small">
                    {{ row.vulnerability?.severity || 'unknown' }}
                  </el-tag>
                </template>
              </el-table-column>
              <el-table-column label="CVE" width="160">
                <template #default="{ row }">{{ row.vulnerability?.cve_id || '-' }}</template>
              </el-table-column>
              <el-table-column label="Title" min-width="220">
                <template #default="{ row }">{{ row.vulnerability?.title || '-' }}</template>
              </el-table-column>
              <el-table-column label="CVSS" width="90">
                <template #default="{ row }">{{ row.vulnerability?.cvss_score ?? '-' }}</template>
              </el-table-column>
              <el-table-column label="Status" width="110">
                <template #default="{ row }">
                  <el-tag :type="row.status === 'open' ? 'danger' : 'success'" size="small">{{ row.status }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column label="Last Detected" width="180">
                <template #default="{ row }">{{ row.last_detected ? formatDate(row.last_detected) : '-' }}</template>
              </el-table-column>
              <template #empty>No vulnerabilities recorded for this asset</template>
            </el-table>
          </el-tab-pane>

          <el-tab-pane name="alerts">
            <template #label>
              Alerts
              <el-badge
                v-if="related && related.alerts.length"
                :value="related.alerts.length"
                type="warning"
                class="tab-badge"
              />
            </template>
            <el-table :data="related?.alerts || []" v-loading="loadingRelated" style="width: 100%" max-height="360">
              <el-table-column label="Severity" width="110">
                <template #default="{ row }">
                  <el-tag :type="getSeverityColor(row.severity)" size="small">{{ row.severity }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column prop="title" label="Title" min-width="240" show-overflow-tooltip />
              <el-table-column label="Source" width="100">
                <template #default="{ row }">
                  <el-tag size="small" effect="plain">{{ row.source || 'rule' }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column label="Status" width="120">
                <template #default="{ row }">
                  <el-tag size="small" effect="plain">{{ row.status }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column label="Time" width="180">
                <template #default="{ row }">{{ formatDate(row.created_at) }}</template>
              </el-table-column>
              <template #empty>No alerts associated with this asset</template>
            </el-table>
          </el-tab-pane>

          <el-tab-pane label="Services" name="services">
            <el-table :data="selectedAsset.services" style="width: 100%" max-height="360">
              <el-table-column prop="port" label="Port" width="80" />
              <el-table-column prop="protocol" label="Protocol" width="100" />
              <el-table-column prop="service_name" label="Service" width="150" />
              <el-table-column prop="service_version" label="Version" width="200" />
              <el-table-column prop="state" label="State" width="100">
                <template #default="{ row }">
                  <el-tag :type="row.state === 'open' ? 'success' : 'info'">{{ row.state }}</el-tag>
                </template>
              </el-table-column>
              <template #empty>No open ports/services recorded</template>
            </el-table>
          </el-tab-pane>
          <el-tab-pane label="Metadata" name="metadata">
            <pre>{{ JSON.stringify(selectedAsset.metadata, null, 2) }}</pre>
          </el-tab-pane>
        </el-tabs>
      </div>
    </el-dialog>

    <!-- Merge Dialog -->
    <el-dialog v-model="showMergeDialog" title="Merge duplicate assets" width="720px" data-test="merge-dialog">
      <p class="merge-intro">
        Choose the asset to keep. The others are merged into it and then deleted: their vulnerability findings,
        services, alerts, endpoint agents and Application Monitoring entries move to the kept asset.
      </p>
      <el-radio-group v-model="mergeKeepId" class="merge-keep" @change="loadMergePreview">
        <el-radio v-for="a in mergeCandidates" :key="a.id" :value="a.id" border class="merge-keep-option">
          <span class="merge-keep-label">{{ assetLabel(a) }}</span>
          <span class="merge-keep-meta">
            #{{ a.id }} · {{ a.discovery_method || 'unknown' }}
            <el-tag v-if="(a.agent_count ?? 0) > 0" size="small" type="success" effect="plain">endpoint agent</el-tag>
          </span>
        </el-radio>
      </el-radio-group>

      <div v-loading="mergePreviewLoading" class="merge-preview">
        <template v-if="mergePreview">
          <h4>Moves to {{ assetLabel(mergePreview.into) }}</h4>
          <ul>
            <li v-for="line in mergeMoveLines(mergePreview.moved)" :key="line">{{ line }}</li>
            <li v-if="mergeMoveLines(mergePreview.moved).length === 0" class="muted">Nothing else references them.</li>
          </ul>
          <h4>Deleted after the merge</h4>
          <ul>
            <li v-for="m in mergePreview.merged" :key="m.id">
              {{ assetLabel(m) }} · #{{ m.id }} · {{ m.discovery_method || 'unknown' }} · {{ m.open_vulnerabilities }} open vulns
            </li>
          </ul>
          <el-alert
            v-for="w in mergePreview.warnings"
            :key="w"
            type="warning"
            :title="w"
            :closable="false"
            show-icon
            style="margin-top: 8px"
          />
        </template>
      </div>
      <template #footer>
        <el-button @click="showMergeDialog = false">Cancel</el-button>
        <el-button type="danger" :disabled="!mergePreview" :loading="merging" @click="confirmMerge">
          Merge {{ mergePreview?.merged.length || '' }} asset{{ mergePreview?.merged.length === 1 ? '' : 's' }}
        </el-button>
      </template>
    </el-dialog>

    <!-- Trigger Scan Dialog -->
    <el-dialog v-model="showScanDialog" title="Trigger Asset Scan" width="600px">
      <el-form :model="scanForm" label-width="120px">
        <el-form-item label="Run from">
          <el-select v-model="scanForm.assignedShipperId" placeholder="Select where to run the scan" style="width: 100%">
            <el-option :label="'SIEMBox backend (built-in)'" :value="null" />
            <el-option
              v-for="s in shippers"
              :key="s.id"
              :label="`${s.name}${s.status !== 'online' ? ` (${s.status})` : ''}`"
              :value="s.id"
              :disabled="s.status !== 'online'"
            />
          </el-select>
          <div class="field-hint">
            <template v-if="scanForm.assignedShipperId">
              Runs on the selected log shipper, out on its LAN. The scan stays queued until the shipper picks it up (within ~30s).
            </template>
            <template v-else>
              Runs on the SIEMBox backend. From inside Docker it may only see the server's own subnet — use a shipper to scan your LAN.
            </template>
          </div>
        </el-form-item>
        <el-form-item label="Scan Type">
          <el-select v-model="scanForm.scanType" placeholder="Select scan type">
            <el-option label="Ping Scan (Fast)" value="ping" />
            <el-option label="Port Scan" value="port" />
            <el-option label="Service Detection" value="service" />
            <el-option label="OS Detection" value="os" />
          </el-select>
        </el-form-item>
        <el-form-item label="Targets">
          <el-input
            v-model="scanForm.targets"
            type="textarea"
            :rows="4"
            placeholder="Enter IP addresses or CIDR ranges (one per line)&#10;Example:&#10;192.168.1.1&#10;192.168.1.0/24"
          />
        </el-form-item>
        <PublicTargetWarning
          v-model="scanPublicConfirmed"
          :targets="scanTargetList"
          @use-suggestion="(from: string, to: string) => (scanForm.targets = replaceTargetToken(scanForm.targets, from, to))"
        />
      </el-form>
      <template #footer>
        <el-button @click="showScanDialog = false">Cancel</el-button>
        <el-button type="primary" @click="triggerScan" :loading="scanLoading" :disabled="scanGate.blocked">Trigger Scan</el-button>
      </template>
    </el-dialog>

    <!-- Scan Details Dialog -->
    <el-dialog v-model="showScanDetailsDialog" title="Scan Details" width="700px">
      <div v-if="selectedScan">
        <el-descriptions :column="2" border>
          <el-descriptions-item label="Scan ID">{{ selectedScan.id }}</el-descriptions-item>
          <el-descriptions-item label="Type">{{ selectedScan.scan_type }}</el-descriptions-item>
          <el-descriptions-item label="Target">{{ selectedScan.target }}</el-descriptions-item>
          <el-descriptions-item label="Status">
            <el-tag :type="getScanStatusColor(selectedScan.status)">{{ scanStatusLabel(selectedScan.status) }}</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="Started">{{ formatDate(selectedScan.started_at) }}</el-descriptions-item>
          <el-descriptions-item label="Completed">{{ selectedScan.completed_at ? formatDate(selectedScan.completed_at) : 'In progress' }}</el-descriptions-item>
          <el-descriptions-item label="Duration">{{ selectedScan.duration_seconds ? `${selectedScan.duration_seconds}s` : '-' }}</el-descriptions-item>
          <el-descriptions-item label="Assets Found">{{ selectedScan.assets_discovered || 0 }}</el-descriptions-item>
          <el-descriptions-item label="Run from">{{ selectedScan.assigned_shipper_name || 'SIEMBox backend (built-in)' }}</el-descriptions-item>
          <el-descriptions-item label="Initiated By" :span="2">{{ selectedScan.initiated_by_username || 'System' }}</el-descriptions-item>
        </el-descriptions>

        <div v-if="selectedScan.error_message" style="margin-top: 20px">
          <el-alert :type="selectedScan.status === 'expired' ? 'warning' : 'error'" :closable="false">
            <strong>{{ selectedScan.status === 'expired' ? 'Expired:' : 'Error:' }}</strong> {{ selectedScan.error_message }}
          </el-alert>
        </div>

        <div v-if="selectedScan.scan_options" style="margin-top: 20px">
          <h4>Scan Options:</h4>
          <pre>{{ JSON.stringify(selectedScan.scan_options, null, 2) }}</pre>
        </div>
      </div>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue';
import { useRoute } from 'vue-router';
import OpenInGraphButton from '@/components/graph/OpenInGraphButton.vue';
import { ElMessage, ElMessageBox } from 'element-plus';
import { Search, Refresh, Cpu, Connection, Warning, Files } from '@element-plus/icons-vue';
import assetService, { type Asset, type AssetWithServices, type AssetRelated, type ShipperSummary } from '@/services/assetService';
import { useAuthStore } from '@/stores/auth';
import { api } from '@/services/api';
import PublicTargetWarning from '@/components/PublicTargetWarning.vue';
import { publicTargetGate, replaceTargetToken, scanStatusLabel, scanStatusTagType } from '@/utils/shipperJobs';
import {
  assetLabel,
  canMergeAssets,
  defaultKeepId,
  duplicateReasonLabel,
  mergeFromIds,
  mergeMoveLines,
  type DuplicateHint,
  type MergeableAsset,
  type MergeResult,
} from '@/utils/assetMerge';

const authStore = useAuthStore();
const canTriggerScans = computed(() => ['admin', 'analyst', 'operator'].includes(authStore.user?.role || ''));
const canMerge = computed(() => canMergeAssets(authStore.user?.role));

const route = useRoute();
const assets = ref<Asset[]>([]);
const loading = ref(false);
const total = ref(0);
const currentPage = ref(1);
const pageSize = ref(50);

const filters = ref({
  search: '',
  status: '',
  criticality: ''
});

const showDetailsDialog = ref(false);
const loadingDetails = ref(false);
const selectedAsset = ref<AssetWithServices | null>(null);
const activeTab = ref('vulnerabilities');
const related = ref<AssetRelated | null>(null);
const loadingRelated = ref(false);

// Possible duplicates of the open asset (hints) and the merge dialog.
const duplicates = ref<DuplicateHint[]>([]);
const duplicateSelection = ref<DuplicateHint[]>([]);
const selectedRows = ref<Asset[]>([]);
const showMergeDialog = ref(false);
const mergeCandidates = ref<MergeableAsset[]>([]);
const mergeKeepId = ref<number | null>(null);
const mergePreview = ref<MergeResult | null>(null);
const mergePreviewLoading = ref(false);
const merging = ref(false);

function apiErrorMessage(error: unknown, fallback: string): string {
  return (error as { response?: { data?: { error?: string } } })?.response?.data?.error || fallback;
}

function onSelectionChange(rows: Asset[]) {
  selectedRows.value = rows;
}

function onRowClick(row: Asset, column?: { type?: string }) {
  if (column?.type === 'selection') return; // the checkbox selects, it doesn't open
  showAssetDetails(row);
}

function openMergeDialog(candidates: MergeableAsset[], keepId?: number) {
  mergeCandidates.value = candidates;
  mergeKeepId.value = keepId ?? defaultKeepId(candidates);
  mergePreview.value = null;
  showMergeDialog.value = true;
  loadMergePreview();
}

async function loadMergePreview() {
  const keep = mergeKeepId.value;
  const from = mergeFromIds(mergeCandidates.value, keep);
  mergePreview.value = null;
  if (keep === null || from.length === 0) return;
  mergePreviewLoading.value = true;
  try {
    const preview = await assetService.mergeAssets(keep, from, true);
    if (mergeKeepId.value === keep) mergePreview.value = preview;
  } catch (error) {
    ElMessage.error(apiErrorMessage(error, 'Failed to preview the merge'));
  } finally {
    mergePreviewLoading.value = false;
  }
}

async function confirmMerge() {
  const keep = mergeKeepId.value;
  if (keep === null || !mergePreview.value) return;
  merging.value = true;
  try {
    const result = await assetService.mergeAssets(keep, mergeFromIds(mergeCandidates.value, keep));
    ElMessage.success(`Merged ${result.merged.length} asset${result.merged.length === 1 ? '' : 's'} into ${assetLabel(result.into)}`);
    showMergeDialog.value = false;
    selectedRows.value = [];
    await loadAssets();
    if (showDetailsDialog.value) openAssetById(keep);
  } catch (error) {
    ElMessage.error(apiErrorMessage(error, 'Failed to merge assets'));
  } finally {
    merging.value = false;
  }
}

function mergeDuplicatesIntoSelected() {
  const current = selectedAsset.value;
  if (!current) return;
  const candidates: MergeableAsset[] = [
    { ...current, agent_count: related.value?.agent ? 1 : 0 },
    ...duplicateSelection.value.map((d) => ({ ...d, agent_count: d.agents })),
  ];
  openMergeDialog(candidates, current.id);
}

const openVulnCount = computed(
  () => related.value?.vulnerabilities.filter((v) => v.status === 'open').length || 0
);

const showScanDialog = ref(false);
const scanLoading = ref(false);
const scanForm = ref<{ scanType: string; targets: string; assignedShipperId: number | null }>({
  scanType: 'ping',
  targets: '',
  assignedShipperId: null
});

// Targets in public address space need the "I'm authorized" confirmation
// before the scan can be sent (the API refuses them otherwise).
const scanPublicConfirmed = ref(false);
const scanTargetList = computed(() => scanForm.value.targets.split('\n').map((t) => t.trim()).filter((t) => t));
const scanGate = computed(() => publicTargetGate(scanTargetList.value, scanPublicConfirmed.value));

// Log shippers available to run a scan from (for the "Run from" picker).
const shippers = ref<ShipperSummary[]>([]);
async function loadShippers() {
  try {
    shippers.value = await assetService.getShippers();
  } catch (error) {
    // Non-fatal: the picker just falls back to "Built-in" only.
    shippers.value = [];
    console.error('Failed to load shippers for scan picker', error);
  }
}

function openScanDialog() {
  showScanDialog.value = true;
  loadShippers(); // refresh each time so newly-added/just-online shippers appear
}

// Scan status tracking
const recentScans = ref<any[]>([]);
const activeScans = ref<any[]>([]);
const showScanDetailsDialog = ref(false);
const selectedScan = ref<any>(null);
let scanPollingInterval: number | null = null;

// Load scans function with graceful error handling
async function loadScans() {
  try {
    // Load recent scans (last 10)
    try {
      const recentResponse = await api.getScans({ limit: 10 });
      recentScans.value = recentResponse.data.scans || [];
      console.log('[Assets] Loaded recent scans:', recentScans.value.length);
    } catch (recentError: any) {
      console.warn('[Assets] Failed to load recent scans:', {
        status: recentError.response?.status,
        message: recentError.response?.data?.error || recentError.message
      });
      recentScans.value = [];
    }

    // Load active scans
    try {
      const activeResponse = await api.getActiveScans();
      activeScans.value = activeResponse.data.scans || [];
      console.log('[Assets] Loaded active scans:', activeScans.value.length);
    } catch (activeError: any) {
      console.warn('[Assets] Failed to load active scans:', {
        status: activeError.response?.status,
        message: activeError.response?.data?.error || activeError.message
      });
      activeScans.value = [];
    }
  } catch (error: any) {
    console.error('[Assets] Unexpected error while loading scans:', error);
    // Gracefully degrade - set empty scan lists rather than breaking
    recentScans.value = [];
    activeScans.value = [];
  }
}

// Show scan details
function showScanDetails(scan: any) {
  selectedScan.value = scan;
  showScanDetailsDialog.value = true;
}

// Get scan status color
function getScanStatusColor(status: string) {
  return scanStatusTagType(status);
}

// Stop polling
function stopScanPolling() {
  if (scanPollingInterval) {
    clearInterval(scanPollingInterval);
    scanPollingInterval = null;
  }
}

async function loadAssets() {
  loading.value = true;
  try {
    const response = await assetService.getAssets({
      ...filters.value,
      limit: pageSize.value,
      offset: (currentPage.value - 1) * pageSize.value
    });
    assets.value = response.assets;
    total.value = response.total;
  } catch (error) {
    ElMessage.error('Failed to load assets');
    console.error(error);
  } finally {
    loading.value = false;
  }
}

async function openAssetById(id: number) {
  showDetailsDialog.value = true;
  loadingDetails.value = true;
  loadingRelated.value = true;
  activeTab.value = 'vulnerabilities';
  related.value = null;
  duplicates.value = [];
  duplicateSelection.value = [];

  assetService
    .getDuplicates(id)
    .then((hints) => {
      duplicates.value = hints;
    })
    .catch((error) => {
      console.error('Failed to load possible duplicates', error);
    });

  // Core asset + correlated entities load in parallel; a failure on one
  // shouldn't blank the other.
  assetService
    .getAsset(id)
    .then((asset) => {
      selectedAsset.value = asset;
    })
    .catch((error) => {
      ElMessage.error('Failed to load asset details');
      console.error(error);
    })
    .finally(() => {
      loadingDetails.value = false;
    });

  assetService
    .getAssetRelated(id)
    .then((data) => {
      related.value = data;
    })
    .catch((error) => {
      console.error('Failed to load related asset data', error);
    })
    .finally(() => {
      loadingRelated.value = false;
    });
}

function showAssetDetails(asset: Asset) {
  openAssetById(asset.id);
}

async function confirmDelete(asset: Asset) {
  try {
    await ElMessageBox.confirm(
      `Are you sure you want to delete asset ${asset.ip_address}?`,
      'Confirm Delete',
      { type: 'warning' }
    );
    await assetService.deleteAsset(asset.id);
    ElMessage.success('Asset deleted successfully');
    await loadAssets();
  } catch (error) {
    if (error !== 'cancel') {
      ElMessage.error('Failed to delete asset');
      console.error(error);
    }
  }
}

async function triggerScan() {
  if (!scanForm.value.targets.trim()) {
    ElMessage.warning('Please enter at least one target');
    return;
  }

  scanLoading.value = true;
  try {
    const targets = scanForm.value.targets.split('\n').map(t => t.trim()).filter(t => t);
    const result = await assetService.triggerScan(
      targets,
      scanForm.value.scanType,
      scanForm.value.assignedShipperId,
      scanGate.value.allowPublicTargets
    );
    const via = scanForm.value.assignedShipperId
      ? ' It will run on the selected shipper once it checks in.'
      : '';
    ElMessage.success(`Scan initiated (ID: ${result.scanId}).${via} Use the Refresh button to check status.`);
    showScanDialog.value = false;
    scanForm.value.targets = '';
    scanForm.value.assignedShipperId = null;
    scanPublicConfirmed.value = false;
    loadScans(); // Refresh scan list once
  } catch (error: any) {
    ElMessage.error(error.response?.data?.error || 'Failed to trigger scan');
    console.error(error);
  } finally {
    scanLoading.value = false;
  }
}

function getAssetTypeColor(type: string) {
  const colors: Record<string, string> = {
    server: '',
    workstation: 'success',
    network: 'warning',
    iot: 'info'
  };
  return colors[type] || '';
}

function getCriticalityColor(criticality: string) {
  const colors: Record<string, string> = {
    critical: 'danger',
    high: 'warning',
    medium: '',
    low: 'info'
  };
  return colors[criticality] || '';
}

function getStatusColor(status: string) {
  const colors: Record<string, string> = {
    active: 'success',
    inactive: 'warning',
    offline: 'danger'
  };
  return colors[status] || '';
}

function getSeverityColor(severity?: string) {
  const colors: Record<string, string> = {
    critical: 'danger',
    high: 'warning',
    medium: '',
    low: 'info',
    unknown: 'info'
  };
  return colors[(severity || '').toLowerCase()] || 'info';
}

function formatDate(date: string) {
  return new Date(date).toLocaleString();
}

function refreshAll() {
  loadAssets();
  loadScans();
}

onMounted(() => {
  loadAssets();
  loadScans(); // Load scans once on mount
  // Polling disabled - use manual refresh button instead

  // Deep link: /assets?id=N opens that asset's details directly. Used by the
  // asset link on the Vulnerability Management page (now that findings map to
  // real per-host assets — see Issue 2 — this lands on the right asset).
  const id = Number(route.query.id);
  if (Number.isInteger(id) && id > 0) {
    openAssetById(id);
  }
});

onUnmounted(() => {
  stopScanPolling();
});
</script>

<style scoped>
.graph-entry {
  display: flex;
  justify-content: flex-end;
  margin-top: 12px;
}

.assets-container {
  padding: 20px;
}

.field-hint {
  font-size: 12px;
  line-height: 1.4;
  color: var(--el-text-color-secondary);
  margin-top: 4px;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.title {
  font-size: 18px;
  font-weight: bold;
}

.header-actions {
  display: flex;
  gap: 10px;
}

.recent-scans {
  margin-bottom: 20px;
  padding: 15px;
  background-color: var(--siembox-bg-color);
  border-radius: 4px;
}

.scans-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  margin-bottom: 15px;
}

.scans-header h3 {
  margin: 0;
  font-size: 16px;
  font-weight: 600;
}

.no-scans {
  text-align: center;
  padding: 20px;
}

.active-scans {
  margin-bottom: 15px;
}

.filters {
  display: flex;
  gap: 15px;
  flex-wrap: wrap;
}

.pagination {
  display: flex;
  justify-content: flex-end;
  margin-top: 20px;
}

.related-summary {
  display: flex;
  gap: 12px;
  margin-top: 16px;
  flex-wrap: wrap;
}

.related-card {
  flex: 1 1 180px;
  border: 1px solid var(--el-border-color-lighter);
  border-radius: 6px;
  padding: 10px 12px;
  background-color: var(--siembox-bg-color);
}

.related-label {
  display: flex;
  align-items: center;
  gap: 6px;
  font-weight: 600;
  font-size: 13px;
  margin-bottom: 8px;
  color: var(--el-text-color-primary);
}

.related-meta {
  font-size: 12px;
  color: var(--el-text-color-secondary);
  margin-top: 4px;
}

.related-meta.muted {
  font-style: italic;
}

.related-counts {
  display: flex;
  gap: 8px;
  flex-wrap: wrap;
}

.tab-badge {
  margin-left: 4px;
}

.duplicate-hints {
  margin-top: 16px;
  border: 1px solid var(--el-color-warning-light-5);
  border-radius: 6px;
  padding: 10px 12px;
  background-color: var(--siembox-bg-color);
}

.duplicate-hints-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.reason-tag {
  margin-right: 4px;
}

.merge-intro {
  margin: 0 0 14px;
  line-height: 1.5;
  color: var(--el-text-color-regular);
}

.merge-keep {
  display: flex;
  flex-direction: column;
  align-items: stretch;
  gap: 8px;
}

.merge-keep-option {
  margin-right: 0;
  height: auto;
  padding: 8px 12px;
}

.merge-keep-label {
  font-weight: 600;
  margin-right: 8px;
}

.merge-keep-meta {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

.merge-preview {
  margin-top: 16px;
  min-height: 60px;
}

.merge-preview h4 {
  margin: 12px 0 4px;
}

.merge-preview ul {
  margin: 0;
  padding-left: 20px;
}

.merge-preview .muted {
  color: var(--el-text-color-secondary);
}
</style>
