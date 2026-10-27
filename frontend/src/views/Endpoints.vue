<template>
  <div class="endpoints">
    <div class="page-header">
      <div>
        <h2>Endpoints</h2>
        <p class="subtitle">Enrolled SIEMBOX Endpoint agents — inventory, vulnerabilities, and detections.</p>
        <p class="subtitle">
          Agent: <a href="https://github.com/cladkins/siembox-endpoint" target="_blank" rel="noopener">github.com/cladkins/siembox-endpoint</a>
        </p>
      </div>
      <div class="actions">
        <el-button
          v-if="canScan"
          :disabled="selected.length === 0 || selected.length > BULK_SCAN_MAX"
          @click="openBulkScan"
        >Scan selected<template v-if="selected.length"> ({{ selected.length }})</template></el-button>
        <el-button
          v-if="canEditPolicy"
          :disabled="selected.length === 0 || selected.length > ASSIGN_MAX"
          data-testid="assign-policy"
          @click="openAssign"
        >Assign policy<template v-if="selected.length"> ({{ selected.length }})</template></el-button>
        <el-button @click="refresh" :loading="loading"><el-icon><Refresh /></el-icon> Refresh</el-button>
        <el-button v-if="isAdmin" type="primary" @click="openTokenDialog"><el-icon><Plus /></el-icon> Enroll an endpoint</el-button>
      </div>
    </div>

    <!-- Agent list -->
    <el-card>
      <p v-if="canScan && selected.length > BULK_SCAN_MAX" class="muted" style="margin: 0 0 8px">
        Select at most {{ BULK_SCAN_MAX }} endpoints per scan request.
      </p>
      <el-table :data="endpoints" v-loading="loading" stripe row-key="agent_id" @selection-change="onSelectionChange">
        <el-table-column v-if="canScan" type="selection" width="42" reserve-selection />
        <el-table-column label="Host" min-width="180">
          <template #default="{ row }">
            <strong>{{ row.hostname || '(unknown)' }}</strong>
            <div class="muted">{{ row.ip || '' }}</div>
            <el-tag v-if="Number(row.scans_outstanding) > 0" size="small" type="info" style="margin-top: 4px">
              {{ row.live_status === 'online' ? 'scan queued or running' : 'scan queued — agent offline' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="OS" min-width="160">
          <template #default="{ row }">
            {{ row.os || '—' }}<span v-if="row.os_version"> {{ row.os_version }}</span>
            <div class="muted">{{ row.arch || '' }}</div>
          </template>
        </el-table-column>
        <el-table-column label="Status" width="110">
          <template #default="{ row }">
            <el-tag :type="row.live_status === 'online' ? 'success' : 'info'" size="small" effect="dark">
              {{ row.live_status }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="Agent" min-width="210">
          <template #default="{ row }">
            <span class="muted">{{ row.agent_version || '—' }}</span>
            <el-tag v-if="isOutdated(row)" type="warning" size="small" style="margin-left: 6px">update available</el-tag>
            <div v-if="row.update_state" class="update-state">
              <el-tooltip :disabled="!row.update_error" :content="row.update_error || ''" placement="top">
                <el-tag :type="updateStateType(row.update_state)" size="small">
                  {{ row.update_state }}<template v-if="row.update_target_version"> → {{ row.update_target_version }}</template>
                </el-tag>
              </el-tooltip>
            </div>
          </template>
        </el-table-column>
        <el-table-column label="Scan policy" min-width="150">
          <template #default="{ row }">
            <span>{{ row.scan_policy_name || 'Default' }}</span>
            <el-tag v-if="Number(row.scan_policy_override_count) > 0" size="small" type="warning" style="margin-left: 4px">
              +{{ row.scan_policy_override_count }} override{{ Number(row.scan_policy_override_count) === 1 ? '' : 's' }}
            </el-tag>
            <div v-if="row.capabilities && !supportsPolicyScans(row)" class="muted">agent runs its own intervals</div>
          </template>
        </el-table-column>
        <el-table-column label="Open vulns" width="110" align="center">
          <template #default="{ row }">
            <el-tag v-if="Number(row.open_vulns) > 0" type="warning" size="small">{{ row.open_vulns }}</el-tag>
            <span v-else class="muted">0</span>
          </template>
        </el-table-column>
        <el-table-column label="Detections (7d)" width="130" align="center">
          <template #default="{ row }">
            <el-tag v-if="Number(row.recent_detections) > 0" type="danger" size="small">{{ row.recent_detections }}</el-tag>
            <span v-else class="muted">0</span>
          </template>
        </el-table-column>
        <el-table-column label="Last seen" width="170">
          <template #default="{ row }">{{ row.last_seen ? formatDate(row.last_seen) : 'never' }}</template>
        </el-table-column>
        <el-table-column label="Last scan" width="190">
          <template #default="{ row }">
            <template v-if="row.last_scan_completed_at || row.last_scan_at">
              {{ formatDate(row.last_scan_completed_at || row.last_scan_at) }}
              <div class="muted" v-if="row.next_scan_at">next ≈ {{ formatDate(row.next_scan_at) }}</div>
            </template>
            <span v-else>—</span>
          </template>
        </el-table-column>
        <el-table-column label="" width="290" align="right">
          <template #default="{ row }">
            <el-button
              v-if="isAdmin && row.update_request_id"
              size="small"
              plain
              :loading="busyAgent === row.agent_id"
              @click="cancelUpdate(row)"
            >Cancel update</el-button>
            <el-button
              v-else-if="isAdmin && canUpdate(row)"
              size="small"
              type="warning"
              plain
              :loading="busyAgent === row.agent_id"
              @click="requestUpdate(row)"
            >Update</el-button>
            <el-button size="small" @click="openDetail(row)">Details</el-button>
            <el-button v-if="isAdmin" size="small" type="danger" plain @click="removeEndpoint(row)">Remove</el-button>
          </template>
        </el-table-column>
        <template #empty>No endpoints enrolled yet. Click <strong>Enroll an endpoint</strong> to generate a token.</template>
      </el-table>
    </el-card>

    <ScanPoliciesCard
      style="margin-top: 16px"
      :policies="policies.list"
      :loading="policies.loading"
      :can-edit="canEditPolicy"
      @changed="onPoliciesChanged"
    />

    <!-- Agent updates (admin) -->
    <el-card v-if="isAdmin" style="margin-top: 16px">
      <template #header>
        <div class="card-header-row">
          <span>Agent updates</span>
          <div class="actions">
            <el-button size="small" :loading="updates.checking" @click="checkRelease">Check now</el-button>
            <el-button
              size="small"
              type="warning"
              :disabled="!outdatedCount"
              :loading="updates.bulkBusy"
              @click="updateAllOutdated"
            >Update all outdated<template v-if="outdatedCount"> ({{ outdatedCount }})</template></el-button>
          </div>
        </div>
      </template>
      <el-descriptions :column="3" size="small" border>
        <el-descriptions-item label="Latest version">
          <el-tag v-if="updates.status?.latest_version" type="success" size="small">v{{ updates.status.latest_version }}</el-tag>
          <span v-else class="muted">unknown</span>
        </el-descriptions-item>
        <el-descriptions-item label="Last checked">
          {{ updates.status?.checked_at ? formatDate(updates.status.checked_at) : 'never' }}
        </el-descriptions-item>
        <el-descriptions-item label="Auto-update">
          <el-switch
            :model-value="!!updates.status?.auto_update"
            :loading="updates.autoBusy"
            @change="toggleAutoUpdate"
          />
        </el-descriptions-item>
      </el-descriptions>
      <el-alert
        v-if="updates.status?.error"
        type="warning"
        :closable="false"
        show-icon
        :title="`Last release check failed: ${updates.status.error}`"
        style="margin-top: 8px"
      />
      <p class="muted" style="margin: 8px 0 0">
        Endpoints download the release from GitHub themselves and verify it against the release's
        <code>SHA256SUMS</code>; they need HTTPS access to github.com. Agents on a development build
        (a version that is not <code>X.Y.Z</code>) can be updated by hand but are skipped by
        auto-update and <strong>Update all outdated</strong>.
      </p>
    </el-card>

    <!-- YARA rules status (admin) -->
    <el-card v-if="isAdmin" style="margin-top: 16px">
      <template #header>
        <div class="card-header-row">
          <span>YARA rules</span>
          <el-button size="small" :loading="yara.refreshing" @click="pullYaraForge">Pull YARA-Forge now</el-button>
        </div>
      </template>
      <el-descriptions :column="4" size="small" border>
        <el-descriptions-item label="Version">
          <el-tag v-if="yara.status && yara.status.version > 0" type="success" size="small">v{{ yara.status.version }}</el-tag>
          <span v-else class="muted">none — agents use baseline only</span>
        </el-descriptions-item>
        <el-descriptions-item label="Source">{{ yara.status?.source || '—' }}</el-descriptions-item>
        <el-descriptions-item label="Size">{{ yara.status ? humanBytes(yara.status.bytes) : '—' }}</el-descriptions-item>
        <el-descriptions-item label="Updated">{{ yara.status?.created_at ? formatDate(yara.status.created_at) : '—' }}</el-descriptions-item>
      </el-descriptions>
      <p class="muted" style="margin: 8px 0 0">
        Served to agents at <code>GET /api/edr/agents/:id/yara</code>; each appends its built-in baseline.
        The starter bundle ships by default — enable the daily YARA-Forge import with
        <code>EDR_YARA_FORGE_ENABLED=true</code>.
      </p>
    </el-card>

    <!-- Enrollment tokens (admin) -->
    <el-card v-if="isAdmin" style="margin-top: 16px">
      <template #header><span>Enrollment tokens</span></template>
      <el-table :data="tokens" size="small" stripe>
        <el-table-column prop="label" label="Label" min-width="160">
          <template #default="{ row }">{{ row.label || '(no label)' }}</template>
        </el-table-column>
        <el-table-column label="Created" width="180">
          <template #default="{ row }">{{ formatDate(row.created_at) }}</template>
        </el-table-column>
        <el-table-column label="Expires" width="180">
          <template #default="{ row }">{{ row.expires_at ? formatDate(row.expires_at) : 'never' }}</template>
        </el-table-column>
        <el-table-column label="Status" width="120">
          <template #default="{ row }">
            <el-tag v-if="row.used" type="info" size="small">used</el-tag>
            <el-tag v-else-if="row.expired" type="danger" size="small">expired</el-tag>
            <el-tag v-else type="success" size="small">active</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="" width="120" align="right">
          <template #default="{ row }">
            <el-button size="small" type="danger" plain @click="revokeToken(row)">
              {{ row.used || row.expired ? 'Remove' : 'Revoke' }}
            </el-button>
          </template>
        </el-table-column>
        <template #empty>No tokens issued.</template>
      </el-table>
    </el-card>

    <!-- Generate-token dialog -->
    <el-dialog v-model="tokenDialog" title="Enroll an endpoint" width="640px">
      <template v-if="!generated">
        <el-form label-width="130px">
          <el-form-item label="Label">
            <el-input v-model="tokenForm.label" placeholder="e.g. web-server-01 (optional)" />
          </el-form-item>
          <el-form-item label="Expires in (hours)">
            <el-input-number v-model="tokenForm.expires_in_hours" :min="0" :step="1" />
            <span class="muted" style="margin-left: 8px">0 = never expires. Tokens are single-use.</span>
          </el-form-item>
        </el-form>
      </template>

      <template v-else>
        <el-alert type="success" :closable="false" title="Token generated — copy it now, it won't be shown again." style="margin-bottom: 12px" />
        <div class="token-row">
          <el-input v-model="generated" readonly />
          <el-button @click="copy(generated)"><el-icon><CopyDocument /></el-icon></el-button>
        </div>
        <p style="margin: 14px 0 6px"><strong>Install on the endpoint</strong></p>
        <p class="muted" style="margin: 0 0 8px">
          Point the agent at this server and enroll with the token above. See the agent's
          <code>scripts/install.sh</code> / release assets in the
          <a href="https://github.com/cladkins/siembox-endpoint" target="_blank" rel="noopener">SIEMBOX Endpoint</a> repo.
        </p>
        <pre class="install">{{ installSnippet }}</pre>
      </template>

      <template #footer>
        <el-button @click="tokenDialog = false">Close</el-button>
        <el-button v-if="!generated" type="primary" :loading="generating" @click="generateToken">Generate</el-button>
        <el-button v-else type="primary" @click="resetToken">Generate another</el-button>
      </template>
    </el-dialog>

    <!-- Endpoint detail drawer -->
    <!-- Scan selected dialog -->
    <el-dialog v-model="bulk.open" title="Scan selected endpoints" width="520px">
      <p style="margin-top: 0">Request these scans on {{ selected.length }} endpoint(s):</p>
      <el-checkbox-group v-model="bulk.types">
        <div v-for="t in SCAN_TYPES" :key="t.value"><el-checkbox :value="t.value">{{ t.label }}</el-checkbox></div>
      </el-checkbox-group>
      <p class="muted">
        Each endpoint runs them on its next heartbeat (about a minute); offline endpoints keep the request for 24 hours.
        A scan already queued or running on an endpoint is not requested twice. Agents before
        v{{ MIN_ADHOC_AGENT_VERSION }} ignore the request.
      </p>
      <template #footer>
        <el-button @click="bulk.open = false">Cancel</el-button>
        <el-button type="primary" :disabled="bulk.types.length === 0" :loading="bulk.busy" @click="submitBulkScan">Request scans</el-button>
      </template>
    </el-dialog>

    <!-- Assign policy dialog -->
    <el-dialog v-model="assign.open" title="Assign a scan policy" width="480px">
      <p style="margin-top: 0">Assign this policy to {{ selected.length }} endpoint(s):</p>
      <el-select v-model="assign.policyId" style="width: 100%" data-testid="assign-policy-select">
        <el-option v-for="p in policies.list" :key="p.id" :value="p.id" :label="p.is_default ? `${p.name} (default)` : p.name" />
      </el-select>
      <p class="muted">
        Each endpoint keeps its per-scan overrides. Agents pick the change up on their next heartbeat; agents before
        v{{ MIN_POLICY_AGENT_VERSION }} keep their own intervals until they are updated.
      </p>
      <template #footer>
        <el-button @click="assign.open = false">Cancel</el-button>
        <el-button type="primary" :disabled="assign.policyId === null" :loading="assign.busy" @click="submitAssign">Assign</el-button>
      </template>
    </el-dialog>

    <el-drawer v-model="detailOpen" @closed="stopHistoryPolling" :title="detail.agent ? (detail.agent.hostname || 'Endpoint') : 'Endpoint'" size="60%">
      <div v-if="detail.agent">
        <el-descriptions :column="2" border size="small" style="margin-bottom: 16px">
          <el-descriptions-item label="Hostname">{{ detail.agent.hostname || '—' }}</el-descriptions-item>
          <el-descriptions-item label="IP">{{ detail.agent.ip || '—' }}</el-descriptions-item>
          <el-descriptions-item label="OS">{{ detail.agent.os }} {{ detail.agent.os_version }}</el-descriptions-item>
          <el-descriptions-item label="Arch">{{ detail.agent.arch || '—' }}</el-descriptions-item>
          <el-descriptions-item label="Agent version">
            {{ detail.agent.agent_version || '—' }}
            <el-tag v-if="isOutdated(detail.agent)" type="warning" size="small" style="margin-left: 6px">update available</el-tag>
          </el-descriptions-item>
          <el-descriptions-item label="Last seen">{{ detail.agent.last_seen ? formatDate(detail.agent.last_seen) : 'never' }}</el-descriptions-item>
          <el-descriptions-item label="Last scan">
            <template v-if="detail.agent.last_scan_completed_at || detail.agent.last_scan_at">
              {{ formatDate(detail.agent.last_scan_completed_at || detail.agent.last_scan_at) }}
              <span class="muted" v-if="scanDuration(detail.agent)"> ({{ scanDuration(detail.agent) }})</span>
            </template>
            <template v-else>never</template>
          </el-descriptions-item>
          <template v-if="supportsPolicyScans(detail.agent)">
            <el-descriptions-item label="Scan policy">
              {{ detail.agent.scan_policy_name || 'Default' }}
              <el-button link type="primary" size="small" @click="detailTab = 'policy'">schedule</el-button>
            </el-descriptions-item>
            <el-descriptions-item label="Scans">scheduled by the server</el-descriptions-item>
          </template>
          <template v-else>
            <el-descriptions-item label="Next scan ≈">{{ detail.agent.next_scan_at ? formatDate(detail.agent.next_scan_at) : '—' }}</el-descriptions-item>
            <el-descriptions-item label="Scan interval">{{ humanInterval(detail.agent.vuln_scan_interval_seconds) }}</el-descriptions-item>
          </template>
          <el-descriptions-item label="Installed packages">
            <template v-if="detail.agent.packages_reported_at">
              {{ Number(detail.agent.package_count ?? 0).toLocaleString() }}
              <span class="muted">(reported {{ formatDate(detail.agent.packages_reported_at) }})</span>
            </template>
            <template v-else>not reported</template>
          </el-descriptions-item>
          <el-descriptions-item label="Package list changed">{{ detail.agent.packages_stored_at ? formatDate(detail.agent.packages_stored_at) : '—' }}</el-descriptions-item>
        </el-descriptions>

        <div class="scan-now" v-if="canScan">
          <el-checkbox-group v-model="scanForm.types" size="small">
            <el-checkbox v-for="t in SCAN_TYPES" :key="t.value" :value="t.value">{{ t.label }}</el-checkbox>
          </el-checkbox-group>
          <el-button
            type="primary"
            size="small"
            :disabled="scanForm.types.length === 0"
            :loading="scanForm.busy"
            @click="scanNow"
          >Scan now</el-button>
        </div>
        <el-alert
          v-if="!supportsAdhocScans(detail.agent)"
          type="info"
          :closable="false"
          show-icon
          style="margin-bottom: 12px"
          :title="`Agent ${detail.agent.agent_version ? 'v' + detail.agent.agent_version : '(unknown version)'} does not run on-demand scans — update it to v${MIN_ADHOC_AGENT_VERSION} or later. Requests wait until it does, then expire after 24 hours.`"
        />

        <el-tabs v-model="detailTab">
          <el-tab-pane :label="`Detections (${detail.detections.length})`" name="detections">
            <el-table :data="detail.detections" v-loading="detail.loading" size="small" stripe max-height="420">
              <el-table-column label="Severity" width="110">
                <template #default="{ row }"><el-tag :type="severityType(row.severity)" size="small">{{ row.severity }}</el-tag></template>
              </el-table-column>
              <el-table-column prop="title" label="Detection" min-width="240" show-overflow-tooltip />
              <el-table-column prop="status" label="Status" width="120" />
              <el-table-column label="When" width="170">
                <template #default="{ row }">{{ formatDate(row.created_at) }}</template>
              </el-table-column>
              <template #empty>No detections for this endpoint.</template>
            </el-table>
          </el-tab-pane>
          <el-tab-pane :label="`Vulnerabilities (${detail.vulns.length})`" name="vulns">
            <el-table :data="detail.vulns" v-loading="detail.loading" size="small" stripe max-height="420">
              <el-table-column label="Severity" width="110">
                <template #default="{ row }">
                  <el-tag :type="severityType(row.vulnerability?.severity)" size="small">{{ row.vulnerability?.severity || '—' }}</el-tag>
                </template>
              </el-table-column>
              <el-table-column label="CVE" width="180">
                <template #default="{ row }">{{ row.vulnerability?.cve_id || '—' }}</template>
              </el-table-column>
              <el-table-column label="Title" min-width="240" show-overflow-tooltip>
                <template #default="{ row }">{{ row.vulnerability?.title || '—' }}</template>
              </el-table-column>
              <el-table-column label="CVSS" width="90" align="center">
                <template #default="{ row }">{{ row.vulnerability?.cvss_score ?? '—' }}</template>
              </el-table-column>
              <el-table-column prop="status" label="Status" width="100" />
              <template #empty>No vulnerabilities reported for this endpoint.</template>
            </el-table>
          </el-tab-pane>
          <el-tab-pane :label="`Scan history (${history.total.toLocaleString()})`" name="scans">
            <div class="history-filters">
              <el-select v-model="history.type" placeholder="All types" clearable size="small" style="width: 160px" @change="reloadHistory">
                <el-option v-for="t in SCAN_TYPES" :key="t.value" :value="t.value" :label="scanTypeLabel(t.value)" />
              </el-select>
              <el-select v-model="history.status" placeholder="All statuses" clearable size="small" style="width: 160px" @change="reloadHistory">
                <el-option v-for="st in SCAN_STATUS_OPTIONS" :key="st" :value="st" :label="st" />
              </el-select>
              <span v-if="history.outstanding > 0" class="muted">Refreshing while a scan is queued or running…</span>
            </div>
            <el-table :data="history.scans" v-loading="history.loading" size="small" stripe max-height="420">
              <el-table-column label="Type" width="130">
                <template #default="{ row }">{{ scanTypeLabel(row.scan_type) }}</template>
              </el-table-column>
              <el-table-column label="Trigger" width="170">
                <template #default="{ row }">
                  {{ triggerLabel(row.trigger) }}
                  <div v-if="row.requested_by_username" class="muted">by {{ row.requested_by_username }}</div>
                  <div v-if="row.trigger === 'policy'" class="muted">{{ policyRunLabel(row) }}</div>
                </template>
              </el-table-column>
              <el-table-column label="Started" width="160">
                <template #default="{ row }">
                  <template v-if="row.started_at">{{ formatDate(row.started_at) }}</template>
                  <span v-else class="muted">requested {{ formatDate(row.requested_at) }}</span>
                </template>
              </el-table-column>
              <el-table-column label="Duration" width="90">
                <template #default="{ row }">{{ formatDuration(row.duration_ms) }}</template>
              </el-table-column>
              <el-table-column label="Status" width="190">
                <template #default="{ row }">
                  <el-tooltip :disabled="!row.error" :content="row.error || ''" placement="top">
                    <el-tag :type="scanStatusTag(row.status)" size="small">{{ scanStatusText(row, detailOnline) }}</el-tag>
                  </el-tooltip>
                </template>
              </el-table-column>
              <el-table-column label="Summary" min-width="220" show-overflow-tooltip>
                <template #default="{ row }">{{ summarizeScan(row) || '—' }}</template>
              </el-table-column>
              <el-table-column v-if="canScan" label="" width="90" align="right">
                <template #default="{ row }">
                  <el-button v-if="row.status === 'pending'" size="small" link type="danger" @click="cancelScan(row)">Cancel</el-button>
                </template>
              </el-table-column>
              <template #empty>No scans recorded yet. Agents before v{{ MIN_ADHOC_AGENT_VERSION }} do not report their scans.</template>
            </el-table>
            <el-pagination
              v-if="history.total > history.pageSize"
              small
              layout="prev, pager, next"
              :total="history.total"
              :page-size="history.pageSize"
              v-model:current-page="history.page"
              style="margin-top: 8px"
              @current-change="loadHistory"
            />
          </el-tab-pane>
          <el-tab-pane label="Scan policy" name="policy">
            <EndpointScanPolicy
              v-if="detailTab === 'policy'"
              :agent-id="detail.agent.agent_id"
              :policies="policies.list"
              :can-edit="canEditPolicy"
              @changed="onEndpointPolicyChanged"
            />
          </el-tab-pane>
          <el-tab-pane :label="`Packages (${detail.packagesTotal.toLocaleString()})`" name="packages">
            <el-input
              v-model="detail.packageQuery"
              placeholder="Filter by name"
              clearable
              size="small"
              style="max-width: 280px; margin-bottom: 8px"
              @input="onPackageQuery"
            />
            <el-table :data="detail.packages" v-loading="detail.packagesLoading" size="small" stripe max-height="420">
              <el-table-column prop="name" label="Package" min-width="220" show-overflow-tooltip />
              <el-table-column prop="version" label="Version" min-width="160" show-overflow-tooltip />
              <el-table-column prop="type" label="Type" width="90" />
              <el-table-column label="First seen" width="170">
                <template #default="{ row }">{{ formatDate(row.first_seen) }}</template>
              </el-table-column>
              <template #empty>No installed packages reported. Agents that predate the software inventory send none.</template>
            </el-table>
            <p v-if="detail.packagesTotal > detail.packages.length" class="muted">
              Showing {{ detail.packages.length }} of {{ detail.packagesTotal.toLocaleString() }}; filter by name to narrow it.
            </p>
          </el-tab-pane>
        </el-tabs>
      </div>
    </el-drawer>
  </div>
</template>

<script setup lang="ts">
import { ref, reactive, computed, onMounted, onBeforeUnmount } from 'vue';
import { api } from '@/services/api';
import { useAuthStore } from '@/stores/auth';
import {
  SCAN_TYPES,
  BULK_SCAN_MAX,
  MIN_ADHOC_AGENT_VERSION,
  canRequestScans,
  formatDuration,
  scanStatusTag,
  scanStatusText,
  scanTypeLabel,
  summarizeScan,
  supportsAdhocScans,
  triggerLabel,
  type ScanRow,
  type ScanType,
} from '@/utils/endpointScans';
import {
  MIN_POLICY_AGENT_VERSION,
  canEditPolicies,
  policyRunLabel,
  supportsPolicyScans,
  type ScanPolicy,
} from '@/utils/scanPolicies';
import ScanPoliciesCard from '@/components/endpoints/ScanPoliciesCard.vue';
import EndpointScanPolicy from '@/components/endpoints/EndpointScanPolicy.vue';
import { ElMessage, ElMessageBox } from 'element-plus';
import { Refresh, Plus, CopyDocument } from '@element-plus/icons-vue';
import { format } from 'date-fns';

const loading = ref(false);
const endpoints = ref<any[]>([]);
const tokens = ref<any[]>([]);
const yara = reactive<{ status: any | null; refreshing: boolean }>({ status: null, refreshing: false });

const updates = reactive<{
  status: { latest_version: string | null; checked_at: string | null; error: string | null; auto_update: boolean } | null;
  checking: boolean;
  autoBusy: boolean;
  bulkBusy: boolean;
}>({ status: null, checking: false, autoBusy: false, bulkBusy: false });
const busyAgent = ref('');

const tokenDialog = ref(false);
const generating = ref(false);
const generated = ref('');
const tokenForm = reactive({ label: '', expires_in_hours: 0 });

const authStore = useAuthStore();
const canScan = computed(() => canRequestScans(authStore.user?.role));
// Analysts and operators see endpoints, findings and scans; enrollment, tokens,
// YARA rules, agent updates and removal are admin-only (the API agrees).
const isAdmin = computed(() => authStore.user?.role === 'admin');
// Scan policies: everyone here reads them; operators and admins edit, assign and override (the API agrees).
const canEditPolicy = computed(() => canEditPolicies(authStore.user?.role));
const policies = reactive<{ list: ScanPolicy[]; loading: boolean }>({ list: [], loading: false });
/** Endpoints one "Assign policy" may name (BULK_ASSIGN_MAX_AGENTS on the server). */
const ASSIGN_MAX = 500;
const assign = reactive<{ open: boolean; policyId: number | null; busy: boolean }>({ open: false, policyId: null, busy: false });
const selected = ref<any[]>([]);
function onSelectionChange(rows: any[]) { selected.value = rows; }
const bulk = reactive<{ open: boolean; types: ScanType[]; busy: boolean }>({ open: false, types: ['vuln'], busy: false });

const SCAN_STATUS_OPTIONS = ['pending', 'running', 'succeeded', 'failed', 'cancelled', 'expired'];
const scanForm = reactive<{ types: ScanType[]; busy: boolean }>({ types: ['vuln'], busy: false });
const history = reactive<{
  scans: ScanRow[]; total: number; outstanding: number; loading: boolean;
  type: string; status: string; page: number; pageSize: number;
}>({ scans: [], total: 0, outstanding: 0, loading: false, type: '', status: '', page: 1, pageSize: 25 });
let historyTimer: ReturnType<typeof setTimeout> | undefined;
const HISTORY_POLL_MS = 5000;

const detailOpen = ref(false);
const detailTab = ref('detections');
const detail = reactive<{
  agent: any; detections: any[]; vulns: any[]; loading: boolean;
  packages: any[]; packagesTotal: number; packageQuery: string; packagesLoading: boolean;
}>({
  agent: null, detections: [], vulns: [], loading: false,
  packages: [], packagesTotal: 0, packageQuery: '', packagesLoading: false,
});

// The API on 8421 serves plain HTTP; an https URL here fails every enrollment.
const serverUrl = computed(() => `http://${window.location.hostname}:8421`);
const installSnippet = computed(() =>
  `# agent.json on the endpoint\n{\n  "server_url": "${serverUrl.value}",\n  "enrollment_token": "${generated.value}"\n}\n\n# then run the agent:\nsiembox-agent -dir /etc/siembox-agent run`
);

async function fetchEndpoints() {
  const res = await api.getEndpoints();
  endpoints.value = res.data.agents || [];
}
async function fetchTokens() {
  const res = await api.getEnrollmentTokens();
  tokens.value = res.data.tokens || [];
}
async function fetchYaraStatus() {
  const res = await api.getYaraStatus();
  yara.status = res.data;
}
async function fetchUpdateStatus() {
  const res = await api.getAgentUpdateStatus();
  updates.status = res.data;
}
async function fetchPolicies() {
  policies.loading = true;
  try {
    const res = await api.getScanPolicies();
    policies.list = res.data.policies || [];
  } finally {
    policies.loading = false;
  }
}
async function refresh() {
  loading.value = true;
  try {
    await Promise.all(isAdmin.value
      ? [fetchEndpoints(), fetchPolicies(), fetchTokens(), fetchYaraStatus(), fetchUpdateStatus()]
      : [fetchEndpoints(), fetchPolicies()]);
  }
  catch { ElMessage.error('Failed to load endpoints'); }
  finally { loading.value = false; }
}
onMounted(refresh);

async function pullYaraForge() {
  try {
    await ElMessageBox.confirm(
      'Download the latest YARA-Forge Extended pack (~3.4 MB) and publish it as a new bundle? ' +
        'Each enrolled endpoint then pulls the full rule set (~16.6 MB) on its next config poll.',
      'Pull YARA-Forge', { type: 'warning', confirmButtonText: 'Pull now', cancelButtonText: 'Cancel' }
    );
  } catch { return; }
  yara.refreshing = true;
  try {
    const res = await api.refreshYaraForge();
    ElMessage.success(res.data.updated ? `Published YARA bundle v${res.data.version}` : 'Already up to date');
    await fetchYaraStatus();
  } catch { ElMessage.error('YARA-Forge refresh failed (check server egress and logs)'); }
  finally { yara.refreshing = false; }
}

// ---- Agent updates ---------------------------------------------------------
const SEMVER = /^\d+\.\d+\.\d+$/;
/** -1/0/1 numeric X.Y.Z compare, or null if either side is not plain X.Y.Z. */
type VersionRow = { agent_version?: string | null };
function cmpVersion(a?: string | null, b?: string | null): number | null {
  if (!a || !b || !SEMVER.test(a) || !SEMVER.test(b)) return null;
  const pa = a.split('.').map(Number);
  const pb = b.split('.').map(Number);
  for (let i = 0; i < 3; i++) if (pa[i] !== pb[i]) return pa[i] < pb[i] ? -1 : 1;
  return 0;
}
/** Behind the latest release (semver agents only; dev builds never show the tag). */
function isOutdated(row: VersionRow): boolean {
  return cmpVersion(row.agent_version, updates.status?.latest_version) === -1;
}
/** Update button: behind latest, or a dev build (manual update is allowed for those). */
function canUpdate(row: VersionRow): boolean {
  const latest = updates.status?.latest_version;
  if (!latest) return false;
  return isOutdated(row) || !SEMVER.test(row.agent_version || '');
}
const outdatedCount = computed(() => endpoints.value.filter(isOutdated).length);
function updateStateType(state: string): string {
  if (state === 'succeeded') return 'success';
  if (state === 'failed') return 'danger';
  return 'info';
}
function errorMessage(e: unknown, fallback: string): string {
  const data = (e as { response?: { data?: { message?: string } } })?.response?.data;
  return data?.message || fallback;
}

async function checkRelease() {
  updates.checking = true;
  try {
    const res = await api.checkAgentRelease();
    updates.status = res.data;
    if (res.data.error) ElMessage.warning('Release check failed: ' + res.data.error);
    else ElMessage.success(`Latest agent release: v${res.data.latest_version}`);
    await fetchEndpoints();
  } catch (e) { ElMessage.error(errorMessage(e, 'Release check failed')); }
  finally { updates.checking = false; }
}

async function toggleAutoUpdate(enabled: boolean | string | number) {
  const on = enabled === true;
  try {
    await ElMessageBox.confirm(
      on
        ? 'Automatically update every endpoint to each new SIEMBOX Endpoint release? New GitHub releases are pushed fleet-wide as soon as they are detected (checked every 6 hours), and outdated endpoints are updated immediately. Endpoints on development builds are skipped.'
        : 'Stop automatically updating endpoints? Updates already requested are not cancelled.',
      on ? 'Enable auto-update' : 'Disable auto-update',
      { type: 'warning', confirmButtonText: on ? 'Enable' : 'Disable', cancelButtonText: 'Cancel' }
    );
  } catch { return; }
  updates.autoBusy = true;
  try {
    const res = await api.setAgentAutoUpdate(on);
    updates.status = res.data;
    ElMessage.success(on ? 'Auto-update enabled' : 'Auto-update disabled');
    await fetchEndpoints();
  } catch (e) { ElMessage.error(errorMessage(e, 'Failed to change auto-update')); }
  finally { updates.autoBusy = false; }
}

async function requestUpdate(row: { agent_id: string }) {
  busyAgent.value = row.agent_id;
  try {
    const res = await api.updateEndpoint(row.agent_id);
    ElMessage.success(`Update to v${res.data.target_version} requested`);
    await fetchEndpoints();
  } catch (e) { ElMessage.error(errorMessage(e, 'Failed to request update')); }
  finally { busyAgent.value = ''; }
}

async function cancelUpdate(row: { agent_id: string }) {
  busyAgent.value = row.agent_id;
  try {
    await api.cancelEndpointUpdate(row.agent_id);
    ElMessage.success('Update request cancelled');
    await fetchEndpoints();
  } catch (e) { ElMessage.error(errorMessage(e, 'Failed to cancel update')); }
  finally { busyAgent.value = ''; }
}

async function updateAllOutdated() {
  try {
    await ElMessageBox.confirm(
      `Request an update to v${updates.status?.latest_version} for ${outdatedCount.value} outdated endpoint(s)? ` +
        'Each downloads the release from GitHub and restarts its agent service.',
      'Update all outdated', { type: 'warning', confirmButtonText: 'Update all', cancelButtonText: 'Cancel' }
    );
  } catch { return; }
  updates.bulkBusy = true;
  try {
    const res = await api.updateOutdatedEndpoints();
    ElMessage.success(`Update requested for ${res.data.requested} endpoint(s)`);
    await fetchEndpoints();
  } catch (e) { ElMessage.error(errorMessage(e, 'Failed to request updates')); }
  finally { updates.bulkBusy = false; }
}

function openTokenDialog() {
  generated.value = '';
  tokenForm.label = '';
  tokenForm.expires_in_hours = 0;
  tokenDialog.value = true;
}
async function generateToken() {
  generating.value = true;
  try {
    const res = await api.createEnrollmentToken({
      label: tokenForm.label || undefined,
      expires_in_hours: tokenForm.expires_in_hours || undefined,
    });
    generated.value = res.data.token;
    fetchTokens();
  } catch { ElMessage.error('Failed to generate token'); }
  finally { generating.value = false; }
}
function resetToken() { generated.value = ''; }

async function revokeToken(row: any) {
  const active = !row.used && !row.expired;
  try {
    await ElMessageBox.confirm(
      active
        ? 'Revoke this enrollment token? It can no longer be used to enroll an endpoint.'
        : 'Remove this token from the list?',
      active ? 'Revoke token' : 'Remove token',
      { type: 'warning', confirmButtonText: active ? 'Revoke' : 'Remove', cancelButtonText: 'Cancel' }
    );
  } catch { return; }
  try {
    await api.revokeEnrollmentToken(row.token_hash);
    ElMessage.success(active ? 'Token revoked' : 'Token removed');
    fetchTokens();
  } catch { ElMessage.error('Failed to revoke token'); }
}

async function copy(text: string) {
  try { await navigator.clipboard.writeText(text); ElMessage.success('Copied'); }
  catch { ElMessage.warning('Copy failed — select and copy manually'); }
}

async function openDetail(agent: any) {
  detail.agent = agent;
  history.scans = [];
  history.total = 0;
  history.outstanding = 0;
  history.type = '';
  history.status = '';
  history.page = 1;
  void loadHistory();
  detail.detections = [];
  detail.vulns = [];
  detail.packages = [];
  detail.packagesTotal = 0;
  detail.packageQuery = '';
  detail.loading = true;
  void loadPackages();
  detailTab.value = 'detections';
  detailOpen.value = true;
  try {
    const [d, v] = await Promise.all([
      api.getEndpointDetections(agent.agent_id),
      api.getEndpointVulnerabilities(agent.agent_id),
    ]);
    detail.detections = d.data.alerts || [];
    detail.vulns = v.data.vulnerabilities || [];
  } catch { ElMessage.error('Failed to load endpoint detail'); }
  finally { detail.loading = false; }
}

async function loadPackages() {
  const agentId = detail.agent?.agent_id;
  if (!agentId) return;
  const q = detail.packageQuery;
  detail.packagesLoading = true;
  try {
    const { data } = await api.getEndpointPackages(agentId, { q: q || undefined, limit: 500 });
    if (detail.agent?.agent_id !== agentId || detail.packageQuery !== q) return; // a newer request is on its way
    detail.packages = data.packages || [];
    detail.packagesTotal = Number(data.total ?? 0);
  } catch { ElMessage.error('Failed to load installed packages'); }
  finally { detail.packagesLoading = false; }
}

let packageQueryTimer: ReturnType<typeof setTimeout> | undefined;
function onPackageQuery() {
  clearTimeout(packageQueryTimer);
  packageQueryTimer = setTimeout(() => void loadPackages(), 300);
}

// ---- Scans ---------------------------------------------------------------------
const detailOnline = computed(() => detail.agent?.live_status === 'online');

function stopHistoryPolling() {
  clearTimeout(historyTimer);
  historyTimer = undefined;
}
onBeforeUnmount(stopHistoryPolling);

async function loadHistory() {
  const agentId = detail.agent?.agent_id;
  if (!agentId) return;
  stopHistoryPolling();
  history.loading = history.scans.length === 0;
  try {
    const { data } = await api.getEndpointScans(agentId, {
      type: history.type || undefined,
      status: history.status || undefined,
      limit: history.pageSize,
      offset: (history.page - 1) * history.pageSize,
    });
    if (detail.agent?.agent_id !== agentId) return;
    history.scans = data.scans || [];
    history.total = Number(data.total ?? 0);
    history.outstanding = Number(data.outstanding ?? 0);
    if (data.supports_adhoc !== undefined && detail.agent) {
      // The list row may predate the agent's first capable heartbeat.
      const caps: string[] = Array.isArray(detail.agent.capabilities) ? detail.agent.capabilities : [];
      if (data.supports_adhoc && !caps.includes('adhoc_scans')) detail.agent.capabilities = [...caps, 'adhoc_scans'];
    }
  } catch { ElMessage.error('Failed to load scan history'); }
  finally { history.loading = false; }
  // Keep the table live while anything is queued or running.
  if (detailOpen.value && history.outstanding > 0) {
    historyTimer = setTimeout(() => void loadHistory(), HISTORY_POLL_MS);
  }
}

function reloadHistory() {
  history.page = 1;
  void loadHistory();
}

async function scanNow() {
  const agent = detail.agent;
  if (!agent) return;
  scanForm.busy = true;
  try {
    const { data } = await api.requestEndpointScans(agent.agent_id, scanForm.types);
    const existing = (data.scans || []).length - Number(data.created ?? 0);
    const where = agent.live_status === 'online' ? 'the agent picks it up within about a minute' : 'the agent is offline; it runs when it reconnects (within 24 hours)';
    ElMessage.success(
      `${data.created} scan(s) requested${existing > 0 ? `, ${existing} already queued or running` : ''} — ${where}`
    );
    detailTab.value = 'scans';
    await Promise.all([loadHistory(), fetchEndpoints()]);
  } catch (e) { ElMessage.error(errorMessage(e, 'Failed to request scans')); }
  finally { scanForm.busy = false; }
}

async function cancelScan(row: ScanRow) {
  const agentId = detail.agent?.agent_id;
  if (!agentId) return;
  try {
    await api.cancelEndpointScan(agentId, row.id);
    ElMessage.success('Scan request cancelled');
    await Promise.all([loadHistory(), fetchEndpoints()]);
  } catch (e) {
    ElMessage.error(errorMessage(e, 'Failed to cancel the scan request'));
    void loadHistory();
  }
}

function onPoliciesChanged() {
  void fetchPolicies();
  void fetchEndpoints();
}
function onEndpointPolicyChanged() {
  void fetchPolicies(); // endpoint counts
  void fetchEndpoints();
}

function openAssign() {
  assign.policyId = policies.list.find((p) => p.is_default)?.id ?? null;
  assign.open = true;
}

async function submitAssign() {
  const ids = selected.value.map((r) => r.agent_id);
  const policy = policies.list.find((p) => p.id === assign.policyId);
  if (!policy || ids.length === 0 || ids.length > ASSIGN_MAX) return;
  assign.busy = true;
  try {
    const { data } = await api.assignScanPolicy(ids, policy.is_default ? null : policy.id);
    const missing = data.missing?.length ? ` (${data.missing.length} no longer enrolled)` : '';
    ElMessage.success(`${data.agents} endpoint(s) now follow ${policy.name}${missing}`);
    assign.open = false;
    await Promise.all([fetchEndpoints(), fetchPolicies()]);
  } catch (e) { ElMessage.error(errorMessage(e, 'Failed to assign the policy')); }
  finally { assign.busy = false; }
}

function openBulkScan() {
  bulk.types = ['vuln'];
  bulk.open = true;
}

async function submitBulkScan() {
  const ids = selected.value.map((r) => r.agent_id);
  if (ids.length === 0 || ids.length > BULK_SCAN_MAX) return;
  try {
    await ElMessageBox.confirm(
      `Request ${bulk.types.map(scanTypeLabel).join(', ')} on ${ids.length} endpoint(s)?`,
      'Scan selected',
      { type: 'warning', confirmButtonText: 'Request scans', cancelButtonText: 'Cancel' }
    );
  } catch { return; }
  bulk.busy = true;
  try {
    const { data } = await api.requestEndpointScansBulk(ids, bulk.types);
    const extra = [
      data.already_outstanding ? `${data.already_outstanding} already queued or running` : '',
      data.missing?.length ? `${data.missing.length} endpoint(s) no longer enrolled` : '',
    ].filter(Boolean).join('; ');
    ElMessage.success(`${data.created} scan(s) requested on ${data.agents} endpoint(s)${extra ? ` (${extra})` : ''}`);
    bulk.open = false;
    await fetchEndpoints();
  } catch (e) { ElMessage.error(errorMessage(e, 'Failed to request scans')); }
  finally { bulk.busy = false; }
}

async function removeEndpoint(agent: any) {
  try {
    await ElMessageBox.confirm(
      `Remove endpoint "${agent.hostname || agent.agent_id}"? This deregisters the agent (its asset, alerts, and vulnerabilities are kept).`,
      'Remove endpoint', { type: 'warning', confirmButtonText: 'Remove', cancelButtonText: 'Cancel' }
    );
  } catch { return; }
  try { await api.deleteEndpoint(agent.agent_id); ElMessage.success('Endpoint removed'); refresh(); }
  catch { ElMessage.error('Failed to remove endpoint'); }
}

function formatDate(d: string) { return format(new Date(d), 'MMM dd, yyyy HH:mm'); }
function scanDuration(a: any): string {
  if (!a?.last_scan_started_at || !a?.last_scan_completed_at) return '';
  const ms = new Date(a.last_scan_completed_at).getTime() - new Date(a.last_scan_started_at).getTime();
  if (!(ms > 0)) return '';
  const s = Math.round(ms / 1000);
  return s < 60 ? `took ${s}s` : `took ${Math.floor(s / 60)}m ${s % 60}s`;
}
function humanInterval(sec?: number): string {
  if (!sec) return '—';
  if (sec === 86400) return 'daily';
  if (sec === 3600) return 'hourly';
  if (sec % 86400 === 0) return `every ${sec / 86400}d`;
  if (sec % 3600 === 0) return `every ${sec / 3600}h`;
  return `every ${Math.round(sec / 60)}m`;
}
function humanBytes(n: number): string {
  if (!n) return '0 B';
  const u = ['B', 'KB', 'MB', 'GB'];
  const i = Math.min(u.length - 1, Math.floor(Math.log(n) / Math.log(1024)));
  return `${(n / Math.pow(1024, i)).toFixed(i ? 1 : 0)} ${u[i]}`;
}
function severityType(sev: string): string {
  const m: Record<string, string> = { critical: 'danger', high: 'danger', medium: 'warning', low: 'info', info: 'info' };
  return m[sev] || 'info';
}
</script>

<style scoped>
.page-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 16px; }
.card-header-row { display: flex; justify-content: space-between; align-items: center; }
.page-header h2 { margin: 0; }
.subtitle { margin: 4px 0 0; color: var(--el-text-color-secondary); font-size: 13px; }
.actions { display: flex; gap: 8px; }
.update-state { margin-top: 4px; }
.scan-now { display: flex; align-items: center; justify-content: space-between; gap: 12px; flex-wrap: wrap; margin-bottom: 12px; }
.history-filters { display: flex; align-items: center; gap: 8px; margin-bottom: 8px; }
.muted { color: var(--el-text-color-secondary); font-size: 12px; }
.token-row { display: flex; gap: 8px; }
.install {
  background: var(--siembox-bg-color, var(--el-fill-color-light));
  padding: 12px; border-radius: 4px; font-size: 12px; overflow-x: auto; margin: 0;
}
</style>
