<template>
  <div class="application-monitoring">
    <div class="page-header">
      <div>
        <h2>Application Monitoring</h2>
        <p class="subtitle">
          The software running on your network, from what SIEMBox already sees: log program names, which parser matched, nmap
          services, the container images log shippers report, endpoint-agent findings, and the user agents and DNS queries in
          your logs, matched against the catalog's application signatures.
        </p>
      </div>
      <div class="header-actions">
        <el-button v-if="canWrite" type="primary" data-test="create-signature" @click="openEditor({ doc: null })">
          <el-icon><Plus /></el-icon> Create signature
        </el-button>
        <el-button v-if="canRefresh" :loading="refreshing" @click="refresh">
          <el-icon><Refresh /></el-icon> Refresh now
        </el-button>
      </div>
    </div>

    <el-alert v-if="loadError" type="error" :closable="false" :title="loadError" show-icon class="block" />
    <div v-if="status" class="status-line" data-test="status">
      <el-tag size="small" :type="status.enabled ? (status.caught_up ? 'success' : 'warning') : 'info'">
        {{ !status.enabled ? 'Switched off' : status.caught_up ? 'Up to date' : 'Building (processing existing logs)' }}
      </el-tag>
      <span>{{ signatureSourceText(status.signatures.source, status.signatures.count) }}</span>
      <span v-if="status.covered_until">· logs up to {{ ageLabel(status.covered_until) }}</span>
      <span>· listed for {{ status.retention_days }} days after last seen</span>
      <el-tooltip v-if="rescanText" content="New or changed signatures are matched against the logs already processed (the backfill window), newest first." placement="bottom">
        <el-tag size="small" type="warning" data-test="rescan">{{ rescanText }}</el-tag>
      </el-tooltip>
      <el-tooltip v-if="status.signatures.error || status.signatures.refused.length" placement="bottom">
        <template #content>
          <div v-if="status.signatures.error">{{ status.signatures.error }}</div>
          <div v-for="(r, i) in status.signatures.refused.slice(0, 10)" :key="i">{{ r.appId }} {{ r.location }}: {{ r.reason }}</div>
        </template>
        <el-tag size="small" type="warning">{{ status.signatures.refused.length ? 'signature problems' : 'catalog notice' }}</el-tag>
      </el-tooltip>
    </div>

    <el-card class="block">
      <div class="filters">
        <el-input v-model="filters.search" placeholder="Search applications" clearable class="f-search" @input="debouncedLoad">
          <template #prefix><el-icon><Search /></el-icon></template>
        </el-input>
        <el-select v-model="filters.category" placeholder="Category" clearable class="f-select" @change="load">
          <el-option v-for="c in categories" :key="c" :label="categoryLabel(c)" :value="c" />
        </el-select>
        <el-select v-model="filters.source" placeholder="Evidence source" clearable class="f-select" @change="load">
          <el-option v-for="s in SOURCE_ORDER" :key="s" :label="SOURCE_LABELS[s].label" :value="s" />
        </el-select>
        <el-input v-model="filters.host" placeholder="Host, IP or shipper" clearable class="f-host" @input="debouncedLoad" />
      </div>

      <el-tabs v-model="tab" class="tabs">
        <el-tab-pane :label="`Inventory (${apps.length})`" name="inventory">
          <el-table v-loading="loading" :data="apps" size="small" class="clickable" empty-text="Nothing identified yet" @row-click="open">
            <el-table-column label="Application" min-width="190">
              <template #default="{ row }">
                <div class="app-name">{{ row.name }}</div>
                <div class="muted">{{ row.vendor }}</div>
              </template>
            </el-table-column>
            <el-table-column label="Category" width="140">
              <template #default="{ row }"><el-tag size="small" effect="plain">{{ categoryLabel(row.category) }}</el-tag></template>
            </el-table-column>
            <el-table-column label="Versions" min-width="170">
              <template #default="{ row }">
                <el-tag
                  v-for="v in row.versions.slice(0, 4)"
                  :key="v.version"
                  size="small"
                  :type="isBehind(v.version, row.latest_version) ? 'warning' : 'success'"
                  class="chip"
                  :title="`${v.locations} location(s)`"
                  >{{ v.version }}</el-tag
                >
                <span v-if="row.versions.length > 4" class="muted">+{{ row.versions.length - 4 }}</span>
                <span v-if="!row.versions.length" class="muted">—</span>
              </template>
            </el-table-column>
            <el-table-column label="Where" width="150">
              <template #default="{ row }">
                {{ whereLabel(row) }}
                <el-tag v-if="row.unmanaged" size="small" type="info" class="chip">network only</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="Evidence" min-width="170">
              <template #default="{ row }">
                <el-tooltip v-for="s in row.sources" :key="s" :content="SOURCE_LABELS[s as InventorySource]?.hint ?? s" placement="top">
                  <el-tag size="small" type="info" effect="plain" class="chip">{{ sourceLabel(s) }}</el-tag>
                </el-tooltip>
              </template>
            </el-table-column>
            <el-table-column label="Vulnerabilities" width="120">
              <template #default="{ row }">
                <el-tag v-if="row.vulnerabilities.total" size="small" :type="row.vulnerabilities.critical ? 'danger' : 'warning'">
                  {{ row.vulnerabilities.total }} open
                </el-tag>
                <span v-else class="muted">—</span>
              </template>
            </el-table-column>
            <el-table-column label="Last seen" width="110">
              <template #default="{ row }">{{ ageLabel(row.last_seen) }}</template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <el-tab-pane :label="`Version drift (${drifting.length})`" name="drift">
          <p class="intro">Applications seen at more than one version (each location counted at the newest version it was seen with). Versions behind the newest are amber.</p>
          <el-table :data="drifting" size="small" class="clickable" empty-text="Every application runs one version" @row-click="open">
            <el-table-column label="Application" prop="name" min-width="180" />
            <el-table-column label="Versions, oldest first" min-width="320">
              <template #default="{ row }">
                <el-tag
                  v-for="v in row.versions"
                  :key="v.version"
                  size="small"
                  :type="isBehind(v.version, row.latest_version) ? 'warning' : 'success'"
                  class="chip"
                  >{{ v.version }} × {{ v.locations }}</el-tag
                >
              </template>
            </el-table-column>
            <el-table-column label="Locations behind" width="150">
              <template #default="{ row }">{{ locationsBehind(row) }}</template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <el-tab-pane :label="`Vulnerabilities (${vulns.length})`" name="vulnerabilities">
          <p class="intro">
            Open findings linked to an application. <strong>Exact</strong>: an endpoint-agent finding for one of its packages.
            <strong>Best effort</strong>: a finding on an asset where the application was seen whose title names the product.
          </p>
          <el-table v-loading="vulnsLoading" :data="vulns" size="small" empty-text="No open vulnerabilities linked to an application">
            <el-table-column label="Application" prop="app_name" min-width="150" />
            <el-table-column label="Version" prop="version" width="150" />
            <el-table-column label="Finding" min-width="230">
              <template #default="{ row }">
                <router-link v-if="canSeeVulnMgmt" :to="vulnerabilityLink(row.cve_id)">{{ row.cve_id }}</router-link>
                <span v-else>{{ row.cve_id }}</span>
                <div class="muted">{{ row.title }}</div>
              </template>
            </el-table-column>
            <el-table-column label="Severity" width="100">
              <template #default="{ row }"><SeverityBadge :severity="row.severity || 'medium'" /></template>
            </el-table-column>
            <el-table-column label="Asset" prop="asset" width="160" />
            <el-table-column label="Match" width="110">
              <template #default="{ row }">
                <el-tag size="small" :type="row.match === 'package' ? 'success' : 'info'">{{ row.match === 'package' ? 'Exact' : 'Best effort' }}</el-tag>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <el-tab-pane :label="`Unmanaged (${unmanaged.length})`" name="unmanaged">
          <p class="intro">
            Seen on the network, not inventoried: applications that only show up in clients' DNS queries or user agents, with no
            host, container, scan or endpoint evidence of yours. A SaaS your users rely on, a remote-access tool, a browser.
          </p>
          <el-table :data="unmanaged" size="small" class="clickable" empty-text="Nothing seen only on the network" @row-click="open">
            <el-table-column label="Application" prop="name" min-width="180" />
            <el-table-column label="Category" width="150">
              <template #default="{ row }">{{ categoryLabel(row.category) }}</template>
            </el-table-column>
            <el-table-column label="Clients" prop="clients" width="100" />
            <el-table-column label="Evidence" min-width="160">
              <template #default="{ row }">
                <el-tag v-for="s in row.sources" :key="s" size="small" type="info" effect="plain" class="chip">{{ sourceLabel(s) }}</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="Last seen" width="110">
              <template #default="{ row }">{{ ageLabel(row.last_seen) }}</template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <el-tab-pane :label="`Not identified (${unmatchedTotal})`" name="unmatched">
          <p class="intro">
            What SIEMBox sees that no signature identifies: log programs, parsers, container images, installed packages,
            network services, user-agent products and DNS domains, most frequent first. If one is an application,
            <template v-if="canWrite"><strong>Create signature</strong> opens it pre-filled in the editor (select several rows to make one signature
              of them); a local signature applies at once, evidence already collected included, and you can then
              <strong>Contribute</strong> it to the</template>
            <template v-else><strong>Suggest</strong> opens a pre-filled file in the</template>
            <a :href="`https://github.com/${status?.catalog_repo ?? 'cladkins/siembox-catalog'}`" target="_blank" rel="noopener noreferrer">catalog</a>.
          </p>
          <div class="filters">
            <el-select v-model="gapFilters.source" placeholder="All kinds" clearable class="f-select" data-test="gap-kind" @change="loadUnmatched">
              <el-option v-for="k in UNMATCHED_KINDS" :key="k" :label="`${unmatchedKindLabel(k)} (${unmatchedCounts[k]?.listed ?? 0})`" :value="k" />
            </el-select>
            <el-input v-model="gapFilters.search" placeholder="Search values" clearable class="f-search" @input="debouncedGaps">
              <template #prefix><el-icon><Search /></el-icon></template>
            </el-input>
            <el-tooltip content="Operating-system and library packages, CDN and telemetry domains, generic nmap services" placement="top">
              <el-checkbox v-model="gapFilters.noise" @change="loadUnmatched">Show system packages &amp; noise ({{ noiseTotal }})</el-checkbox>
            </el-tooltip>
            <el-checkbox v-model="gapFilters.ignored" @change="loadUnmatched">Show ignored ({{ ignoredTotal }})</el-checkbox>
            <el-button v-if="canWrite && gapSelection.length" size="small" type="primary" @click="createFromGaps(gapSelection)">
              Create signature from {{ gapSelection.length }} selected
            </el-button>
          </div>
          <el-table v-loading="unmatchedLoading" :data="unmatched" size="small" empty-text="Everything seen is identified" data-test="gaps" @selection-change="(rows: Unmatched[]) => (gapSelection = rows)">
            <el-table-column v-if="canWrite" type="selection" width="36" />
            <el-table-column label="Kind" width="140">
              <template #default="{ row }">
                {{ unmatchedKindLabel(row.source) }}
                <el-tag v-if="row.noise" size="small" type="info" effect="plain" class="chip">system</el-tag>
                <el-tag v-if="row.ignored" size="small" type="info" class="chip">ignored</el-tag>
                <el-tag v-if="row.detail?.vulnerable" size="small" type="danger" effect="plain" class="chip">EDR finding</el-tag>
              </template>
            </el-table-column>
            <el-table-column label="Value" min-width="220">
              <template #default="{ row }">
                <code>{{ row.value }}</code>
                <div v-if="row.sample && row.sample !== row.value" class="muted sample">{{ row.sample }}</div>
              </template>
            </el-table-column>
            <el-table-column label="Seen" width="90">
              <template #default="{ row }">{{ row.events.toLocaleString('en-US') }}</template>
            </el-table-column>
            <el-table-column label="Locations" width="90" prop="locations" />
            <el-table-column label="Example location" width="160">
              <template #default="{ row }">{{ row.location_label ?? row.sample_location ?? '—' }}</template>
            </el-table-column>
            <el-table-column label="Last seen" width="100">
              <template #default="{ row }">{{ ageLabel(row.last_seen) }}</template>
            </el-table-column>
            <el-table-column :width="canWrite ? 250 : 130" fixed="right">
              <template #default="{ row }">
                <el-button v-if="canWrite" size="small" type="primary" link data-test="gap-create" @click="createFromGaps([row])">Create signature</el-button>
                <el-button v-if="canWrite && !row.ignored" size="small" link @click="setIgnored(row, true)">Ignore</el-button>
                <el-button v-if="canWrite && row.ignored" size="small" link @click="setIgnored(row, false)">Unignore</el-button>
                <el-link :href="row.suggest_url" target="_blank" rel="noopener noreferrer" type="info" class="suggest">Suggest</el-link>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>

        <el-tab-pane :label="`Signatures (${localSigs.length})`" name="signatures">
          <p class="intro">
            Local signatures: written here in the catalog's format and used next to its {{ sigCatalog?.count ?? '' }} signatures
            (a local one with a catalog id overrides it). <strong>Contribute</strong> checks one with the catalog's CI rules and
            opens a pre-filled pull request in your browser.
          </p>
          <el-table v-loading="sigsLoading" :data="localSigs" size="small" empty-text="No local signatures yet: create one from the Not identified list" data-test="signatures">
            <el-table-column label="Signature" min-width="200">
              <template #default="{ row }">
                <div class="app-name">{{ row.name }}</div>
                <div class="muted"><code>{{ row.id }}</code> · {{ row.vendor }}</div>
              </template>
            </el-table-column>
            <el-table-column label="Category" width="140">
              <template #default="{ row }"><el-tag size="small" effect="plain">{{ categoryLabel(row.category) }}</el-tag></template>
            </el-table-column>
            <el-table-column label="Catalog" width="170">
              <template #default="{ row }">
                <el-tooltip :content="CATALOG_STATUS[row.catalog_status as CatalogStatus]?.hint ?? ''" placement="top">
                  <el-tag size="small" :type="CATALOG_STATUS[row.catalog_status as CatalogStatus]?.type ?? 'info'">{{ CATALOG_STATUS[row.catalog_status as CatalogStatus]?.label ?? row.catalog_status }}</el-tag>
                </el-tooltip>
                <el-tag v-if="row.origin === 'override'" size="small" type="warning" effect="plain" class="chip">local override</el-tag>
                <el-tooltip v-if="!row.valid" :content="row.errors.join('; ')" placement="top"><el-tag size="small" type="danger" class="chip">invalid</el-tag></el-tooltip>
              </template>
            </el-table-column>
            <el-table-column label="Enabled" width="90">
              <template #default="{ row }">
                <el-switch v-model="row.enabled" :disabled="!canWrite" size="small" @change="toggleSig(row)" />
              </template>
            </el-table-column>
            <el-table-column label="Updated" width="150">
              <template #default="{ row }">{{ ageLabel(row.updated_at) }}<div class="muted">{{ row.updated_by ?? '' }}</div></template>
            </el-table-column>
            <el-table-column label="" width="250" fixed="right">
              <template #default="{ row }">
                <el-button size="small" @click="editSig(row.id)">{{ canWrite ? 'Edit' : 'View' }}</el-button>
                <el-button size="small" data-test="contribute" @click="contribute(row.id)">Contribute</el-button>
                <el-button v-if="canWrite" size="small" type="danger" @click="deleteSig(row)">Delete</el-button>
              </template>
            </el-table-column>
          </el-table>
        </el-tab-pane>
      </el-tabs>
    </el-card>

    <el-drawer v-model="detailOpen" :title="detail ? detail.name : 'Application'" size="60%" class="detail-drawer">
      <div v-loading="detailLoading">
        <template v-if="detail">
          <p class="muted">
            {{ detail.vendor }} · {{ categoryLabel(detail.category) }}
            <template v-if="detail.website"> · <a :href="detail.website" target="_blank" rel="noopener noreferrer">website</a></template>
          </p>
          <p v-if="detail.description">{{ detail.description }}</p>
          <div class="detail-actions">
            <OpenInGraphButton type="application" :value="detail.id" window="30d" size="small" @navigate="detailOpen = false" />
            <el-tag v-if="localSigs.some((l) => l.id === detail?.id)" size="small" type="warning">local signature</el-tag>
            <el-button size="small" @click="editSig(detail.id)">{{ canWrite ? (localSigs.some((l) => l.id === detail?.id) ? 'Edit signature' : 'Override signature') : 'View signature' }}</el-button>
          </div>
          <el-descriptions :column="2" size="small" border class="block">
            <el-descriptions-item label="Where">{{ whereLabel(detail) }}</el-descriptions-item>
            <el-descriptions-item label="Evidence">{{ detail.sources.map(sourceLabel).join(', ') || '—' }}</el-descriptions-item>
            <el-descriptions-item label="First seen">{{ ageLabel(detail.first_seen) }}</el-descriptions-item>
            <el-descriptions-item label="Last seen">{{ ageLabel(detail.last_seen) }}</el-descriptions-item>
            <el-descriptions-item label="Versions" :span="2">
              <el-tag v-for="v in detail.versions" :key="v.version" size="small" class="chip" :type="isBehind(v.version, detail.latest_version) ? 'warning' : 'success'">
                {{ v.version }} × {{ v.locations }}
              </el-tag>
              <span v-if="!detail.versions.length" class="muted">no version seen</span>
            </el-descriptions-item>
          </el-descriptions>

          <h4>Locations ({{ detail.locations_total }})</h4>
          <el-table :data="detail.locations" size="small" class="block">
            <el-table-column label="Location" min-width="170">
              <template #default="{ row }">
                <router-link v-if="row.asset && canSeeAssets" :to="{ path: '/asset-inventory', query: { id: String(row.asset.id) } }">{{ row.label }}</router-link>
                <span v-else>{{ row.label }}</span>
                <div class="muted">{{ LOCATION_TYPE_LABELS[row.loc_type] ?? row.loc_type }}</div>
              </template>
            </el-table-column>
            <el-table-column label="Version" width="120">
              <template #default="{ row }">{{ row.current_version ?? '—' }}</template>
            </el-table-column>
            <el-table-column label="Evidence" min-width="260">
              <template #default="{ row }">
                <div v-for="(e, i) in row.evidence.slice(0, 3)" :key="i" class="evidence">
                  <el-tag size="small" type="info" effect="plain">{{ sourceLabel(e.source) }}</el-tag>
                  <span class="evidence-text">{{ evidenceText(e.evidence) }}</span>
                  <router-link v-if="logsLink(e.evidence, e.source, row.loc_key)" :to="logsLink(e.evidence, e.source, row.loc_key)!" class="logs-link">logs</router-link>
                </div>
              </template>
            </el-table-column>
            <el-table-column label="Last seen" width="100">
              <template #default="{ row }">{{ ageLabel(row.last_seen) }}</template>
            </el-table-column>
          </el-table>

          <h4>Open vulnerabilities ({{ detail.vulnerability_list.length }})</h4>
          <el-table :data="detail.vulnerability_list" size="small" empty-text="None linked">
            <el-table-column label="Finding" min-width="200">
              <template #default="{ row }">
                <router-link v-if="canSeeVulnMgmt" :to="vulnerabilityLink(row.cve_id)">{{ row.cve_id }}</router-link>
                <span v-else>{{ row.cve_id }}</span>
                <div class="muted">{{ row.title }}</div>
              </template>
            </el-table-column>
            <el-table-column label="Severity" width="100">
              <template #default="{ row }"><SeverityBadge :severity="row.severity || 'medium'" /></template>
            </el-table-column>
            <el-table-column label="Asset" prop="asset" width="150" />
            <el-table-column label="Match" width="110">
              <template #default="{ row }">{{ row.match === 'package' ? `Exact${row.version ? ` (${row.version})` : ''}` : 'Best effort' }}</template>
            </el-table-column>
          </el-table>
        </template>
      </div>
    </el-drawer>

    <SignatureEditor
      v-model="editorOpen"
      :initial-doc="editor.doc"
      :initial-yaml="editor.yaml"
      :editing-id="editor.editingId"
      :origin="editor.origin"
      :gap-items="editor.gaps"
      :can-ai="isAdmin"
      :ai-available="aiAvailable"
      @saved="afterSave"
    />

    <!-- Contribute to the community catalog (browser hand-off, no token needed), as on the Parsers page -->
    <el-dialog v-model="contributeOpen" title="Contribute to the community catalog" width="660px">
      <div v-loading="contributeLoading" style="min-height: 60px">
        <template v-if="contribution">
          <el-alert v-if="contribution.ready" type="success" :closable="false" show-icon title="Validated and its tests pass: ready to propose." class="block" />
          <el-alert v-else type="error" :closable="false" show-icon title="Not ready: fix the issues below, then try again." class="block" />
          <p class="intro">
            This opens GitHub's pre-filled <strong>"propose new file"</strong> page for <code>{{ contribution.path }}</code>. You finish the fork and
            pull request in your browser, signed in as you; SIEMBox never touches your GitHub credentials. A maintainer reviews it and the
            catalog's CI runs these same checks before it can merge.
          </p>
          <div v-if="contribution.tests?.total" class="intro">
            Tests:
            <el-tag :type="contribution.tests.failures.length ? 'danger' : 'success'" size="small">
              {{ contribution.tests.total - contribution.tests.failures.length }}/{{ contribution.tests.total }} passed
            </el-tag>
          </div>
          <ul v-if="contribution.errors?.length" class="contrib-issues error"><li v-for="(e, i) in contribution.errors" :key="'e' + i">{{ e }}</li></ul>
          <ul v-if="contribution.warnings?.length" class="contrib-issues warn"><li v-for="(w, i) in contribution.warnings" :key="'w' + i">{{ w }}</li></ul>
          <pre class="contrib-preview">{{ contribution.content }}</pre>
        </template>
      </div>
      <template #footer>
        <el-button @click="contributeOpen = false">Close</el-button>
        <el-button v-if="contribution" @click="copyContribution">Copy YAML</el-button>
        <el-button type="primary" :disabled="!contribution?.ready" data-test="open-pr" @click="openContribution">Open GitHub PR</el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref, watch } from 'vue';
import { useRoute } from 'vue-router';
import { ElMessage, ElMessageBox } from 'element-plus';
import { Plus, Refresh, Search } from '@element-plus/icons-vue';
import { api } from '@/services/api';
import { useAuthStore } from '@/stores/auth';
import SeverityBadge from '@/components/SeverityBadge.vue';
import OpenInGraphButton from '@/components/graph/OpenInGraphButton.vue';
import SignatureEditor, { type GapItem } from '@/components/applications/SignatureEditor.vue';
import { CATALOG_STATUS, mergeDrafts, unmatchedKindLabel, UNMATCHED_KINDS, type CatalogStatus } from '@/utils/applicationSignatures';
import {
  ageLabel,
  categoryLabel,
  driftOrder,
  isBehind,
  locationsBehind,
  logsLink,
  LOCATION_TYPE_LABELS,
  signatureSourceText,
  sourceLabel,
  SOURCE_LABELS,
  SOURCE_ORDER,
  vulnerabilityLink,
  whereLabel,
  type ApplicationRow,
  type InventorySource,
} from '@/utils/applications';

interface Status {
  enabled: boolean;
  retention_days: number;
  caught_up: boolean;
  covered_until: string | null;
  last_run_at: string | null;
  signatures: { source: string | null; count: number; error: string | null; refused: Array<{ appId: string; location: string; reason: string }> };
  catalog_repo: string;
}
interface Unmatched {
  source: string;
  value: string;
  events: number;
  locations: number;
  last_seen: string;
  sample_location: string | null;
  location_label: string | null;
  sample: string | null;
  detail: Record<string, unknown> | null;
  noise: boolean;
  ignored: boolean;
  draft: Record<string, unknown>;
  suggest_url: string;
}
interface LocalSig {
  id: string;
  name: string;
  vendor: string;
  category: string;
  enabled: boolean;
  origin: 'local' | 'override';
  catalog_status: string;
  valid: boolean;
  errors: string[];
  updated_by: string | null;
  updated_at: string;
}
interface VulnRow {
  app_id: string;
  app_name: string;
  version: string;
  cve_id: string;
  title: string | null;
  severity: string | null;
  asset: string;
  match: string;
}
interface Detail extends ApplicationRow {
  description: string;
  website: string | null;
  locations_total: number;
  locations: Array<{
    loc_type: string;
    loc_key: string;
    label: string;
    asset: { id: number } | null;
    current_version: string | null;
    last_seen: string;
    evidence: Array<{ source: string; evidence: Record<string, unknown> | null }>;
  }>;
  vulnerability_list: Array<{ cve_id: string; title: string | null; severity: string | null; asset: string; match: string; version: string }>;
}

const CATEGORIES = [
  'auth', 'automation', 'backup', 'browser', 'container-runtime', 'database', 'dev-tools', 'dns', 'file-sharing', 'game', 'home-automation',
  'http-client', 'mail', 'media-server', 'messaging', 'monitoring', 'network', 'operating-system', 'os-component', 'password-manager',
  'productivity', 'remote-access', 'reverse-proxy', 'saas', 'security', 'virtualization', 'vpn', 'web-server',
];

const authStore = useAuthStore();
const role = computed(() => authStore.user?.role ?? 'viewer');
const canRefresh = computed(() => ['admin', 'operator', 'analyst'].includes(role.value));
const canSeeVulnMgmt = computed(() => ['admin', 'operator'].includes(role.value));
const canSeeAssets = computed(() => ['admin', 'operator', 'analyst'].includes(role.value));
// Local signatures, ignoring values and the editor's checks: analyst and up (as parsers); the AI draft: admin.
const canWrite = computed(() => authStore.canAnalyst);
const isAdmin = computed(() => authStore.isAdmin);

const tab = ref('inventory');
const filters = reactive({ search: '', category: '', source: '', host: '' });
const route = useRoute();
const apps = ref<ApplicationRow[]>([]);
const status = ref<Status | null>(null);
const loading = ref(false);
const loadError = ref('');
const refreshing = ref(false);
const vulns = ref<VulnRow[]>([]);
const vulnsLoading = ref(false);
const unmatched = ref<Unmatched[]>([]);
const unmatchedLoading = ref(false);
const unmatchedCounts = ref<Record<string, { listed: number; noise: number; ignored: number; total: number }>>({});
const gapFilters = reactive({ source: '', search: '', noise: false, ignored: false });
const gapSelection = ref<Unmatched[]>([]);
const localSigs = ref<LocalSig[]>([]);
const sigsLoading = ref(false);
const sigCatalog = ref<{ count: number; source: string; repo: string } | null>(null);
const aiAvailable = ref(false);
const rescan = ref<{ apps: string[]; pending: string[]; progress: number | null } | null>(null);
const editorOpen = ref(false);
const editor = reactive<{ doc: Record<string, unknown> | null; yaml: string | null; editingId: string | null; origin: 'local' | 'override' | 'catalog' | null; gaps: GapItem[] }>({
  doc: null, yaml: null, editingId: null, origin: null, gaps: [],
});
const contributeOpen = ref(false);
const contributeLoading = ref(false);
const contribution = ref<any>(null);
const detailOpen = ref(false);
const detailLoading = ref(false);
const detail = ref<Detail | null>(null);

const categories = computed(() => {
  const seen = new Set(apps.value.map((a) => a.category));
  return CATEGORIES.filter((c) => seen.has(c) || c === filters.category);
});
const drifting = computed(() => driftOrder(apps.value));
const unmanaged = computed(() => apps.value.filter((a) => a.unmanaged));
const unmatchedTotal = computed(() => Object.values(unmatchedCounts.value).reduce((n, c) => n + c.listed, 0) || unmatched.value.length);
const noiseTotal = computed(() => Object.values(unmatchedCounts.value).reduce((n, c) => n + c.noise, 0));
const ignoredTotal = computed(() => Object.values(unmatchedCounts.value).reduce((n, c) => n + c.ignored, 0));
const rescanText = computed(() => {
  const r = rescan.value;
  if (!r) return '';
  if (r.apps.length) return `Looking back over older logs for ${r.apps.length} signature(s)${r.progress !== null ? `: ${Math.round(r.progress * 100)}%` : ''}`;
  if (r.pending.length) return `${r.pending.length} signature(s) queued to look back over older logs`;
  return '';
});

function message(err: unknown, fallback: string): string {
  return (err as { response?: { data?: { message?: string } } })?.response?.data?.message ?? fallback;
}

function params(): Record<string, string> {
  const p: Record<string, string> = {};
  for (const [k, v] of Object.entries(filters)) if (v) p[k] = v;
  return p;
}

async function load() {
  loading.value = true;
  loadError.value = '';
  try {
    const { data } = await api.getApplications(params());
    apps.value = data.applications;
    status.value = data.status;
  } catch (err) {
    loadError.value = message(err, 'Could not load the application inventory.');
  } finally {
    loading.value = false;
  }
}

let timer: ReturnType<typeof setTimeout> | null = null;
function debouncedLoad() {
  if (timer) clearTimeout(timer);
  timer = setTimeout(load, 300);
}

async function loadVulns() {
  vulnsLoading.value = true;
  try {
    vulns.value = (await api.getApplicationVulnerabilities()).data.vulnerabilities;
  } catch (err) {
    ElMessage.error(message(err, 'Could not load the vulnerabilities.'));
  } finally {
    vulnsLoading.value = false;
  }
}

async function loadUnmatched() {
  unmatchedLoading.value = true;
  const p: Record<string, string> = {};
  if (gapFilters.source) p.source = gapFilters.source;
  if (gapFilters.search.trim()) p.search = gapFilters.search.trim();
  if (gapFilters.noise) p.noise = 'true';
  if (gapFilters.ignored) p.ignored = 'true';
  try {
    const { data } = await api.getApplicationsUnmatched(p);
    unmatched.value = data.unmatched;
    unmatchedCounts.value = data.counts ?? {};
  } catch (err) {
    ElMessage.error(message(err, 'Could not load the unidentified list.'));
  } finally {
    unmatchedLoading.value = false;
  }
}

let gapTimer: ReturnType<typeof setTimeout> | null = null;
function debouncedGaps() {
  if (gapTimer) clearTimeout(gapTimer);
  gapTimer = setTimeout(loadUnmatched, 300);
}

async function loadSignatures() {
  sigsLoading.value = true;
  try {
    const { data } = await api.getApplicationSignatures();
    localSigs.value = data.signatures;
    sigCatalog.value = data.catalog;
    aiAvailable.value = !!data.ai_available;
    rescan.value = data.rescan;
  } catch (err) {
    ElMessage.error(message(err, 'Could not load the local signatures.'));
  } finally {
    sigsLoading.value = false;
  }
}

function openEditor(opts: { doc: Record<string, unknown> | null; yaml?: string | null; editingId?: string | null; origin?: 'local' | 'override' | 'catalog' | null; gaps?: GapItem[] }) {
  editor.doc = opts.doc;
  editor.yaml = opts.yaml ?? null;
  editor.editingId = opts.editingId ?? null;
  editor.origin = opts.origin ?? null;
  editor.gaps = opts.gaps ?? [];
  editorOpen.value = true;
}

function createFromGaps(rows: Unmatched[]) {
  if (!rows.length) return;
  openEditor({
    doc: mergeDrafts(rows.map((r) => r.draft)),
    gaps: rows.slice(0, 10).map((r) => ({ source: r.source, value: r.value, sample: r.sample, detail: r.detail })),
  });
}

async function editSig(id: string) {
  try {
    const { data } = await api.getApplicationSignature(id);
    openEditor({
      doc: data.definition,
      yaml: data.origin === 'catalog' ? null : data.yaml,
      editingId: data.origin === 'catalog' ? null : id,
      origin: data.origin,
    });
  } catch (err) {
    ElMessage.error(message(err, 'Could not load the signature.'));
  }
}

async function afterSave() {
  await Promise.all([loadSignatures(), loadUnmatched()]);
  // The save started an inventory run: show its results when it is done.
  setTimeout(() => void Promise.all([load(), loadUnmatched(), loadSignatures()]), 8000);
}

async function toggleSig(row: LocalSig) {
  try {
    await api.updateApplicationSignature(row.id, { enabled: row.enabled });
    ElMessage.success(row.enabled ? `${row.name} is used again` : `${row.name} is switched off`);
    await loadSignatures();
  } catch (err) {
    row.enabled = !row.enabled;
    ElMessage.error(message(err, 'Could not change the signature.'));
  }
}

async function deleteSig(row: LocalSig) {
  try {
    await ElMessageBox.confirm(
      row.origin === 'override'
        ? `Delete the local copy of "${row.name}"? The catalog's signature takes over again.`
        : `Delete "${row.name}"? It is no longer identified (its inventory rows go too).`,
      'Delete signature',
      { type: 'warning', confirmButtonText: 'Delete' }
    );
  } catch {
    return;
  }
  try {
    await api.deleteApplicationSignature(row.id);
    ElMessage.success('Signature deleted');
    await Promise.all([loadSignatures(), load()]);
  } catch (err) {
    ElMessage.error(message(err, 'Could not delete the signature.'));
  }
}

async function setIgnored(row: Unmatched, ignored: boolean) {
  try {
    if (ignored) await api.ignoreApplicationUnmatched(row.source, row.value);
    else await api.unignoreApplicationUnmatched(row.source, row.value);
    await loadUnmatched();
  } catch (err) {
    ElMessage.error(message(err, 'Could not change it.'));
  }
}

async function contribute(id: string) {
  contribution.value = null;
  contributeLoading.value = true;
  contributeOpen.value = true;
  try {
    contribution.value = (await api.getApplicationSignatureContribution(id)).data;
  } catch (err) {
    ElMessage.error(message(err, 'Could not prepare the contribution.'));
    contributeOpen.value = false;
  } finally {
    contributeLoading.value = false;
  }
}

function openContribution() {
  if (contribution.value?.contribute_url) window.open(contribution.value.contribute_url, '_blank', 'noopener');
}

async function copyContribution() {
  if (!contribution.value?.content) return;
  try {
    await navigator.clipboard.writeText(contribution.value.content);
    ElMessage.success('YAML copied');
  } catch {
    ElMessage.warning('Could not copy: select the text in the preview instead');
  }
}

async function open(row: Pick<ApplicationRow, 'id'>) {
  detailOpen.value = true;
  detailLoading.value = true;
  detail.value = null;
  try {
    detail.value = (await api.getApplication(row.id)).data;
  } catch (err) {
    ElMessage.error(message(err, 'Could not load the application.'));
  } finally {
    detailLoading.value = false;
  }
}

async function refresh() {
  refreshing.value = true;
  try {
    const { data } = await api.refreshApplications();
    ElMessage.success(`Inventory refreshed: ${data.summary}`);
    await Promise.all([load(), loadVulns(), loadUnmatched(), loadSignatures()]);
  } catch (err) {
    ElMessage.warning(message(err, 'Could not refresh the inventory.'));
  } finally {
    refreshing.value = false;
  }
}

function evidenceText(e: Record<string, unknown> | null): string {
  if (!e) return '';
  if (typeof e.image === 'string') return e.image;
  if (typeof e.package === 'string') {
    const version = e.installed_version ?? e.version;
    return `${e.package}${version ? ` ${version}` : ''}${typeof e.type === 'string' && e.type ? ` (${e.type})` : ''}`;
  }
  if (e.port !== undefined) return `${e.port}/${e.protocol ?? 'tcp'} ${e.service_name ?? ''}`.trim();
  if (typeof e.os_version === 'string') return e.os_version;
  if (typeof e.value === 'string') return e.value.length > 120 ? `${e.value.slice(0, 120)}…` : e.value;
  return '';
}

watch(tab, (t) => {
  if (t === 'vulnerabilities' && !vulns.value.length) void loadVulns();
  if (t === 'unmatched' && !unmatched.value.length) void loadUnmatched();
  if (t === 'signatures') void loadSignatures();
});

onMounted(async () => {
  // ?app=<id> (the Context Graph's link): open that application's detail.
  const linked = typeof route.query.app === 'string' && /^[a-z0-9][a-z0-9-]{0,63}$/.test(route.query.app) ? route.query.app : null;
  if (linked) void open({ id: linked });
  await load();
  // ?tab=unmatched|signatures opens that tab.
  if (typeof route.query.tab === 'string' && ['inventory', 'drift', 'vulnerabilities', 'unmanaged', 'unmatched', 'signatures'].includes(route.query.tab)) tab.value = route.query.tab;
  void loadVulns();
  void loadUnmatched();
  void loadSignatures();
});
</script>

<style scoped>
.page-header {
  display: flex;
  justify-content: space-between;
  align-items: flex-start;
  gap: 16px;
  margin-bottom: 12px;
}
.header-actions {
  display: flex;
  gap: 8px;
}
.detail-actions {
  display: flex;
  align-items: center;
  gap: 8px;
  margin-bottom: 8px;
}
.suggest {
  margin-left: 8px;
  font-size: 12px;
}
.contrib-issues {
  margin: 6px 0;
  padding-left: 18px;
  font-size: 13px;
}
.contrib-issues.error {
  color: var(--el-color-danger);
}
.contrib-issues.warn {
  color: var(--el-color-warning);
}
.contrib-preview {
  max-height: 260px;
  overflow: auto;
  background: var(--el-fill-color-light);
  padding: 8px;
  font-size: 12px;
  border-radius: 4px;
}
.page-header h2 {
  margin: 0 0 4px;
}
.subtitle {
  margin: 0;
  max-width: 900px;
  color: var(--siembox-text-secondary, #909399);
  font-size: 14px;
}
.block {
  margin-bottom: 16px;
}
.status-line {
  display: flex;
  flex-wrap: wrap;
  align-items: center;
  gap: 8px;
  margin-bottom: 12px;
  font-size: 13px;
  color: var(--siembox-text-secondary, #909399);
}
.filters {
  display: flex;
  flex-wrap: wrap;
  gap: 8px;
  margin-bottom: 8px;
}
.f-search {
  width: 240px;
}
.f-select {
  width: 180px;
}
.f-host {
  width: 200px;
}
.intro {
  margin: 0 0 12px;
  font-size: 13px;
  color: var(--siembox-text-secondary, #909399);
}
.app-name {
  font-weight: 500;
}
.muted {
  font-size: 12px;
  color: var(--siembox-text-secondary, #909399);
}
.sample {
  word-break: break-all;
}
.chip {
  margin: 0 4px 4px 0;
}
.clickable :deep(.el-table__row) {
  cursor: pointer;
}
.evidence {
  display: flex;
  align-items: center;
  gap: 6px;
  margin-bottom: 4px;
  font-size: 12px;
}
.evidence-text {
  word-break: break-all;
}
.logs-link {
  white-space: nowrap;
}
</style>
