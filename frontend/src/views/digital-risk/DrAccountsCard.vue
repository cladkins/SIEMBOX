<template>
  <el-card ref="cardRef" class="dr-accounts">
    <template #header>
      <div class="card-header">
        <span>
          Accounts to act on
          <HelpTip text="Accounts in open breach findings, those whose password, password hash or auth token leaked (or that turned up in a stealer log) first. Click a row to see its findings." />
        </span>
        <el-text v-if="accounts.total" size="small" type="info">{{ pluralize(accounts.to_reset, 'account') }} to reset</el-text>
      </div>
    </template>

    <template v-if="accounts.top.length">
      <el-table :data="accounts.top" size="small" class="accounts-table clickable-rows" row-key="account" @row-click="onRow">
        <el-table-column label="Account" min-width="170">
          <template #default="{ row }">
            <span class="account-name">{{ row.account }}</span>
          </template>
        </el-table-column>
        <el-table-column label="Breaches" min-width="170">
          <template #default="{ row }">
            <span class="breaches">
              <el-tooltip
                v-for="b in row.breaches"
                :key="b.title"
                :content="b.date ? `Breached ${formatDay(b.date) || b.date}` : 'Breach date unknown'"
                placement="top"
              >
                <span class="breach-title">{{ b.title }}</span>
              </el-tooltip>
              <span v-if="row.open > row.breaches.length" class="more">+{{ row.open - row.breaches.length }} more</span>
            </span>
          </template>
        </el-table-column>
        <el-table-column label="Exposed" min-width="120">
          <template #default="{ row }">
            <el-tag v-if="row.credential_exposures > 0" size="small" type="danger" effect="light" class="exposed-tag">Passwords</el-tag>
            <el-tag v-if="row.stealer_log" size="small" type="warning" effect="light" class="exposed-tag">Stealer log</el-tag>
            <span v-if="!row.credential_exposures && !row.stealer_log" class="muted">—</span>
          </template>
        </el-table-column>
        <el-table-column label="Worst" width="96">
          <template #default="{ row }">
            <SeverityBadge :severity="row.worst_severity" size="small" effect="light" :show-icon="false" />
          </template>
        </el-table-column>
        <el-table-column label="Open" width="64" align="right" prop="open" />
      </el-table>

      <p class="footer-line">
        <template v-if="accounts.total > accounts.top.length">
          Showing {{ accounts.top.length }} of {{ pluralize(accounts.total, 'breached account') }}; all are in the findings below.
        </template>
        <template v-else>
          {{ accounts.total === 1 ? 'The breached account is' : `All ${accounts.total} breached accounts are` }} in the findings below.
        </template>
      </p>
      <p class="guidance">
        Reset these passwords everywhere they were reused, revoke sessions and require MFA. For stealer-log
        entries, also check the device for malware.
      </p>
      <HibpAttribution />
    </template>

    <div v-else class="empty">
      <template v-if="!checksReady">
        <p class="empty-title">{{ breachTitle }}</p>
        <p class="empty-text">No breached accounts can be found until breach checks run.</p>
      </template>
      <p v-else class="empty-text">
        No breached accounts among {{ pluralize(identitiesEnabled, 'monitored identity', 'monitored identities') }}<template
          v-if="lastChecked"
        > (last checked {{ formatRelative(lastChecked) }})</template>.
      </p>
    </div>
  </el-card>
</template>

<script setup lang="ts">
import { ref } from 'vue';
import HelpTip from '@/components/HelpTip.vue';
import HibpAttribution from '@/components/HibpAttribution.vue';
import SeverityBadge from '@/components/SeverityBadge.vue';
import type { ExposureSummary, ExposureSummaryAccount } from '@/services/exposureService';
import { formatDay, formatRelative, pluralize } from '@/utils/exposure';
import type { FindingsFilters } from './dashboard';

defineProps<{
  accounts: ExposureSummary['accounts'];
  /** Breach checks can run (switched on, a usable HIBP key). */
  checksReady: boolean;
  /** The Monitoring card's breach headline, said again when checks can't run. */
  breachTitle: string;
  identitiesEnabled: number;
  lastChecked: string | null;
}>();
const emit = defineEmits<{ (e: 'filter', filters: FindingsFilters): void }>();

const cardRef = ref<{ $el: HTMLElement } | null>(null);

function onRow(row: ExposureSummaryAccount) {
  emit('filter', { account: row.account, event_type: 'breach', category: 'credentials', open_only: true, sort: 'severity' });
}

/** Bring the card into view (the Accounts tile). */
function scrollIntoView() {
  cardRef.value?.$el?.scrollIntoView?.({ behavior: 'smooth', block: 'start' });
}

defineExpose({ scrollIntoView });
</script>

<style scoped>
.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 8px;
  flex-wrap: wrap;
}

.clickable-rows :deep(.el-table__row) {
  cursor: pointer;
}

.account-name {
  font-weight: 500;
  overflow-wrap: anywhere;
}

.breaches {
  display: flex;
  flex-wrap: wrap;
  gap: 2px 8px;
}

.breach-title {
  border-bottom: 1px dotted var(--siembox-text-tertiary);
}

.more,
.muted {
  color: var(--siembox-text-secondary);
}

.exposed-tag {
  margin: 0 4px 2px 0;
}

.footer-line,
.guidance {
  margin: 10px 0 0;
  font-size: 12px;
  color: var(--siembox-text-secondary);
}

.guidance {
  color: var(--siembox-text-color);
}

.empty {
  padding: 16px 0;
  text-align: center;
}

.empty-title {
  margin: 0 0 4px;
  font-weight: 500;
  color: var(--siembox-text-color);
}

.empty-text {
  margin: 0;
  font-size: 13px;
  color: var(--siembox-text-secondary);
}
</style>
