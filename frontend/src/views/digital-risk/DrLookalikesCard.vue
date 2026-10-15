<template>
  <el-card ref="cardRef" class="dr-lookalikes">
    <template #header>
      <div class="card-header">
        <span>
          Lookalike domains
          <HelpTip text="Registered names that look like your watched domains, from the last lookalike check. It includes the ones already registered when a domain was first checked, which are recorded without a finding. Riskiest first: those that receive mail, then those with a current TLS certificate." />
        </span>
        <el-text v-if="lookalikes.state === 'checked'" size="small" type="info">
          {{ lookalikes.registered.toLocaleString() }} registered · {{ lookalikes.with_mx.toLocaleString() }} with mail
        </el-text>
      </div>
    </template>

    <div v-if="monitorOff" class="empty">
      <p class="empty-text">{{ monitorOff }}</p>
    </div>
    <div v-else-if="lookalikes.state === 'not_watched'" class="empty">
      <p v-if="isAdmin" class="empty-text">
        No domain is checked for lookalikes. <router-link to="/settings/digital-risk">Add a domain in Settings → Digital Risk →</router-link>
      </p>
      <p v-else class="empty-text">No domains are watched for lookalikes.</p>
    </div>
    <div v-else-if="lookalikes.state === 'not_checked'" class="empty">
      <p class="empty-text">The first lookalike check hasn't run yet.</p>
    </div>
    <div v-else-if="lookalikes.registered === 0" class="empty">
      <p class="empty-text">
        No registered lookalikes among {{ pluralize(lookalikes.candidates_checked, 'candidate') }} checked.
      </p>
    </div>

    <template v-else>
      <el-table
        :data="lookalikes.top"
        size="small"
        max-height="480"
        class="lookalikes-table"
        :row-key="(r: ExposureSummaryLookalike) => `${r.domain_id}:${r.lookalike}`"
      >
        <el-table-column label="Lookalike" min-width="150">
          <template #default="{ row }">
            <span class="name">{{ row.lookalike }}</span>
          </template>
        </el-table-column>
        <el-table-column label="Looks like" min-width="150">
          <template #default="{ row }">
            <span class="name">{{ row.watched_domain }}</span>
            <el-tag size="small" effect="plain" :type="row.scope === 'brand' ? 'info' : undefined" class="scope-tag">
              {{ row.scope === 'brand' ? 'Brand' : 'Owned' }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column label="Technique" min-width="110">
          <template #default="{ row }">{{ row.technique ? techniqueLabel(row.technique) : '—' }}</template>
        </el-table-column>
        <el-table-column label="Mail (MX)" width="96">
          <template #default="{ row }">
            <span class="yesno" :class="yesNo(row.has_mx).cls">
              <el-icon aria-hidden="true"><component :is="yesNo(row.has_mx).icon" /></el-icon>{{ yesNo(row.has_mx).text }}
            </span>
          </template>
        </el-table-column>
        <el-table-column label="Web (A/AAAA)" width="110">
          <template #default="{ row }">
            <span class="yesno" :class="yesNo(row.has_address).cls">
              <el-icon aria-hidden="true"><component :is="yesNo(row.has_address).icon" /></el-icon>{{ yesNo(row.has_address).text }}
            </span>
          </template>
        </el-table-column>
        <el-table-column label="TLS certificate" width="120">
          <template #default="{ row }">
            <span class="yesno" :class="CERTS[row.certs as Certs].cls">
              <el-icon aria-hidden="true"><component :is="CERTS[row.certs as Certs].icon" /></el-icon>{{ CERTS[row.certs as Certs].text }}
            </span>
          </template>
        </el-table-column>
        <el-table-column label="Registered" min-width="150">
          <template #default="{ row }">
            <span v-if="row.reported_at">Reported {{ formatDay(row.reported_at) }}</span>
            <span v-else class="muted">Already registered when first checked</span>
          </template>
        </el-table-column>
        <el-table-column label="Finding" width="130">
          <template #default="{ row }">
            <button
              v-if="row.open_findings"
              type="button"
              class="finding-button"
              :aria-label="`Show the ${row.open_findings.count} open findings for ${row.lookalike}`"
              @click="emit('filter', { lookalike: row.lookalike, domain_id: row.domain_id, open_only: true, sort: 'severity' })"
            >
              <SeverityBadge :severity="row.open_findings.worst_severity" size="small" effect="light" :show-icon="false" />
              <span class="finding-count">{{ row.open_findings.count }}</span>
            </button>
            <span v-else class="muted">—</span>
          </template>
        </el-table-column>
      </el-table>

      <p class="footer-line">
        <template v-if="shownNames < lookalikes.registered">
          Showing the {{ shownNames }} riskiest of {{ lookalikes.registered.toLocaleString() }}.
        </template>
        {{ lookalikes.with_current_cert.toLocaleString() }} with a current TLS certificate ·
        {{ pluralize(lookalikes.candidates_checked, 'candidate') }} checked.
      </p>
      <p class="guidance">
        Lookalikes that receive mail are usually phishing infrastructure. Block them at your mail and web
        gateways, and consider a takedown request to the registrar.
      </p>
    </template>
  </el-card>
</template>

<script setup lang="ts">
import { computed, ref } from 'vue';
import { CircleCheck, CircleClose, QuestionFilled, Clock } from '@element-plus/icons-vue';
import HelpTip from '@/components/HelpTip.vue';
import SeverityBadge from '@/components/SeverityBadge.vue';
import type { ExposureSummary, ExposureSummaryLookalike } from '@/services/exposureService';
import { formatDay, pluralize, type DomainMonitorState } from '@/utils/exposure';
import type { FindingsFilters } from './dashboard';

const props = defineProps<{
  lookalikes: ExposureSummary['lookalikes'];
  domainMonitor: DomainMonitorState;
  isAdmin: boolean;
}>();
const emit = defineEmits<{ (e: 'filter', filters: FindingsFilters): void }>();

const cardRef = ref<{ $el: HTMLElement } | null>(null);

// The totals count each registered name once; the table has a row per watched
// domain it looks like (acme.co can imitate both acme.com and acme.net).
const shownNames = computed(() => new Set(props.lookalikes.top.map((r) => r.lookalike)).size);

const monitorOff = computed(() =>
  props.domainMonitor === 'unavailable'
    ? "Domain monitoring isn't available in this backend."
    : props.domainMonitor === 'off'
      ? 'Domain monitoring is switched off, so lookalikes are not checked.'
      : ''
);

// The lookalike generator's fuzzer names (the backend's domainMonitor/lookalike.ts), as people say them.
const TECHNIQUES: Record<string, string> = {
  homoglyph: 'Homoglyph',
  'tld-swap': 'TLD swap',
  omission: 'Omission',
  transposition: 'Transposition',
  repetition: 'Repetition',
  replacement: 'Replacement',
  hyphenation: 'Hyphenation',
  'vowel-swap': 'Vowel swap',
  addition: 'Addition',
  bitsquatting: 'Bit flip',
  dnstwist: 'dnstwist list',
};
const techniqueLabel = (t: string) => TECHNIQUES[t] ?? t;

type Certs = 'current' | 'none' | 'not_checked';
const CERTS: Record<Certs, { text: string; icon: unknown; cls: string }> = {
  current: { text: 'Current', icon: CircleCheck, cls: 'is-yes' },
  none: { text: 'None', icon: CircleClose, cls: 'is-no' },
  not_checked: { text: 'Not checked yet', icon: Clock, cls: 'is-unknown' },
};

function yesNo(v: boolean | null): { text: string; icon: unknown; cls: string } {
  if (v === true) return { text: 'Yes', icon: CircleCheck, cls: 'is-yes' };
  if (v === false) return { text: 'No', icon: CircleClose, cls: 'is-no' };
  return { text: 'Unknown', icon: QuestionFilled, cls: 'is-unknown' };
}

/** Bring the card into view (the Lookalikes tile). */
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

.name {
  overflow-wrap: anywhere;
}

.scope-tag {
  margin-left: 6px;
}

.yesno {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  white-space: nowrap;
}

/* "Yes" is the risky answer here (the lookalike can receive mail or serve a site). */
.yesno.is-yes {
  color: var(--el-color-danger);
  font-weight: 500;
}

.yesno.is-no,
.yesno.is-unknown,
.muted {
  color: var(--siembox-text-secondary);
}

.finding-button {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  padding: 2px 4px;
  border: 1px solid transparent;
  border-radius: 4px;
  background: none;
  color: var(--siembox-text-color);
  font: inherit;
  cursor: pointer;
}

.finding-button:hover,
.finding-button:focus-visible {
  border-color: var(--el-color-primary);
}

.finding-count {
  font-weight: 600;
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

.empty-text {
  margin: 0;
  font-size: 13px;
  color: var(--siembox-text-secondary);
}

.empty-text a {
  color: var(--el-color-primary);
  text-decoration: none;
}
</style>
