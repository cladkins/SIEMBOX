<template>
  <div class="rules">
    <!-- Recommendations: not-installed catalog rules whose conditions are
         satisfied by samples of the user's real parsed logs. -->
    <el-card v-if="recsLoading || recs" class="recommendations-card">
      <template #header>
        <div class="card-header">
          <span>
            Recommended for your logs
            <el-tooltip
              content="Each not-installed catalog rule's conditions are test-run against samples of your recent parsed logs with the real condition evaluator. A recommendation means your live data satisfies the rule — it would actually engage, ranked by matching traffic × rule severity."
              placement="top"
            >
              <el-icon style="vertical-align: middle"><InfoFilled /></el-icon>
            </el-tooltip>
          </span>
          <el-button size="small" :loading="recsLoading" @click="loadRecommendations(true)">
            Refresh
          </el-button>
        </div>
      </template>

      <div v-loading="recsLoading">
        <el-table v-if="recs?.recommendations?.length" :data="recs.recommendations" size="small">
          <el-table-column prop="name" label="Rule" min-width="220" show-overflow-tooltip />
          <el-table-column label="Severity" width="100">
            <template #default="{ row }">
              <el-tag :type="severityType(row.severity)" size="small">{{ row.severity }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column label="Fed by your parsers" min-width="220">
            <template #default="{ row }">
              <el-tag
                v-for="s in row.sources"
                :key="s.parser_name"
                size="small"
                style="margin-right: 4px"
              >
                {{ s.parser_name }} {{ s.matched }}/{{ s.sampled }}
              </el-tag>
            </template>
          </el-table-column>
          <el-table-column label="Matching logs/day" width="150" align="right">
            <template #default="{ row }">
              <el-tooltip
                v-if="row.aggregation"
                :content="`Fires at ≥${row.aggregation.threshold} matches in ${row.aggregation.timeframe} per ${row.aggregation.field}`"
                placement="top"
              >
                <span>{{ row.est_daily_matches.toLocaleString() }} ⏱</span>
              </el-tooltip>
              <span v-else>{{ row.est_daily_matches.toLocaleString() }}</span>
            </template>
          </el-table-column>
          <el-table-column v-if="canEdit" label="" width="110" align="right">
            <template #default="{ row }">
              <el-button
                type="primary"
                size="small"
                :loading="installing === row.name"
                @click="installRecommended(row)"
              >
                Install
              </el-button>
            </template>
          </el-table-column>
        </el-table>
        <el-empty
          v-else-if="recs && !recs.recommendations.length"
          description="No not-installed catalog rule matches your parsed data — your relevant rules may already be installed."
          :image-size="60"
        />
      </div>
    </el-card>

    <el-card>
      <template #header>
        <div class="card-header">
          <span>Detection Rules</span>
          <div class="header-actions">
            <el-button v-if="isAdmin" size="small" @click="openAiBuilder">
              <el-icon><MagicStick /></el-icon> Generate with AI
            </el-button>
            <el-button size="small" @click="openCatalog">
              <el-icon><Shop /></el-icon> Browse Catalog
            </el-button>
            <el-button size="small" data-testid="open-sigma-library" @click="sigmaLibraryVisible = true">
              <el-icon><Collection /></el-icon> SigmaHQ
            </el-button>
            <el-button size="small" tag="a" href="https://github.com/cladkins/siembox-catalog" target="_blank" rel="noopener">
              Catalog repo ↗
            </el-button>
            <el-button v-if="isAdmin" size="small" @click="openSigmaImport">
              <el-icon><Upload /></el-icon> Import Sigma
            </el-button>
            <el-button v-if="canEdit" type="primary" size="small" @click="showCreateDialog">
              <el-icon><Plus /></el-icon> Add Rule
            </el-button>
          </div>
        </div>
      </template>

      <div class="rules-filter" data-testid="rules-attack-filter">
        <TechniqueSelect v-model="ruleTechniqueFilter" placeholder="ATT&CK technique" style="width: 280px" />
        <TacticSelect v-model="ruleTacticFilter" placeholder="ATT&CK tactic" style="width: 200px" />
        <span v-if="ruleTechniqueFilter || ruleTacticFilter" class="catalog-count">
          {{ filteredRules.length }} / {{ rules.length }} rules
        </span>
        <router-link to="/attack" class="coverage-link">ATT&amp;CK coverage →</router-link>
      </div>

      <el-table :data="filteredRules" v-loading="loading" stripe>
        <el-table-column prop="name" label="Name" min-width="250">
          <template #default="{ row }">
            {{ row.name }}<UnsafeRegexTag :safety="row.regex_safety" />
            <span v-if="row.sigma" class="sigma-provenance">
              <el-tooltip
                :content="`Added from SigmaHQ (rule ${row.sigma.sigma_id}${row.sigma.author ? ` by ${row.sigma.author}` : ''}, release ${row.sigma.release}), Detection Rule License 1.1`"
                placement="top"
              >
                <a v-if="row.sigma.url" :href="row.sigma.url" target="_blank" rel="noopener" data-testid="sigma-chip">
                  <el-tag size="small" type="primary" effect="plain">SigmaHQ ↗</el-tag>
                </a>
                <el-tag v-else size="small" type="primary" effect="plain" data-testid="sigma-chip">SigmaHQ</el-tag>
              </el-tooltip>
              <el-tag
                v-if="provenanceBadge(row.sigma)"
                size="small"
                :type="provenanceBadge(row.sigma)!.type"
                class="sigma-badge"
                data-testid="sigma-badge"
                @click="sigmaLibraryVisible = true"
              >{{ provenanceBadge(row.sigma)!.label }}</el-tag>
            </span>
          </template>
        </el-table-column>
        <el-table-column prop="severity" label="Severity" width="120" sortable>
          <template #default="{ row }">
            <el-tag :type="getSeverityType(row.severity)">
              {{ row.severity.toUpperCase() }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column v-if="catalog.length" label="Catalog" width="110">
          <template #default="{ row }">
            <el-tooltip
              v-if="catalogStatus(row.name) === 'match'"
              content="Accepted into the community catalog — your installed copy matches the published version."
              placement="top"
            >
              <el-tag type="success" size="small">In catalog</el-tag>
            </el-tooltip>
            <el-tooltip
              v-else-if="catalogStatus(row.name) === 'differs'"
              content="Exists in the community catalog with different content: either the catalog version moved ahead (install the update from Browse Catalog), or your local edits haven't been contributed yet."
              placement="top"
            >
              <el-tag type="warning" size="small">Differs</el-tag>
            </el-tooltip>
            <el-tooltip
              v-else
              content="Not in the community catalog. Use Contribute to validate it and open a submission."
              placement="top"
            >
              <el-tag type="info" size="small">Local only</el-tag>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column prop="enabled" label="Status" width="120">
          <template #default="{ row }">
            <el-switch
              v-model="row.enabled"
              @change="toggleRule(row)"
              :disabled="updating || !canEdit"
            />
          </template>
        </el-table-column>
        <el-table-column label="Triggered" width="150" sortable :sort-method="sortByTriggers">
          <template #header>
            Triggered
            <el-tooltip
              content="Alerts this rule raised, from the alerts still stored (data retention removes older ones). Click a count to see them. Updated within a minute."
              placement="top"
            >
              <el-icon class="triggered-help"><InfoFilled /></el-icon>
            </el-tooltip>
          </template>
          <template #default="{ row }">
            <el-tooltip
              v-if="row.triggers?.total"
              :content="`Last triggered ${formatWhen(row.triggers.last_triggered_at)} (${formatRelative(row.triggers.last_triggered_at)})`"
              placement="top"
            >
              <router-link :to="{ path: '/alerts', query: { ruleId: String(row.id) } }" class="trigger-count" data-testid="rule-trigger-count">
                <span class="trigger-total">{{ row.triggers.total.toLocaleString() }}</span>
                <span class="trigger-recent">24h {{ row.triggers.last_24h.toLocaleString() }} · 7d {{ row.triggers.last_7d.toLocaleString() }}</span>
              </router-link>
            </el-tooltip>
            <span v-else class="trigger-never">Never</span>
          </template>
        </el-table-column>
        <el-table-column prop="tags" label="Tags" min-width="220">
          <template #default="{ row }">
            <TechniqueChips :tags="row.tags" class="row-techniques" />
            <el-tag v-for="tag in plainTagsOf(row.tags)" :key="tag" size="small" style="margin-right: 5px">
              {{ tag }}
            </el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="description" label="Description" min-width="300" show-overflow-tooltip />
        <el-table-column label="Actions" width="300" fixed="right">
          <template #default="{ row }">
            <el-button size="small" @click="editRule(row)">{{ canEdit ? 'Edit' : 'View' }}</el-button>
            <el-button size="small" @click="contributeRule(row)">Contribute</el-button>
            <el-button v-if="canEdit" type="danger" size="small" @click="deleteRule(row)">Delete</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-card>

    <!-- Create/Edit Rule Dialog (read-only "View" for viewers) -->
    <el-dialog
      v-model="dialogVisible"
      :title="editMode ? (canEdit ? 'Edit Detection Rule' : 'View Detection Rule') : 'Create Detection Rule'"
      width="1000px"
      @close="resetForm"
    >
      <!-- A refused save, a stored unsafe regex, or a save's warnings: inline (scrolled
           into view: Save is below the fold), with a short toast pointing at it. -->
      <RegexProblemAlert :problem="editorProblem" auto-scroll />
      <el-form :model="ruleForm" :rules="formRules" ref="formRef" label-width="120px" :disabled="!canEdit">
        <el-form-item label="Name" prop="name">
          <el-input v-model="ruleForm.name" placeholder="e.g., SSH Brute Force Detection" />
        </el-form-item>

        <el-form-item label="Description" prop="description">
          <el-input
            v-model="ruleForm.description"
            type="textarea"
            :rows="2"
            placeholder="What does this rule detect?"
          />
        </el-form-item>

        <el-row :gutter="20">
          <el-col :span="12">
            <el-form-item label="Severity" prop="severity">
              <el-select v-model="ruleForm.severity" style="width: 100%">
                <el-option label="Critical" value="critical">
                  <el-tag type="danger">CRITICAL</el-tag>
                </el-option>
                <el-option label="High" value="high">
                  <el-tag type="warning">HIGH</el-tag>
                </el-option>
                <el-option label="Medium" value="medium">
                  <el-tag type="primary">MEDIUM</el-tag>
                </el-option>
                <el-option label="Low" value="low">
                  <el-tag type="success">LOW</el-tag>
                </el-option>
              </el-select>
            </el-form-item>
          </el-col>
          <el-col :span="12">
            <el-form-item label="Template">
              <el-select v-model="selectedTemplate" placeholder="Use a template" @change="applyTemplate" clearable>
                <el-option label="SSH Brute Force" value="ssh_brute" />
                <el-option label="Failed Authentication" value="failed_auth" />
                <el-option label="Root Login" value="root_login" />
                <el-option label="Web Scanning" value="web_scan" />
                <el-option label="Privilege Escalation" value="priv_esc" />
                <el-option label="Custom (Blank)" value="custom" />
              </el-select>
            </el-form-item>
          </el-col>
        </el-row>

        <el-form-item label="Tags" prop="tags">
          <el-select v-model="ruleForm.tags" multiple placeholder="Add tags" allow-create filterable style="width: 100%">
            <el-option label="authentication" value="authentication" />
            <el-option label="ssh" value="ssh" />
            <el-option label="web" value="web" />
            <el-option label="privilege" value="privilege" />
            <el-option label="brute-force" value="brute-force" />
            <el-option label="security" value="security" />
          </el-select>
        </el-form-item>

        <!-- ATT&CK techniques: written into the same tags as attack.tNNNN[.NNN] (RULES.md "MITRE ATT&CK Tagging"). -->
        <el-form-item label="ATT&CK" data-testid="attack-picker">
          <div class="attack-picker">
            <TechniqueSelect
              v-if="canEdit"
              :model-value="null"
              placeholder="Add a technique: search ID or name (T1110, brute force)"
              style="width: 100%"
              @pick="addTechnique"
            />
            <TechniqueChips
              :tags="ruleForm.tags"
              show-names
              :closable="canEdit"
              class="attack-picker-chips"
              @remove="removeTechnique"
            />
            <el-text v-if="!formTechniqueCount" size="small" type="info">
              No technique tagged. Tag the most specific technique the rule detects; its tactics follow from it.
            </el-text>
          </div>
        </el-form-item>

        <el-form-item label="Rule YAML" prop="rule_yaml">
          <div class="yaml-editor-container">
            <el-input
              v-model="ruleForm.rule_yaml"
              type="textarea"
              :rows="15"
              placeholder="Enter YAML rule definition..."
              class="yaml-editor"
            />
            <div class="yaml-help">
              <el-text size="small" type="info">
                <strong>YAML Rule Format:</strong><br>
                conditions: List of field conditions to match<br>
                exclude: Groups of conditions; a log matching every condition of a group doesn't fire (optional)<br>
                aggregation: Count events over timeframe (optional)<br>
                actions: Define alert title and description with variables
              </el-text>
            </div>
          </div>
          <el-button type="info" size="small" @click="validateYaml" style="margin-top: 10px">
            <el-icon><CircleCheck /></el-icon> Validate YAML
          </el-button>
        </el-form-item>

        <el-alert v-if="yamlError" type="error" :title="yamlError" :closable="false" style="margin-bottom: 20px" />
        <el-alert v-if="yamlValid" type="success" title="YAML is valid!" :closable="false" style="margin-bottom: 20px" />
      </el-form>

      <template #footer>
        <el-button @click="dialogVisible = false">{{ canEdit ? 'Cancel' : 'Close' }}</el-button>
        <el-button v-if="canEdit" type="primary" @click="saveRule" :loading="saving">
          {{ editMode ? 'Update' : 'Create' }} Rule
        </el-button>
      </template>
    </el-dialog>

    <!-- SigmaHQ library: compatible community rules, one-click add (disabled) and update -->
    <SigmaLibraryDialog v-model="sigmaLibraryVisible" :can-edit="canEdit" @changed="fetchRules" />

    <!-- Detection Catalog Dialog -->
    <el-dialog v-model="catalogDialogVisible" title="Detection Catalog" width="900px">
      <div class="catalog-toolbar">
        <el-input
          v-model="catalogSearch"
          placeholder="Search name, tag, description…"
          clearable
          size="small"
          style="width: 220px"
        />
        <el-select v-model="catalogSeverityFilter" size="small" style="width: 130px">
          <el-option label="All severities" value="all" />
          <el-option label="Critical" value="critical" />
          <el-option label="High" value="high" />
          <el-option label="Medium" value="medium" />
          <el-option label="Low" value="low" />
        </el-select>
        <TechniqueSelect v-model="catalogTechniqueFilter" size="small" placeholder="Technique" style="width: 200px" />
        <TacticSelect v-model="catalogTacticFilter" size="small" placeholder="Tactic" style="width: 150px" />
        <el-select v-model="catalogStatusFilter" size="small" style="width: 150px">
          <el-option label="All statuses" value="all" />
          <el-option label="Available" value="available" />
          <el-option label="Installed" value="installed" />
          <el-option label="Update available" value="update" />
          <el-option label="Invalid" value="invalid" />
          <el-option label="Fills a gap" value="gap" />
        </el-select>
        <div style="flex: 1" />
        <span class="catalog-count">{{ filteredRuleCatalog.length }} / {{ catalog.length }}</span>
        <el-button
          v-if="canEdit"
          size="small"
          type="primary"
          :loading="installingAll"
          :disabled="catalogLoading || catalog.length === 0"
          @click="installAll"
        >
          <el-icon><Download /></el-icon> Install all
        </el-button>
        <el-button v-if="canEdit" size="small" :loading="catalogLoading" @click="loadCatalog(true)">
          <el-icon><Refresh /></el-icon> Refresh
        </el-button>
      </div>
      <div v-if="catalogSource" class="catalog-source catalog-source-line">
        Source: <a :href="`https://github.com/${catalogSource.repo}`" target="_blank" rel="noopener"><code>{{ catalogSource.repo }}@{{ catalogSource.ref }}/{{ catalogSource.path }}</code></a>
      </div>

      <el-alert v-if="catalogError" type="error" :closable="false" :title="catalogError" style="margin-bottom: 12px" />
      <RegexProblemAlert :problem="catalogProblem" />

      <el-table :data="filteredRuleCatalog" v-loading="catalogLoading" stripe max-height="460" :default-sort="{ prop: 'name', order: 'ascending' }">
        <el-table-column prop="name" label="Name" min-width="220" sortable>
          <template #default="{ row }">
            <strong>{{ row.name }}</strong>
            <div v-if="row.description" class="catalog-sub">{{ row.description }}</div>
          </template>
        </el-table-column>
        <el-table-column label="Severity" width="110" sortable :sort-method="sortBySeverity">
          <template #default="{ row }">
            <el-tag v-if="row.severity" :type="severityType(row.severity)" size="small">{{ row.severity }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="Tags" width="200">
          <template #default="{ row }">
            <TechniqueChips :tags="row.tags" class="catalog-tag" />
            <el-tag v-for="t in plainTagsOf(row.tags)" :key="t" size="small" class="catalog-tag">{{ t }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="Status" width="120">
          <template #default="{ row }">
            <el-tag v-if="!row.valid" type="danger" size="small">Invalid</el-tag>
            <el-tag v-else-if="row.update_available" type="warning" size="small">Update</el-tag>
            <el-tag v-else-if="row.installed" type="success" size="small">Installed</el-tag>
            <el-tag v-else type="info" size="small" effect="plain">Available</el-tag>
            <el-tooltip
              v-if="!row.installed && catalogGaps(row).length"
              :content="`Tagged with ${catalogGaps(row).join(', ')}, which no rule of yours covers yet (ATT&CK coverage: none)`"
              placement="top"
            >
              <el-tag type="success" size="small" class="catalog-gap" data-testid="fills-gap">Fills a gap</el-tag>
            </el-tooltip>
          </template>
        </el-table-column>
        <el-table-column v-if="canEdit" label="Action" width="130" fixed="right">
          <template #default="{ row }">
            <el-tooltip v-if="!row.valid" :content="(row.errors && row.errors[0]) || 'Invalid rule'" placement="top">
              <el-button size="small" disabled>Invalid</el-button>
            </el-tooltip>
            <el-button
              v-else-if="row.update_available"
              size="small"
              type="warning"
              :loading="installing === row.name"
              @click="installRule(row)"
            >Update</el-button>
            <el-button
              v-else-if="row.installed"
              size="small"
              :loading="installing === row.name"
              @click="installRule(row)"
            >Reinstall</el-button>
            <el-button v-else size="small" type="primary" :loading="installing === row.name" @click="installRule(row)">Install</el-button>
          </template>
        </el-table-column>
      </el-table>
    </el-dialog>

    <!-- AI Detection Builder Dialog -->
    <el-dialog v-model="aiDialogVisible" title="Generate Detection with AI" width="760px">
      <el-form label-position="top">
        <el-form-item label="Describe the detection">
          <el-input
            v-model="aiDescription"
            type="textarea"
            :rows="3"
            placeholder="e.g. 5 failed SSH logins from the same IP within 5 minutes"
          />
        </el-form-item>
        <el-form-item label="Context (optional)">
          <el-input
            v-model="aiContext"
            type="textarea"
            :rows="2"
            placeholder="e.g. service=sshd; fields: source_ip, user, event (login_failure / login_success)"
          />
        </el-form-item>
        <el-button type="primary" :loading="aiGenerating" @click="runAiGenerate">
          <el-icon><MagicStick /></el-icon> {{ aiResult ? 'Regenerate' : 'Generate' }}
        </el-button>
      </el-form>

      <template v-if="aiError">
        <el-divider />
        <el-alert type="error" :closable="false" :title="aiError" />
      </template>

      <template v-if="aiResult">
        <el-divider />
        <el-alert
          :type="aiResult.ok ? 'success' : 'warning'"
          :closable="false"
          style="margin-bottom: 10px"
          :title="aiResult.ok
            ? `Valid rule (${aiResult.attempts} attempt(s))`
            : `Not fully valid after ${aiResult.attempts} attempt(s) — review or regenerate`"
        >
          <div v-if="aiResult.rule">
            <strong>{{ aiResult.rule.name }}</strong>
            <el-tag v-if="aiResult.rule.severity" size="small" :type="severityType(aiResult.rule.severity)">{{ aiResult.rule.severity }}</el-tag>
          </div>
          <ul v-if="aiResult.validation && aiResult.validation.errors.length">
            <li v-for="(e, i) in aiResult.validation.errors" :key="i">{{ e }}</li>
          </ul>
          <ul v-if="aiRedosVulnerable.length">
            <li v-for="(f, i) in aiRedosVulnerable" :key="'r' + i">
              ReDoS: regex at {{ f.location }} is vulnerable ({{ f.complexity }}) — saving it would be refused
            </li>
          </ul>
        </el-alert>
        <pre v-if="aiResult.rule" class="ai-preview">{{ aiRuleYaml }}</pre>
      </template>
      <RegexProblemAlert :problem="aiProblem" />

      <template #footer>
        <el-button @click="aiDialogVisible = false">Close</el-button>
        <el-button type="primary" :disabled="!aiResult || !aiResult.ok" :loading="aiSaving" @click="saveAiRule">
          Save Rule
        </el-button>
      </template>
    </el-dialog>

    <!-- Contribute to the community catalog (browser hand-off — no token needed) -->
    <el-dialog v-model="contributeDialogVisible" title="Contribute to the community catalog" width="640px">
      <div v-loading="contributeLoading" style="min-height: 60px">
        <template v-if="contributeData">
          <el-alert
            v-if="contributeData.ready"
            type="success" :closable="false" show-icon
            title="Validated — ready to propose."
            style="margin-bottom: 12px"
          />
          <el-alert
            v-else
            type="error" :closable="false" show-icon
            title="Not ready — fix the issues below, then try again."
            style="margin-bottom: 12px"
          />

          <p style="margin: 0 0 10px; color: var(--el-text-color-secondary); font-size: 13px">
            This opens GitHub's pre-filled <strong>“propose new file”</strong> page for
            <code>{{ contributeData.path }}</code>. You finish the fork + pull request in your browser,
            signed in as you — SIEMBox never touches your GitHub credentials. A maintainer reviews it and
            the catalog's CI re-runs validation before it can merge.
          </p>

          <ul v-if="contributeData.errors && contributeData.errors.length" class="contrib-issues error">
            <li v-for="(e, i) in contributeData.errors" :key="'e' + i">{{ e }}</li>
          </ul>
          <ul v-if="contributeData.warnings && contributeData.warnings.length" class="contrib-issues warn">
            <li v-for="(w, i) in contributeData.warnings" :key="'w' + i">{{ w }}</li>
          </ul>
        </template>
      </div>
      <template #footer>
        <el-button @click="contributeDialogVisible = false">Close</el-button>
        <el-button v-if="contributeData" @click="copyContributeContent">Copy YAML</el-button>
        <el-button type="primary" :disabled="!contributeData || !contributeData.ready" @click="openContributeUrl">
          Open GitHub PR
        </el-button>
      </template>
    </el-dialog>

    <!-- Import Sigma rules (convert community Sigma YAML to portable detections) -->
    <el-dialog v-model="sigmaDialogVisible" title="Import Sigma rules" width="820px">
      <p style="margin: 0 0 10px; color: var(--el-text-color-secondary); font-size: 13px">
        Paste one or more <a href="https://sigmahq.io" target="_blank" rel="noopener">Sigma</a> rules
        (YAML, <code>---</code> separated for multiple). They're converted to SIEMBox detections.
        Imported rules are created <strong>disabled</strong> so you can review them first.
        A condition with OR (<code>or</code>, <code>1 of selection_*</code>) imports as one rule per
        alternative (at most 10); NOT (<code>and not filter</code>) becomes the rule's
        <code>exclude</code> list. Anything else that doesn't fit (NOT inside NOT, <code>| count</code>)
        is reported and skipped rather than mistranslated.
      </p>

      <el-input
        v-model="sigmaText"
        type="textarea"
        :rows="12"
        placeholder="title: ...&#10;logsource: ...&#10;detection:&#10;  selection:&#10;    ...&#10;  condition: selection"
        spellcheck="false"
        style="font-family: var(--el-font-family-mono, monospace)"
      />

      <div style="margin-top: 14px">
        <RegexProblemAlert :problem="sigmaProblem" />
      </div>
      <div v-if="sigmaPreview.length" style="margin-top: 14px">
        <el-alert
          :type="sigmaConvertible > 0 ? 'success' : 'warning'"
          :closable="false"
          show-icon
          :title="`${sigmaConvertible} of ${sigmaPreview.length} rule(s) convertible`"
          style="margin-bottom: 10px"
        />
        <div v-for="(r, i) in sigmaPreview" :key="i" class="sigma-preview-item">
          <div class="sigma-preview-head">
            <el-icon v-if="r.ok" color="var(--el-color-success)"><CircleCheck /></el-icon>
            <el-icon v-else color="var(--el-color-warning)"><Warning /></el-icon>
            <strong>{{ r.title || '(untitled)' }}</strong>
            <el-tag v-if="r.ok && r.rule" size="small" :type="getSeverityType(r.rule.severity)">
              {{ r.rule.severity }}
            </el-tag>
            <span v-if="r.ok && r.rule" class="sigma-cond-count">
              {{ r.rule.conditions.length }} condition(s)
            </span>
          </div>
          <ul v-if="r.errors && r.errors.length" class="contrib-issues error">
            <li v-for="(e, j) in r.errors" :key="'se' + j">{{ e }}</li>
          </ul>
          <ul v-if="r.warnings && r.warnings.length" class="contrib-issues warn">
            <li v-for="(w, j) in r.warnings" :key="'sw' + j">{{ w }}</li>
          </ul>
        </div>
      </div>

      <template #footer>
        <el-button @click="sigmaDialogVisible = false">Close</el-button>
        <el-button :loading="sigmaPreviewing" :disabled="!sigmaText.trim()" @click="runSigmaPreview">
          Preview
        </el-button>
        <el-button
          type="primary"
          :loading="sigmaImporting"
          :disabled="!sigmaText.trim() || sigmaConvertible === 0"
          @click="runSigmaImport"
        >
          Import {{ sigmaConvertible || '' }}
        </el-button>
      </template>
    </el-dialog>
  </div>
</template>

<script setup lang="ts">
import { ref, onMounted, reactive, computed } from 'vue';
import { api } from '@/services/api';
import { useAuthStore } from '@/stores/auth';
import { ElMessage, ElMessageBox, FormInstance, FormRules } from 'element-plus';
import { Plus, CircleCheck, Shop, Refresh, MagicStick, Download, Upload, Warning, InfoFilled, Collection } from '@element-plus/icons-vue';
import SigmaLibraryDialog from '@/components/rules/SigmaLibraryDialog.vue';
import { provenanceBadge } from '@/utils/sigmaLibrary';
import yaml from 'js-yaml';
import RegexProblemAlert from '@/components/RegexProblemAlert.vue';
import UnsafeRegexTag from '@/components/UnsafeRegexTag.vue';
import { batchProblem, problemFromError, storedUnsafeProblem, warningsProblem, type InlineProblem } from '@/utils/regexSafety';
import { useRoute } from 'vue-router';
import TechniqueChips from '@/components/attack/TechniqueChips.vue';
import TechniqueSelect from '@/components/attack/TechniqueSelect.vue';
import TacticSelect from '@/components/attack/TacticSelect.vue';
import { useAttackIndex } from '@/composables/useAttackIndex';
import { formatRelative, formatWhen } from '@/utils/exposure';
import {
  addTechniqueTag,
  gapsFilled,
  isTechniqueId,
  isTechniqueTag,
  removeTechniqueTag,
  tagsMatchAttackFilter,
  techniqueIdsFromTags,
  type CoverageTechnique,
} from '@/utils/attack';

// Viewers browse rules and contribute them. Changing rules (create, edit,
// enable, catalog install, delete) is analyst and up; the AI builder and Sigma
// import are admin-only, matching the API's role gates.
const authStore = useAuthStore();
const canEdit = computed(() => authStore.canAnalyst);
const isAdmin = computed(() => authStore.isAdmin);

const rules = ref<any[]>([]);
const sigmaLibraryVisible = ref(false);

// ATT&CK: technique names and tactics for the chips and filters, and the
// coverage (loaded with the catalog) for its "Fills a gap" badge.
/** Detection Rules → Triggered: most alerts first when sorted descending. */
function sortByTriggers(a: any, b: any): number {
  return (a.triggers?.total ?? 0) - (b.triggers?.total ?? 0);
}

const route = useRoute();
const attackIndex = useAttackIndex();
const queryTechnique =
  typeof route.query.technique === 'string' && isTechniqueId(route.query.technique)
    ? route.query.technique.toUpperCase()
    : null;
const ruleTechniqueFilter = ref<string | null>(queryTechnique);
const ruleTacticFilter = ref<string | null>(typeof route.query.tactic === 'string' ? route.query.tactic : null);
const filteredRules = computed(() =>
  ruleTechniqueFilter.value || ruleTacticFilter.value
    ? rules.value.filter((r) =>
        tagsMatchAttackFilter(
          r.tags,
          { technique: ruleTechniqueFilter.value, tactic: ruleTacticFilter.value },
          attackIndex.value
        )
      )
    : rules.value
);

/** A rule's tags other than its ATT&CK technique tags (those show as technique chips). */
function plainTagsOf(tags: unknown): string[] {
  return Array.isArray(tags) ? tags.filter((t) => typeof t === 'string' && !isTechniqueTag(t)) : [];
}

const coverageById = ref(new Map<string, CoverageTechnique>());
let coverageRequested = false;
async function loadCoverageForGaps() {
  if (coverageRequested) return;
  coverageRequested = true;
  try {
    const { data } = await api.getAttackCoverage();
    coverageById.value = new Map((data.techniques as CoverageTechnique[]).map((t) => [t.id, t]));
  } catch {
    // Best effort: without it the catalog simply shows no "Fills a gap" badge.
    coverageRequested = false;
  }
}
function catalogGaps(row: any): string[] {
  return gapsFilled(row.tags, coverageById.value);
}
const recs = ref<any>(null);
const recsLoading = ref(false);
const loading = ref(false);
const updating = ref(false);
const saving = ref(false);

// Inline problems (a refused ReDoS-vulnerable regex, a save's warnings, a
// batch's skipped items), shown in the dialog that caused them, not a toast.
const editorProblem = ref<InlineProblem | null>(null);
const catalogProblem = ref<InlineProblem | null>(null);
const aiProblem = ref<InlineProblem | null>(null);
const sigmaProblem = ref<InlineProblem | null>(null);

// Detection catalog (browse/install from GitHub)
const catalogDialogVisible = ref(false);
const catalogLoading = ref(false);
const catalog = ref<any[]>([]);
const catalogSource = ref<any>(null);

// Community-catalog presence for the table badge. The catalog listing already
// carries installed/update_available per entry (content-signature comparison
// against the local copy), so this is a pure inversion: is THIS local rule
// published, and does the published content match? Mirrors Parsers.vue.
const catalogEntryByName = computed(() => {
  const m = new Map<string, any>();
  for (const e of catalog.value) m.set(e.name, e);
  return m;
});

function catalogStatus(name: string): 'match' | 'differs' | 'local' {
  const entry = catalogEntryByName.value.get(name);
  if (!entry) return 'local';
  return entry.update_available ? 'differs' : 'match';
}

const catalogError = ref('');
const installing = ref('');
const installingAll = ref(false);
const catalogSearch = ref('');
const catalogStatusFilter = ref('all');
const catalogSeverityFilter = ref('all');
const catalogTechniqueFilter = ref<string | null>(null);
const catalogTacticFilter = ref<string | null>(null);

const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1 };
function sortBySeverity(a: any, b: any) {
  return (SEV_RANK[a.severity] || 0) - (SEV_RANK[b.severity] || 0);
}
function ruleStatus(r: any) {
  return !r.valid ? 'invalid' : r.update_available ? 'update' : r.installed ? 'installed' : 'available';
}

const filteredRuleCatalog = computed(() => {
  const q = catalogSearch.value.trim().toLowerCase();
  return catalog.value.filter((r) => {
    if (catalogStatusFilter.value === 'gap') {
      if (r.installed || catalogGaps(r).length === 0) return false;
    } else if (catalogStatusFilter.value !== 'all' && ruleStatus(r) !== catalogStatusFilter.value) return false;
    if (
      (catalogTechniqueFilter.value || catalogTacticFilter.value) &&
      !tagsMatchAttackFilter(
        r.tags,
        { technique: catalogTechniqueFilter.value, tactic: catalogTacticFilter.value },
        attackIndex.value
      )
    )
      return false;
    if (catalogSeverityFilter.value !== 'all' && r.severity !== catalogSeverityFilter.value) return false;
    if (q) {
      const hay = [r.name, r.description, ...(r.tags || [])].join(' ').toLowerCase();
      if (!hay.includes(q)) return false;
    }
    return true;
  });
});

function severityType(sev: string) {
  return { critical: 'danger', high: 'danger', medium: 'warning', low: 'info' }[sev] || 'info';
}

function openCatalog() {
  catalogProblem.value = null;
  catalogDialogVisible.value = true;
  if (catalog.value.length === 0) loadCatalog(false);
  void loadCoverageForGaps();
}

async function loadCatalog(refresh: boolean) {
  catalogLoading.value = true;
  catalogError.value = '';
  try {
    const res = await api.getRuleCatalog(refresh);
    catalog.value = res.data.rules || [];
    catalogSource.value = res.data.source || null;
  } catch (error: any) {
    catalogError.value = error.response?.data?.message || 'Failed to load detection catalog';
  } finally {
    catalogLoading.value = false;
  }
}

async function installRule(row: any) {
  installing.value = row.name;
  catalogProblem.value = null;
  try {
    const res = await api.installCatalogRule(row.name);
    ElMessage.success(`Rule "${row.name}" ${res.data.action}`);
    catalogProblem.value = warningsProblem(res.data?.warnings, `"${row.name}" installed — but a regex could not be proven safe`);
    await Promise.all([fetchRules(), loadCatalog(false)]);
  } catch (error: any) {
    const problem = problemFromError(error, `Failed to install "${row.name}"`);
    // Recommendations install from the page, not the catalog dialog: a message there.
    if (catalogDialogVisible.value) catalogProblem.value = { ...problem, title: `"${row.name}": ${problem.title}` };
    else ElMessage.error(problem.lines[0] || problem.title);
  } finally {
    installing.value = '';
  }
}

async function loadRecommendations(refresh = false) {
  recsLoading.value = true;
  try {
    recs.value = (await api.getRuleRecommendations(refresh)).data;
  } catch {
    // Best-effort panel: a catalog/network hiccup shouldn't block the page.
    recs.value = null;
  } finally {
    recsLoading.value = false;
  }
}

async function installRecommended(row: any) {
  await installRule(row);
  await loadRecommendations(true);
}

async function installAll() {
  installingAll.value = true;
  catalogProblem.value = null;
  try {
    const { data } = await api.installAllCatalogRules();
    const msg = `Detections: ${data.installed} installed, ${data.updated} updated` +
      (data.failed?.length ? `, ${data.failed.length} failed` : '');
    catalogProblem.value = batchProblem(msg, data);
    if (!catalogProblem.value) ElMessage.success(msg);
    await Promise.all([fetchRules(), loadCatalog(false)]);
  } catch (error: any) {
    catalogProblem.value = problemFromError(error, 'Failed to install catalog');
  } finally {
    installingAll.value = false;
  }
}

// AI detection builder
const aiDialogVisible = ref(false);
const aiDescription = ref('');
const aiContext = ref('');
const aiGenerating = ref(false);
const aiResult = ref<any>(null);
const aiError = ref('');
const aiSaving = ref(false);
const aiRedosVulnerable = computed<any[]>(() =>
  (aiResult.value?.redos || []).filter((f: any) => f.status === 'vulnerable')
);
const aiRuleYaml = computed(() => {
  try {
    return aiResult.value?.rule ? yaml.dump(aiResult.value.rule) : '';
  } catch {
    return '';
  }
});

function openAiBuilder() {
  aiResult.value = null;
  aiError.value = '';
  aiProblem.value = null;
  aiDialogVisible.value = true;
}

async function runAiGenerate() {
  if (!aiDescription.value.trim()) {
    ElMessage.warning('Describe the detection first');
    return;
  }
  aiGenerating.value = true;
  aiError.value = '';
  aiResult.value = null;
  try {
    const res = await api.generateDetectionAI(aiDescription.value, aiContext.value || undefined);
    aiResult.value = res.data;
    if (res.data.error) aiError.value = res.data.error;
  } catch (error: any) {
    aiError.value =
      error.response?.data?.message ||
      (error.code === 'ECONNABORTED' ? 'Timed out waiting for the model — try again' : error.message) ||
      'Generation failed';
  } finally {
    aiGenerating.value = false;
  }
}

async function saveAiRule() {
  const rule = aiResult.value?.rule;
  if (!rule) return;
  aiSaving.value = true;
  aiProblem.value = null;
  try {
    await api.createRule({
      name: rule.name,
      description: rule.description,
      enabled: rule.enabled !== false,
      severity: rule.severity,
      rule_yaml: yaml.dump(rule),
      tags: rule.tags || [],
    });
    ElMessage.success(`Rule "${rule.name}" created`);
    aiDialogVisible.value = false;
    fetchRules();
  } catch (error: any) {
    aiProblem.value = problemFromError(error, 'Failed to save rule');
  } finally {
    aiSaving.value = false;
  }
}

const dialogVisible = ref(false);
const editMode = ref(false);
const selectedRule = ref<any>(null);
const selectedTemplate = ref('');

const formRef = ref<FormInstance>();
const ruleForm = reactive({
  name: '',
  description: '',
  severity: 'medium',
  rule_yaml: '',
  tags: [] as string[],
  enabled: true,
});

const yamlError = ref('');
const yamlValid = ref(false);

// The ATT&CK picker adds attack.tNNNN tags to the same ruleForm.tags the Tags
// select edits (a tag typed there by hand shows as a chip too), and its chips
// remove them again.
const formTechniqueCount = computed(() => techniqueIdsFromTags(ruleForm.tags).length);
function addTechnique(id: string) {
  ruleForm.tags = addTechniqueTag(ruleForm.tags, id);
}
function removeTechnique(id: string) {
  ruleForm.tags = removeTechniqueTag(ruleForm.tags, id);
}

const formRules: FormRules = {
  name: [{ required: true, message: 'Name is required', trigger: 'blur' }],
  severity: [{ required: true, message: 'Severity is required', trigger: 'change' }],
  rule_yaml: [{ required: true, message: 'Rule YAML is required', trigger: 'blur' }],
};

const ruleTemplates = {
  ssh_brute: {
    name: 'SSH Brute Force Detection',
    description: 'Detects multiple failed SSH authentication attempts from the same source',
    severity: 'high',
    tags: ['ssh', 'authentication', 'brute-force'],
    rule_yaml: `conditions:
  - field: event_type
    operator: equals
    value: ssh_auth
  - field: status
    operator: equals
    value: failed

aggregation:
  field: source_ip
  timeframe: 5m
  threshold: 5

actions:
  alert:
    title: "SSH Brute Force Attack Detected"
    description: "Multiple failed SSH login attempts from {{source_ip}} ({{count}} attempts in 5 minutes)"`,
  },
  failed_auth: {
    name: 'Failed Authentication Alert',
    description: 'Detects failed authentication attempts',
    severity: 'medium',
    tags: ['authentication', 'security'],
    rule_yaml: `conditions:
  - field: event_type
    operator: contains
    value: auth
  - field: status
    operator: equals
    value: failed

actions:
  alert:
    title: "Failed Authentication Attempt"
    description: "Failed authentication from {{source_ip}} for user {{username}}"`,
  },
  root_login: {
    name: 'Root Login Detection',
    description: 'Alerts on successful root or administrator logins',
    severity: 'critical',
    tags: ['authentication', 'privilege'],
    rule_yaml: `conditions:
  - field: event_type
    operator: equals
    value: ssh_auth
  - field: username
    operator: equals
    value: root
  - field: status
    operator: equals
    value: success

actions:
  alert:
    title: "Root Login Detected"
    description: "Root login from {{source_ip}} at {{timestamp}}"`,
  },
  web_scan: {
    name: 'Web Vulnerability Scanning',
    description: 'Detects potential web vulnerability scanning activity',
    severity: 'high',
    tags: ['web', 'security', 'scanning'],
    rule_yaml: `conditions:
  - field: event_type
    operator: equals
    value: http_request
  - field: status_code
    operator: equals
    value: 404

aggregation:
  field: source_ip
  timeframe: 1m
  threshold: 20

actions:
  alert:
    title: "Web Scanning Detected"
    description: "Potential web scan from {{source_ip}} ({{count}} 404 errors in 1 minute)"`,
  },
  priv_esc: {
    name: 'Privilege Escalation Detection',
    description: 'Detects sudo or privilege escalation attempts',
    severity: 'critical',
    tags: ['privilege', 'security'],
    rule_yaml: `conditions:
  - field: event_type
    operator: equals
    value: sudo
  - field: command
    operator: contains
    value: root

actions:
  alert:
    title: "Privilege Escalation Detected"
    description: "User {{username}} executed sudo command: {{command}}"`,
  },
  custom: {
    name: '',
    description: '',
    severity: 'medium',
    tags: [],
    rule_yaml: `conditions:
  - field:
    operator: equals
    value:

actions:
  alert:
    title: ""
    description: ""`,
  },
};

onMounted(async () => {
  await fetchRules();
  // /rules?rule=<id> (the ATT&CK Coverage panel's rule links) opens that rule;
  // /rules?catalog=1 opens the catalog.
  const linked = typeof route.query.rule === 'string' ? Number(route.query.rule) : NaN;
  const linkedRule = Number.isInteger(linked) ? rules.value.find((r) => r.id === linked) : undefined;
  if (linkedRule) editRule(linkedRule);
  if (route.query.catalog === '1') openCatalog();
  loadRecommendations();
  // Not awaited: this hits GitHub, and the Catalog column is the only thing
  // waiting on it. The table renders immediately and the column appears when
  // the listing lands, rather than holding the page on a network round trip.
  loadCatalog(false);
});

async function fetchRules() {
  loading.value = true;
  try {
    const response = await api.getRules();
    rules.value = response.data;
  } catch (error) {
    ElMessage.error('Failed to fetch rules');
  } finally {
    loading.value = false;
  }
}

function showCreateDialog() {
  editMode.value = false;
  resetForm();
  dialogVisible.value = true;
}

function editRule(rule: any) {
  editMode.value = true;
  selectedRule.value = rule;
  editorProblem.value = storedUnsafeProblem(rule.regex_safety, 'rule');

  Object.assign(ruleForm, {
    name: rule.name,
    description: rule.description,
    severity: rule.severity,
    rule_yaml: rule.rule_yaml,
    tags: rule.tags || [],
    enabled: rule.enabled,
  });

  dialogVisible.value = true;
}

function resetForm() {
  Object.assign(ruleForm, {
    name: '',
    description: '',
    severity: 'medium',
    rule_yaml: '',
    tags: [],
    enabled: true,
  });
  selectedTemplate.value = '';
  yamlError.value = '';
  yamlValid.value = false;
  editorProblem.value = null;
  formRef.value?.clearValidate();
}

function applyTemplate() {
  if (!selectedTemplate.value) return;

  const template = ruleTemplates[selectedTemplate.value as keyof typeof ruleTemplates];
  if (template) {
    ruleForm.name = template.name;
    ruleForm.description = template.description;
    ruleForm.severity = template.severity;
    ruleForm.rule_yaml = template.rule_yaml;
    ruleForm.tags = [...template.tags];
    yamlError.value = '';
    yamlValid.value = false;
  }
}

function validateYaml() {
  yamlError.value = '';
  yamlValid.value = false;

  if (!ruleForm.rule_yaml) {
    yamlError.value = 'YAML cannot be empty';
    return;
  }

  try {
    const parsed = yaml.load(ruleForm.rule_yaml) as any;

    // Validate structure
    if (!parsed.conditions || !Array.isArray(parsed.conditions)) {
      yamlError.value = 'YAML must contain a "conditions" array';
      return;
    }

    if (!parsed.actions || !parsed.actions.alert) {
      yamlError.value = 'YAML must contain "actions.alert" with title and description';
      return;
    }

    // Validate conditions
    for (const condition of parsed.conditions) {
      if (!condition.field || !condition.operator || condition.value === undefined) {
        yamlError.value = 'Each condition must have field, operator, and value';
        return;
      }
    }

    // Validate exclude groups if present: a list of non-empty condition lists
    if (parsed.exclude !== undefined) {
      const groups = parsed.exclude;
      const ok =
        Array.isArray(groups) &&
        groups.every(
          (g: any) => Array.isArray(g) && g.length > 0 && g.every((c: any) => c && c.field && c.operator && c.value !== undefined)
        );
      if (!ok) {
        yamlError.value = 'exclude must be a list of condition lists, each condition with field, operator, and value';
        return;
      }
    }

    // Validate aggregation if present
    if (parsed.aggregation) {
      if (!parsed.aggregation.field || !parsed.aggregation.timeframe || !parsed.aggregation.threshold) {
        yamlError.value = 'Aggregation must have field, timeframe, and threshold';
        return;
      }
    }

    yamlValid.value = true;
    ElMessage.success('YAML validation passed!');
  } catch (error: any) {
    yamlError.value = `YAML parsing error: ${error.message}`;
  }
}

async function saveRule() {
  if (!formRef.value) return;

  await formRef.value.validate(async (valid) => {
    if (!valid) return;

    // Validate YAML before saving
    yamlError.value = '';
    try {
      yaml.load(ruleForm.rule_yaml);
    } catch (error: any) {
      yamlError.value = `Invalid YAML: ${error.message}`;
      ElMessage.error('Please fix YAML errors before saving');
      return;
    }

    const data = {
      name: ruleForm.name,
      description: ruleForm.description,
      severity: ruleForm.severity,
      rule_yaml: ruleForm.rule_yaml,
      tags: ruleForm.tags,
      enabled: ruleForm.enabled,
    };

    saving.value = true;
    editorProblem.value = null;
    try {
      const res =
        editMode.value && selectedRule.value
          ? await api.updateRule(selectedRule.value.id, data)
          : await api.createRule(data);
      fetchRules();
      // Saved, but a regex could not be proven safe: say so here and keep the
      // editor open on the saved rule, rather than closing over the warning.
      // ATT&CK tag notes (a tactic none of its techniques belongs to) come with the regex ones.
      const saveWarnings: unknown[] = Array.isArray(res.data?.warnings) ? res.data.warnings : [];
      const attackOnly = saveWarnings.length > 0 && saveWarnings.every((w) => /^attack\./i.test(String(w)));
      const warned = warningsProblem(
        saveWarnings,
        attackOnly ? 'Saved — with a note about its ATT&CK tags' : 'Saved — with warnings (a regex could not be proven safe, or an ATT&CK tag note)'
      );
      if (warned) {
        editMode.value = true;
        selectedRule.value = res.data;
        editorProblem.value = warned;
        ElMessage.warning('Saved, with a warning: see the top of the editor');
        return;
      }
      ElMessage.success(editMode.value ? 'Rule updated successfully' : 'Rule created successfully');
      dialogVisible.value = false;
    } catch (error: any) {
      editorProblem.value = problemFromError(error, 'Failed to save rule');
      ElMessage.error('Not saved: see the top of the editor');
    } finally {
      saving.value = false;
    }
  });
}

async function toggleRule(rule: any) {
  updating.value = true;
  try {
    await api.updateRule(rule.id, { enabled: rule.enabled });
    ElMessage.success(`Rule ${rule.enabled ? 'enabled' : 'disabled'}`);
  } catch (error) {
    rule.enabled = !rule.enabled; // Revert on error
    ElMessage.error('Failed to update rule');
  } finally {
    updating.value = false;
  }
}

async function deleteRule(rule: any) {
  try {
    await ElMessageBox.confirm(
      `Are you sure you want to delete rule "${rule.name}"?`,
      'Confirm Delete',
      {
        confirmButtonText: 'Delete',
        cancelButtonText: 'Cancel',
        type: 'warning',
      }
    );

    await api.deleteRule(rule.id);
    ElMessage.success('Rule deleted');
    fetchRules();
  } catch (error: any) {
    if (error !== 'cancel') {
      ElMessage.error('Failed to delete rule');
    }
  }
}

// --- Contribute to the community catalog (browser hand-off; no token needed) ---
const contributeDialogVisible = ref(false);
const contributeLoading = ref(false);
const contributeData = ref<any>(null);

async function contributeRule(rule: any) {
  contributeData.value = null;
  contributeLoading.value = true;
  contributeDialogVisible.value = true;
  try {
    const { data } = await api.getRuleContribution(rule.id);
    contributeData.value = data;
  } catch (error: any) {
    ElMessage.error(error.response?.data?.message || 'Failed to prepare contribution');
    contributeDialogVisible.value = false;
  } finally {
    contributeLoading.value = false;
  }
}

function openContributeUrl() {
  if (contributeData.value?.contribute_url) {
    window.open(contributeData.value.contribute_url, '_blank', 'noopener');
  }
}

async function copyContributeContent() {
  if (!contributeData.value?.content) return;
  try {
    await navigator.clipboard.writeText(contributeData.value.content);
    ElMessage.success('Copied detection YAML — you can paste it into GitHub manually');
  } catch {
    ElMessage.warning('Copy failed');
  }
}

const getSeverityType = (severity: string) => {
  const types: Record<string, any> = {
    critical: 'danger',
    high: 'warning',
    medium: 'primary',
    low: 'success',
  };
  return types[severity] || 'info';
};

// ---- Sigma import ---------------------------------------------------------
const sigmaDialogVisible = ref(false);
const sigmaText = ref('');
const sigmaPreview = ref<any[]>([]);
const sigmaPreviewing = ref(false);
const sigmaImporting = ref(false);
const sigmaConvertible = computed(() => sigmaPreview.value.filter((r) => r.ok).length);

function openSigmaImport() {
  sigmaText.value = '';
  sigmaPreview.value = [];
  sigmaProblem.value = null;
  sigmaDialogVisible.value = true;
}

async function runSigmaPreview() {
  if (!sigmaText.value.trim()) return;
  sigmaPreviewing.value = true;
  sigmaProblem.value = null;
  try {
    // Each converted rule passes the import's regex gate in the preview too, so
    // a refused (ReDoS-vulnerable) one shows its reason in its own entry below.
    const { data } = await api.previewSigmaImport(sigmaText.value);
    sigmaPreview.value = data.results || [];
    if (sigmaConvertible.value === 0) {
      ElMessage.warning('No rules could be converted — see the reasons below');
    }
  } catch (error: any) {
    sigmaProblem.value = problemFromError(error, 'Preview failed');
  } finally {
    sigmaPreviewing.value = false;
  }
}

async function runSigmaImport() {
  if (!sigmaText.value.trim()) return;
  sigmaImporting.value = true;
  sigmaProblem.value = null;
  try {
    const { data } = await api.importSigma(sigmaText.value);
    const parts = [`${data.created} created`, `${data.updated} updated`];
    if (data.failed?.length) parts.push(`${data.failed.length} skipped`);
    const summary = `Sigma import: ${parts.join(', ')}`;
    const problem = batchProblem(summary, data);
    if (problem) {
      // Keep the dialog open with every skipped rule and its reason inline.
      await runSigmaPreview();
      sigmaProblem.value = problem;
    } else {
      ElMessage.success(summary);
      sigmaDialogVisible.value = false;
    }
    await fetchRules();
  } catch (error: any) {
    sigmaProblem.value = problemFromError(error, 'Import failed');
  } finally {
    sigmaImporting.value = false;
  }
}
</script>

<style scoped>
.sigma-provenance {
  margin-left: 6px;
  white-space: nowrap;
}
.sigma-provenance a {
  text-decoration: none;
}
.sigma-badge {
  margin-left: 4px;
  cursor: pointer;
}
.recommendations-card {
  margin-bottom: 20px;
}

.rules {
  padding: 0;
}

.card-header {
  display: flex;
  justify-content: space-between;
  align-items: center;
}

.header-actions {
  display: flex;
  gap: 10px;
  align-items: center;
}

.catalog-toolbar {
  display: flex;
  gap: 10px;
  align-items: center;
  margin-bottom: 8px;
}

.catalog-count {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

.catalog-source-line {
  margin-bottom: 12px;
}

.catalog-source {
  font-size: 13px;
  color: var(--el-text-color-secondary);
}

.catalog-sub {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}

.catalog-tag {
  margin: 0 4px 4px 0;
}

.catalog-gap {
  margin-left: 4px;
}

.rules-filter {
  display: flex;
  flex-wrap: wrap;
  gap: 10px;
  align-items: center;
  margin-bottom: 12px;
}

.coverage-link {
  margin-left: auto;
  font-size: 13px;
}

.row-techniques {
  margin-right: 5px;
}

.attack-picker {
  display: flex;
  flex-direction: column;
  gap: 6px;
  width: 100%;
}

.ai-preview {
  background: var(--siembox-bg-color);
  padding: 12px;
  border-radius: 4px;
  max-height: 280px;
  overflow: auto;
  font-size: 12px;
  white-space: pre-wrap;
}

.yaml-editor-container {
  width: 100%;
}

.yaml-editor {
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', monospace;
  font-size: 13px;
}

.yaml-editor :deep(textarea) {
  font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', 'Consolas', monospace;
  font-size: 13px;
  line-height: 1.5;
}

.yaml-help {
  margin-top: 10px;
  padding: 10px;
  background: var(--siembox-bg-color);
  border-radius: 4px;
  font-size: 12px;
}
.contrib-issues {
  margin: 6px 0 0;
  padding-left: 18px;
  font-size: 13px;
}
.contrib-issues.error { color: var(--el-color-danger); }
.contrib-issues.warn { color: var(--el-color-warning); }

.sigma-preview-item {
  padding: 8px 0;
  border-top: 1px solid var(--el-border-color-lighter);
}
.sigma-preview-head {
  display: flex;
  align-items: center;
  gap: 8px;
}
.sigma-cond-count {
  color: var(--el-text-color-secondary);
  font-size: 12px;
}
.trigger-count {
  display: inline-flex;
  flex-direction: column;
  line-height: 1.25;
  text-decoration: none;
  color: var(--el-color-primary);
}
.trigger-total {
  font-weight: 600;
}
.trigger-recent {
  font-size: 12px;
  color: var(--el-text-color-secondary);
}
.trigger-never {
  color: var(--el-text-color-placeholder);
}
.triggered-help {
  vertical-align: middle;
  margin-left: 2px;
  cursor: help;
}
</style>
