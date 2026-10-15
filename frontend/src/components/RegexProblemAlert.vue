<template>
  <el-alert
    v-if="problem"
    ref="alertRef"
    :type="problem.type"
    :title="problem.title"
    :closable="false"
    show-icon
    class="regex-problem"
    data-testid="regex-problem"
  >
    <ul v-if="problem.lines.length" class="regex-problem-lines">
      <li v-for="(line, i) in problem.lines" :key="i">{{ line }}</li>
    </ul>
    <div v-for="(f, i) in problem.findings" :key="'f' + i" class="regex-problem-finding">
      <div>
        <strong>{{ f.location }}</strong>
        <span v-if="f.complexity"> — {{ f.complexity }} backtracking</span>
      </div>
      <code class="regex-problem-source">{{ f.source }}</code>
      <div v-if="f.attack" class="regex-problem-attack">Slow input, for example: <code>{{ f.attack }}</code></div>
    </div>
    <div v-if="problem.findings.length || problem.code === 'REGEX_TIMEOUT'" class="regex-problem-help">
      Rewrite it so no two parts of the pattern can match the same text: anchor it, use bounded character
      classes such as <code>[^"]*</code> or <code>\S+</code>, and never nest or chain quantifiers over the same
      characters (<code>(a+)+</code>, <code>.*x.*</code>). For "A, then later B" use a gap that cannot contain A,
      e.g. <code>curl(?:[^c|]|c(?!url))*\|</code>. See "Regex safety" in PARSERS.md / RULES.md.
    </div>
  </el-alert>
</template>

<script setup lang="ts">
import { nextTick, ref, watch } from 'vue';
import type { InlineProblem } from '@/utils/regexSafety';

const props = defineProps<{
  problem: InlineProblem | null;
  /**
   * Bring the alert into view whenever a new problem appears. For dialogs
   * whose Save button sits below the fold, where the alert renders at the
   * top: without it a refused (or warned) save looks like nothing happened.
   */
  autoScroll?: boolean;
}>();

const alertRef = ref<{ $el?: Element } | null>(null);

watch(
  () => props.problem,
  async (problem) => {
    if (!problem || !props.autoScroll) return;
    await nextTick();
    const el = alertRef.value?.$el;
    if (el && typeof (el as HTMLElement).scrollIntoView === 'function') {
      (el as HTMLElement).scrollIntoView({ block: 'nearest', behavior: 'smooth' });
    }
  }
);
</script>

<style scoped>
.regex-problem {
  margin-bottom: 12px;
}
.regex-problem-lines {
  margin: 4px 0;
  padding-left: 18px;
}
.regex-problem-finding {
  margin-top: 8px;
}
.regex-problem-source {
  display: block;
  margin-top: 2px;
  white-space: pre-wrap;
  word-break: break-all;
}
.regex-problem-attack {
  margin-top: 2px;
  font-size: 12px;
}
.regex-problem-help {
  margin-top: 8px;
  font-size: 12px;
}
</style>
