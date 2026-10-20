<template>
  <span v-if="ids.length" class="technique-chips">
    <el-tooltip v-for="id in ids" :key="id" :content="techniqueLabel(index, id)" placement="top">
      <router-link v-if="link" :to="{ path: '/attack', query: { technique: id } }" class="technique-chip-link">
        <el-tag size="small" type="danger" effect="plain" class="technique-chip" data-testid="technique-chip">
          {{ id }}<template v-if="showNames && name(id)"> {{ name(id) }}</template>
        </el-tag>
      </router-link>
      <el-tag
        v-else
        size="small"
        type="danger"
        effect="plain"
        class="technique-chip"
        data-testid="technique-chip"
        :closable="closable"
        @close="emit('remove', id)"
      >
        {{ id }}<template v-if="showNames && name(id)"> {{ name(id) }}</template>
      </el-tag>
    </el-tooltip>
  </span>
</template>

<script setup lang="ts">
import { computed } from 'vue';
import { useAttackIndex } from '@/composables/useAttackIndex';
import { techniqueIdsFromTags, techniqueLabel } from '@/utils/attack';

/**
 * ATT&CK technique chips: the IDs from `techniques` (alerts.attack_techniques)
 * or the `attack.t…` entries of `tags` (a rule's), each with its name in a
 * tooltip (or inline with `show-names`). `link` makes each chip open the
 * technique on the ATT&CK Coverage page.
 */
const props = withDefaults(
  defineProps<{
    tags?: string[] | null;
    techniques?: string[] | null;
    link?: boolean;
    showNames?: boolean;
    closable?: boolean;
  }>(),
  { tags: null, techniques: null, link: false, showNames: false, closable: false }
);
const emit = defineEmits<{ remove: [id: string] }>();

const index = useAttackIndex();
const ids = computed(() =>
  props.techniques ? [...new Set(props.techniques.map((t) => t.toUpperCase()))].sort() : techniqueIdsFromTags(props.tags)
);
const name = (id: string) => index.value?.byId.get(id)?.fullName ?? '';
</script>

<style scoped>
.technique-chips {
  display: inline-flex;
  flex-wrap: wrap;
  gap: 4px;
  vertical-align: middle;
}
.technique-chip-link {
  text-decoration: none;
}
.technique-chip {
  font-variant-numeric: tabular-nums;
}
</style>
