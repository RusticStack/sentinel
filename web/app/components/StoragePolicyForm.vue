<script setup lang="ts">
import type { StoragePolicy } from "~~/shared/types/api";

// One storage policy (R01): a quota and two retentions, each left blank to
// inherit. `inherited` shows what blank means here — the tenant's value for
// a repository, the deployment's for a tenant.
const props = defineProps<{
  id: string;
  policy: StoragePolicy;
  inherited: { quota_bytes: number; log_retention_ms: number; artifact_retention_ms: number };
  /** A repository may only narrow: its retentions cap at these. */
  maxLogDays?: number;
  maxArtifactDays?: number;
}>();
const emit = defineEmits<{ save: [{ quota_bytes: number | null; log_retention_secs: number | null; artifact_retention_secs: number | null }] }>();
const DAY = 86_400_000;
const GIB = 2 ** 30;
const quota = ref<number | undefined>(props.policy.quota_bytes ? props.policy.quota_bytes / GIB : undefined);
const logs = ref<number | undefined>(props.policy.log_retention_ms ? props.policy.log_retention_ms / DAY : undefined);
const artifacts = ref<number | undefined>(props.policy.artifact_retention_ms ? props.policy.artifact_retention_ms / DAY : undefined);
const days = (ms: number) => `${Math.round((ms / DAY) * 10) / 10} days`;

function save() {
  emit("save", {
    quota_bytes: quota.value ? Math.round(quota.value * GIB) : null,
    log_retention_secs: logs.value ? Math.round(logs.value * 86_400) : null,
    artifact_retention_secs: artifacts.value ? Math.round(artifacts.value * 86_400) : null,
  });
}
function inheritAll() {
  quota.value = logs.value = artifacts.value = undefined;
  save();
}
</script>

<template>
  <form class="space-y-3" :aria-label="`Storage policy ${id}`" @submit.prevent="save">
    <div class="grid gap-3 sm:grid-cols-3">
      <UFormField label="Quota (GiB)" :name="`${id}-quota`" :help="`Blank: ${inherited.quota_bytes ? fmtBytes(inherited.quota_bytes) : 'no limit'}`">
        <UInputNumber :id="`${id}-quota`" v-model="quota" :min="0.001" :step="1" :step-snapping="false" placeholder="inherit" class="w-full" />
      </UFormField>
      <UFormField label="Keep logs (days)" :name="`${id}-logs`" :help="`Blank: ${days(inherited.log_retention_ms)}`">
        <UInputNumber :id="`${id}-logs`" v-model="logs" :min="0.05" :max="maxLogDays ?? 366" :step="1" :step-snapping="false" placeholder="inherit" class="w-full" />
      </UFormField>
      <UFormField label="Keep artifacts at most (days)" :name="`${id}-artifacts`" :help="`Blank: ${days(inherited.artifact_retention_ms)}`">
        <UInputNumber :id="`${id}-artifacts`" v-model="artifacts" :min="0.05" :max="maxArtifactDays ?? 366" :step="1" :step-snapping="false" placeholder="inherit" class="w-full" />
      </UFormField>
    </div>
    <div class="flex gap-2">
      <UButton type="submit" size="sm" label="Save" />
      <UButton size="sm" color="neutral" variant="ghost" label="Inherit everything" @click="inheritAll" />
    </div>
    <p class="text-xs text-muted">A shorter retention applies to what is already stored, from the next maintenance pass.</p>
  </form>
</template>
