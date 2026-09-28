<script setup lang="ts">
import type { DeploymentStorage } from "~~/shared/types/api";

// The deployment's disk (R01): free space against the watermarks, the
// metadata database and the reserve it holds, and what every tenant stores
// against the deployment's own limits.
const api = useApi();
const { data } = await useAsyncData("platform-storage", () => api<DeploymentStorage>("/api/v1/admin/storage"));
const DAY = 86_400_000;
const used = computed(() => (data.value?.filesystem_bytes && data.value.free_bytes !== null ? data.value.filesystem_bytes - data.value.free_bytes : null));
</script>

<template>
  <section v-if="data" aria-labelledby="disk-h" class="space-y-3">
    <h2 id="disk-h" class="text-base font-semibold">Disk</h2>
    <UAlert v-if="data.admission_open === false" color="warning" variant="subtle" icon="i-lucide-hard-drive" role="alert"
      title="Storage admission is closed" description="Free space fell below the low watermark: new artifacts and uploads are refused and no new work is placed until space frees above the high watermark." />
    <div class="grid gap-3 sm:grid-cols-3">
      <UCard>
        <p class="text-sm text-muted">Data filesystem</p>
        <p class="text-lg font-semibold">{{ fmtBytes(data.free_bytes) }} free</p>
        <p class="text-xs text-muted">of {{ fmtBytes(data.filesystem_bytes) }}<template v-if="used !== null"> · {{ fmtBytes(used) }} used</template></p>
      </UCard>
      <UCard>
        <p class="text-sm text-muted">Metadata database</p>
        <p class="text-lg font-semibold">{{ fmtBytes(data.metadata_bytes) }}</p>
        <p class="text-xs text-muted">reserve held for it: {{ fmtBytes(data.watermarks?.reserve_bytes) }}</p>
      </UCard>
      <UCard>
        <p class="text-sm text-muted">Stored by tenants</p>
        <p class="text-lg font-semibold">{{ fmtBytes(data.stored_bytes) }}</p>
        <p class="text-xs text-muted">{{ data.quota_bytes ? `deployment cap ${fmtBytes(data.quota_bytes)}` : "no deployment cap" }}</p>
      </UCard>
    </div>
    <dl v-if="data.watermarks" class="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1 text-sm">
      <dt class="text-muted">Reserve</dt><dd>{{ fmtBytes(data.watermarks.reserve_bytes) }} (configured {{ fmtBytes(data.watermarks.configured_reserve_bytes) }})</dd>
      <dt class="text-muted">Closes below</dt><dd>{{ fmtBytes(data.watermarks.low_watermark_bytes) }} free above the reserve</dd>
      <dt class="text-muted">Reopens above</dt><dd>{{ fmtBytes(data.watermarks.high_watermark_bytes) }}</dd>
      <dt class="text-muted">Logs refused below</dt><dd>{{ fmtBytes(data.watermarks.log_floor_bytes) }} free</dd>
      <dt class="text-muted">Tenant default quota</dt><dd>{{ data.tenant_quota_bytes ? fmtBytes(data.tenant_quota_bytes) : "none" }}</dd>
      <dt class="text-muted">Logs kept</dt><dd>{{ Math.round(data.log_retention_ms / DAY) }} days by default</dd>
      <dt class="text-muted">Artifacts kept at most</dt><dd>{{ Math.round(data.artifact_retention_ms / DAY) }} days by default</dd>
      <dt class="text-muted">Artifacts per run</dt><dd>{{ fmtBytes(data.run_artifact_bytes) }}</dd>
    </dl>
    <p class="text-sm text-muted">Deployment limits come from the controller's <code>[storage]</code> configuration; a tenant's own limits are set from Tenants.</p>
  </section>
  <section v-if="data" aria-labelledby="s3-h" class="space-y-3">
    <h2 id="s3-h" class="text-base font-semibold">External copy (S3)</h2>
    <p v-if="!data.s3" class="text-sm text-muted">Not configured: objects and logs live on the controller's disk only. See <code>[s3]</code> in the configuration.</p>
    <template v-else>
      <UAlert v-if="data.s3.state === 'degraded'" color="warning" variant="subtle" icon="i-lucide-cloud-off" role="alert"
        :title="data.s3.backlog_full ? 'New artifacts and uploads are paused: the external copy is behind' : 'The external copy is failing'"
        :description="data.s3.last_error ?? 'Local copies are kept until it catches up.'" />
      <div class="grid gap-3 sm:grid-cols-3">
        <UCard>
          <p class="text-sm text-muted">State</p>
          <p class="text-lg font-semibold"><StateBadge :state="data.s3.state === 'healthy' ? 'online' : data.s3.state === 'degraded' ? 'failed' : 'pending'" :label="data.s3.state" /></p>
          <p class="text-xs text-muted">last success <RelTime :ms="data.s3.last_success_ms" /></p>
        </UCard>
        <UCard>
          <p class="text-sm text-muted">Waiting to be copied</p>
          <p class="text-lg font-semibold">{{ fmtBytes(data.s3.backlog_bytes) }}</p>
          <p class="text-xs text-muted">{{ data.s3.unreplicated_logs }} logs · oldest <RelTime :ms="data.s3.oldest_unreplicated_ms" /></p>
        </UCard>
        <UCard>
          <p class="text-sm text-muted">Copied</p>
          <p class="text-lg font-semibold">{{ fmtBytes(data.s3.replicated_bytes) }}</p>
          <p class="text-xs text-muted">{{ data.s3.replicated_objects }} objects · {{ data.s3.replicated_logs }} logs since start</p>
        </UCard>
      </div>
      <dl class="grid grid-cols-[max-content_1fr] gap-x-6 gap-y-1 text-sm">
        <dt class="text-muted">Held locally</dt><dd>{{ fmtBytes(data.s3.local_bytes) }}</dd>
        <dt class="text-muted">Evicted / fetched back</dt><dd>{{ data.s3.evicted_objects }} / {{ data.s3.fetched_objects }} since start</dd>
        <dt class="text-muted">Copies deleted</dt><dd>{{ data.s3.deleted_copies }}</dd>
        <dt class="text-muted">Abandoned uploads aborted</dt><dd>{{ data.s3.aborted_uploads }}</dd>
        <dt class="text-muted">Failures in a row</dt><dd>{{ data.s3.consecutive_failures }}</dd>
      </dl>
    </template>
  </section>
</template>
