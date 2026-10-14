<script setup lang="ts">
// Guidance under a new-password field: a five-step meter and what would make
// the password stronger, judged in the page (nothing is sent). The meter is
// decorative; the words carry the meaning and are announced politely.
const props = defineProps<{ password: string; context?: string[]; id: string }>();
const advice = computed(() => passwordAdvice(props.password, props.context ?? []));
const colors = ["bg-error", "bg-error", "bg-warning", "bg-success", "bg-success"];
</script>

<template>
  <div :id="id" class="space-y-1">
    <div class="flex gap-1" aria-hidden="true">
      <span v-for="n in 4" :key="n" class="h-1 flex-1 rounded-full" :class="password && advice.score >= n ? colors[advice.score] : 'bg-accented'" />
    </div>
    <p class="text-xs text-muted" aria-live="polite">
      <template v-if="password"><span class="font-medium text-default">{{ advice.label }}.</span> {{ advice.hints[0] ?? "Looks good." }}</template>
      <template v-else>At least {{ PASSWORD_MIN_BYTES }} characters. A password manager can make and keep one for you.</template>
    </p>
  </div>
</template>
