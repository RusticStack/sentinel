<script setup lang="ts">
// A state as a badge: the word always, colour and icon as reinforcement.
const props = defineProps<{ state: string | null | undefined; label?: string }>();
const look = computed(() => stateLook(props.state || "unknown"));
</script>

<template>
  <UBadge :color="look.color" variant="subtle" :icon="look.icon" :label="label ?? words(state || 'unknown')" class="whitespace-nowrap" />
</template>
