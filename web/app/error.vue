<script setup lang="ts">
import type { NuxtError } from "#app";
// A refusal or a missing page, in words: the controller answers the same
// "not found" for what does not exist and what the caller may not see.
const props = defineProps<{ error: NuxtError }>();
const notFound = computed(() => props.error.statusCode === 404);
useHead({ title: notFound.value ? "Not found · Sentinel" : "Error · Sentinel" });
</script>

<template>
  <UApp>
    <main id="main" class="min-h-screen flex items-center justify-center p-4">
      <UEmpty
        :icon="notFound ? 'i-lucide-search-x' : 'i-lucide-triangle-alert'"
        :title="notFound ? 'Not found' : 'Something went wrong'"
        :description="notFound ? 'It does not exist, or you no longer have access to it.' : error.statusMessage || error.message"
        :actions="[{ label: 'Back to your tenants', icon: 'i-lucide-house', onClick: () => clearError({ redirect: '/' }) }]"
      >
        <template #title><h1 class="text-lg font-semibold">{{ notFound ? "Not found" : "Something went wrong" }}</h1></template>
      </UEmpty>
    </main>
  </UApp>
</template>
