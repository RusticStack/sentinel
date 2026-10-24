<script setup lang="ts">
// #main is the skip-link target.
defineProps<{ id: string; title: string }>();
</script>

<template>
  <UDashboardPanel :id="id">
    <template #header>
      <UDashboardNavbar :title="title">
        <template #leading>
          <UDashboardSidebarCollapse />
        </template>
        <template #right>
          <slot name="actions" />
        </template>
      </UDashboardNavbar>
      <slot name="toolbar" />
    </template>
    <template #body>
      <main id="main" tabindex="-1" class="space-y-6 focus:outline-none">
        <slot />
      </main>
    </template>
  </UDashboardPanel>
</template>
