<script setup lang="ts">
// One view: its title (the page's only level-one heading), actions, and
// the main content landmark the skip link lands on.
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
