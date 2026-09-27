<script setup lang="ts">
const api = useApi();
const act = useAct();
const { data } = await useAsyncData("policy", () => api<{ registration: string; tenant_creation: string; installation_binding: string }>("/api/v1/admin/policy"));
const form = reactive({ registration: data.value?.registration ?? "invite_only", tenant_creation: data.value?.tenant_creation ?? "super_admin_only", installation_binding: data.value?.installation_binding ?? "super_admin_only" });
async function save() { await act("Admission policy", () => api("/api/v1/admin/policy", { method: "PUT", body: { ...form } })); }
</script>

<template>
  <section aria-labelledby="policy-h" class="space-y-3 max-w-lg">
    <h2 id="policy-h" class="text-base font-semibold">Admission policy</h2>
    <form class="space-y-4" @submit.prevent="save">
      <UFormField label="Registration" name="registration">
        <USelect id="pol-reg" v-model="form.registration" class="w-full"
          :items="[{ label: 'Closed', value: 'closed' }, { label: 'Invitation only', value: 'invite_only' }, { label: 'Anyone may apply; an admin approves', value: 'approval_required' }]" />
      </UFormField>
      <UFormField label="Tenant creation" name="tenant_creation">
        <USelect id="pol-tenant" v-model="form.tenant_creation" class="w-full"
          :items="[{ label: 'Platform administrators only', value: 'super_admin_only' }, { label: 'Approved users may create a personal namespace', value: 'approved_users' }]" />
      </UFormField>
      <UFormField label="GitHub installation binding" name="installation_binding">
        <USelect id="pol-install" v-model="form.installation_binding" class="w-full"
          :items="[{ label: 'Platform administrators only', value: 'super_admin_only' }, { label: 'Tenant administrators, for their tenant', value: 'tenant_admins' }]" />
      </UFormField>
      <UButton type="submit" icon="i-lucide-save" label="Save policy" />
    </form>
  </section>
</template>
