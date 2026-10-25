<script setup lang="ts">
import type { Invitation, NamespaceSettings } from "~~/shared/types/api";

// A GitHub-managed organization, or one with a GitHub App installed, takes no email invitations.
const props = defineProps<{ slug: string; settings: NamespaceSettings | null; settingsFailure?: { code: string; words: string } | null; retrySettings?: () => unknown }>();
const api = useApi();
const act = useAct();
const showOnce = useShowOnce();
const { ready, withReason } = useOverride(() => props.slug);

const applies = computed(() => props.settings?.kind === "organization" && props.settings.membership === "app" && !props.settings.github_installation);
const ROLES = [{ label: "Reader", value: "reader" }, { label: "Operator", value: "operator" }, { label: "Admin", value: "admin" }];
const LIFETIMES = [{ label: "1 day", value: 86_400 }, { label: "7 days", value: 7 * 86_400 }, { label: "30 days", value: 30 * 86_400 }];
const STATE_LOOK: Record<Invitation["state"], { color: "info" | "success" | "neutral" | "warning"; label: string }> = {
  pending: { color: "info", label: "Pending" },
  redeemed: { color: "success", label: "Accepted" },
  revoked: { color: "neutral", label: "Revoked" },
  expired: { color: "warning", label: "Expired" },
};

const { data, refresh, status } = await useAsyncData(`invitations-${props.slug}`, async () => {
  if (!applies.value) return { invitations: [] as Invitation[], failure: null as string | null };
  try {
    return { ...(await api<{ invitations: Invitation[] }>(`/api/v1/tenants/${props.slug}/invitations`)), failure: null };
  } catch (e) {
    return { invitations: [] as Invitation[], failure: refusal(e as ApiError) };
  }
}, { watch: [applies] });

const email = ref("");
const role = ref("reader");
const lifetime = ref(7 * 86_400);
const formError = ref("");
const sending = ref(false);
const confirmRevoke = ref<Invitation | null>(null);
const emailInput = useTemplateRef<{ inputRef?: HTMLInputElement }>("emailInput");

async function invite() {
  formError.value = "";
  if (!looksLikeEmail(email.value)) {
    formError.value = "Enter an email address such as name@example.com.";
    nextTick(() => emailInput.value?.inputRef?.focus());
    return;
  }
  if (sending.value || !ready()) return;
  sending.value = true;
  const address = email.value.trim();
  try {
    const done = await act(`Invite ${address}`, () => api<{ delivery: "email" | "link"; token?: string }>(`/api/v1/tenants/${props.slug}/invitations`, {
      method: "POST",
      body: withReason({ email: address, role: role.value, expires_in_secs: lifetime.value }),
    }));
    if (!done) return;
    email.value = "";
    if (done.delivery === "link" && done.token) {
      const link = `${location.origin}/invitations/accept#token=${done.token}`;
      await showOnce({
        title: "Send this invitation link",
        description: `This instance does not send email. Give ${address} this link yourself; it works once.`,
        secrets: [link],
        filename: `sentinel-invitation-${props.slug}.txt`,
        note: "Only the person who holds that address can use it, once it is confirmed.",
      });
    }
    await refresh();
  } finally {
    sending.value = false;
  }
}

async function revoke() {
  const inv = confirmRevoke.value;
  confirmRevoke.value = null;
  if (!inv || !ready()) return;
  const body = withReason({});
  if (await act(`Revoke the invitation for ${inv.email ?? "a link"}`, () => api(`/api/v1/tenants/${props.slug}/invitations/${inv.id}`, { method: "DELETE", body }))) await refresh();
}

const columns = [{ id: "who", header: "Invited" }, { id: "role", header: "Role" }, { id: "state", header: "State" }, { id: "expires", header: "Expires" }, { id: "actions", header: "Actions" }];
</script>

<template>
  <section aria-labelledby="invite-h" class="space-y-3">
    <h2 id="invite-h" class="text-base font-semibold">Invite people</h2>

    <UAlert v-if="settingsFailure" color="error" variant="subtle" icon="i-lucide-circle-alert" role="alert" title="Could not load namespace settings."
      :description="settingsFailure.words" :actions="[{ label: 'Try again', onClick: () => retrySettings?.() }]" />
    <UAlert v-else-if="settings?.kind === 'personal'" color="neutral" variant="subtle" icon="i-lucide-user" title="A personal namespace has no other members."
      description="Create an organization to work with others." :actions="[{ label: 'Organizations', to: '/organizations' }]" />
    <UAlert v-else-if="settings && !applies" color="neutral" variant="subtle" icon="i-lucide-github" title="Membership of this organization is managed by GitHub."
      :description="settings.membership === 'github'
        ? 'People join and leave on GitHub, and Sentinel follows. Email invitations and email domains do not apply.'
        : 'A GitHub App is installed for this organization, so email invitations do not apply to it.'" />

    <template v-else-if="settings">
      <form class="flex flex-wrap items-end gap-3" aria-label="Invite by email" novalidate @submit.prevent="invite">
        <UFormField label="Email address" name="invite-email">
          <UInput id="inv-email" ref="emailInput" v-model="email" type="email" autocomplete="off" autocapitalize="off" spellcheck="false" required class="w-64 max-w-full" />
        </UFormField>
        <UFormField label="Role" name="invite-role">
          <USelect id="inv-role" v-model="role" :items="ROLES" class="w-36" />
        </UFormField>
        <UFormField label="Expires after" name="invite-lifetime">
          <USelect id="inv-lifetime" v-model="lifetime" :items="LIFETIMES" class="w-32" />
        </UFormField>
        <UButton type="submit" icon="i-lucide-mail-plus" label="Send invitation" :loading="sending" />
      </form>
      <UAlert v-if="formError" color="error" variant="subtle" icon="i-lucide-circle-alert" :title="formError" role="alert" />
      <p class="text-xs text-muted">The invitation works once and only for the account that confirms that address. Readers can see runs and logs; operators can also start and cancel them; admins manage the organization.</p>

      <h3 class="text-sm font-medium pt-2">Invitations</h3>
      <UAlert v-if="data?.failure" color="error" variant="subtle" icon="i-lucide-circle-alert" role="alert" title="Could not load the invitations." :description="data.failure"
        :actions="[{ label: 'Try again', onClick: () => { refresh(); } }]" />
      <USkeleton v-else-if="status === 'pending' && !data" class="h-24 w-full" />
      <p v-else-if="!data?.invitations.length" class="text-sm text-muted">No invitations yet.</p>
      <UTable v-else :data="data.invitations" :columns="columns" caption="Invitations" class="rounded-lg border border-default">
        <template #who-cell="{ row }">
          <span class="break-all">{{ row.original.email ?? "Link invitation" }}</span>
        </template>
        <template #role-cell="{ row }">{{ ROLES.find((r) => r.value === row.original.role)?.label ?? "—" }}</template>
        <template #state-cell="{ row }">
          <UBadge :color="STATE_LOOK[row.original.state].color" variant="subtle" :label="STATE_LOOK[row.original.state].label" />
        </template>
        <template #expires-cell="{ row }"><time :datetime="new Date(row.original.expires_ms).toISOString()">{{ new Date(row.original.expires_ms).toISOString().slice(0, 16).replace("T", " ") }} UTC</time></template>
        <template #actions-cell="{ row }">
          <UButton v-if="row.original.state === 'pending'" size="sm" color="error" variant="ghost" icon="i-lucide-x" :aria-label="`Revoke the invitation for ${row.original.email ?? 'a link'}`" label="Revoke" @click="confirmRevoke = row.original" />
        </template>
      </UTable>
    </template>
  </section>

  <UModal :open="!!confirmRevoke" :title="`Revoke the invitation for ${confirmRevoke?.email ?? 'a link'}?`"
    description="The link stops working at once. You can invite the person again later." @update:open="(o) => !o && (confirmRevoke = null)">
    <template #footer>
      <div class="flex justify-end gap-2 w-full">
        <UButton color="neutral" variant="ghost" label="Keep" @click="confirmRevoke = null" />
        <UButton color="error" label="Revoke" @click="revoke" />
      </div>
    </template>
  </UModal>
</template>
