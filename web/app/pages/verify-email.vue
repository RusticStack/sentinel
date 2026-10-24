<script setup lang="ts">
// The secret stays in the fragment so no server sees it, and is spent only on Confirm, since mail scanners open links.
definePageMeta({ layout: "auth" });
useHead({ title: "Confirm your email address · Sentinel" });
const api = useApi();
const session = useSession();

type Phase = "reading" | "ready" | "confirming" | "verified" | "invalid" | "missing";
const phase = ref<Phase>("reading");
const joined = ref(false);
const error = ref("");
let token: string | null = null;
const heading = useTemplateRef<HTMLElement>("heading");
const { waiting, start: wait } = useRetryWait();

onMounted(() => {
  token = fragmentToken(location.hash, "verification");
  if (location.hash) history.replaceState(history.state, "", location.pathname + location.search);
  phase.value = token ? "ready" : "missing";
});
onBeforeUnmount(() => { token = null; });

function settle(next: Phase) {
  phase.value = next;
  nextTick(() => heading.value?.focus());
}

async function confirm() {
  if (!token || phase.value === "confirming" || waiting.value) return;
  phase.value = "confirming";
  error.value = "";
  try {
    const done = await api<{ verified: boolean; joined: boolean }>("/api/v1/email/verify", { method: "POST", body: { token } });
    token = null;
    joined.value = done.joined;
    if (session.me.value) await session.load(true);
    settle("verified");
  } catch (e) {
    const err = e as ApiError;
    if (err.code === "rate_limited") {
      wait(err);
      error.value = `Too many attempts from here. Try again in ${retryAfter(err)}.`;
      phase.value = "ready";
      return;
    }
    token = null;
    if (err.code === "invalid_request") settle("invalid");
    else {
      error.value = refusal(err);
      phase.value = "ready";
    }
  }
}

const email = ref(session.me.value?.email && !session.me.value.email_verified ? session.me.value.email : "");
const resending = ref(false);
const resent = ref<"email" | "operator" | null>(null);
const resendError = ref("");
const resendWait = useRetryWait();

async function resend() {
  if (resending.value || resendWait.waiting.value) return;
  resendError.value = "";
  if (!looksLikeEmail(email.value)) {
    resendError.value = "Enter the address you signed up with.";
    return;
  }
  resending.value = true;
  try {
    const done = await api<{ verification: "email" | "operator" }>("/api/v1/email/resend", { method: "POST", body: { email: email.value.trim() } });
    resent.value = done.verification;
  } catch (e) {
    const err = e as ApiError;
    if (err.code === "rate_limited") {
      resendWait.start(err);
      resendError.value = `Too many requests from here. Try again in ${retryAfter(err)}.`;
    } else {
      resendError.value = err.code === "invalid_request" ? "Enter a plain email address, such as name@example.com." : refusal(err);
    }
  } finally {
    resending.value = false;
  }
}

const title = computed(() => ({
  reading: "Confirm your email address",
  ready: "Confirm your email address",
  confirming: "Confirming…",
  verified: "Address confirmed",
  invalid: "This link cannot be used",
  missing: "Get a new confirmation link",
}[phase.value]));
</script>

<template>
  <UCard class="w-full max-w-md">
    <template #header>
      <div class="flex items-center gap-2">
        <UIcon name="i-lucide-radar" class="size-6 text-primary" />
        <h1 ref="heading" tabindex="-1" class="text-lg font-semibold focus:outline-none">{{ title }}</h1>
      </div>
    </template>

    <div class="space-y-4">
      <p v-if="phase === 'reading'" class="text-sm text-muted" role="status">Reading the link…</p>

      <template v-else-if="phase === 'ready' || phase === 'confirming'">
        <p class="text-sm">Press Confirm to prove this mailbox is yours. The link works once.</p>
        <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-circle-alert" :title="error" role="alert" />
        <UButton :label="waiting ? `Wait ${waiting} s` : 'Confirm my address'" icon="i-lucide-mail-check" block :loading="phase === 'confirming'" :disabled="!!waiting" @click="confirm" />
      </template>

      <template v-else-if="phase === 'verified'">
        <UAlert color="success" variant="subtle" icon="i-lucide-circle-check" role="status" title="Your email address is confirmed."
          :description="joined ? 'The invitation it carried is accepted too: you are now a member of the organization.' : undefined" />
        <UButton v-if="session.me.value" to="/" label="Continue" block />
        <template v-else>
          <p class="text-sm">You can now sign in with this address. If this instance reviews new accounts, an administrator approves yours first.</p>
          <UButton :to="{ path: '/login', query: { reason: 'verified' } }" label="Sign in" block />
        </template>
      </template>

      <template v-else>
        <UAlert v-if="phase === 'invalid'" color="warning" variant="subtle" icon="i-lucide-link-2-off" role="alert" title="The link is invalid or has expired."
          description="A link works once and for 24 hours, and a newer link replaces an older one. Ask for a new link below." />
        <p v-else class="text-sm">The link you opened is incomplete, or you came here directly. Enter your address and, if it is waiting for confirmation, a new link is sent.</p>

        <CheckEmail v-if="resent" :email="email" :verification="resent" />
        <form v-else class="space-y-3" aria-label="Send a new confirmation link" novalidate @submit.prevent="resend">
          <UFormField label="Email address" name="email">
            <UInput id="resend-email" v-model="email" type="email" autocomplete="email" autocapitalize="off" spellcheck="false" required class="w-full" />
          </UFormField>
          <UAlert v-if="resendError" color="error" variant="subtle" icon="i-lucide-circle-alert" :title="resendError" role="alert" />
          <UButton type="submit" :label="resendWait.waiting.value ? `Wait ${resendWait.waiting.value} s` : 'Send a new link'" block :loading="resending" :disabled="!!resendWait.waiting.value" />
        </form>
      </template>
    </div>

    <template #footer>
      <p class="text-sm text-center"><ULink :to="session.me.value ? '/' : '/login'" class="font-medium text-primary">{{ session.me.value ? "Back to Sentinel" : "Back to sign-in" }}</ULink></p>
    </template>
  </UCard>
</template>
