<script setup lang="ts">
// Where an invitation link lands (`/invitations/accept#token=sntl_…`). The
// secret is in the fragment, so no server sees it; the page reads it once
// in the browser and removes it from the address bar. Nothing about the
// invitation is shown before the controller accepts it: there is no route
// that reveals an invitation without spending it, so the organization's
// name appears only once the person has joined. A signed-out visitor signs
// in or signs up here, keeping the secret in this page's memory; only the
// GitHub sign-in round trip parks it in this tab's session storage, for ten
// minutes at most, and it is removed as soon as it is read back.
definePageMeta({ layout: "auth" });
useHead({ title: "Accept an invitation · Sentinel" });
const api = useApi();
const session = useSession();

const STASH = "sentinel-invitation";
const STASH_MS = 10 * 60 * 1000;

type Phase = "reading" | "missing" | "ready" | "accepting" | "joined" | "member" | "redeemed" | "verify" | "unusable";
const phase = ref<Phase>("reading");
const tenant = ref<string | null>(null);
const verification = ref<"email" | "operator">("email");
const error = ref("");
const mode = ref<"signin" | "signup">("signin");
const signedUp = ref<{ email: string; verification: "email" | "operator" } | null>(null);
const token = shallowRef<string | null>(null);
const heading = useTemplateRef<HTMLElement>("heading");
const { waiting, start: wait } = useRetryWait();

const { data: health } = await useAsyncData("health", () => api<{ github_sign_in?: boolean }>("/api/v1/health"));

function unstash(): string | null {
  try {
    const raw = sessionStorage.getItem(STASH);
    sessionStorage.removeItem(STASH);
    if (!raw) return null;
    const { token: t, until } = JSON.parse(raw);
    return typeof t === "string" && isInvitationToken(t) && Number(until) > Date.now() ? t : null;
  } catch {
    return null;
  }
}

onMounted(() => {
  token.value = fragmentToken(location.hash, "invitation") ?? unstash();
  // Back here by another way than `/` (signing in as someone else): the
  // return marker has served.
  try { if (sessionStorage.getItem("sentinel-return") === "/invitations/accept") sessionStorage.removeItem("sentinel-return"); } catch { /* ignore */ }
  if (location.hash) history.replaceState(history.state, "", location.pathname + location.search);
  phase.value = token.value ? "ready" : "missing";
});
onBeforeUnmount(() => { token.value = null; });

function settle(next: Phase) {
  phase.value = next;
  token.value = next === "ready" ? token.value : null;
  nextTick(() => heading.value?.focus());
}

async function accept() {
  if (!token.value || phase.value === "accepting" || waiting.value) return;
  phase.value = "accepting";
  error.value = "";
  try {
    const done = await api<{ status: string; tenant?: string; verification?: "email" | "operator" }>("/api/v1/invitations/accept", { method: "POST", body: { token: token.value } });
    if (done.status === "joined") {
      tenant.value = done.tenant ?? null;
      await session.refreshTenants();
      settle("joined");
    } else if (done.status === "already_member") settle("member");
    else if (done.status === "verification_sent") {
      verification.value = done.verification ?? "email";
      settle("verify");
    } else settle("redeemed");
  } catch (e) {
    const err = e as ApiError;
    if (err.code === "unauthenticated") return;
    if (err.code === "not_found") return settle("unusable");
    phase.value = "ready";
    if (err.code === "rate_limited") {
      wait(err);
      error.value = `Too many attempts from here. Try again in ${retryAfter(err)}.`;
    } else error.value = refusal(err);
  }
}

/// Park the secret for a round trip that leaves the page (GitHub sign-in,
/// signing in as someone else), to come back here.
function stash() {
  try {
    if (token.value) sessionStorage.setItem(STASH, JSON.stringify({ token: token.value, until: Date.now() + STASH_MS }));
    sessionStorage.setItem("sentinel-return", "/invitations/accept");
  } catch { /* storage off: the person opens the link again after signing in */ }
}

function switchAccount() {
  stash();
  token.value = null;
  return session.signOut("/invitations/accept");
}

function signedUpWith(result: { email: string; verification: "email" | "operator" }) {
  signedUp.value = result;
  token.value = null;
  nextTick(() => heading.value?.focus());
}

const who = computed(() => session.me.value?.email || session.me.value?.username || "your account");
const title = computed(() => {
  if (signedUp.value) return "Confirm your address";
  switch (phase.value) {
    case "joined": return tenant.value ? `You joined ${tenant.value}` : "Invitation accepted";
    case "member": return "You are already a member";
    case "redeemed": return "Invitation accepted";
    case "verify": return "Confirm your address to join";
    case "unusable": return "This invitation cannot be used";
    case "missing": return "Open your invitation link";
    default: return "You have been invited";
  }
});
</script>

<template>
  <UCard class="w-full max-w-md">
    <template #header>
      <div class="flex items-center gap-2">
        <UIcon name="i-lucide-mail-open" class="size-6 text-primary" />
        <h1 ref="heading" tabindex="-1" class="text-lg font-semibold focus:outline-none">{{ title }}</h1>
      </div>
    </template>

    <div class="space-y-4 text-sm">
      <p v-if="phase === 'reading'" class="text-muted" role="status">Reading the link…</p>

      <template v-else-if="phase === 'missing'">
        <p>This page needs the full link from your invitation email. Open the link again, or copy all of it into the address bar; it ends with <code>#token=…</code>.</p>
      </template>

      <!-- Signed in: accept as this account. -->
      <template v-else-if="(phase === 'ready' || phase === 'accepting') && session.me.value">
        <p>You have an invitation to join an organization on Sentinel. Accept it as <strong class="break-all">{{ who }}</strong>.</p>
        <p class="text-muted">An invitation sent to an email address can only be used by the account that holds that address, once it is confirmed.</p>
        <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-circle-alert" :title="error" role="alert" />
        <div class="flex flex-wrap gap-2">
          <UButton :label="waiting ? `Wait ${waiting} s` : 'Accept invitation'" icon="i-lucide-check" :loading="phase === 'accepting'" :disabled="!!waiting" @click="accept" />
          <UButton color="neutral" variant="ghost" label="Not me — sign out" @click="switchAccount" />
        </div>
      </template>

      <!-- Signed out: sign in or sign up here, keeping the link. -->
      <template v-else-if="phase === 'ready' && !signedUp">
        <p>You have an invitation to join an organization on Sentinel. Sign in, or create an account with the address the invitation was sent to.</p>
        <div role="group" aria-label="How to continue" class="grid grid-cols-2 gap-1 rounded-lg bg-elevated p-1">
          <UButton :variant="mode === 'signin' ? 'solid' : 'ghost'" :color="mode === 'signin' ? 'primary' : 'neutral'" block label="I have an account" :aria-pressed="mode === 'signin'" @click="mode = 'signin'" />
          <UButton :variant="mode === 'signup' ? 'solid' : 'ghost'" :color="mode === 'signup' ? 'primary' : 'neutral'" block label="I'm new here" :aria-pressed="mode === 'signup'" @click="mode = 'signup'" />
        </div>
        <SignInForm v-if="mode === 'signin'" />
        <SignUpForm v-else :invitation="token" @accepted="signedUpWith" />
        <UButton v-if="health?.github_sign_in && mode === 'signin'" to="/auth/github/start?return_to=%2F" external icon="i-lucide-github" color="neutral" variant="outline" label="Sign in with GitHub" block @click="stash" />
      </template>

      <CheckEmail v-else-if="signedUp" :email="signedUp.email" :verification="signedUp.verification" joining />

      <template v-else-if="phase === 'joined'">
        <UAlert color="success" variant="subtle" icon="i-lucide-circle-check" role="status" :title="tenant ? `You are now a member of ${tenant}.` : 'The invitation is accepted.'" />
        <UButton :to="tenant ? `/t/${tenant}` : '/'" :label="tenant ? `Open ${tenant}` : 'Continue'" block />
      </template>

      <template v-else-if="phase === 'member'">
        <p>Your account already belongs to this organization; the invitation was left unused.</p>
        <UButton to="/organizations" label="Your organizations" block />
      </template>

      <template v-else-if="phase === 'redeemed'">
        <p>The invitation is accepted.</p>
        <UButton to="/" label="Continue" block />
      </template>

      <template v-else-if="phase === 'verify'">
        <CheckEmail :verification="verification" joining />
      </template>

      <template v-else-if="phase === 'unusable'">
        <UAlert color="warning" variant="subtle" icon="i-lucide-mail-x" role="alert" title="Sentinel could not accept this invitation."
          description="It may have expired, already been used or been withdrawn; it may have been sent to a different email address than your account's; or the organization's membership may be managed by GitHub, where invitations do not apply." />
        <ul class="list-disc ps-5 space-y-1">
          <li>Sent to another address? Sign in with the account that holds it, or ask for an invitation to your address.</li>
          <li>Otherwise ask whoever invited you for a new invitation.</li>
        </ul>
        <UButton to="/" color="neutral" variant="outline" label="Back to Sentinel" block />
      </template>
    </div>
  </UCard>
</template>
