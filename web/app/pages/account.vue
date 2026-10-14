<script setup lang="ts">
import type { Security } from "~~/shared/types/api";

// The signed-in person's own security: an authenticator app (enroll with a
// QR code or the key, confirm with a code, recovery codes shown once and
// reissued under step-up), the password, and linked identities. Secrets
// (the seed, codes, passwords) live in this page's memory only, are
// cleared as soon as they have served, and never reach storage or a URL.
useHead({ title: "Account security · Sentinel" });
const api = useApi();
const session = useSession();
const toast = useToast();
const withStepUp = useStepUp();
const endSession = useEndSession();
const showOnce = useShowOnce();

const { data: security, error: loadError, refresh, status } = await useAsyncData("account-security", () => api<Security>("/api/v1/me/security"));
const github = computed(() => security.value?.identities.find((i) => i.provider === "github") ?? null);
const isoDate = (ms: number) => new Date(ms).toISOString().slice(0, 10);

// --- Authenticator app -------------------------------------------------

const reissuing = ref(false);

async function reissue() {
  if (reissuing.value) return;
  reissuing.value = true;
  try {
    const fresh = await withStepUp(() => api<{ recovery_codes: string[] }>("/api/v1/mfa/recovery-codes", { method: "POST", body: {} }));
    await showOnce({
      title: "Your new recovery codes",
      description: "The earlier codes no longer work.",
      secrets: fresh.recovery_codes,
      filename: "sentinel-recovery-codes.txt",
    });
    await refresh();
  } catch (e) {
    if (e instanceof StepUpDeclined) return;
    const err = e as ApiError;
    if (err.code === "unauthenticated") return;
    toast.add({ title: `Recovery codes: ${err.code === "not_found" ? "no authenticator is set up" : refusal(err)}.`, color: "error", icon: "i-lucide-circle-alert", duration: 8000 });
  } finally {
    reissuing.value = false;
  }
}

// --- Password ----------------------------------------------------------

const current = ref("");
const fresh = ref("");
const again = ref("");
const passwordError = ref("");
const changing = ref(false);
const bytes = (s: string) => new TextEncoder().encode(s).length;
function clearPasswords() {
  current.value = "";
  fresh.value = "";
  again.value = "";
}

async function changePassword() {
  if (changing.value) return;
  passwordError.value = "";
  const n = bytes(fresh.value);
  if (n < 12 || n > 256) {
    passwordError.value = "The new password must be 12 to 256 bytes long.";
    return;
  }
  if (fresh.value !== again.value) {
    passwordError.value = "The new password and its repetition differ.";
    return;
  }
  changing.value = true;
  const body = { current: current.value, new: fresh.value };
  try {
    await withStepUp(() => api("/api/v1/password", { method: "POST", body }));
    clearPasswords();
    await endSession("password-changed");
  } catch (e) {
    if (e instanceof StepUpDeclined) return;
    const err = e as ApiError;
    if (err.code === "unauthenticated") return clearPasswords();
    current.value = "";
    passwordError.value = err.code === "forbidden" ? "The current password was not accepted. Five wrong attempts end this session."
      : err.code === "invalid_request" ? "The new password must be 12 to 256 bytes long."
        : err.code === "rate_limited" ? `Too many attempts. Try again in ${retryAfter(err)}.`
          : refusal(err);
  } finally {
    changing.value = false;
  }
}

// --- Email address -----------------------------------------------------
// A new address is a claim until its link is opened; the confirmed one stays
// the account's until then. Every answer reads the same whether or not
// another account holds the address.

const newEmail = ref("");
const emailNote = ref<"sent-email" | "sent-operator" | null>(null);
const emailError = ref("");
const savingEmail = ref(false);
const resendingEmail = ref(false);
const emailWait = useRetryWait();

async function changeEmail() {
  if (savingEmail.value || emailWait.waiting.value) return;
  emailError.value = "";
  emailNote.value = null;
  if (!looksLikeEmail(newEmail.value)) {
    emailError.value = "Enter an email address such as name@example.com.";
    return;
  }
  savingEmail.value = true;
  try {
    const done = await withStepUp(() => api<{ verification: "email" | "operator" }>("/api/v1/me/email", { method: "POST", body: { email: newEmail.value.trim() } }));
    emailNote.value = done.verification === "email" ? "sent-email" : "sent-operator";
    newEmail.value = "";
    await session.load(true);
  } catch (e) {
    if (e instanceof StepUpDeclined) return;
    const err = e as ApiError;
    if (err.code === "unauthenticated") return;
    if (err.code === "rate_limited") emailWait.start(err);
    emailError.value = err.code === "invalid_request" ? "Enter a plain email address, such as name@example.com." : refusal(err);
  } finally {
    savingEmail.value = false;
  }
}

async function resendEmail() {
  if (resendingEmail.value || emailWait.waiting.value) return;
  resendingEmail.value = true;
  emailError.value = "";
  try {
    const done = await api<{ verification: "email" | "operator" }>("/api/v1/me/email/resend", { method: "POST", body: {} });
    emailNote.value = done.verification === "email" ? "sent-email" : "sent-operator";
  } catch (e) {
    const err = e as ApiError;
    if (err.code === "unauthenticated") return;
    if (err.code === "rate_limited") emailWait.start(err);
    emailError.value = err.code === "conflict" ? "No address is waiting for confirmation." : err.code === "rate_limited" ? `You asked for several links already. Try again in ${retryAfter(err)}.` : refusal(err);
  } finally {
    resendingEmail.value = false;
  }
}

// --- Linked identities -------------------------------------------------

const linking = ref(false);
async function linkGitHub() {
  if (linking.value) return;
  linking.value = true;
  try {
    const started = await withStepUp(() => api<{ authorize_url: string }>("/api/v1/identities/github/link", { method: "POST", body: {} }));
    if (!/^https:\/\//.test(started.authorize_url)) throw new ApiError(0, { code: "invalid_response", message: "the controller gave an unexpected address" });
    // The round trip ends on `/`, which continues here.
    rememberReturn("/account");
    await navigateTo(started.authorize_url, { external: true });
  } catch (e) {
    linking.value = false;
    if (e instanceof StepUpDeclined) return;
    const err = e as ApiError;
    if (err.code === "unauthenticated") return;
    toast.add({ title: `Link GitHub: ${refusal(err)}.`, color: "error", icon: "i-lucide-circle-alert", duration: 8000 });
  }
}

onBeforeUnmount(clearPasswords);
</script>

<template>
  <SPage id="account" title="Account security">
    <div class="max-w-3xl space-y-6">
      <UAlert v-if="loadError" color="error" variant="subtle" icon="i-lucide-circle-alert" title="Could not load your account's security settings."
        :description="loadError.message" role="alert" :actions="[{ label: 'Try again', onClick: () => { refresh(); } }]" />

      <template v-else-if="security">
        <!-- Authenticator app -->
        <UCard as="section" aria-labelledby="mfa-h">
          <template #header>
            <div class="flex flex-wrap items-center justify-between gap-2">
              <h2 id="mfa-h" class="text-base font-semibold flex items-center gap-2"><UIcon name="i-lucide-smartphone" />Authenticator app</h2>
              <UBadge v-if="security.mfa.enrolled" color="success" variant="subtle" icon="i-lucide-shield-check" label="On" />
              <UBadge v-else color="neutral" variant="outline" label="Off" />
            </div>
          </template>

          <div v-if="security.mfa.enrolled" class="space-y-4">
            <p class="text-sm">Codes from your authenticator app confirm sensitive changes: issuing service credentials, administration, your password.</p>
            <div class="flex flex-wrap items-center justify-between gap-3 rounded-md border border-default p-3">
              <div>
                <h3 class="text-sm font-medium">Recovery codes</h3>
                <p class="text-sm" :class="security.mfa.recovery_codes_remaining <= 3 ? 'text-warning' : 'text-muted'">
                  {{ security.mfa.recovery_codes_remaining }} of 10 left<template v-if="security.mfa.recovery_codes_remaining === 0"> — replace them now</template><template v-else-if="security.mfa.recovery_codes_remaining <= 3"> — consider replacing them</template>.
                </p>
              </div>
              <UButton color="neutral" variant="outline" icon="i-lucide-refresh-cw" label="Replace recovery codes" :loading="reissuing" @click="reissue" />
            </div>
            <p class="text-xs text-muted">Lost the device and every code? An operator can remove the authenticator on the controller host (<code>sentinel admin mfa disable</code>); that also signs out every session.</p>
          </div>

          <TotpEnroll v-else :has-password="security.password" :pending="security.mfa.pending" :username="session.me.value?.username" @done="refresh()" @cancel="refresh()" />
        </UCard>

        <!-- Email address -->
        <UCard as="section" aria-labelledby="email-h">
          <template #header>
            <div class="flex flex-wrap items-center justify-between gap-2">
              <h2 id="email-h" class="text-base font-semibold flex items-center gap-2"><UIcon name="i-lucide-mail" />Email address</h2>
              <UBadge v-if="session.me.value?.email && session.me.value.email_verified" color="success" variant="subtle" icon="i-lucide-badge-check" label="Confirmed" />
              <UBadge v-else-if="session.me.value?.email" color="warning" variant="subtle" label="Not confirmed" />
            </div>
          </template>
          <div class="space-y-4 text-sm">
            <p v-if="session.me.value?.email" class="break-all"><span class="text-muted">Address:</span> {{ session.me.value.email }}</p>
            <p v-else class="text-muted">No email address. Adding one lets you sign in with it and accept invitations sent to it.</p>
            <div v-if="session.me.value?.email && !session.me.value.email_verified" class="flex flex-wrap items-center gap-3">
              <span>Open the link sent to this address to confirm it; until then it cannot sign in.</span>
              <UButton size="sm" color="neutral" variant="outline" icon="i-lucide-send" :label="emailWait.waiting.value ? `Wait ${emailWait.waiting.value} s` : 'Send the link again'" :loading="resendingEmail" :disabled="!!emailWait.waiting.value" @click="resendEmail" />
            </div>
            <form class="flex flex-wrap items-end gap-3" aria-label="Change your email address" novalidate @submit.prevent="changeEmail">
              <UFormField :label="session.me.value?.email ? 'New address' : 'Address'" name="new-email">
                <UInput id="new-email" v-model="newEmail" type="email" autocomplete="email" autocapitalize="off" spellcheck="false" class="w-72 max-w-full" />
              </UFormField>
              <UButton type="submit" :label="session.me.value?.email ? 'Change address' : 'Add address'" :loading="savingEmail" :disabled="!!emailWait.waiting.value" />
            </form>
            <p class="text-xs text-muted">A new address takes effect once you open the link sent to it; your current confirmed address keeps working until then.</p>
            <div aria-live="polite">
              <UAlert v-if="emailNote === 'sent-email'" color="success" variant="subtle" icon="i-lucide-mail-check" title="If that address can be used, a confirmation link is on its way." description="It works once, for 24 hours." />
              <UAlert v-else-if="emailNote === 'sent-operator'" color="info" variant="subtle" icon="i-lucide-user-cog" title="This instance does not send email."
                description="Ask your administrator for the confirmation link (sentinel admin account email-link)." />
              <UAlert v-if="emailError" color="error" variant="subtle" icon="i-lucide-circle-alert" :title="emailError" role="alert" />
            </div>
          </div>
        </UCard>

        <!-- Password -->
        <UCard as="section" aria-labelledby="password-h">
          <template #header>
            <h2 id="password-h" class="text-base font-semibold flex items-center gap-2"><UIcon name="i-lucide-key-round" />Password</h2>
          </template>
          <form v-if="security.password" class="space-y-4" aria-label="Change your password" @submit.prevent="changePassword">
            <input type="text" name="username" autocomplete="username" :value="session.me.value?.username ?? ''" class="sr" tabindex="-1" aria-hidden="true" readonly>
            <UFormField label="Current password" name="current">
              <UInput id="pw-current" v-model="current" type="password" autocomplete="current-password" required class="w-full sm:w-80" />
            </UFormField>
            <UFormField label="New password" name="new" hint="12 to 256 bytes">
              <UInput id="pw-new" v-model="fresh" type="password" autocomplete="new-password" minlength="12" required class="w-full sm:w-80" />
            </UFormField>
            <UFormField label="New password again" name="again">
              <UInput id="pw-again" v-model="again" type="password" autocomplete="new-password" minlength="12" required class="w-full sm:w-80" />
            </UFormField>
            <UAlert v-if="passwordError" color="error" variant="subtle" icon="i-lucide-circle-alert" :title="passwordError" role="alert" />
            <p class="text-xs text-muted">Changing it signs out every session and app of your account, this one included<template v-if="security.mfa.enrolled">, and asks for a code from your authenticator first</template>.</p>
            <UButton type="submit" label="Change password" :loading="changing" />
          </form>
          <p v-else class="text-sm text-muted">Your account has no local password: you sign in with GitHub.</p>
        </UCard>

        <!-- Linked identities -->
        <UCard as="section" aria-labelledby="identities-h">
          <template #header>
            <h2 id="identities-h" class="text-base font-semibold flex items-center gap-2"><UIcon name="i-lucide-link" />Linked identities</h2>
          </template>
          <div class="space-y-4">
            <ul v-if="security.identities.length" class="divide-y divide-default">
              <li v-for="i in security.identities" :key="i.provider" class="flex items-center justify-between gap-2 py-2 text-sm">
                <span class="flex items-center gap-2 font-medium capitalize"><UIcon :name="i.provider === 'github' ? 'i-lucide-github' : 'i-lucide-link'" />{{ i.provider }}</span>
                <span class="text-muted">linked <time :datetime="new Date(i.linked_ms).toISOString()">{{ isoDate(i.linked_ms) }}</time></span>
              </li>
            </ul>
            <p v-else class="text-sm text-muted">No external account is linked.</p>
            <div v-if="security.github_link && !github" class="space-y-2">
              <p class="text-sm">Link your GitHub account to sign in with it and to join organizations whose membership GitHub manages. You confirm it's you first, then approve on GitHub and come back here.</p>
              <UButton icon="i-lucide-github" color="neutral" variant="outline" label="Link a GitHub account" :loading="linking" @click="linkGitHub" />
            </div>
          </div>
        </UCard>
      </template>

      <USkeleton v-else-if="status === 'pending'" class="h-40 w-full" />
    </div>
  </SPage>
</template>
