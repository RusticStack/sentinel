<script setup lang="ts">
// First-run setup, shown only while the controller says it is open (no
// administrator exists yet; the route middleware sends everyone away once
// it is closed). It is gated by the one-time token the controller wrote on
// its host, so the first visitor to reach the port gets nothing.
//
// The answers are kept in this tab's session storage as the person goes, so
// a refresh resumes where they were — except the setup token and the
// passwords, which live in this page's memory only and are asked for again.
// Everything is sent in one request at the end; the controller creates the
// administrator, the policy, the instance settings and the optional
// namespaces in one commit and signs the administrator in. An authenticator
// is then offered (not forced), and a last screen says what to do next.
import type { RegistrationChoice, SmtpTls, TenantCreationChoice, WizardDraft } from "~/utils/onboarding";

definePageMeta({ layout: "auth" });
useHead({ title: "Set up Sentinel" });
const api = useApi();
const session = useSession();
const setupStatus = useSetupStatus();

const STEPS = ["Setup token", "Administrator", "Who can join", "Instance", "Email", "Namespaces", "Review"] as const;
const LAST_DRAFT_STEP = STEPS.length - 1;
const SECURE = STEPS.length; // after setup: the authenticator
const DONE = STEPS.length + 1;

const draft = reactive<WizardDraft>(emptyDraft());
const step = ref(0);
// Where a resumed wizard was; the steps whose secrets were not kept are
// asked again on the way back to it.
const resumeAt = ref(0);
const resumed = ref(false);
const token = ref("");
const password = ref("");
const again = ref("");
const smtpPassword = ref("");
const smtpTo = ref("");
const completed = ref<{ organization: string | null; personal: string | null } | null>(null);
const heading = useTemplateRef<HTMLElement>("heading");

function load(): string | null {
  try { return sessionStorage.getItem(DRAFT_KEY); } catch { return null; }
}
function save() {
  if (completed.value) return;
  try { sessionStorage.setItem(DRAFT_KEY, serializeDraft({ ...draft, step: Math.min(step.value, LAST_DRAFT_STEP) })); } catch { /* storage off: no resume */ }
}
function forget() {
  try { sessionStorage.removeItem(DRAFT_KEY); } catch { /* ignore */ }
}

onMounted(() => {
  const stored = parseDraft(load(), LAST_DRAFT_STEP);
  Object.assign(draft, stored);
  if (!draft.baseUrl) draft.baseUrl = location.origin;
  if (stored.step > 0) {
    resumeAt.value = stored.step;
    resumed.value = true;
  }
  step.value = 0;
});
watch([draft, step], save, { deep: true });

function focusHeading() {
  nextTick(() => heading.value?.focus());
}
watch(step, focusHeading);

onBeforeUnmount(() => {
  token.value = "";
  password.value = "";
  again.value = "";
  smtpPassword.value = "";
});

// --- Moving between steps ------------------------------------------------

const stepError = ref("");

function problem(at: number): string | null {
  switch (at) {
    case 0:
      return isSetupToken(token.value) ? null : "The setup token is 64 characters of 0–9 and a–f. Copy it whole from the file or the log line.";
    case 1: {
      if (!looksLikeEmail(draft.email)) return "Enter the administrator's email address, such as you@example.com.";
      const advice = passwordAdvice(password.value);
      if (!advice.acceptable) return advice.hints[0] ?? "Choose a longer password.";
      if (password.value !== again.value) return "The password and its repetition differ.";
      if (draft.displayName.length > 128) return "Use at most 128 characters for the name.";
      return null;
    }
    case 3:
      if (!draft.instanceName.trim()) return "Give the instance a name.";
      if (draft.instanceName.trim().length > 64) return "Use at most 64 characters for the instance name.";
      return baseUrlProblem(draft.baseUrl);
    case 5: {
      for (const [label, value] of [["Personal namespace", draft.personalNamespace], ["Organization", draft.organization]] as const) {
        const p = value ? slugProblem(value) : null;
        if (p) return `${label}: ${p}`;
      }
      if (draft.personalNamespace && draft.personalNamespace === draft.organization) return "The personal namespace and the organization need different names.";
      return null;
    }
    default:
      return null;
  }
}

function next() {
  const p = problem(step.value);
  stepError.value = p ?? "";
  if (p) return;
  const target = step.value + 1;
  if (resumeAt.value > target) {
    // Back to where a resumed wizard was, through the password if it was
    // not kept.
    if (step.value === 0 && !password.value) { step.value = 1; return; }
    step.value = resumeAt.value;
    resumeAt.value = 0;
    return;
  }
  step.value = target;
}
function back() {
  stepError.value = "";
  if (step.value > 0) step.value--;
}
function goTo(at: number) {
  stepError.value = "";
  resumeAt.value = 0;
  // A secret that was not kept is asked first.
  step.value = !isSetupToken(token.value) ? 0 : at > 1 && !password.value ? 1 : at;
}

// --- The choices, in words -------------------------------------------------

const REGISTRATIONS: { value: RegistrationChoice; label: string; description: string }[] = [
  { value: "invite-only", label: "By invitation only", description: "Nobody can sign up on their own. You (or an organization's administrators) invite people by email; an invitation is their approval. Recommended." },
  { value: "approval-required", label: "Anyone may ask; you approve", description: "Anyone who reaches this instance can sign up, and their account waits until a platform administrator approves it." },
  { value: "closed", label: "Closed", description: "No new accounts at all, invited or not. Good while you finish preparing; you can open it later." },
];
const CREATIONS: { value: TenantCreationChoice; label: string; description: string }[] = [
  { value: "super-admin-only", label: "Only platform administrators", description: "You create organizations and add people to them." },
  { value: "approved-users", label: "Any approved account", description: "Every admitted person may create up to 10 organizations of their own and administer them." },
];
const TLS_CHOICES: { value: SmtpTls; label: string }[] = [
  { value: "starttls", label: "STARTTLS (usually port 587)" },
  { value: "implicit", label: "TLS from the start (usually port 465)" },
  { value: "none", label: "None (a relay on this host only)" },
];
const regLabel = computed(() => REGISTRATIONS.find((r) => r.value === draft.registration)?.label ?? draft.registration);
const creationLabel = computed(() => CREATIONS.find((c) => c.value === draft.tenantCreation)?.label ?? draft.tenantCreation);
watch(() => draft.smtpTls, (tls, old) => {
  const defaults: Record<SmtpTls, number> = { starttls: 587, implicit: 465, none: 25 };
  if (draft.smtpPort === defaults[old]) draft.smtpPort = defaults[tls];
});

// --- SMTP test -------------------------------------------------------------

type SmtpResult = { kind: "sent" } | { kind: "failed"; failure: string; reason: string } | { kind: "error"; message: string };
const smtpResult = ref<SmtpResult | null>(null);
const testing = ref(false);
const smtpWait = useRetryWait();
const smtpSnippet = computed(() => [
  `SENTINEL_SMTP_HOST=${draft.smtpHost || "smtp.example.com"}`,
  `SENTINEL_SMTP_PORT=${draft.smtpPort}`,
  `SENTINEL_SMTP_TLS=${draft.smtpTls}`,
  `SENTINEL_SMTP_FROM=${draft.smtpFrom || "ci@example.com"}`,
  ...(draft.smtpUsername ? ["SENTINEL_SMTP_CREDENTIALS_FILE=/etc/sentinel/smtp-credentials  # owner-only: username = …, password = …"] : []),
].join("\n"));

async function testSmtp() {
  if (testing.value || smtpWait.waiting.value) return;
  smtpResult.value = null;
  if (!draft.smtpHost.trim() || !looksLikeEmail(draft.smtpFrom) || !looksLikeEmail(smtpTo.value || draft.email)) {
    smtpResult.value = { kind: "error", message: "Fill in the relay's host, the sender address and where the test should go." };
    return;
  }
  if (!!draft.smtpUsername !== !!smtpPassword.value) {
    smtpResult.value = { kind: "error", message: "Give both the user name and the password, or neither." };
    return;
  }
  testing.value = true;
  const body: Record<string, unknown> = {
    token: token.value.trim(),
    host: draft.smtpHost.trim(),
    port: draft.smtpPort,
    tls: draft.smtpTls,
    from: draft.smtpFrom.trim(),
    to: (smtpTo.value || draft.email).trim(),
  };
  if (draft.smtpUsername) {
    body.username = draft.smtpUsername;
    body.password = smtpPassword.value;
  }
  try {
    const done = await api<{ sent: boolean; failure?: string; reason?: string }>("/api/v1/setup/smtp-test", { method: "POST", body });
    smtpResult.value = done.sent ? { kind: "sent" } : { kind: "failed", failure: done.failure ?? "transient", reason: done.reason ?? "" };
  } catch (e) {
    const err = e as ApiError;
    if (err.code === "forbidden" && err.message === "setup token refused") {
      tokenRefused();
      return;
    }
    if (err.code === "not_found") return setupGone();
    if (err.code === "rate_limited") smtpWait.start(err);
    smtpResult.value = { kind: "error", message: err.code === "rate_limited" ? `Another test is running or too many were sent. Try again in ${retryAfter(err)}.` : refusal(err) };
  } finally {
    body.password = undefined;
    testing.value = false;
  }
}

const FAILURE_WORDS: Record<string, string> = {
  invalid_settings: "The settings themselves are not usable",
  transient: "The relay could not be reached or refused for now (address, port, TLS mode or credentials)",
  permanent: "The relay refused the message",
};

// --- Finishing -------------------------------------------------------------

const finishing = ref(false);
const finishError = ref("");
const gone = ref(false);
const finishWait = useRetryWait();

function tokenRefused() {
  token.value = "";
  step.value = 0;
  stepError.value = "The setup token was not accepted. It may be mistyped, older than an hour, replaced by a restart, or locked for five minutes after repeated wrong tries. Read the current one on the host.";
}
function setupGone() {
  gone.value = true;
  forget();
  setupStatus.markClosed();
  focusHeading();
}

async function finish() {
  if (finishing.value || finishWait.waiting.value) return;
  for (const at of [0, 1, 3, 5]) {
    const p = problem(at);
    if (p) { goTo(at); stepError.value = p; return; }
  }
  finishing.value = true;
  finishError.value = "";
  const body: Record<string, unknown> = {
    token: token.value.trim(),
    email: draft.email.trim(),
    password: password.value,
    registration: draft.registration,
    tenant_creation: draft.tenantCreation,
    instance_name: draft.instanceName.trim(),
  };
  if (draft.displayName.trim()) body.display_name = draft.displayName.trim();
  if (draft.baseUrl.trim()) body.base_url = draft.baseUrl.trim().replace(/\/+$/, "");
  if (draft.personalNamespace) body.personal_namespace = draft.personalNamespace;
  if (draft.organization) body.organization = draft.organization;
  try {
    const done = await api<{ csrf: string; organization: string | null; personal_namespace: string | null }>("/api/v1/setup", { method: "POST", body });
    setCsrfToken(done.csrf);
    token.value = "";
    again.value = "";
    smtpPassword.value = "";
    completed.value = { organization: done.organization ?? null, personal: done.personal_namespace ?? null };
    forget();
    setupStatus.markClosed();
    await session.load(true);
    step.value = SECURE;
  } catch (e) {
    const err = e as ApiError;
    if (err.code === "forbidden" && err.message === "setup token refused") tokenRefused();
    else if (err.code === "not_found") setupGone();
    else if (err.code === "conflict") finishError.value = "That address or one of the names is already taken. Change the administrator's address or the namespace names and try again.";
    else if (err.code === "invalid_request") finishError.value = `The controller refused a field (${err.message}). Check the answers above.`;
    else if (err.code === "rate_limited") {
      finishWait.start(err);
      finishError.value = `Too many attempts. Try again in ${retryAfter(err)}.`;
    } else finishError.value = refusal(err);
  } finally {
    body.password = undefined;
    finishing.value = false;
  }
}

function leaveSecure() {
  password.value = "";
  step.value = DONE;
}

const title = computed(() => {
  if (gone.value) return "Setup is already complete";
  if (step.value === SECURE) return "Protect your account";
  if (step.value === DONE) return "Sentinel is ready";
  return STEPS[step.value] ?? "Set up Sentinel";
});
const firstNamespace = computed(() => completed.value?.organization ?? completed.value?.personal ?? null);
</script>

<template>
  <UCard class="w-full max-w-2xl" :ui="{ body: 'space-y-5' }">
    <template #header>
      <div class="space-y-3">
        <div class="flex items-center gap-2">
          <UIcon name="i-lucide-radar" class="size-6 text-primary" />
          <span class="text-sm font-medium text-muted">Set up Sentinel</span>
        </div>
        <nav v-if="step <= LAST_DRAFT_STEP && !gone" aria-label="Setup steps">
          <ol class="flex flex-wrap gap-x-3 gap-y-1 text-xs">
            <li v-for="(name, i) in STEPS" :key="name" :aria-current="i === step ? 'step' : undefined"
              class="flex items-center gap-1" :class="i === step ? 'font-semibold text-highlighted' : i < step ? 'text-default' : 'text-muted'">
              <UIcon :name="i < step ? 'i-lucide-circle-check' : 'i-lucide-circle'" class="size-3.5" :class="i < step ? 'text-success' : ''" />
              <span>{{ i + 1 }}. {{ name }}</span>
            </li>
          </ol>
        </nav>
        <h1 ref="heading" tabindex="-1" class="text-lg font-semibold focus:outline-none">{{ title }}</h1>
      </div>
    </template>

    <!-- Completed elsewhere meanwhile. -->
    <template v-if="gone">
      <p class="text-sm">Someone finished setting up this instance (from another browser or on the host) before this wizard did. Nothing from this wizard was saved.</p>
      <UButton to="/login" label="Go to sign-in" block />
    </template>

    <form v-else-if="step <= LAST_DRAFT_STEP" class="space-y-5" novalidate :aria-label="STEPS[step]" @submit.prevent="step === LAST_DRAFT_STEP ? finish() : next()">
      <!-- 1. Setup token -->
      <template v-if="step === 0">
        <UAlert v-if="resumed" color="info" variant="subtle" icon="i-lucide-history" role="status" title="Picking up where you left off."
          description="Your answers were kept in this tab. For safety the setup token and passwords were not: enter them again." />
        <p class="text-sm">This proves you run the server. When the controller starts without an administrator, it writes a one-time setup token to a file only its service user can read and prints it once in its log:</p>
        <ul class="list-disc ps-5 text-sm space-y-1">
          <li>the file <code>setup-token</code> in the controller's data directory, or</li>
          <li>the <code>setup_required</code> line in the controller's log.</li>
        </ul>
        <p class="text-sm text-muted">It works for one hour; restarting the controller makes a new one. Five wrong tries lock setup for five minutes.</p>
        <UFormField label="Setup token" name="setup-token" required>
          <UInput id="setup-token" v-model="token" type="password" autocomplete="off" autocapitalize="off" spellcheck="false" maxlength="80" required autofocus class="w-full font-mono" />
        </UFormField>
      </template>

      <!-- 2. Administrator -->
      <template v-else-if="step === 1">
        <p class="text-sm">This account administers the whole instance. Its address is trusted as confirmed, so it can sign in right away.</p>
        <UFormField label="Email address" name="email" required>
          <UInput id="admin-email" v-model="draft.email" type="email" autocomplete="email" autocapitalize="off" spellcheck="false" required autofocus class="w-full" />
        </UFormField>
        <UFormField label="Your name" name="display_name" hint="Optional">
          <UInput id="admin-name" v-model="draft.displayName" autocomplete="name" maxlength="128" class="w-full" />
        </UFormField>
        <input type="text" name="username" autocomplete="username" :value="draft.email" class="sr" tabindex="-1" aria-hidden="true" readonly>
        <UFormField label="Password" name="password" required>
          <UInput id="admin-password" v-model="password" type="password" autocomplete="new-password" minlength="12" maxlength="256" required class="w-full" aria-describedby="admin-advice" />
        </UFormField>
        <PasswordAdvice id="admin-advice" :password="password" :context="[draft.email, draft.displayName, draft.instanceName]" />
        <UFormField label="Password again" name="again" required>
          <UInput id="admin-again" v-model="again" type="password" autocomplete="new-password" required class="w-full" />
        </UFormField>
      </template>

      <!-- 3. Who can join -->
      <template v-else-if="step === 2">
        <URadioGroup v-model="draft.registration" :items="REGISTRATIONS" legend="Who can create an account" variant="card" :ui="{ fieldset: 'gap-2' }" />
        <URadioGroup v-model="draft.tenantCreation" :items="CREATIONS" legend="Who can create organizations" variant="card" :ui="{ fieldset: 'gap-2' }" />
        <p class="text-xs text-muted">Both can be changed later under Platform → Policy. Whatever you choose, people only ever see the organizations they belong to.</p>
      </template>

      <!-- 4. Instance -->
      <template v-else-if="step === 3">
        <UFormField label="Instance name" name="instance_name" required hint="Up to 64 characters">
          <UInput id="instance-name" v-model="draft.instanceName" maxlength="64" required autofocus class="w-full" />
        </UFormField>
        <UFormField label="Address people use" name="base_url" hint="Optional" description="The address of this web interface, as people type it.">
          <UInput id="instance-url" v-model="draft.baseUrl" type="url" inputmode="url" autocapitalize="off" spellcheck="false" maxlength="255" placeholder="https://ci.example.com" class="w-full" />
        </UFormField>
        <p class="text-xs text-muted">Links in emails and GitHub keep using the controller's configured <code>public_url</code>; keep the two the same.</p>
      </template>

      <!-- 5. Email -->
      <template v-else-if="step === 4">
        <p class="text-sm">Optional. Sentinel can email confirmation links and invitations through your mail relay. Without one, nobody is locked out: you hand links over yourself.</p>
        <UAlert color="info" variant="subtle" icon="i-lucide-info" title="The wizard only tests these settings."
          description="Nothing typed here is stored. To turn email on, put the settings in the controller's configuration ([mail], or the environment lines below) and restart it." />
        <div class="grid gap-4 sm:grid-cols-[1fr_8rem]">
          <UFormField label="Relay host" name="smtp-host">
            <UInput id="smtp-host" v-model="draft.smtpHost" autocapitalize="off" spellcheck="false" placeholder="smtp.example.com" class="w-full" />
          </UFormField>
          <UFormField label="Port" name="smtp-port">
            <UInput id="smtp-port" v-model.number="draft.smtpPort" type="number" min="1" max="65535" class="w-full" />
          </UFormField>
        </div>
        <UFormField label="Encryption" name="smtp-tls">
          <USelect id="smtp-tls" v-model="draft.smtpTls" :items="TLS_CHOICES" class="w-full" />
        </UFormField>
        <UFormField label="Sender address" name="smtp-from">
          <UInput id="smtp-from" v-model="draft.smtpFrom" type="email" autocapitalize="off" spellcheck="false" placeholder="ci@example.com" class="w-full" />
        </UFormField>
        <div class="grid gap-4 sm:grid-cols-2">
          <UFormField label="User name" name="smtp-user" hint="If the relay asks">
            <UInput id="smtp-user" v-model="draft.smtpUsername" autocomplete="off" autocapitalize="off" spellcheck="false" class="w-full" />
          </UFormField>
          <UFormField label="Password" name="smtp-password" hint="Not kept">
            <UInput id="smtp-password" v-model="smtpPassword" type="password" autocomplete="off" class="w-full" />
          </UFormField>
        </div>
        <div class="flex flex-wrap items-end gap-3">
          <UFormField label="Send the test to" name="smtp-to">
            <UInput id="smtp-to" v-model="smtpTo" type="email" :placeholder="draft.email || 'you@example.com'" autocapitalize="off" spellcheck="false" class="w-64 max-w-full" />
          </UFormField>
          <UButton type="button" color="neutral" variant="outline" icon="i-lucide-send" :label="smtpWait.waiting.value ? `Wait ${smtpWait.waiting.value} s` : 'Send test message'" :loading="testing" :disabled="!!smtpWait.waiting.value" @click="testSmtp" />
        </div>
        <div aria-live="polite">
          <UAlert v-if="smtpResult?.kind === 'sent'" color="success" variant="subtle" icon="i-lucide-mail-check" title="Test message sent."
            description="Check that it arrived (and not in spam). Then put these settings in the controller's configuration." />
          <UAlert v-else-if="smtpResult?.kind === 'failed'" color="warning" variant="subtle" icon="i-lucide-mail-warning" :title="`${FAILURE_WORDS[smtpResult.failure] ?? 'The test failed'}.`"
            :description="smtpResult.reason ? `The relay said: ${smtpResult.reason}` : undefined" />
          <UAlert v-else-if="smtpResult?.kind === 'error'" color="error" variant="subtle" icon="i-lucide-circle-alert" :title="smtpResult.message" />
        </div>
        <details class="rounded-md border border-default p-3 text-sm">
          <summary class="cursor-pointer font-medium">Configuration lines for the controller</summary>
          <pre class="mt-2 overflow-x-auto rounded bg-muted p-2 text-xs"><code>{{ smtpSnippet }}</code></pre>
          <p class="mt-2 text-xs text-muted">The relay's password goes in the owner-only credentials file, never in the environment.</p>
        </details>
      </template>

      <!-- 6. Namespaces -->
      <template v-else-if="step === 5">
        <p class="text-sm">Optional. Names are 2 to 63 lowercase letters, digits and hyphens, and are part of addresses (<code>/t/name</code>).</p>
        <UFormField label="Your personal namespace" name="personal" hint="Optional" description="A space only you belong to.">
          <UInput id="ns-personal" v-model="draft.personalNamespace" autocomplete="off" autocapitalize="off" spellcheck="false" maxlength="63" placeholder="your-name" class="w-full sm:w-80" />
        </UFormField>
        <UFormField label="First organization" name="organization" hint="Optional" description="You administer it and can invite people to it by email.">
          <UInput id="ns-org" v-model="draft.organization" autocomplete="off" autocapitalize="off" spellcheck="false" maxlength="63" placeholder="my-team" class="w-full sm:w-80" />
        </UFormField>
      </template>

      <!-- 7. Review -->
      <template v-else-if="step === 6">
        <p class="text-sm">Nothing is created until you finish. Then everything below is created at once.</p>
        <dl class="divide-y divide-default rounded-lg border border-default text-sm">
          <div v-for="row in [
            { at: 1, label: 'Administrator', value: draft.displayName ? `${draft.displayName} <${draft.email}>` : draft.email },
            { at: 2, label: 'Who can create an account', value: regLabel },
            { at: 2, label: 'Who can create organizations', value: creationLabel },
            { at: 3, label: 'Instance', value: draft.baseUrl ? `${draft.instanceName} — ${draft.baseUrl}` : draft.instanceName },
            { at: 4, label: 'Email', value: smtpResult?.kind === 'sent' ? 'Tested; configure it on the controller' : 'Not tested (optional)' },
            { at: 5, label: 'Personal namespace', value: draft.personalNamespace || 'None' },
            { at: 5, label: 'First organization', value: draft.organization || 'None' },
          ]" :key="row.label" class="flex flex-wrap items-center justify-between gap-2 px-3 py-2">
            <dt class="text-muted">{{ row.label }}</dt>
            <dd class="flex items-center gap-2 min-w-0"><span class="break-all">{{ row.value }}</span>
              <UButton size="xs" color="neutral" variant="link" label="Change" :aria-label="`Change ${row.label.toLowerCase()}`" @click="goTo(row.at)" />
            </dd>
          </div>
        </dl>
        <UAlert v-if="finishError" color="error" variant="subtle" icon="i-lucide-circle-alert" :title="finishError" role="alert" />
      </template>

      <UAlert v-if="stepError" color="error" variant="subtle" icon="i-lucide-circle-alert" :title="stepError" role="alert" />

      <div class="flex flex-wrap justify-between gap-2 pt-1">
        <UButton v-if="step > 0" type="button" color="neutral" variant="ghost" icon="i-lucide-arrow-left" label="Back" @click="back" />
        <span v-else />
        <UButton v-if="step < LAST_DRAFT_STEP" type="submit" trailing-icon="i-lucide-arrow-right" :label="step === 4 || step === 5 ? 'Next (optional step)' : 'Next'" />
        <UButton v-else type="submit" icon="i-lucide-check" :label="finishWait.waiting.value ? `Wait ${finishWait.waiting.value} s` : 'Finish setup'" :loading="finishing" :disabled="!!finishWait.waiting.value" />
      </div>
    </form>

    <!-- After setup: an authenticator, offered. -->
    <template v-else-if="step === SECURE">
      <UAlert color="success" variant="subtle" icon="i-lucide-circle-check" role="status" title="Setup is complete and you are signed in." />
      <TotpEnroll :has-password="true" :password="password" :username="draft.email" @done="leaveSecure">
        <template #intro>
          <p class="text-sm">Your account can change everything on this instance. An authenticator app adds a code that changes every 30 seconds, asked for before sensitive changes, so a stolen session or password alone is not enough. Recommended; you can also do it later from Account security.</p>
        </template>
        <template #actions>
          <UButton type="button" color="neutral" variant="ghost" label="Skip for now" @click="leaveSecure" />
        </template>
      </TotpEnroll>
    </template>

    <!-- Done. -->
    <template v-else>
      <p class="text-sm">Here is what to do next:</p>
      <ul class="space-y-2 text-sm">
        <li v-if="completed?.organization" class="flex items-start gap-2"><UIcon name="i-lucide-mail-plus" class="mt-0.5 shrink-0 text-primary" />
          <span><ULink :to="`/t/${completed.organization}/admin/invitations`" class="font-medium text-primary">Invite people to {{ completed.organization }}</ULink> by email.</span></li>
        <li v-else class="flex items-start gap-2"><UIcon name="i-lucide-building-2" class="mt-0.5 shrink-0 text-primary" />
          <span><ULink to="/organizations" class="font-medium text-primary">Create an organization</ULink> and invite people to it.</span></li>
        <li class="flex items-start gap-2"><UIcon name="i-lucide-server" class="mt-0.5 shrink-0 text-primary" />
          <span>Connect a worker and set up worker pools under <ULink to="/platform/pools" class="font-medium text-primary">Platform → Pools</ULink>.</span></li>
        <li class="flex items-start gap-2"><UIcon name="i-lucide-scale" class="mt-0.5 shrink-0 text-primary" />
          <span>Review who can join under <ULink to="/platform/policy" class="font-medium text-primary">Platform → Policy</ULink>.</span></li>
        <li v-if="!session.me.value?.mfa" class="flex items-start gap-2"><UIcon name="i-lucide-shield-check" class="mt-0.5 shrink-0 text-warning" />
          <span>Set up an authenticator under <ULink to="/account" class="font-medium text-primary">Account security</ULink>.</span></li>
      </ul>
      <UButton :to="firstNamespace ? `/t/${firstNamespace}` : '/'" label="Open Sentinel" block />
    </template>
  </UCard>
</template>
