<script setup lang="ts">
// Enrolling an authenticator app: start (with the account's password, or a
// recent sign-in for a GitHub-only account), scan the QR code drawn in the
// page or type the key, confirm with a code, then see the recovery codes
// once. Shared by the account page and the first-run wizard. The seed lives
// in this component's memory only and is dropped when it has served, on
// cancel and on unmount.
const props = defineProps<{
  /** The account has a local password, which starting needs. */
  hasPassword: boolean;
  /** An enrollment was begun and not confirmed. */
  pending?: boolean;
  /** For password managers: which account the password belongs to. */
  username?: string | null;
  /** A password the caller already holds (the wizard just set it); the
   *  field is then not shown. Sent once and never kept here. */
  password?: string | null;
}>();
const emit = defineEmits<{ started: []; done: []; cancel: [] }>();
const api = useApi();
const session = useSession();
const toast = useToast();
const showOnce = useShowOnce();

const enrollPassword = ref("");
const enrollError = ref("");
const reauthenticate = ref(false);
const enrolling = ref(false);
const uri = ref<string | null>(null);
const confirmCode = ref("");
const confirmError = ref("");
const confirming = ref(false);
const qr = computed(() => (uri.value ? encodeQr(uri.value) : null));
const qrBox = computed(() => (qr.value ? qr.value.size + 8 : 0));
const secret = computed(() => (uri.value ? totpSecret(uri.value) : null));
const codeInput = useTemplateRef<{ inputRef?: HTMLInputElement }>("codeInput");
const { waiting, start: wait } = useRetryWait();

async function startEnroll() {
  if (enrolling.value || waiting.value) return;
  enrolling.value = true;
  enrollError.value = "";
  reauthenticate.value = false;
  const given = props.password ?? enrollPassword.value;
  const body = props.hasPassword ? { password: given } : {};
  enrollPassword.value = "";
  try {
    const started = await api<{ provisioning_uri: string }>("/api/v1/mfa/enroll", { method: "POST", body });
    uri.value = started.provisioning_uri;
    confirmCode.value = "";
    confirmError.value = "";
    emit("started");
    nextTick(() => codeInput.value?.inputRef?.focus());
  } catch (e) {
    const err = e as ApiError;
    if (err.code === "unauthenticated") return;
    if (err.code === "forbidden" && err.details?.reauthenticate) {
      reauthenticate.value = true;
      enrollError.value = "Setting up an authenticator needs a recent sign-in. Sign in again, then come back here.";
    } else if (err.code === "forbidden" && err.message === "enrollment refused") {
      enrollError.value = "That password was not accepted. Five wrong attempts end this session.";
    } else if (err.code === "conflict") {
      enrollError.value = "An authenticator is already set up.";
      emit("done");
    } else if (err.code === "rate_limited") {
      wait(err);
      enrollError.value = `Too many attempts. Try again in ${retryAfter(err)}.`;
    } else {
      enrollError.value = err.code === "forbidden" ? err.message : refusal(err);
    }
  } finally {
    enrolling.value = false;
  }
}

function cancelEnroll() {
  uri.value = null;
  confirmCode.value = "";
  confirmError.value = "";
  emit("cancel");
}

async function confirmEnroll() {
  if (confirming.value) return;
  const code = confirmCode.value.replace(/\s+/g, "");
  confirmCode.value = "";
  if (!/^\d{6}$/.test(code)) {
    confirmError.value = "Enter the six-digit code the app shows now.";
    return;
  }
  confirming.value = true;
  confirmError.value = "";
  try {
    const done = await api<{ recovery_codes: string[] }>("/api/v1/mfa/enroll/confirm", { method: "POST", body: { code } });
    uri.value = null;
    if (session.me.value) {
      session.me.value.mfa = true;
      session.me.value.stepped_up = true;
    }
    await showOnce({
      title: "Save your recovery codes",
      description: "Each code confirms it's you once if the authenticator is not at hand.",
      secrets: done.recovery_codes,
      filename: "sentinel-recovery-codes.txt",
      note: "Keep them apart from the device that runs the authenticator.",
    });
    toast.add({ title: "Authenticator set up", color: "success", icon: "i-lucide-check" });
    emit("done");
  } catch (e) {
    const err = e as ApiError;
    if (err.code === "unauthenticated") return;
    confirmError.value = err.code === "forbidden" ? "That code was not accepted. Check the device's clock and use the current code; five wrong codes end this session."
      : err.code === "not_found" ? "No setup is in progress any more. Start again."
        : refusal(err);
    if (err.code === "not_found") uri.value = null;
    nextTick(() => codeInput.value?.inputRef?.focus());
  } finally {
    confirming.value = false;
  }
}

onBeforeUnmount(() => {
  uri.value = null;
  confirmCode.value = "";
  enrollPassword.value = "";
});
</script>

<template>
  <!-- Step 2: scan and confirm -->
  <div v-if="uri" class="space-y-4">
    <ol class="list-decimal ps-5 text-sm space-y-1">
      <li>Scan the code with an authenticator app, or enter the key by hand.</li>
      <li>Type the six-digit code the app then shows.</li>
    </ol>
    <div class="flex flex-col gap-4 sm:flex-row sm:items-start">
      <svg v-if="qr" :viewBox="`0 0 ${qrBox} ${qrBox}`" class="size-48 shrink-0 rounded-md bg-white" shape-rendering="crispEdges" role="img" aria-label="QR code for your authenticator app; the same key is written beside it">
        <path :d="qrPath(qr)" fill="#000" />
      </svg>
      <div class="space-y-2 min-w-0">
        <p class="text-sm text-muted">Key (time-based, 6 digits, 30 seconds)</p>
        <p id="totp-key" class="font-mono text-sm break-all select-all rounded-md border border-default bg-muted px-3 py-2">{{ secret ?? "—" }}</p>
        <UButton :to="uri" external size="sm" color="neutral" variant="link" icon="i-lucide-external-link" label="Open in an authenticator app on this device" class="px-0" />
      </div>
    </div>
    <form class="flex flex-wrap items-end gap-3" aria-label="Confirm the authenticator" @submit.prevent="confirmEnroll">
      <UFormField label="Code from the app" name="totp" hint="6 digits" :error="!!confirmError">
        <UInput id="totp-confirm" ref="codeInput" v-model="confirmCode" autocomplete="one-time-code" inputmode="numeric" maxlength="7" required class="w-40" />
      </UFormField>
      <UButton type="submit" label="Confirm" :loading="confirming" />
      <UButton color="neutral" variant="ghost" label="Cancel" @click="cancelEnroll" />
    </form>
    <UAlert v-if="confirmError" color="error" variant="subtle" icon="i-lucide-circle-alert" :title="confirmError" role="alert" />
  </div>

  <!-- Step 1: start -->
  <div v-else class="space-y-4">
    <slot name="intro">
      <p class="text-sm">An authenticator app on your phone gives a code that changes every 30 seconds. Sentinel asks for it before sensitive changes, so a stolen session alone cannot make them.</p>
    </slot>
    <UAlert v-if="pending" color="info" variant="subtle" icon="i-lucide-info" title="A setup was started and not finished."
      description="Start again for a new key; the earlier one stops working." />
    <form class="flex flex-wrap items-end gap-3" aria-label="Set up an authenticator" @submit.prevent="startEnroll">
      <template v-if="hasPassword && password == null">
        <!-- For password managers: which account this password belongs to. -->
        <input type="text" name="username" autocomplete="username" :value="username ?? ''" class="sr" tabindex="-1" aria-hidden="true" readonly>
        <UFormField label="Your password" name="enroll-password" :error="!!enrollError && !reauthenticate">
          <UInput id="enroll-password" v-model="enrollPassword" type="password" autocomplete="current-password" required class="w-64 max-w-full" />
        </UFormField>
      </template>
      <UButton type="submit" icon="i-lucide-qr-code" :label="waiting ? `Wait ${waiting} s` : pending ? 'Start again' : 'Set up'" :loading="enrolling" :disabled="!!waiting" />
      <slot name="actions" />
    </form>
    <p v-if="!hasPassword" class="text-xs text-muted">Your account signs in with GitHub, so setting up needs a sign-in within the last few minutes.</p>
    <UAlert v-if="enrollError" color="error" variant="subtle" icon="i-lucide-circle-alert" :title="enrollError" role="alert"
      :actions="reauthenticate ? [{ label: 'Sign in again', icon: 'i-lucide-log-in', onClick: () => { session.signOut('/account'); } }] : undefined" />
  </div>
</template>
