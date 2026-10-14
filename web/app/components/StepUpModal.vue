<script setup lang="ts">
// Confirm it's you: a code from the authenticator app, a recovery
// code, or the password for an account without TOTP; the session is
// stamped for the policy window and the action that asked is retried.
// The proof lives in this component only and is cleared after every try.
const props = defineProps<{ mfa: boolean; password: boolean }>();
const emit = defineEmits<{ close: [boolean] }>();
const api = useApi();

type Method = "totp" | "recovery" | "password";
const methods = [
  { label: "Authenticator app", value: "totp", description: "The six-digit code it shows now" },
  { label: "Recovery code", value: "recovery", description: "One of the codes saved at enrollment; each works once" },
];
const method = ref<Method>(props.mfa ? "totp" : "password");
// A GitHub-only account without an authenticator has nothing to prove
// presence with here: it enrolls one first.
const impossible = !props.mfa && !props.password;
const code = ref("");
const error = ref("");
const busy = ref(false);
const { waiting, start: wait } = useRetryWait();
const input = useTemplateRef<{ inputRef?: HTMLInputElement }>("input");

const field = computed(() => method.value === "totp"
  ? { label: "Code from the app", type: "text", autocomplete: "one-time-code", inputmode: "numeric" as const, maxlength: 7, hint: "6 digits" }
  : method.value === "recovery"
    ? { label: "Recovery code", type: "text", autocomplete: "off", inputmode: "text" as const, maxlength: 64, hint: undefined }
    : { label: "Your password", type: "password", autocomplete: "current-password", inputmode: "text" as const, maxlength: 1024, hint: undefined });

watch(method, () => {
  code.value = "";
  error.value = "";
  nextTick(() => input.value?.inputRef?.focus());
});

onBeforeUnmount(() => {
  code.value = "";
});

async function submit() {
  if (busy.value || waiting.value) return;
  // An app shows its code as "123 456"; a recovery code is retype-tolerant
  // on the controller, so only the ends are trimmed.
  const proof = method.value === "totp" ? code.value.replace(/\s+/g, "") : method.value === "recovery" ? code.value.trim() : code.value;
  code.value = "";
  if (!proof) {
    error.value = method.value === "password" ? "Enter your password." : "Enter a code.";
    return;
  }
  busy.value = true;
  error.value = "";
  try {
    await api("/api/v1/step-up", { method: "POST", body: { method: method.value, code: proof } });
    emit("close", true);
  } catch (e) {
    const err = e as ApiError;
    if (err.code === "unauthenticated") {
      // Five wrong proofs end the session, and a locked authenticator ends
      // them all; `useApi` is already on its way to sign-in.
      emit("close", false);
      return;
    }
    if (err.code === "rate_limited") {
      wait(err);
      error.value = `Too many attempts. Try again in ${retryAfter(err)}.`;
    } else if (err.code === "forbidden" && err.details?.step_up) {
      error.value = method.value === "totp"
        ? "That code was not accepted. Wait for the next one and check the device's clock."
        : method.value === "recovery" ? "That recovery code was not accepted, or it was already used." : "That password was not accepted.";
    } else {
      error.value = refusal(err);
    }
    nextTick(() => input.value?.inputRef?.focus());
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <UModal title="Confirm it's you" :description="impossible ? 'This change needs a second factor.' : 'This change needs a recent second factor. It stays confirmed for a few minutes.'"
    @update:open="(open) => !open && emit('close', false)">
    <template #body>
      <div v-if="impossible" class="space-y-3 text-sm">
        <p>Your account signs in with GitHub and has no password, so it proves it is you with an authenticator app. Set one up first, then try again.</p>
        <UButton to="/account" icon="i-lucide-shield-check" label="Set up an authenticator" @click="emit('close', false)" />
      </div>
      <form v-else id="step-up" class="space-y-4" novalidate @submit.prevent="submit">
        <URadioGroup v-if="mfa" v-model="method" :items="methods" legend="Confirm with" />
        <UFormField :label="field.label" name="code" :hint="field.hint" :error="!!error">
          <UInput id="stepup-code" ref="input" v-model="code" :type="field.type" :autocomplete="field.autocomplete" :inputmode="field.inputmode"
            :maxlength="field.maxlength" autocapitalize="off" spellcheck="false" required autofocus class="w-full" />
        </UFormField>
        <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-circle-alert" :title="error" role="alert" />
        <p class="text-xs text-muted">
          Wrong attempts are counted: five in a row end this session<template v-if="mfa">, and ten wrong codes lock the authenticator for 15 minutes</template>.
        </p>
      </form>
    </template>
    <template #footer>
      <div class="flex gap-2 justify-end w-full">
        <UButton color="neutral" variant="ghost" label="Cancel" @click="emit('close', false)" />
        <UButton v-if="!impossible" type="submit" form="step-up" :label="waiting ? `Wait ${waiting} s` : 'Confirm'" :loading="busy" :disabled="!!waiting" />
      </div>
    </template>
  </UModal>
</template>
