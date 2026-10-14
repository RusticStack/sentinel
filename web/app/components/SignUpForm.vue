<script setup lang="ts">
// Every outcome reads the same whether the address is new or already has an account.
const props = defineProps<{ invitation?: string | null }>();
const emit = defineEmits<{ accepted: [{ email: string; verification: "email" | "operator" }] }>();
const api = useApi();
const email = ref("");
const displayName = ref("");
const password = ref("");
const again = ref("");
const error = ref("");
const policy = ref<"closed" | "invitation" | "unusable" | null>(null);
const busy = ref(false);
const { waiting, start: wait } = useRetryWait();
const emailInput = useTemplateRef<{ inputRef?: HTMLInputElement }>("emailInput");

async function submit() {
  if (busy.value || waiting.value) return;
  error.value = "";
  policy.value = null;
  if (!looksLikeEmail(email.value)) {
    error.value = "Enter an email address such as name@example.com.";
    nextTick(() => emailInput.value?.inputRef?.focus());
    return;
  }
  const advice = passwordAdvice(password.value);
  if (!advice.acceptable) {
    error.value = advice.hints[0] ?? "Choose a longer password.";
    return;
  }
  if (password.value !== again.value) {
    error.value = "The password and its repetition differ.";
    return;
  }
  busy.value = true;
  const body: Record<string, string> = { email: email.value.trim(), password: password.value };
  if (displayName.value.trim()) body.display_name = displayName.value.trim();
  if (props.invitation) body.invitation = props.invitation;
  password.value = "";
  again.value = "";
  try {
    const done = await api<{ status: string; verification: "email" | "operator" }>("/api/v1/register", { method: "POST", body });
    emit("accepted", { email: body.email!, verification: done.verification });
  } catch (e) {
    const err = e as ApiError;
    if (err.code === "rate_limited") {
      wait(err);
      error.value = `Too many sign-up attempts from here. Try again in ${retryAfter(err)}.`;
    } else if (err.code === "forbidden" && err.message.includes("closed")) {
      policy.value = "closed";
    } else if (err.code === "forbidden" && err.message.includes("needs an invitation")) {
      policy.value = "invitation";
    } else if (err.code === "forbidden" && err.message.includes("invitation")) {
      policy.value = "unusable";
    } else if (err.code === "forbidden") {
      error.value = "Sign-up was refused for this address. Open Sentinel at the address it is configured with.";
    } else if (err.code === "invalid_request") {
      error.value = "Check the email address and the password (12 to 256 characters).";
    } else {
      error.value = refusal(err);
    }
  } finally {
    busy.value = false;
  }
}

onBeforeUnmount(() => {
  password.value = "";
  again.value = "";
});
</script>

<template>
  <form class="space-y-4" aria-label="Create an account" novalidate @submit.prevent="submit">
    <UFormField label="Email address" name="email" required>
      <UInput id="su-email" ref="emailInput" v-model="email" type="email" autocomplete="email" autocapitalize="off" spellcheck="false" required autofocus class="w-full" />
    </UFormField>
    <UFormField label="Your name" name="display_name" hint="Optional">
      <UInput id="su-name" v-model="displayName" autocomplete="name" maxlength="128" class="w-full" />
    </UFormField>
    <!-- For password managers: the new password belongs to this address. -->
    <input type="text" name="username" autocomplete="username" :value="email" class="sr" tabindex="-1" aria-hidden="true" readonly>
    <UFormField label="Password" name="password" required>
      <UInput id="su-password" v-model="password" type="password" autocomplete="new-password" minlength="12" maxlength="256" required class="w-full" aria-describedby="su-advice" />
    </UFormField>
    <PasswordAdvice id="su-advice" :password="password" :context="[email, displayName]" />
    <UFormField label="Password again" name="again" required>
      <UInput id="su-again" v-model="again" type="password" autocomplete="new-password" required class="w-full" />
    </UFormField>
    <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-circle-alert" :title="error" role="alert" />
    <UAlert v-else-if="policy === 'closed'" color="warning" variant="subtle" icon="i-lucide-lock" role="alert" title="Sign-up is closed on this instance."
      description="The administrator is not accepting new accounts. If you already have one, sign in." />
    <UAlert v-else-if="policy === 'invitation'" color="warning" variant="subtle" icon="i-lucide-mail" role="alert" title="Sign-up needs an invitation."
      description="Ask an administrator to invite you by email, then open the link in the invitation." />
    <UAlert v-else-if="policy === 'unusable'" color="warning" variant="subtle" icon="i-lucide-mail-x" role="alert" title="This invitation cannot be used."
      description="It may have expired, been used or been withdrawn. Ask whoever invited you for a new one." />
    <UButton type="submit" :label="waiting ? `Wait ${waiting} s` : 'Create account'" block :loading="busy" :disabled="!!waiting" />
  </form>
</template>
