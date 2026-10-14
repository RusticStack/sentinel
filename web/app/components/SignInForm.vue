<script setup lang="ts">
// A refusal never says whether the account exists; the password is cleared after every try.
const emit = defineEmits<{ signedIn: [] }>();
const session = useSession();
const api = useApi();
const username = ref("");
const password = ref("");
const error = ref("");
const busy = ref(false);
const passwordInput = useTemplateRef<{ inputRef?: HTMLInputElement }>("passwordInput");
const { waiting, start: wait } = useRetryWait();

async function submit() {
  if (busy.value || waiting.value) return;
  busy.value = true;
  error.value = "";
  try {
    const me = await api<{ csrf: string }>("/api/v1/login", { method: "POST", body: { username: username.value.trim(), password: password.value } });
    setCsrfToken(me.csrf);
    password.value = "";
    await session.load(true);
    emit("signedIn");
  } catch (e) {
    const err = e as ApiError;
    if (err.code === "rate_limited") wait(err);
    error.value = err.code === "unauthenticated"
      ? "Sign-in refused. Check the email address or username and the password. An email address signs in only once it is verified; after repeated failures sign-in pauses for a while."
      : err.code === "rate_limited" ? `Too many sign-in attempts. Try again in ${retryAfter(err)}.`
        : err.code === "forbidden" ? "Sign-in was refused for this address. Open Sentinel at the address it is configured with."
          : refusal(err);
    password.value = "";
    nextTick(() => passwordInput.value?.inputRef?.focus());
  } finally {
    busy.value = false;
  }
}

onBeforeUnmount(() => { password.value = ""; });
</script>

<template>
  <form class="space-y-4" aria-label="Sign in" @submit.prevent="submit">
    <slot name="notice" :error="error" />
    <UFormField label="Email or username" name="username">
      <UInput id="username" v-model="username" autocomplete="username" autocapitalize="off" spellcheck="false" required autofocus class="w-full" />
    </UFormField>
    <UFormField label="Password" name="password">
      <template #hint>
        <ULink to="/forgot-password" class="text-xs">Forgot your password?</ULink>
      </template>
      <UInput id="password" ref="passwordInput" v-model="password" type="password" autocomplete="current-password" required class="w-full" />
    </UFormField>
    <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-circle-alert" :title="error" role="alert" />
    <UButton type="submit" :label="waiting ? `Wait ${waiting} s` : 'Sign in'" block :loading="busy" :disabled="!!waiting" />
  </form>
</template>
