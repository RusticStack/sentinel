<script setup lang="ts">
definePageMeta({ layout: "auth" });
useHead({ title: "Sign in · Sentinel" });

const route = useRoute();
const session = useSession();
const api = useApi();
const username = ref("");
const password = ref("");
const error = ref("");
const busy = ref(false);
const passwordInput = useTemplateRef<{ inputRef?: HTMLInputElement }>("passwordInput");

// GitHub sign-in is offered only when the controller has it configured.
const { data: health } = await useAsyncData("health", () => api<{ github_sign_in?: boolean }>("/api/v1/health"));
const github = computed(() => !!health.value?.github_sign_in);

const next = computed(() => sameOriginPath(route.query.next));
// Why sign-in is asked for again, when the interface sent the person here.
const notice = computed(() => {
  switch (route.query.reason) {
    case "expired": return { title: "Your session ended", description: "Sign in again to continue where you were." };
    case "password-changed": return { title: "Password changed", description: "Every session of your account was signed out. Sign in with the new password." };
    default: return null;
  }
});

async function submit() {
  if (busy.value) return;
  busy.value = true;
  error.value = "";
  try {
    const me = await api<{ csrf: string }>("/api/v1/login", { method: "POST", body: { username: username.value, password: password.value } });
    setCsrfToken(me.csrf);
    password.value = "";
    await session.load(true);
    await navigateTo(next.value);
  } catch (e) {
    const err = e as ApiError;
    error.value = err.code === "unauthenticated" ? "Sign-in refused. Check the username and password; after repeated failures sign-in pauses for a while."
      : err.code === "rate_limited" ? `Too many sign-in attempts. Try again in ${retryAfter(err)}.`
        : err.code === "forbidden" ? "Sign-in was refused for this address. Open Sentinel at the address it is configured with."
          : refusal(err);
    password.value = "";
    nextTick(() => passwordInput.value?.inputRef?.focus());
  } finally {
    busy.value = false;
  }
}

function withGitHub() {
  try { sessionStorage.setItem("sentinel-return", next.value); } catch { /* ignore */ }
}
</script>

<template>
  <UCard class="w-full max-w-sm">
    <template #header>
      <div class="flex items-center gap-2">
        <UIcon name="i-lucide-radar" class="size-6 text-primary" />
        <h1 class="text-lg font-semibold">Sign in to Sentinel</h1>
      </div>
    </template>
    <form class="space-y-4" @submit.prevent="submit">
      <UAlert v-if="notice && !error" color="info" variant="subtle" icon="i-lucide-info" :title="notice.title" :description="notice.description" role="status" />
      <UFormField label="Username" name="username">
        <UInput id="username" v-model="username" autocomplete="username" autocapitalize="off" spellcheck="false" required autofocus class="w-full" />
      </UFormField>
      <UFormField label="Password" name="password">
        <UInput id="password" ref="passwordInput" v-model="password" type="password" autocomplete="current-password" required class="w-full" />
      </UFormField>
      <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-circle-alert" :title="error" role="alert" />
      <UButton type="submit" label="Sign in" block :loading="busy" />
    </form>
    <template v-if="github" #footer>
      <UButton :to="`/auth/github/start?return_to=%2F`" external icon="i-lucide-github" color="neutral" variant="outline" label="Sign in with GitHub" block @click="withGitHub" />
    </template>
  </UCard>
</template>
