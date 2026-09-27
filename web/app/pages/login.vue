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

// GitHub sign-in is offered only when the controller has it configured.
const { data: health } = await useAsyncData("health", () => api<{ github_sign_in?: boolean }>("/api/v1/health"));
const github = computed(() => !!health.value?.github_sign_in);

const next = computed(() => (typeof route.query.next === "string" && route.query.next.startsWith("/") ? route.query.next : "/"));

async function submit() {
  busy.value = true;
  error.value = "";
  try {
    const me = await api<{ csrf: string }>("/api/v1/login", { method: "POST", body: { username: username.value, password: password.value } });
    setCsrfToken(me.csrf);
    password.value = "";
    await session.load(true);
    await navigateTo(next.value);
  } catch (e) {
    error.value = e instanceof ApiError && e.code === "unauthenticated" ? "Sign-in refused." : (e as Error).message;
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
      <UFormField label="Username" name="username">
        <UInput id="username" v-model="username" autocomplete="username" required autofocus class="w-full" />
      </UFormField>
      <UFormField label="Password" name="password">
        <UInput id="password" v-model="password" type="password" autocomplete="current-password" required class="w-full" />
      </UFormField>
      <UAlert v-if="error" color="error" variant="subtle" icon="i-lucide-circle-alert" :title="error" role="alert" />
      <UButton type="submit" label="Sign in" block :loading="busy" />
    </form>
    <template v-if="github" #footer>
      <UButton :to="`/auth/github/start?return_to=%2F`" external icon="i-lucide-github" color="neutral" variant="outline" label="Sign in with GitHub" block @click="withGitHub" />
    </template>
  </UCard>
</template>
