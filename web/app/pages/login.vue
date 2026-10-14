<script setup lang="ts">
definePageMeta({ layout: "auth" });
useHead({ title: "Sign in · Sentinel" });

const route = useRoute();
const api = useApi();

// GitHub sign-in is offered only when the controller has it configured.
const { data: health } = await useAsyncData("health", () => api<{ github_sign_in?: boolean }>("/api/v1/health"));
const github = computed(() => !!health.value?.github_sign_in);

const next = computed(() => sameOriginPath(route.query.next));
// Why sign-in is asked for again, when the interface sent the person here.
const notice = computed(() => {
  switch (route.query.reason) {
    case "expired": return { title: "Your session ended", description: "Sign in again to continue where you were." };
    case "password-changed": return { title: "Password changed", description: "Every session of your account was signed out. Sign in with the new password." };
    case "verified": return { title: "Address verified", description: "Sign in with your email address and password." };
    default: return null;
  }
});

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
    <SignInForm @signed-in="navigateTo(next)">
      <template #notice="{ error }">
        <UAlert v-if="notice && !error" color="info" variant="subtle" icon="i-lucide-info" :title="notice.title" :description="notice.description" role="status" />
      </template>
    </SignInForm>
    <template #footer>
      <div class="space-y-3">
        <UButton v-if="github" :to="`/auth/github/start?return_to=%2F`" external icon="i-lucide-github" color="neutral" variant="outline" label="Sign in with GitHub" block @click="withGitHub" />
        <p class="text-sm text-center">New here? <ULink to="/register" class="font-medium text-primary">Create an account</ULink></p>
        <p class="text-xs text-center text-muted"><ULink to="/verify-email" class="underline">Didn't get the verification email?</ULink></p>
      </div>
    </template>
  </UCard>
</template>
