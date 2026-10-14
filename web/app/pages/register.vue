<script setup lang="ts">
// Sign-up by email. Whether it is open, needs an invitation or waits for an
// administrator is the deployment's policy, which the controller applies and
// the form explains when it refuses.
definePageMeta({ layout: "auth" });
useHead({ title: "Create an account · Sentinel" });
const sent = ref<{ email: string; verification: "email" | "operator" } | null>(null);
const heading = useTemplateRef<HTMLElement>("heading");
function accepted(result: { email: string; verification: "email" | "operator" }) {
  sent.value = result;
  nextTick(() => heading.value?.focus());
}
</script>

<template>
  <UCard class="w-full max-w-md">
    <template #header>
      <div class="flex items-center gap-2">
        <UIcon name="i-lucide-radar" class="size-6 text-primary" />
        <h1 ref="heading" tabindex="-1" class="text-lg font-semibold focus:outline-none">{{ sent ? "Confirm your address" : "Create an account" }}</h1>
      </div>
    </template>
    <CheckEmail v-if="sent" :email="sent.email" :verification="sent.verification" />
    <SignUpForm v-else @accepted="accepted" />
    <template #footer>
      <p class="text-sm text-center">Already have an account? <ULink to="/login" class="font-medium text-primary">Sign in</ULink></p>
    </template>
  </UCard>
</template>
