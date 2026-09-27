<script setup lang="ts">
// Confirm it's you (A06): a TOTP code, a recovery code, or the password for
// an account without TOTP; the session is stamped for the policy window.
const props = defineProps<{ mfa: boolean }>();
const emit = defineEmits<{ close: [boolean] }>();
const api = useApi();
const methods = computed(() => props.mfa
  ? [{ label: "Authenticator code", value: "totp" }, { label: "Recovery code", value: "recovery" }]
  : [{ label: "Password", value: "password" }]);
const method = ref(props.mfa ? "totp" : "password");
const code = ref("");
const error = ref("");
const busy = ref(false);

async function submit() {
  busy.value = true;
  error.value = "";
  try {
    await api("/api/v1/step-up", { method: "POST", body: { method: method.value, code: code.value } });
    emit("close", true);
  } catch (e) {
    error.value = e instanceof ApiError && e.code === "forbidden" ? "That was not accepted." : (e as Error).message;
    code.value = "";
  } finally {
    busy.value = false;
  }
}
</script>

<template>
  <UModal title="Confirm it's you" description="This change needs a recent second factor." @update:open="(open) => !open && emit('close', false)">
    <template #body>
      <form id="step-up" class="space-y-4" @submit.prevent="submit">
        <UFormField label="Method" name="method">
          <USelect v-model="method" :items="methods" class="w-full" />
        </UFormField>
        <UFormField label="Code" name="code" :error="error || undefined">
          <UInput id="stepup-code" v-model="code" type="password" autocomplete="one-time-code" required autofocus class="w-full" />
        </UFormField>
      </form>
    </template>
    <template #footer>
      <div class="flex gap-2 justify-end w-full">
        <UButton color="neutral" variant="ghost" label="Cancel" @click="emit('close', false)" />
        <UButton type="submit" form="step-up" label="Confirm" :loading="busy" />
      </div>
    </template>
  </UModal>
</template>
