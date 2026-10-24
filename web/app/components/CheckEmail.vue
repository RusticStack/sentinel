<script setup lang="ts">
// Worded so it never reveals whether the address already has an account.
defineProps<{ email?: string; verification: "email" | "operator"; joining?: boolean }>();
</script>

<template>
  <div class="space-y-3 text-sm" role="status">
    <template v-if="verification === 'email'">
      <p class="flex items-center gap-2 font-medium text-highlighted"><UIcon name="i-lucide-mail-check" class="size-5 text-success" />Check your email</p>
      <p>
        If <template v-if="email"><strong class="break-all">{{ email }}</strong></template><template v-else>that address</template> can be used here, a message with a confirmation link is on its way.
        The link works once, for 24 hours<template v-if="joining">, and finishes joining the organization when you open it</template>.
      </p>
      <p class="text-muted">Nothing after a few minutes? Look in spam, then <ULink to="/verify-email" class="underline">ask for a new link</ULink>.</p>
    </template>
    <template v-else>
      <p class="flex items-center gap-2 font-medium text-highlighted"><UIcon name="i-lucide-user-cog" class="size-5 text-info" />Ask your administrator for the link</p>
      <p>
        This instance does not send email. If the address can be used here, the administrator can create its confirmation link on the server
        (<code>sentinel admin account email-link</code>) and give it to you<template v-if="joining">; opening it also finishes joining the organization</template>.
      </p>
    </template>
    <p>Once the address is confirmed, <ULink to="/login" class="font-medium text-primary">sign in</ULink> with it and your password. If this instance reviews new accounts, an administrator approves yours first.</p>
  </div>
</template>
