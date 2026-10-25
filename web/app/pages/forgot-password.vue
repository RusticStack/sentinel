<script setup lang="ts">
// No email reset: a reset link would make the mailbox a second password for every account, including administrators'.
definePageMeta({ layout: "auth" });
useHead({ title: "Forgot your password · Sentinel" });
</script>

<template>
  <UCard class="w-full max-w-md">
    <template #header>
      <div class="flex items-center gap-2">
        <UIcon name="i-lucide-radar" class="size-6 text-primary" />
        <h1 class="text-lg font-semibold">Forgot your password?</h1>
      </div>
    </template>
    <div class="space-y-3 text-sm">
      <p>This instance does not reset passwords by email. Ask your Sentinel administrator: they can set a new password for your account on the server, which also signs out every session of it.</p>
      <details class="rounded-md border border-default p-3">
        <summary class="cursor-pointer font-medium">For the administrator</summary>
        <p class="mt-2">On the controller host, as the service user:</p>
        <p class="mt-2">Give the administrator your registered email address. For an email-registered account, the username is generated; find it by email in the metadata database before running recovery.</p>
        <pre class="mt-2 overflow-x-auto rounded bg-muted p-2 text-xs"><code>sqlite3 &lt;PATH&gt;/metadata.sqlite "SELECT username FROM local_credentials JOIN users ON users.id = local_credentials.user_id WHERE users.email = '&lt;EMAIL&gt;'"
sentinel admin recover --data-dir &lt;PATH&gt; --username &lt;USERNAME&gt;</code></pre>
        <p class="mt-2 text-muted">It resets the password, clears sign-in and second-factor lockouts and revokes the account's sessions.</p>
      </details>
      <p class="text-muted">Never got the email that confirms your address? <ULink to="/verify-email" class="underline">Ask for a new link</ULink>.</p>
    </div>
    <template #footer>
      <p class="text-sm text-center"><ULink to="/login" class="font-medium text-primary">Back to sign-in</ULink></p>
    </template>
  </UCard>
</template>
