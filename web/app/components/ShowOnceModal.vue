<script setup lang="ts">
// A secret the controller hands over once — recovery codes, a service
// grant's refresh token. It is shown in this dialog only (no toast, no
// storage, no URL), can be copied or downloaded, and the dialog closes only
// after the person says it is saved; then the values leave the page.
const props = defineProps<{ title: string; description: string; secrets: string[]; filename: string; note?: string }>();
const emit = defineEmits<{ close: [] }>();
const values = ref<string[]>([...props.secrets]);
const saved = ref(false);
const status = ref("");
const text = () => values.value.join("\n") + "\n";

async function copy() {
  try {
    await navigator.clipboard.writeText(text());
    status.value = values.value.length > 1 ? "Copied all to the clipboard." : "Copied to the clipboard.";
  } catch {
    status.value = "The browser refused the clipboard; select the text or download it instead.";
  }
}

function download() {
  const url = URL.createObjectURL(new Blob([text()], { type: "text/plain" }));
  const a = document.createElement("a");
  a.href = url;
  a.download = props.filename;
  a.click();
  setTimeout(() => URL.revokeObjectURL(url), 0);
  status.value = `Downloaded ${props.filename}.`;
}

function done() {
  if (!saved.value) return;
  values.value = [];
  emit("close");
}
onBeforeUnmount(() => { values.value = []; });
</script>

<template>
  <UModal :title="title" :description="description" :dismissible="false" :close="false">
    <template #body>
      <div class="space-y-4">
        <ul :class="values.length > 1 ? 'grid grid-cols-1 gap-2 sm:grid-cols-2' : ''" :aria-label="title">
          <li v-for="(v, i) in values" :key="i" class="rounded-md border border-default bg-muted px-3 py-2 font-mono text-sm break-all select-all">{{ v }}</li>
        </ul>
        <p v-if="note" class="text-sm text-muted">{{ note }}</p>
        <div class="flex flex-wrap gap-2">
          <UButton color="neutral" variant="outline" icon="i-lucide-copy" label="Copy" @click="copy" />
          <UButton color="neutral" variant="outline" icon="i-lucide-download" label="Download" @click="download" />
        </div>
        <p role="status" aria-live="polite" class="text-sm text-muted min-h-5">{{ status }}</p>
        <UCheckbox v-model="saved" label="I have saved this somewhere safe" description="It is not shown again." />
      </div>
    </template>
    <template #footer>
      <div class="flex justify-end w-full">
        <UButton label="Done" :disabled="!saved" @click="done" />
      </div>
    </template>
  </UModal>
</template>
