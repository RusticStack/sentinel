import ShowOnceModal from "~/components/ShowOnceModal.vue";

// Destroyed on close so the secret values do not outlive the dialog.
export function useShowOnce() {
  const overlay = useOverlay();
  return (props: { title: string; description: string; secrets: string[]; filename: string; note?: string }) =>
    overlay.create(ShowOnceModal, { destroyOnClose: true }).open(props);
}
