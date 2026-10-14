import ShowOnceModal from "~/components/ShowOnceModal.vue";

/// Show a secret the controller hands over once (`ShowOnceModal`); resolves
/// when the person has said it is saved. A fresh overlay each time, destroyed
/// on close, so the values do not outlive the dialog.
export function useShowOnce() {
  const overlay = useOverlay();
  return (props: { title: string; description: string; secrets: string[]; filename: string; note?: string }) =>
    overlay.create(ShowOnceModal, { destroyOnClose: true }).open(props);
}
