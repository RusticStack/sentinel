/// Whether first-run setup is open (`GET /setup`). Closed is permanent, so
/// once seen it is remembered for the page's life and never asked again. A
/// controller that cannot be reached counts as closed: sign-in then shows its
/// own error instead of a wizard that could not finish.
export function useSetupStatus() {
  const closed = useState<boolean>("setup-closed", () => false);
  const api = useApi();
  async function isOpen(): Promise<boolean> {
    if (closed.value) return false;
    try {
      const open = (await api<{ open: boolean }>("/api/v1/setup")).open === true;
      if (!open) closed.value = true;
      return open;
    } catch {
      return false;
    }
  }
  /** Setup just completed in this page. */
  const markClosed = () => { closed.value = true; };
  return { isOpen, markClosed };
}
