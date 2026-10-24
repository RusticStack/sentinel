export function useOverride(slug: () => string) {
  const session = useSession();
  const toast = useToast();
  const needed = computed(() => !!session.me.value?.super_admin && session.roleIn(slug()) !== "admin");
  const reason = useState(`override-reason-${slug()}`, () => "");
  function ready(): boolean {
    if (!needed.value || reason.value.trim()) return true;
    toast.add({ title: "Give a reason for acting as platform administrator first.", color: "warning", icon: "i-lucide-circle-alert" });
    document.getElementById("override-reason")?.focus();
    return false;
  }
  function withReason<T extends object>(body: T): T & { reason?: string } {
    return needed.value ? { ...body, reason: reason.value.trim() } : body;
  }
  return { needed, reason, ready, withReason };
}
