/// A platform administrator who is not an administrator of `slug` reaches
/// it by platform scope alone: a change that grants access (a member's
/// role, repository access, service accounts and their credentials) then
/// needs a step-up and a stated reason, audited as `platform-override`.
/// `needed` says whether this is that case; `reason` is the one the admin
/// pages share for the tenant, and `withReason` adds it to a body when it
/// applies. `ready` is false, says why and moves to the field, while a
/// needed reason is empty.
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
