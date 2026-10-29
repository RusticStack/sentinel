// Worker enrollment (docs/web-ui.md, "Worker enrollment"). The enrollment secret and the Tailcat address exist only inside
// the shown-once dialog: they are never put in loader data, router state, a URL, storage, a toast or an error sentence,
// and the page keeps nothing but the fields in `Target`.
import { useState, type FormEvent } from "react";
import { api, apiBytes, ApiError } from "../../lib/api.ts";
import { StepUpDeclined, useRetryWait, withStepUp } from "../../lib/act.tsx";
import {
  type Ceilings, type CeilingField, digestCommand, digestVerdict, enrollmentError, fmtUtc, identityCommand, installCommand, parseIdentityLine,
  parseTerms, rollbackCommand, SCRIPT_NAME, secretFileCommand, sha256Hex, uninstallCommand, type Context, type Verdict,
} from "../../lib/enrollment.ts";
import { cpu as fmtCpu, fmtBytes } from "../../lib/format.ts";
import { useLoaded } from "../../lib/hooks.ts";
import { toast } from "../../lib/overlay.tsx";
import { useSession } from "../../lib/session.ts";
import { confirmChange } from "../admin/Confirm.tsx";
import { showOnce } from "../ShowOnceDialog.tsx";
import { Alert, Badge, Button, Field, Input, Select, Table } from "../ui.tsx";

type Transport = "tailcat" | "direct";
interface TransportOptions { available: boolean; address_ready?: boolean; helper_version?: string | null; bootstrap_sha256: string | null }
export interface BootstrapOptions {
  configured: boolean; release_version?: string; redeem?: "https" | "link"; archs?: string[];
  transports?: { direct: TransportOptions; tailcat: TransportOptions };
}
interface PoolRow { id: string; name: string; kind: string; active: boolean }
interface HostPolicy { cpu_millis: number | null; memory_bytes: number | null; disk_bytes: number | null; priority: number }
interface EnrollmentRow { id: string; pool: string; state: "pending" | "redeemed" | "revoked" | "expired"; transport: Transport; created_ms: number; expires_ms: number; host: HostPolicy }
interface HostRow { id: string; pool: string; name: string; arch: string; connected: boolean; transport: Transport; last_seen_ms: number | null; uninstall_requested_ms: number | null; host: { approved: HostPolicy } }
export interface WorkersPage { options: BootstrapOptions; pools: PoolRow[]; enrollments: EnrollmentRow[]; workers: HostRow[] }

const readEnrollments = () => api<{ enrollments: EnrollmentRow[] }>("/api/v1/admin/worker-enrollments?limit=50");
const readWorkers = () => api<{ workers: HostRow[] }>("/api/v1/admin/workers");
export async function loadWorkers(): Promise<WorkersPage | null> {
  try {
    const [options, pools, enrollments, workers] = await Promise.all([
      api<BootstrapOptions>("/api/v1/admin/worker-bootstrap"), api<{ pools: PoolRow[] }>("/api/v1/admin/pools"), readEnrollments(), readWorkers(),
    ]);
    return { options, pools: pools.pools, enrollments: enrollments.enrollments, workers: workers.workers };
  } catch {
    return null;
  }
}

/** The answer to the issue call. Its `secret` and `tailcat_address` go to the dialog and nowhere else. */
interface Issued {
  id: string; pool: string; transport: Transport; expires_ms: number; bootstrap_path: string; bootstrap_sha256: string; redeem: "https" | "link";
  secret: string; tailcat_address: string | null;
}

/** What the next-steps panel knows about one enrollment: nothing secret. */
interface Target { id: string; pool: string; transport: Transport; expires_ms: number; redeem: "https" | "link"; sha256: string | null; path: string }
type ScriptState =
  | { kind: "idle" }
  | { kind: "working" }
  | { kind: "ready"; verdict: Verdict; computed: string | null; stated: string | null; did: "downloaded" | "copied" }
  | { kind: "mismatch"; computed: string; stated: string | null }
  | { kind: "failed"; text: string };

const failure = (e: unknown) => {
  const err = e instanceof ApiError ? e : new ApiError(0, null);
  return { status: err.status, code: err.code, message: err.message, details: err.details };
};
const limit = <T,>(v: T | null | undefined, f: (v: T) => string) => (v === null || v === undefined ? "no limit" : f(v));
const policyText = (h: HostPolicy) => `${limit(h.cpu_millis, fmtCpu)} · ${limit(h.memory_bytes, fmtBytes)} memory · ${limit(h.disk_bytes, fmtBytes)} disk · priority ${h.priority}`;
const STATE_COLOR = { pending: "info", redeemed: "success", revoked: "neutral", expired: "warning" } as const;

function Command({ text, label }: { text: string; label: string }) {
  const [note, setNote] = useState("");
  async function copy() {
    try {
      await navigator.clipboard.writeText(text);
      setNote("Copied.");
    } catch {
      setNote("The browser refused the clipboard; select the command instead.");
    }
  }
  return (
    <div className="space-y-1">
      <div className="flex flex-wrap items-start gap-2">
        <code aria-label={label} className="min-w-0 flex-1 select-all break-all whitespace-pre-wrap rounded-md border border-line bg-subtle px-3 py-2 font-mono text-sm">{text}</code>
        <Button color="neutral" variant="outline" size="sm" icon="copy" label="Copy" aria-label={`Copy: ${label}`} onClick={copy} />
      </div>
      <p role="status" aria-live="polite" className="min-h-4 text-xs text-muted">{note}</p>
    </div>
  );
}

export function Workers({ initial }: { initial: WorkersPage | null }) {
  const { me } = useSession();
  const [data, setData] = useLoaded(initial);
  const refresh = () => Promise.all([readEnrollments(), readWorkers()]).then(([e, w]) => setData(data ? { ...data, enrollments: e.enrollments, workers: w.workers } : data), () => {});

  const options = data?.options;
  const pools = (data?.pools ?? []).filter((p) => p.active);
  const tailcat = options?.transports?.tailcat;
  const poolName = (id: string) => data?.pools.find((p) => p.id === id)?.name ?? id;

  const [pool, setPool] = useState("");
  const [transport, setTransport] = useState<Transport | "">("");
  const [ceilings, setCeilings] = useState<Ceilings>({ cpu: "", memoryGiB: "", diskGiB: "", priority: "0", lifetimeHours: "1" });
  const [invalid, setInvalid] = useState<{ field: CeilingField; message: string } | null>(null);
  const [issuing, setIssuing] = useState(false);
  const [problem, setProblem] = useState("");
  const [cancelled, setCancelled] = useState(false);
  const wait = useRetryWait();
  const chosenPool = pool && pools.some((p) => p.id === pool) ? pool : (pools[0]?.id ?? "");
  const chosenTransport: Transport = transport || (tailcat?.available ? "tailcat" : "direct");

  const [target, setTarget] = useState<Target | null>(null);
  const [script, setScript] = useState<ScriptState>({ kind: "idle" });
  const [name, setName] = useState("build-1");
  const [identity, setIdentity] = useState("");
  const [keyNote, setKeyNote] = useState<{ ok: boolean; text: string } | null>(null);
  const [authorizing, setAuthorizing] = useState(false);
  const [listProblem, setListProblem] = useState("");

  const setCeiling = (field: CeilingField, value: string) => {
    setCeilings((c) => ({ ...c, [field]: value }));
    setInvalid(null);
  };

  async function issue(e: FormEvent) {
    e.preventDefault();
    if (issuing || wait.waiting || !chosenPool) return;
    setProblem("");
    setCancelled(false);
    const terms = parseTerms(ceilings);
    if (!terms.ok) {
      setInvalid({ field: terms.field, message: terms.message });
      return;
    }
    setInvalid(null);
    setIssuing(true);
    let answer: Issued | null = null;
    try {
      const body = { pool: chosenPool, transport: chosenTransport, ...terms.value };
      answer = await withStepUp(() => api<Issued>("/api/v1/admin/worker-enrollments", { method: "POST", body }), me);
      setTarget({
        id: answer.id, pool: answer.pool, transport: answer.transport, expires_ms: answer.expires_ms, redeem: answer.redeem,
        sha256: answer.bootstrap_sha256, path: answer.bootstrap_path,
      });
      setScript({ kind: "idle" });
      setKeyNote(null);
      const address = answer.tailcat_address;
      const secrets = address ? [answer.secret, address] : [answer.secret];
      const labels = address ? ["Enrollment secret (line 1 of the file)", "Controller Tailcat address (line 2 of the file)"] : ["Enrollment secret (the whole file)"];
      // The secret is on this dialog and nowhere else; this page drops its own reference before the dialog is even answered.
      answer = null;
      await showOnce({
        title: "Enrollment secret",
        description: address ? "The worker needs both lines. They are shown once and the controller keeps neither." : "The worker needs this secret. It is shown once and the controller keeps only its digest.",
        secrets, labels, filename: "enrollment",
        note: "Save the file as `enrollment` and put it on the machine as /root/enrollment, root-owned and mode 0600. Nothing on this page can show it again.",
      });
      await refresh();
    } catch (x) {
      if (x instanceof StepUpDeclined) {
        setCancelled(true);
        return;
      }
      const f = failure(x);
      if (f.code === "unauthenticated") return;
      const sentence = enrollmentError(f, "issue");
      if (sentence.retryMs) wait.start(sentence.retryMs);
      setProblem(sentence.text);
    } finally {
      setIssuing(false);
    }
  }

  const say = (context: Context, x: unknown) => {
    const f = failure(x);
    return f.code === "unauthenticated" ? "" : enrollmentError(f, context).text;
  };

  async function withdraw(row: EnrollmentRow) {
    setListProblem("");
    try {
      await withStepUp(() => api(`/api/v1/admin/worker-enrollments/${row.id}`, { method: "DELETE" }), me);
      if (target?.id === row.id) setTarget(null);
      toast({ title: "Enrollment withdrawn: done", color: "success", icon: "check" });
    } catch (x) {
      if (x instanceof StepUpDeclined) return;
      setListProblem(say("withdraw", x));
    }
    await refresh();
  }

  async function uninstall(row: HostRow) {
    setListProblem("");
    const sure = await confirmChange({
      title: `Request the uninstall of ${row.name}?`,
      description: "The controller stops giving it work, lets its accepted attempts settle, then revokes the machine with its identity and Tailcat key. Run the uninstall on the machine afterwards.",
      action: "Request uninstall", keep: "Keep it",
    });
    if (!sure) return;
    try {
      await withStepUp(() => api(`/api/v1/admin/workers/${row.id}/uninstall`, { method: "POST", body: {} }), me);
      toast({ title: `Uninstall of ${row.name} requested`, color: "success", icon: "check" });
    } catch (x) {
      if (x instanceof StepUpDeclined) return;
      setListProblem(say("uninstall", x));
    }
    await refresh();
  }

  function showSteps(row: EnrollmentRow) {
    setTarget({
      id: row.id, pool: row.pool, transport: row.transport, expires_ms: row.expires_ms, redeem: options?.redeem ?? "https",
      sha256: options?.transports?.[row.transport].bootstrap_sha256 ?? null, path: `/api/v1/admin/worker-enrollments/${row.id}/bootstrap.sh`,
    });
    setScript({ kind: "idle" });
    setKeyNote(null);
  }

  // The bytes are checked against the digests the controller states before they are offered; the check proves the copy is
  // intact on its way here, not that the controller itself is genuine (the artifact pins inside the script bind the release).
  async function fetchScript(t: Target, did: "downloaded" | "copied") {
    setScript({ kind: "working" });
    try {
      const [bytes, current] = await Promise.all([apiBytes(t.path), api<BootstrapOptions>("/api/v1/admin/worker-bootstrap").catch(() => null)]);
      const computed = await sha256Hex(bytes);
      const stated = [t.sha256, current?.transports?.[t.transport].bootstrap_sha256];
      const verdict = digestVerdict(computed, stated);
      const shown = stated.find((d): d is string => typeof d === "string" && d !== "") ?? null;
      if (verdict === "mismatch") {
        setScript({ kind: "mismatch", computed: computed ?? "", stated: shown });
        return null;
      }
      setScript({ kind: "ready", verdict, computed, stated: shown, did });
      return bytes;
    } catch (x) {
      setScript({ kind: "failed", text: say("download", x) || "Your session has ended. Sign in again." });
      return null;
    }
  }

  async function download(t: Target) {
    const bytes = await fetchScript(t, "downloaded");
    if (!bytes) return;
    const url = URL.createObjectURL(new Blob([bytes], { type: "text/x-shellscript" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = SCRIPT_NAME;
    a.click();
    setTimeout(() => URL.revokeObjectURL(url), 10_000);
  }

  async function copyScript(t: Target) {
    const bytes = await fetchScript(t, "copied");
    if (!bytes) return;
    try {
      await navigator.clipboard.writeText(new TextDecoder().decode(bytes));
    } catch {
      setScript({ kind: "failed", text: "The browser refused the clipboard. Download the script instead." });
    }
  }

  async function authorize(e: FormEvent) {
    e.preventDefault();
    if (!target || authorizing) return;
    setKeyNote(null);
    const parsed = parseIdentityLine(identity);
    if (!parsed) {
      setKeyNote({ ok: false, text: "Paste the one line the identity command printed: nodekey: followed by 64 hexadecimal characters, a space and the worker id (wrk_…)." });
      return;
    }
    setAuthorizing(true);
    try {
      await withStepUp(() => api(`/api/v1/admin/worker-enrollments/${target.id}/node-key`, { method: "POST", body: parsed }), me);
      setIdentity("");
      setKeyNote({ ok: true, text: "The controller will admit that key to its Tailcat network now. Start the worker on the machine." });
    } catch (x) {
      if (x instanceof StepUpDeclined) {
        setKeyNote({ ok: false, text: "Confirmation cancelled. Nothing was authorized." });
      } else {
        const text = say("node-key", x);
        if (text) setKeyNote({ ok: false, text });
      }
    } finally {
      setAuthorizing(false);
    }
  }

  if (!data || !options) {
    return <Alert color="error" role="alert" title="The worker lists could not be read" description="Reload the page to try again." />;
  }
  if (!options.configured) {
    return (
      <section aria-labelledby="w-add-h" className="space-y-3">
        <h2 id="w-add-h" className="text-base font-semibold text-strong">Add a machine</h2>
        <Alert color="info" title="Worker enrollment is not configured on this controller"
          description="Add a [worker_bootstrap] section to the server configuration and restart the server. The operator checklist is in docs/worker-enrollment.md." />
      </section>
    );
  }

  const transports = [
    { label: "Tailcat (private tunnel)", value: "tailcat", description: tailcat?.available ? `Helper ${tailcat.helper_version ?? "pinned"}` : "Not configured on this controller" },
    { label: "Direct TLS", value: "direct", description: "The machine dials the controller's link address" },
  ].filter((t) => t.value === "direct" || tailcat?.available);
  const needsKey = target?.transport === "tailcat" && target.redeem === "link";
  const fieldError = (f: CeilingField) => (invalid?.field === f ? invalid.message : undefined);
  const shortId = (id: string) => id.replace(/^(tok_[0-9a-f]{8}).*$/, "$1…");

  return (
    <>
      <section aria-labelledby="w-add-h" className="space-y-3">
        <h2 id="w-add-h" className="text-base font-semibold text-strong">Add a machine</h2>
        <p className="max-w-prose text-sm text-muted">
          Issue a single-use enrollment for one machine. The ceilings and priority are what this controller approves for it; the machine can never raise them.
          Release {options.release_version} for {options.archs?.join(" and ")}.
        </p>
        {tailcat?.available && !tailcat.address_ready ? (
          <Alert color="warning" role="status" description="The controller has not written its Tailcat address yet, so a Tailcat enrollment is refused until it is serving. Direct TLS works now." />
        ) : null}
        {pools.length === 0 ? <Alert color="warning" role="status" description="There is no active pool to enrol a machine into. Create one under Pools first." /> : null}
        <form className="flex flex-wrap items-start gap-3" aria-label="Issue a worker enrollment" onSubmit={issue} noValidate>
          <Select id="w-pool" label="Pool" ariaLabel="Pool" value={chosenPool} onChange={setPool} className="w-48" isDisabled={pools.length === 0}
            items={pools.map((p) => ({ value: p.id, label: p.name, description: p.kind }))} />
          <Select id="w-transport" label="Transport" ariaLabel="Transport" value={chosenTransport} onChange={(v) => setTransport(v === "direct" ? "direct" : "tailcat")} className="w-56" items={transports} />
          <Field label="CPU ceiling" htmlFor="w-cpu" hint="cores" error={fieldError("cpu")}>
            <Input id="w-cpu" name="w-cpu" inputMode="decimal" autoComplete="off" placeholder="no limit" value={ceilings.cpu} onChange={(e) => setCeiling("cpu", e.target.value)} aria-invalid={invalid?.field === "cpu" || undefined} className="w-28 max-w-full" />
          </Field>
          <Field label="Memory ceiling" htmlFor="w-mem" hint="GiB" error={fieldError("memoryGiB")}>
            <Input id="w-mem" name="w-mem" inputMode="numeric" autoComplete="off" placeholder="no limit" value={ceilings.memoryGiB} onChange={(e) => setCeiling("memoryGiB", e.target.value)} aria-invalid={invalid?.field === "memoryGiB" || undefined} className="w-28 max-w-full" />
          </Field>
          <Field label="Disk ceiling" htmlFor="w-disk" hint="GiB" error={fieldError("diskGiB")}>
            <Input id="w-disk" name="w-disk" inputMode="numeric" autoComplete="off" placeholder="no limit" value={ceilings.diskGiB} onChange={(e) => setCeiling("diskGiB", e.target.value)} aria-invalid={invalid?.field === "diskGiB" || undefined} className="w-28 max-w-full" />
          </Field>
          <Field label="Priority" htmlFor="w-priority" hint="-100 to 100" error={fieldError("priority")}>
            <Input id="w-priority" name="w-priority" inputMode="numeric" autoComplete="off" value={ceilings.priority} onChange={(e) => setCeiling("priority", e.target.value)} aria-invalid={invalid?.field === "priority" || undefined} className="w-28 max-w-full" />
          </Field>
          <Field label="Open for" htmlFor="w-hours" hint="hours, 1 to 24" error={fieldError("lifetimeHours")}>
            <Input id="w-hours" name="w-hours" inputMode="numeric" autoComplete="off" value={ceilings.lifetimeHours} onChange={(e) => setCeiling("lifetimeHours", e.target.value)} aria-invalid={invalid?.field === "lifetimeHours" || undefined} className="w-28 max-w-full" />
          </Field>
          <div className="self-end">
            <Button type="submit" icon="plus" loading={issuing} disabled={!chosenPool || wait.waiting > 0}
              label={wait.waiting > 0 ? `Try again in ${wait.waiting} s` : "Issue enrollment"} />
          </div>
        </form>
        {problem ? <Alert color="error" role="alert" description={<span id="w-error">{problem}</span>} /> : null}
        {cancelled ? <p role="status" className="text-sm text-muted">Confirmation cancelled. Nothing was issued.</p> : null}
      </section>

      {target ? (
        <section aria-labelledby="w-next-h" className="space-y-3 rounded-lg border border-line p-4">
          <h2 id="w-next-h" className="text-base font-semibold text-strong">Next steps for enrollment {shortId(target.id)}</h2>
          <p className="text-sm text-muted">
            Pool {poolName(target.pool)}, {target.transport === "tailcat" ? "Tailcat" : "direct TLS"}, open until {fmtUtc(target.expires_ms)}.
            The script holds no secret: it carries the controller's public fingerprint and the digests of the release it installs.
          </p>
          <ol className="list-decimal space-y-4 pl-5 text-sm">
            <li className="space-y-2">
              <p className="font-medium text-strong">Get the script</p>
              <div className="flex flex-wrap gap-2">
                <Button color="neutral" variant="outline" icon="download" label="Download script" loading={script.kind === "working"} onClick={() => void download(target)} />
                <Button color="neutral" variant="outline" icon="copy" label="Copy script" disabled={script.kind === "working"} onClick={() => void copyScript(target)} />
              </div>
              <div role="status" aria-live="polite" id="w-script-status" className="min-h-5 space-y-1 text-sm">
                {script.kind === "ready" ? (
                  script.verdict === "verified" ? (
                    <p>The script's SHA-256 matches the controller digest, so the copy is intact: <code className="break-all font-mono text-xs">{script.computed}</code></p>
                  ) : (
                    <p>This browser could not compute a SHA-256 (it needs HTTPS or localhost), so nothing was compared. Before running it, check on the machine that <code className="font-mono text-xs">{digestCommand()}</code> prints <code className="break-all font-mono text-xs">{script.stated}</code></p>
                  )
                ) : null}
                {script.kind === "mismatch" ? (
                  <p role="alert" className="text-error">The script does not match the digest the controller stated for it (got <code className="break-all font-mono text-xs">{script.computed}</code>, expected <code className="break-all font-mono text-xs">{script.stated ?? "none"}</code>). Do not run it. Reload the page and try again; if it persists, something between this browser and the controller changes the script.</p>
                ) : null}
                {script.kind === "failed" ? <p role="alert" className="text-error">{script.text}</p> : null}
              </div>
              <p className="max-w-prose text-xs text-muted">
                The digest is the controller's own: it shows the copy arrived whole, not that the controller is genuine. The release pins inside the script bind the software it installs.
              </p>
            </li>
            <li className="space-y-2">
              <p className="font-medium text-strong">Put the secret file on the machine</p>
              <p className="text-muted">The file saved from the one-time dialog is the whole input. It exists nowhere else, so if it is lost, withdraw this enrollment and issue another.</p>
              <Command label="Install the secret file" text={secretFileCommand()} />
            </li>
            <li className="space-y-2">
              <p className="font-medium text-strong">Install and start the worker</p>
              <Field label="Worker name" htmlFor="w-name" hint="as it will appear here">
                <Input id="w-name" name="w-name" autoComplete="off" value={name} onChange={(e) => setName(e.target.value)} maxLength={63} className="w-48 max-w-full" />
              </Field>
              <Command label="Install the worker" text={installCommand(name)} />
              <p className="text-xs text-muted">{target.redeem === "https" ? "The worker redeems the enrollment over HTTPS, so there is nothing more to do here." : "This controller has no api_url: the worker presents its secret with its first link hello."}</p>
            </li>
            {needsKey ? (
              <li className="space-y-2">
                <p className="font-medium text-strong">Admit the machine's Tailcat key</p>
                <p className="text-muted">This controller cannot be reached before the tunnel exists, so the machine's key is admitted from here. On the machine run the command below and paste its one line.</p>
                <Command label="Print the machine's identity" text={identityCommand()} />
                <form className="flex flex-wrap items-end gap-2" aria-label="Authorize a node key" onSubmit={authorize} noValidate>
                  <Field label="Identity line" htmlFor="w-identity" className="min-w-0 flex-1 basis-80">
                    <Input id="w-identity" name="w-identity" autoComplete="off" spellCheck={false} value={identity} onChange={(e) => { setIdentity(e.target.value); setKeyNote(null); }} placeholder="nodekey:… wrk_…" className="font-mono" />
                  </Field>
                  <Button type="submit" label="Authorize key" loading={authorizing} />
                </form>
                {keyNote ? <p role={keyNote.ok ? "status" : "alert"} className={keyNote.ok ? "text-sm" : "text-sm text-error"}>{keyNote.text}</p> : null}
              </li>
            ) : null}
          </ol>
        </section>
      ) : null}

      <section aria-labelledby="w-enr-h" className="space-y-3">
        <h2 id="w-enr-h" className="text-base font-semibold text-strong">Enrollments</h2>
        {listProblem ? <Alert color="error" role="alert" description={<span id="w-list-error">{listProblem}</span>} /> : null}
        <Table caption="Worker enrollments">
          <thead><tr><th>Enrollment</th><th>Pool</th><th>Transport</th><th>State</th><th>Approved</th><th>Open until</th><th><span className="sr">Actions</span></th></tr></thead>
          <tbody>
            {data.enrollments.length ? data.enrollments.map((r) => (
              <tr key={r.id}>
                <td className="font-mono text-xs">{shortId(r.id)}</td>
                <td>{poolName(r.pool)}</td>
                <td>{r.transport === "tailcat" ? "Tailcat" : "Direct TLS"}</td>
                <td><Badge color={STATE_COLOR[r.state]}>{r.state}</Badge></td>
                <td className="text-muted">{policyText(r.host)}</td>
                <td className="whitespace-nowrap">{fmtUtc(r.expires_ms)}</td>
                <td>
                  {r.state === "pending" ? (
                    <div className="flex flex-wrap gap-2">
                      <Button size="sm" color="neutral" variant="outline" label="Install steps" aria-label={`Install steps for ${shortId(r.id)}`} onClick={() => showSteps(r)} />
                      <Button size="sm" color="error" variant="outline" label="Withdraw" aria-label={`Withdraw ${shortId(r.id)}`} onClick={() => void withdraw(r)} />
                    </div>
                  ) : null}
                </td>
              </tr>
            )) : <tr><td colSpan={7} className="text-center text-muted">No enrollments</td></tr>}
          </tbody>
        </Table>
      </section>

      <section aria-labelledby="w-workers-h" className="space-y-3">
        <h2 id="w-workers-h" className="text-base font-semibold text-strong">Workers</h2>
        <Table caption="Enrolled workers">
          <thead><tr><th>Worker</th><th>Pool</th><th>Transport</th><th>Status</th><th>Approved</th><th><span className="sr">Actions</span></th></tr></thead>
          <tbody>
            {data.workers.length ? data.workers.map((w) => (
              <tr key={w.id}>
                <td><span className="font-medium text-strong">{w.name}</span> <span className="text-muted">{w.arch}</span></td>
                <td>{poolName(w.pool)}</td>
                <td>{w.transport === "tailcat" ? "Tailcat" : "Direct TLS"}</td>
                <td>{w.uninstall_requested_ms ? <Badge color="warning">uninstalling</Badge> : w.connected ? <Badge color="success">connected</Badge> : <Badge>offline</Badge>}</td>
                <td className="text-muted">{policyText(w.host.approved)}</td>
                <td>
                  {w.uninstall_requested_ms ? null : (
                    <Button size="sm" color="error" variant="outline" label="Request uninstall" aria-label={`Request the uninstall of ${w.name}`} onClick={() => void uninstall(w)} />
                  )}
                </td>
              </tr>
            )) : <tr><td colSpan={6} className="text-center text-muted">No workers</td></tr>}
          </tbody>
        </Table>
      </section>

      <section aria-labelledby="w-remove-h" className="space-y-3">
        <h2 id="w-remove-h" className="text-base font-semibold text-strong">Roll back or remove a machine</h2>
        <ul className="list-disc space-y-3 pl-5 text-sm">
          <li className="space-y-2">
            <p><span className="font-medium text-strong">Roll back an upgrade.</span> Run it again with a newer script to upgrade. If the new release misbehaves, on the machine:</p>
            <Command label="Roll back the worker" text={rollbackCommand()} />
          </li>
          <li className="space-y-2">
            <p><span className="font-medium text-strong">Remove a machine.</span> First use Request uninstall above, so accepted work finishes and the controller revokes the machine with its key. Then, on the machine, remove the service, its files and the account the script created (add <code className="font-mono text-xs">--keep-data</code> to keep the data directory):</p>
            <Command label="Uninstall the worker" text={uninstallCommand()} />
          </li>
          <li>A failed first install removes whatever it created and leaves the enrollment unspent, so run it again. If the failure came after the controller accepted the enrollment, the message names the worker: request its uninstall here and issue a new enrollment.</li>
        </ul>
      </section>
    </>
  );
}
