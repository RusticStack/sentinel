// Pure helpers for the worker enrollment page (docs/web-ui.md, "Worker enrollment"). Nothing here touches the network or
// keeps a secret: the page hands the issued secret to the shown-once dialog and keeps only the fields below.

export interface Ceilings { cpu: string; memoryGiB: string; diskGiB: string; priority: string; lifetimeHours: string }
export type CeilingField = keyof Ceilings;
export type Parsed<T> = { ok: true; value: T } | { ok: false; field: CeilingField; message: string };

/** The body of POST /api/v1/admin/worker-enrollments (the pool and transport are added by the page). */
export interface Terms { cpu_millis?: number; memory_bytes?: number; disk_bytes?: number; priority: number; lifetime_ms: number }

const GIB = 2 ** 30;
const HOUR_MS = 3_600_000;
/** The largest whole number of GiB whose byte count is still an exactly representable integer. */
export const MAX_GIB = Math.floor(Number.MAX_SAFE_INTEGER / GIB);
export const MAX_CORES = 100_000;
export const PRIORITY_MIN = -100;
export const PRIORITY_MAX = 100;
export const MAX_LIFETIME_HOURS = 24;

const WHOLE = /^[0-9]+$/;
const CORES = /^([0-9]+)(?:\.([0-9]{1,3}))?$/;
const SIGNED = /^-?[0-9]+$/;

const bad = (field: CeilingField, message: string): Parsed<never> => ({ ok: false, field, message });

/** Blank means "no ceiling": the host's own report is then the only limit. */
function wholeGiB(field: CeilingField, label: string, text: string): Parsed<number | undefined> {
  const t = text.trim();
  if (t === "") return { ok: true, value: undefined };
  if (!WHOLE.test(t)) return bad(field, `${label} must be a whole number of GiB, such as 16, or empty for no ceiling.`);
  const n = Number(t);
  if (n < 1 || n > MAX_GIB) return bad(field, `${label} must be between 1 and ${MAX_GIB} GiB, or empty for no ceiling.`);
  return { ok: true, value: n * GIB };
}

export function parseTerms(c: Ceilings): Parsed<Terms> {
  const terms: Terms = { priority: 0, lifetime_ms: HOUR_MS };

  const cpu = c.cpu.trim();
  if (cpu !== "") {
    const m = CORES.exec(cpu);
    if (!m) return bad("cpu", "CPU must be a number of cores, such as 4 or 0.5 (at most three decimals), or empty for no ceiling.");
    const millis = Number(m[1]) * 1000 + Number((m[2] ?? "").padEnd(3, "0"));
    if (millis < 1 || millis > MAX_CORES * 1000) return bad("cpu", `CPU must be more than zero and at most ${MAX_CORES} cores, or empty for no ceiling.`);
    terms.cpu_millis = millis;
  }

  const memory = wholeGiB("memoryGiB", "Memory", c.memoryGiB);
  if (!memory.ok) return memory;
  if (memory.value !== undefined) terms.memory_bytes = memory.value;
  const disk = wholeGiB("diskGiB", "Disk", c.diskGiB);
  if (!disk.ok) return disk;
  if (disk.value !== undefined) terms.disk_bytes = disk.value;

  const priority = c.priority.trim();
  if (priority !== "") {
    const n = Number(priority);
    if (!SIGNED.test(priority) || n < PRIORITY_MIN || n > PRIORITY_MAX) return bad("priority", `Priority must be a whole number from ${PRIORITY_MIN} to ${PRIORITY_MAX}; 0 is neutral.`);
    terms.priority = n === 0 ? 0 : n;
  }

  const hours = c.lifetimeHours.trim();
  if (hours !== "") {
    const n = Number(hours);
    if (!WHOLE.test(hours) || n < 1 || n > MAX_LIFETIME_HOURS) return bad("lifetimeHours", `The enrollment must stay open for a whole number of hours from 1 to ${MAX_LIFETIME_HOURS}.`);
    terms.lifetime_ms = n * HOUR_MS;
  }
  return { ok: true, value: terms };
}

const NODE_KEY = /^nodekey:[0-9a-f]{64}$/;
const WORKER = /^wrk_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** `sh bootstrap identity` prints `nodekey:<64 hex> wrk_<id>` on one line; anything else is refused. */
export function parseIdentityLine(text: string): { worker: string; node_key: string } | null {
  const t = text.trim();
  if (t.length === 0 || t.length > 200) return null;
  const parts = t.split(/\s+/);
  if (parts.length !== 2) return null;
  const [key, worker] = parts as [string, string];
  return NODE_KEY.test(key) && WORKER.test(worker) ? { worker, node_key: key } : null;
}

/** SHA-256 of the bytes as 64 lower-case hex characters, or null where the browser has no Web Crypto (an insecure context). */
export async function sha256Hex(bytes: ArrayBuffer): Promise<string | null> {
  const subtle = globalThis.crypto?.subtle;
  if (!subtle) return null;
  const digest = new Uint8Array(await subtle.digest("SHA-256", bytes));
  let out = "";
  for (const b of digest) out += b.toString(16).padStart(2, "0");
  return out;
}

export const SCRIPT_NAME = "sentinel-worker-bootstrap.sh";
const NAME = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;
/** The name the worker reports; anything the script would refuse falls back to the example. */
export const workerName = (text: string) => (NAME.test(text.trim()) ? text.trim() : "build-1");

/** Commands that carry no secret: the secret stays in the file the administrator saved from the one-time dialog. */
export const installCommand = (name: string) => `sudo sh ${SCRIPT_NAME} install --name ${workerName(name)} --secret-file /root/enrollment`;
export const secretFileCommand = () => "sudo install -m 600 -o root -g root enrollment /root/enrollment";
export const identityCommand = () => `sudo sh ${SCRIPT_NAME} identity`;
export const rollbackCommand = () => `sudo sh ${SCRIPT_NAME} rollback`;
export const uninstallCommand = () => `sudo sh ${SCRIPT_NAME} uninstall`;
export const digestCommand = () => `sha256sum ${SCRIPT_NAME}`;

export type Verdict = "verified" | "mismatch" | "unverified";
/** Compares the digest the page computed with the ones the controller stated; a missing computation is never a pass. */
export function digestVerdict(computed: string | null, stated: readonly (string | null | undefined)[]): Verdict {
  if (computed === null) return "unverified";
  const known = stated.filter((d): d is string => typeof d === "string" && d !== "");
  return known.length > 0 && known.every((d) => d === computed) ? "verified" : "mismatch";
}

/** What a failed call told us, as the page needs it. `details` is the controller's, never the person's input. */
export interface Failure { status: number; code: string; message: string; details?: Record<string, any> }
export type Context = "issue" | "withdraw" | "node-key" | "download" | "uninstall" | "load";

const SECRETISH = /sntl_[0-9a-fA-F]{64}|nodekey:[0-9a-fA-F]{64}|[0-9a-fA-F]{64}/g;
/** A controller message with anything secret-shaped removed, so no sentence the page shows can repeat one. */
export const scrub = (text: string) => text.replace(SECRETISH, "…").slice(0, 300);

const seconds = (details: Failure["details"]) => {
  const s = Math.max(1, Math.ceil(Number(details?.retry_after_ms ?? 1000) / 1000));
  return s === 1 ? "a second" : `${s} seconds`;
};

export interface Sentence { text: string; retryMs?: number }

/** The 409, 404 and 429 states in plain words, per action. Fixed text plus the controller's own scrubbed reason. */
export function enrollmentError(f: Failure, context: Context): Sentence {
  switch (f.code) {
    case "rate_limited": {
      const retryMs = Math.max(1000, Number(f.details?.retry_after_ms ?? 1000)) || 1000;
      return { text: `Too many requests in a short time. Try again in ${seconds(f.details)}.`, retryMs };
    }
    case "network":
      return { text: context === "issue"
        ? "The answer did not arrive. If an enrollment was issued its secret is lost for good: withdraw any pending enrollment below that you did not receive, then issue a new one."
        : "The controller could not be reached. Nothing was changed that this page can confirm; reload and check the lists below." };
    case "forbidden":
      return { text: f.details?.step_up ? "A recent second factor is needed, and it was not confirmed." : "You are not permitted to do that." };
    case "not_found":
      switch (context) {
        case "issue": return { text: "That pool does not exist or is no longer active. Reload the page and choose another pool." };
        case "withdraw": return { text: "That enrollment is already used, withdrawn or gone, so there is nothing to withdraw." };
        case "node-key": return { text: "That enrollment does not exist any more. Issue a new one." };
        case "download": return { text: "That enrollment does not exist any more, so there is no script for it. Issue a new one." };
        case "uninstall": return { text: "That worker is not enrolled any more." };
        default: return { text: "Not found, or you no longer have access to it." };
      }
    case "conflict":
      switch (context) {
        case "issue": return { text: `The controller cannot issue this enrollment now: ${scrub(f.message)}` };
        case "withdraw": return { text: "That enrollment is already used, withdrawn or expired." };
        case "node-key": return { text: "This enrollment is no longer pending, already names a different worker or key, or that worker or key is already enrolled. Issue a new enrollment if the machine must start again." };
        case "download": return { text: "This enrollment is no longer pending (it was redeemed, withdrawn or has expired), so the controller serves no script for it." };
        default: return { text: `Not allowed now: ${scrub(f.message)}` };
      }
    case "invalid_request":
      return { text: context === "node-key"
        ? "The controller refused that line. A direct enrollment takes no node key; a Tailcat one needs the exact line the identity command printed."
        : `The controller refused the values: ${scrub(f.message)}` };
    case "unauthenticated":
      return { text: "Your session has ended. Sign in again." };
    default:
      return { text: `The controller refused the request (${f.status || "no answer"}).` };
  }
}

export const fmtUtc = (ms: number) => `${new Date(ms).toISOString().slice(0, 16).replace("T", " ")} UTC`;
