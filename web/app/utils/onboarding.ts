const HEX64 = /^[0-9a-fA-F]{64}$/;
const INVITATION = /^sntl_[0-9a-fA-F]{64}$/;

export const isSetupToken = (text: string) => HEX64.test(text.trim());
export const isVerificationToken = (text: string) => HEX64.test(text);
export const isInvitationToken = (text: string) => INVITATION.test(text);

// The token sits in the fragment, so no server log or Referer ever records it.
export function fragmentToken(hash: string, kind: "verification" | "invitation"): string | null {
  if (!hash.startsWith("#") || hash.length > 512) return null;
  const params = new URLSearchParams(hash.slice(1));
  const all = params.getAll("token");
  if (all.length !== 1) return null;
  const token = all[0]!.trim();
  return (kind === "invitation" ? isInvitationToken(token) : isVerificationToken(token)) ? token : null;
}

export const INVITATION_STASH = "sentinel-invitation";
export const INVITATION_STASH_MS = 10 * 60 * 1000;
export const stashInvitation = (token: string, now: number) => JSON.stringify({ token, until: now + INVITATION_STASH_MS });

export function unstashInvitation(raw: string | null, now: number): string | null {
  if (!raw || raw.length > 512) return null;
  try {
    const { token, until } = JSON.parse(raw);
    return typeof token === "string" && isInvitationToken(token) && Number(until) > now && Number(until) <= now + INVITATION_STASH_MS ? token : null;
  } catch {
    return null;
  }
}

export const byteLength = (s: string) => new TextEncoder().encode(s).length;

export const PASSWORD_MIN_BYTES = 12;
export const PASSWORD_MAX_BYTES = 256;

export interface PasswordAdvice {
  acceptable: boolean;
  // Guidance only: the controller's bounds, not the score, decide acceptance.
  score: 0 | 1 | 2 | 3 | 4;
  label: string;
  hints: string[];
}

const COMMON = ["password", "sentinel", "qwerty", "letmein", "welcome", "admin", "123456", "iloveyou", "monkey", "dragon"];

export function passwordAdvice(password: string, context: string[] = []): PasswordAdvice {
  const bytes = byteLength(password);
  const hints: string[] = [];
  if (bytes < PASSWORD_MIN_BYTES) hints.push(`Use at least ${PASSWORD_MIN_BYTES} characters; a few unrelated words make a long password easy to remember.`);
  if (bytes > PASSWORD_MAX_BYTES) hints.push(`Use at most ${PASSWORD_MAX_BYTES} bytes.`);
  const blank = password.trim() === "";
  if (password && blank) hints.push("A password cannot be only spaces.");
  const acceptable = bytes >= PASSWORD_MIN_BYTES && bytes <= PASSWORD_MAX_BYTES && !blank;
  if (!acceptable) return { acceptable, score: 0, label: password ? "Too short" : "", hints };

  const lower = password.toLowerCase();
  let penalty = 0;
  if (COMMON.some((w) => lower.includes(w))) {
    penalty++;
    hints.push("Avoid common words such as “password” or the product's name.");
  }
  const words = context.flatMap((c) => c.toLowerCase().split(/[^a-z0-9]+/)).filter((w) => w.length >= 4);
  if (words.some((w) => lower.includes(w))) {
    penalty++;
    hints.push("Avoid your address, name or the instance's name.");
  }
  if (/^(.)\1+$/.test(password) || new Set(password).size < 5) {
    penalty += 2;
    hints.push("Repeat fewer characters.");
  }
  const classes = [/[a-z]/, /[A-Z]/, /[0-9]/, /[^A-Za-z0-9]/].filter((re) => re.test(password)).length;
  let score = (bytes >= 20 ? 3 : bytes >= 16 ? 2 : 1) + (classes >= 3 ? 1 : 0) - penalty;
  score = Math.max(1, Math.min(4, score));
  if (score < 3 && bytes < 20) hints.push("Longer is stronger: 20 characters or more is a good aim.");
  const label = ["Too short", "Weak", "Fair", "Good", "Strong"][score]!;
  return { acceptable, score: score as PasswordAdvice["score"], label, hints };
}

export function slugProblem(slug: string): string | null {
  if (slug.length < 2 || slug.length > 63) return "Use 2 to 63 characters.";
  if (!/^[a-z0-9-]+$/.test(slug)) return "Use lowercase letters, digits and hyphens only.";
  if (slug.startsWith("-") || slug.endsWith("-")) return "A name cannot start or end with a hyphen.";
  return null;
}

export const looksLikeEmail = (s: string) => /^[^\s@]{1,64}@[^\s@]+\.[^\s@]+$/.test(s.trim()) && s.trim().length <= 254;

export function baseUrlProblem(text: string): string | null {
  const value = text.trim();
  if (!value) return null;
  let url: URL;
  try { url = new URL(value); } catch { return "Enter a full address, such as https://ci.example.com."; }
  if (url.protocol !== "https:" && url.protocol !== "http:") return "Use an https:// (or http://) address.";
  if (url.username || url.password) return "An address cannot carry a user name or password.";
  if (url.search || url.hash) return "Leave out any ? or # part.";
  return null;
}

export type RegistrationChoice = "closed" | "invite-only" | "approval-required";
export type TenantCreationChoice = "super-admin-only" | "approved-users";

export interface WizardDraft {
  step: number;
  email: string;
  displayName: string;
  registration: RegistrationChoice;
  tenantCreation: TenantCreationChoice;
  instanceName: string;
  baseUrl: string;
  personalNamespace: string;
  organization: string;
}

export const DRAFT_KEY = "sentinel-setup-draft";

export function emptyDraft(): WizardDraft {
  return {
    step: 0,
    email: "",
    displayName: "",
    registration: "invite-only",
    tenantCreation: "super-admin-only",
    instanceName: "Sentinel",
    baseUrl: "",
    personalNamespace: "",
    organization: "",
  };
}

const REGISTRATIONS: readonly string[] = ["closed", "invite-only", "approval-required"];
const CREATIONS: readonly string[] = ["super-admin-only", "approved-users"];
const str = (v: unknown, max: number) => (typeof v === "string" ? v.slice(0, max) : "");

export function serializeDraft(draft: WizardDraft): string {
  const keep: WizardDraft = {
    step: draft.step,
    email: draft.email,
    displayName: draft.displayName,
    registration: draft.registration,
    tenantCreation: draft.tenantCreation,
    instanceName: draft.instanceName,
    baseUrl: draft.baseUrl,
    personalNamespace: draft.personalNamespace,
    organization: draft.organization,
  };
  return JSON.stringify(keep);
}

export function parseDraft(text: string | null, maxStep: number): WizardDraft {
  const out = emptyDraft();
  if (!text || text.length > 8192) return out;
  let raw: any;
  try { raw = JSON.parse(text); } catch { return out; }
  if (!raw || typeof raw !== "object") return out;
  if (Number.isInteger(raw.step) && raw.step >= 0 && raw.step <= maxStep) out.step = raw.step;
  out.email = str(raw.email, 254);
  out.displayName = str(raw.displayName, 128);
  if (REGISTRATIONS.includes(raw.registration)) out.registration = raw.registration;
  if (CREATIONS.includes(raw.tenantCreation)) out.tenantCreation = raw.tenantCreation;
  out.instanceName = str(raw.instanceName, 128) || out.instanceName;
  out.baseUrl = str(raw.baseUrl, 2048);
  out.personalNamespace = str(raw.personalNamespace, 63);
  out.organization = str(raw.organization, 63);
  return out;
}

export interface GitHubSync { confirmed_ms: number | null; check_due: boolean; unanswered: number }

export type Standing = "confirmed" | "checking" | "unknown" | "unconfirmed";

export function githubStanding(sync: GitHubSync | undefined | null): Standing {
  if (!sync) return "unconfirmed";
  if (sync.unanswered > 0) return "unknown";
  if (sync.check_due) return "checking";
  return sync.confirmed_ms === null ? "unconfirmed" : "confirmed";
}
