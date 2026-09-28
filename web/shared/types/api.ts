// The controller's API documents the interface reads (docs/api.md).

export type Role = "reader" | "operator" | "admin";

export interface Me {
  user: string;
  username: string | null;
  super_admin: boolean;
  via: "bearer" | "session" | "oauth";
  scopes: string[];
  stepped_up: boolean;
  mfa: boolean;
}

export interface TenantChoice { slug: string; role: Role }

export interface RunSummary {
  id: string;
  sha: string;
  created_ms: number;
  state: string;
  trigger: string | null;
  ref: string | null;
  pr: number | null;
}

export interface JobTimestamps {
  queued_ms: number | null;
  leased_ms: number | null;
  preparing_ms: number | null;
  running_ms: number | null;
  finalizing_ms: number | null;
  terminal_ms: number | null;
}

export interface JobStatus {
  id: string;
  name: string;
  state: string;
  terminal: boolean;
  failure_class: string | null;
  cancel_requested: boolean;
  attempt: string | null;
  log_state: "pending" | "incomplete" | "complete" | null;
  fence: number;
  timestamps: JobTimestamps;
}

export interface Run {
  id: string;
  tenant: string;
  repo: string;
  sha: string;
  created_ms: number;
  cancel_requested: boolean;
  state: string;
  trigger: string | null;
  jobs: JobStatus[];
}

export interface Explanation {
  jobs: { name: string; needs: string[]; image: string; cpu_millis: number; memory_bytes: number; steps: { id: string; timeout_secs: number }[] }[];
}

export interface StepRecord { index: number; id: string; outcome: string; exit_code?: number; signal?: number; duration_ns?: number }

export interface Steps {
  attempt: string;
  present: boolean;
  timings_ns?: Record<string, number>;
  steps?: StepRecord[];
}

export interface Frame { seq: number; step: number; stream: "stdout" | "stderr"; text: string }

export interface LogPage {
  attempt: string;
  frames: Frame[];
  complete: boolean;
  gaps: [number, number][];
  next_after: number | null;
  next: string;
  step_done: boolean;
  /** Set when retention removed this log (R01): when it did. */
  expired_ms?: number;
}

/** Scheduled backups (R04). */
export interface Backups {
  configured: boolean;
  scheduler?: {
    target: string;
    interval_secs: number;
    keep: number;
    running: boolean;
    last_success_ms: number | null;
    last_failure_ms: number | null;
    last_failure: string | null;
    last_backup: { id: string; took_ms: number; objects: number; objects_copied: number; object_bytes_copied: number; log_bytes_copied: number } | null;
  };
  backups: { id: string; started_ms: number; took_ms: number; schema: number; version: string; metadata_bytes: number; objects: number; objects_remote_only: number; key_required: boolean; key_ids: number[] }[];
}

/** A storage policy as set (R01); `null` inherits. */
export interface StoragePolicy {
  quota_bytes: number | null;
  log_retention_ms: number | null;
  artifact_retention_ms: number | null;
}

export interface StorageEffective {
  tenant_quota_bytes: number;
  repo_quota_bytes: number;
  log_retention_ms: number;
  artifact_retention_ms: number;
}

export interface TenantStorage {
  usage: { object_bytes: number; log_bytes: number };
  policy: StoragePolicy;
  effective: StorageEffective;
  repos: {
    id: string;
    name: string;
    usage: { artifact_bytes: number; log_bytes: number };
    policy: StoragePolicy;
    effective: StorageEffective;
  }[];
}

export interface DeploymentStorage {
  filesystem_bytes: number | null;
  free_bytes: number | null;
  metadata_bytes: number;
  admission_open: boolean | null;
  inflight_bytes: number | null;
  watermarks: {
    reserve_bytes: number;
    configured_reserve_bytes: number;
    low_watermark_bytes: number;
    high_watermark_bytes: number;
    log_floor_bytes: number;
  } | null;
  stored_bytes: number;
  quota_bytes: number;
  tenant_quota_bytes: number;
  log_retention_ms: number;
  artifact_retention_ms: number;
  run_artifact_bytes: number;
  /** The external S3 copy (R02/R03), when configured. */
  s3: {
    state: "healthy" | "degraded" | "unknown";
    backlog_bytes: number;
    backlog_full: boolean;
    oldest_unreplicated_ms: number | null;
    unreplicated_logs: number;
    local_bytes: number;
    last_success_ms: number | null;
    last_failure_ms: number | null;
    consecutive_failures: number;
    last_error: string | null;
    replicated_objects: number;
    replicated_bytes: number;
    replicated_logs: number;
    evicted_objects: number;
    fetched_objects: number;
    deleted_copies: number;
    aborted_uploads: number;
  } | null;
}

export interface ApiErrorBody { code: string; message: string; details?: Record<string, any> }

export interface Capacity { cpu_millis: number; memory_bytes: number; disk_bytes?: number }

export interface Worker {
  id: string;
  name: string;
  arch: string;
  connected: boolean;
  last_seen_ms: number | null;
  transport: { path: string; reconnects: number; bytes_in: number; bytes_out: number; rtt_ns?: number; helper_version?: string } | null;
  draining: boolean;
  draining_since_ms?: number;
  labels: string[];
  held_attempts: number;
  held: Capacity;
  free: Capacity;
  capacity?: Capacity;
  cache_bytes?: number;
  host_workers?: number;
}

export interface Pool { id: string; name: string; active: boolean; kind: "shared" | "dedicated"; workers: Worker[] }

export interface RepoSync {
  id: string;
  name: string;
  pending: number;
  oldest_pending_ms: number | null;
  refused: number;
  last_refused_ms: number | null;
  last_published_ms: number | null;
  open_deliveries: number;
  oldest_delivery_ms: number | null;
}
