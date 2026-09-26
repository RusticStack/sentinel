# Scoped secret records and bindings (S02)

Migration 38 stores tenant-owned secret identities, immutable encrypted versions, repository allowlists, explicit bindings, and an audit trail. Each secret name belongs either to one tenant or one repository. Names use `[A-Z_][A-Z0-9_]*` and at most 64 bytes. A value is 1–65,536 bytes. The current version increases on rotation; a stale expected version fails with a conflict. Deleted names stay reserved and all their versions are revoked. A single historical version can also be revoked permanently. Ciphertext uses [sealed storage](sealed-storage.md), with tenant, optional repository, name, and version in its authenticated context. No plaintext read-back function is exposed to callers.

The existing `WRITE_SECRETS` repository permission is independent of `RUN` and repository operator status. A tenant admin can give a reader or service account that bit for one repository through the normal repository grant. The secret writer can create and rotate repository secrets and bind eligible secrets for that repository. Creating a tenant secret or changing its repository allowlist requires live tenant administration. Every mutation checks that authority in the same writer transaction, including before replaying an idempotent response. Metadata listing and description accept either read or secret-write authority for the relevant scope, so a delegated writer can learn the version needed for a compare-and-set update. HTTP routes also require the `secrets:metadata` or `secrets:write` OAuth scope. No repository grant or super-admin identity gives ambient cross-tenant secret access.

A tenant secret must be allowlisted for a repository before it can be bound there. Removing the allowlist removes its bindings in the same transaction, so reallowing needs an explicit new binding. A binding identifies a repository, secret name, source secret ID, and optional job and step IDs. Empty job selects all jobs; empty step selects all steps of the named job. A compiled job still has to declare the name before a value can be delivered. The resolver prefers an exact job and step binding, then a job binding, then the repository-wide binding. A repository secret whose name collides with an allowlisted tenant secret requires an explicit `override_tenant` binding. A tenant binding with an active repository secret of the same name fails as ambiguous. A later secret change can make an old binding ambiguous; resolution checks again rather than silently changing source.

The metadata resolver returns secret ID, source scope, name, and current version, never the sealed value. It refuses missing or revoked versions and inactive tenants or secrets. During preparation, one writer transaction checks the acknowledged attempt's worker, fence and live lease, resolves only declared target names, opens the current active values and writes use audit rows. The transaction serializes delivery against rotation, revocation, binding changes and lease changes. Audit rows record action, result, actor when applicable, tenant, repository, secret/version IDs, attempt and step when applicable, and time. They contain no value or value-derived digest.

The `secrets`, `secret_versions`, `secret_repo_allow`, `secret_bindings`, `secret_audit`, and bounded `secret_idempotency` tables live in SQLite. Backup the database and master key as a matching pair. Sealed historical versions remain available for audit until explicitly revoked or deleted. Every new attempt, including a rerun, receives the current active version at its preparation transaction; an old version is never selected just because an earlier attempt used it. A secret's repository allowlist is an authorization boundary, not an injection instruction.

## CLI and HTTP writes (S03–S04)

`sentinel secret set`, `rotate`, `list`, `describe`, `delete` and `import` use the API. Set values come from hidden terminal input, redirected stdin, or a protected regular file, never an argument. The API accepts raw value bytes up to 65,536 and seals them inside the same SQLite writer transaction as the version and audit row. Compare-and-set uses `If-Match`; the required idempotency key saves only a metadata response and a request fingerprint in a bounded table. Authorization is checked again before a retry may replay a response. Source files must be regular nonsymlinks with owner-only access: Unix mode and ownership is checked, and Windows DACLs may grant only the current user and SYSTEM.

`secret import --env-file` parses UTF-8 `NAME=value` records literally. It accepts CRLF, blank lines and `#` comments; it does not interpret quotes, escapes or variable expansion. The 1 MiB file limit, 100-entry limit, name/value bounds, duplicate checks and complete expected-version map are validated before writes. All entries seal and audit in one writer transaction, so any conflict rolls back the import. Preview lists names and expected versions only. The CLI and API never echo imported values; secret values are not included in argv, diagnostics or response output.

## Execution binding and cleanup (S05–S06)

Jobs declare names in `secrets`. A step can consume a name as an environment variable with `steps[].secrets` or as a file with `steps[].secret_files`; a job can select one declared name for host-only registry authentication with `registry_auth`. Example:

```yaml
jobs:
  test:
    image: ghcr.io/acme/ci@sha256:...
    secrets: [TOKEN, CLIENT_CERT, OCI_AUTH]
    registry_auth: OCI_AUTH
    steps:
      - id: unit
        run: ./test.sh
        secrets: [TOKEN]
        secret_files:
          CLIENT_CERT: tls/client.pem
```

The worker runs only jobs requiring this contract when it negotiates protocol 10 and advertises `SECRET_DELIVERY`. The controller sends the bounded bundle after the durable offer acknowledgement, bound to that attempt and fence. The store records selected version IDs and the job/step use in the same transaction that opens the sealed values. Each value is at most 64 KiB and the whole bundle is at most 1 MiB. The worker checks that the received target set exactly matches the stored run spec, rejects invalid env values and unsafe file paths, and registers every value with the attempt redactor before opening the log pipe.

Environment values are written to an owner-only temporary env file and passed to `podman exec`; they do not appear in process arguments. Secret files live outside the workspace and cache at `/run/sentinel-secrets/<relative-path>` in the container, mounted read-only. The worker materializes only a step's files immediately before that step, then zeroes and removes them. Secret target paths may not overlap or conflict with step environment names. Default artifact and cache collection only sees the workspace and declared cache views; the secret mount is outside both. Container teardown stops step processes, and the worker removes the attempt directory on every terminal path. Startup recovery reaps secret directories left by a process crash.

Private registry auth is an OCI auth JSON object containing only an `auths` map. It is written to an owner-only host file for the image pull, removed immediately afterward and never passed into the job container. Every attempt explicitly runs `podman pull` with that attempt's auth file, even if the digest is present locally. This means a local layer cache cannot authorize a different tenant or a revoked credential. Pulls suppress ambient auth-file overrides and external credential-helper executables; use `registry_auth` rather than a worker-wide Podman login for private images. Prefetch is anonymous and does not grant access: the attempt performs its own authorized pull before using the image.

Redaction runs before spool persistence and controller delivery. It handles a secret split across log frames by holding a bounded stream tail. It cannot hide transformations of a secret (for example, a program that prints a hash or a substring), so jobs should still avoid deriving and printing secret material.

## Verification (S07)

`sentinel-store/tests/secret_delivery.rs` checks acknowledgement/fence gating, declared target resolution, selected-version audit, current-version selection after rerun, and refusal of a revoked version. The Linux rootless `sentinel-worker/tests/end_to_end.rs` runs a real protocol-10 secret job: its bound `TOKEN` reaches the declared step environment, and the controller receives its output redacted. The separate `inspect`-job redaction fixture registers a synthetic value before each attempt. `sentinel/tests/oauth_e2e.rs::a_delegated_cli_writer_can_provision_a_secret_for_a_job_without_disclosure` extends the delivery path from the authorized CLI writer: the CLI-created value is bound to a job, consumed through both environment and file targets, redacted from controller logs, absent from sealed ciphertext and audit metadata as plaintext, and removed from worker scratch after completion. An artifact declaration using the same relative path as the secret file resolves absent, and a scan of worker cache/scratch files finds no plaintext.

Import idempotency and competing version writes are covered by API tests, including synchronized concurrent retries with one idempotent result and two different imports racing on the same expected versions. Image tests verify that tenant or credential changes do not share an in-flight authorized pull; the rootless Podman test uses an explicit auth file even for a resident image. Sealed-key tests rotate, restore the matching key backup and reject values sealed after that backup. These checks run on the full Windows CLI/API suite and the Linux server/worker suite; rootless execution uses `SENTINEL_PODMAN_TESTS=1` as the worker account.
