# Sources: bindings, credentials and forge associations (G01)

A **repository** in Sentinel is a tenant-owned row. A **source binding** is
what makes that repository executable and fetchable: an administrator-approved
clone URL, the refs runs may use, the pipeline path, a credential reference,
and — optionally — the forge installation the repository belongs to. A
repository with no binding keeps working as the explicit manual mode that
Part 04 exercised: a dispatch names its own remote and gets no credential.

## Two transports, one authority

| | Generic binding | GitHub App association |
|---|---|---|
| Remote | `https://host[:port]/path` or `ssh://user@host[:port]/path` | `https://github.com/owner/repo.git` |
| Credential | `Public`, an HTTPS username/token, or an SSH deploy key | short-lived App installation token, `contents: read` |
| Trust | PEM roots (HTTPS) or `known_hosts` lines (SSH) | GitHub's public CA |
| Lifecycle | explicit bind/rotate/revoke with compare-and-set versions | App + installation lifecycle, checked live |

Both paths are approved by the same deployment destination allowlist
(`<data_dir>/source-destinations.json`): transport, host and explicit port,
with no userinfo, query or fragment. A run's spec can never substitute a
remote that is not the binding's exact URL, so neither pipeline YAML nor an
event can point a job at somebody else's server.

Refs are limited to `refs/heads/` and `refs/tags/`; a trailing `*` in an
allowed ref is a prefix match (`refs/tags/v*`). The bound ref on a run must be
allowed for the binding.

## Credentials are sealed, delivered per attempt, and never persisted

The credential reference is **not** a run-spec field. It is sealed with the
existing key-outside-database mechanism ([second-factor seeds](local-authentication.md)
use the same `master.key`) and its associated data binds the ciphertext to
*(tenant, repository, version)*: a row copied to another repository or tenant
fails to open. The **version** advances on every bind, rotate and revoke, and
mutations are compare-and-set, so two administrators cannot silently overwrite
each other.

`admin key create` already provisions `<data_dir>/master.key`; G01 adds no new
key material, and a deployment that never binds a credential never needs it.
A stolen database therefore yields no deploy token and no private key, and a
rotated credential's ciphertext is replaced, not appended to.

Delivery is scoped to one attempt:

1. The worker asks for the spec (`NeedSpec`) **after** its `Ack` is on the
   wire, so the attempt is acknowledged under a live lease.
2. The controller re-checks, in the database, that the attempt is held by
   that worker under its current fence, that the lease has not expired, that
   the job is preparing or running, that cancellation is not desired, and that
   the tenant and pool may still run it. Any failure is `NoSpec`.
3. The credential is opened and sent as a `Source` message ahead of the spec
   chunks, together with the event facts the spec's expressions may read —
   **protocol 3**. A worker below protocol 3 is served `NoSpec` instead:
   checking out a bound repository without its credential would either fail
   or, worse, succeed against a public mirror, and a worker that cannot decode
   the context must not misread it.

The token never reaches a URL, `.git/config`, the job environment or a log
line. Errors carry one bounded, control-character-free line of Git/SSH output
with the credential itself replaced before it can be interpolated.

## Checkout on the worker

`checkout::checkout_authorized` validates the access object (expiry, exact
remote, allowed ref) before starting Git, then:

- **HTTPS with CA trust** writes the PEM roots to an owner-only file outside
  the workspace and passes `GIT_SSL_CAINFO`; an SSH transport additionally
  writes `known_hosts` and refuses unless it has one.
- **HTTPS credentials** use the askpass helper as before.
- **SSH deploy keys** write the private key `0600` and an `GIT_SSH` wrapper
  that pins `ssh -F /dev/null`, `BatchMode`, `IdentitiesOnly`,
  `StrictHostKeyChecking=yes` and `UserKnownHostsFile` to the bound trust, so
  nothing from the host's SSH configuration or agent is consulted.
- Git is pinned to a single protocol (`protocol.allow=never` plus exactly one
  of `protocol.https.allow=always` / `protocol.ssh.allow=always`), follow
  redirects are off, and the credential helper list is empty.

Everything the checkout installs lives in a sibling `*-askpass` directory
created `0700` and removed on every path, including failure.

## GitHub App association

`<data_dir>/github-app.json` names the App and an absolute, owner-only PEM
key file:

```json
{"app_id": 1234, "private_key_file": "/etc/sentinel/github-app.pem"}
```

The App key is read at startup (and by `admin source`), never stored in
SQLite. For an associated repository, the controller:

1. `GET /app/installations/{id}` with a `RS256` JWT and requires the account
   is the one bound, the installation is not suspended, `checks: write` is
   present and `contents` is at least readable. Unchanged `lifecycle_version`
   is compared after the round trip, so a webhook observed in the meantime is
   never overwritten by a stale response.
2. `POST /app/installations/{id}/access_tokens` with `repository_ids` (the
   immutable numeric ID) and `permissions: {contents: read}` — explicitly
   narrowed, never inherited from the App.
3. `GET /repositories/{id}` **with that token** and requires the ID, the
   owner's account ID and the exact clone URL to match what was bound. A
   rename is a mismatch, not a silent rebind.

Only then is the spec released. Installation lifecycle is a local snapshot
refreshed from GitHub's API (`admin source refresh-installation`) and
invalidated by `admin source remove-installation`; a webhook (G02) is a hint
to refresh, never authority to revive an installation that was removed or
transferred.

The same access is what event resolution uses ([intake](intake.md)): before it
reads the pipeline from the bound remote, the controller mints the sealed
credential or the App token exactly as above, rechecks the binding's version
and lifecycle after any round trip, and then discards the credential with the
resolution's scratch directory. A generic repository's events never touch the
App, and a forge-associated one never falls back to a generic credential.

## Commands

```sh
# A tenant-owned repository row, then its binding
sentinel admin source create --data-dir "$DATA" --actor usr_... \
  --tenant tnt_... --name app
printf '%s' '{"binding":{"remote":"https://git.example:8443/team/repo.git",
  "allowed_refs":["refs/heads/main"],"pipeline_path":".sentinel.yml",
  "trust":"<pem>"},"credential":{"Https":{"username":"deploy","secret":"..."}},
  "forge":null}' | sentinel admin source bind --data-dir "$DATA" \
  --actor usr_... --repo rep_... --expected 0
sentinel admin source show   --data-dir "$DATA" --actor usr_... --repo rep_...
sentinel admin source revoke --data-dir "$DATA" --actor usr_... --repo rep_... --expected 1

# The repository's intake hook secret (shown once; rotates on the next call)
sentinel admin source hook-token --data-dir "$DATA" --actor usr_... --repo rep_...
sentinel admin source hook-token --data-dir "$DATA" --actor usr_... --repo rep_... --revoke

# GitHub App lifecycle (platform administration)
sentinel admin source refresh-installation --data-dir "$DATA" --actor usr_... \
  --external-id 12345678 --expected 0
sentinel admin source bind-installation   --data-dir "$DATA" --actor usr_... \
  --installation ins_... --tenant tnt_...
sentinel admin source remove-installation --data-dir "$DATA" --actor usr_... \
  --installation ins_...
```

`sentinel admin intake list --data-dir "$DATA" --repo rep_… [--state …]` shows
the newest event deliveries and `admin intake purge --older-than 7d` retires
settled ones ([intake](intake.md)). The `post-receive` hook and its relay live
in `examples/hooks/`. A GitHub App installation is bound with
`admin source bind-installation`; its webhook secret is the operator's to set
in `<data_dir>/github-webhook.json`.

`show` reports the binding, version, revocation and forge association —
metadata only, never credential material. `bind` reads its JSON from standard
input; there is no argument form that would put a deploy token in the process
list or shell history. The CLI runs on the controller's own host, so its
authority is the same filesystem access that already lets an operator open the
database: `--actor` names the account the audit attributes the change to, and
it is recorded verbatim, not re-authorized. The store also carries a
credentialed path (`Authority::credential`) that rechecks administration of
*that* tenant through the live authorization layer; the future API route uses
it, and the store tests exercise both.

Deploy credentials must be provisioned **read-only** at the Git provider.
Sentinel stores and delivers them, and cannot make a write-capable token safe.

## Compatibility

Migration 17 adds `source_bindings` and `source_audit` and extends
`installations`; migration 18 adds `source_intake_tokens` and
`webhook_deliveries` ([intake](intake.md)); migration 19 adds the resolved
delivery states and per-run provenance ([intake](intake.md)). Existing
repositories stay unbound and unbound legacy runs keep working. Protocol 2
adds the `Source` message and protocol 3 the event context; workers negotiate
`1..=3`, and anything below 3 is served `NoSpec`. The HTTP API gains
`POST /api/v1/hooks/github` and `POST /api/v1/intake/{repo}`; both are additive
under the `/api/v1` path policy. See [compatibility](compatibility.md).

## Verification

- `crates/sentinel-store/tests/sources.rs`: binding without a forge row;
  sealed ciphertext unusable from another repository/tenant; rotation and
  revocation with compare-and-set; ref and destination policy; installation
  lifecycle including suspension, transfer and deletion; migration from
  version 16 preserving repositories with no invented binding.
- `crates/sentinel-store/tests/intake.rs`: hook secrets and the delivery
  lifecycle ([intake](intake.md#verification)).
- `crates/sentinel-worker/tests/checkout.rs`: a private HTTPS checkout against
  a loopback server with CA trust, a rotated credential and a removed CA, with
  no credential file left behind; a real `sshd` deployment-key checkout with
  pinned host trust and a refused wrong host, both proving the private
  directory is removed and the key never reaches `.git/config`.
- `crates/sentinel-link/tests/source_delivery.rs`: a bound source reaches a
  protocol-2 worker with its credential only after acknowledgement, and a
  protocol-1 worker receives `NoSpec` rather than running without it.
- `crates/sentinel-github` unit tests: installation identity, account type,
  suspension, permission validity, a read-only scoped token, lifetime bounds
  and redacted debug output.

A live GitHub App private-key round trip against github.com, a real
self-hosted Gitea/Forgejo/GitLab HTTPS or SSH host, and idempotent
installation lifecycle webhooks remain verification for G02 and G08 and a
dedicated pilot; they are recorded as prerequisites, not simulated.
