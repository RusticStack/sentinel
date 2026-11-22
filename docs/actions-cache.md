# Cache and artifacts on the worker's own disk

A runner-mode job's `actions/cache`, the `setup-*` actions' caches and `upload-artifact`/
`download-artifact` keep working unmodified, and their bytes land on the worker host's NVMe instead of
GitHub's storage ([plan 16.10](../plan.md#1610-github-actions-runner-mode)). Three facts make that
transparent, and this page is each of them, plus what this release proves and what it cannot.

| Fact | Where it lives |
|---|---|
| One certificate authority per sandbox, trusted only inside it | [`sentinel-actions::ca`](../crates/sentinel-actions/src/ca.rs) |
| One name answer per sandbox: the two service hosts resolve to it, every other name is refused | [`sentinel-actions::dns`](../crates/sentinel-actions/src/dns.rs) |
| One boundary per sandbox, decided by the listener the request reaches | [`sentinel-actions::endpoint`](../crates/sentinel-actions/src/endpoint.rs) |

## What the endpoint speaks, and from where

GitHub publishes the actions and their limits, not the service protocols, so both services are
implemented from the open-source clients at pinned versions:

| Client | Pinned at | Surface served |
|---|---|---|
| `actions/cache` | 4.2.0, over `@actions/cache` 4.0.0 | `GET _apis/artifactcache/cache?keys=…&version=…`, `GET _apis/artifactcache/caches?key=…`, `POST _apis/artifactcache/caches`, `PATCH _apis/artifactcache/caches/{id}` with `Content-Range`, `POST _apis/artifactcache/caches/{id}` |
| `upload-artifact` | 4.6.2, over `@actions/artifact` 2.0.1 | Twirp `CreateArtifact`, `FinalizeArtifact`, `ListArtifacts`, `GetSignedArtifactURL`, and the Azure block upload (`comp=block`, `comp=blocklist`) its signed URL is spent on |

`download-artifact` reads back through `ListArtifacts` → `GetSignedArtifactURL` → `GET`, so a later job
of the same GitHub run finds what an earlier one produced. `setup-*` actions cache through
`@actions/cache`, so they need nothing of their own.

Both hosts the clients can be pointed at are covered: `artifactcache.actions.githubusercontent.com`
(the v1 `ACTIONS_CACHE_URL`) and `results-receiver.actions.githubusercontent.com` (the v2
`ACTIONS_RESULTS_URL`, which serves the cache service and the whole artifact service). Nothing else is
intercepted: the sandbox gets two `/etc/hosts` entries and every other GitHub host keeps GitHub's own
answers.

## The sandbox's own authority

A worker-wide authority would let one sandbox's key impersonate the cache service for every other
sandbox, so the authority is minted **with the sandbox**:

- one CA key, one leaf covering exactly the two names, both generated per sandbox;
- the anchor (the CA certificate alone — never a key) is written under the sandbox's own directory and
  mounted **read-only into that container only**, at `/sentinel-ca/ca.crt`;
- the container is told where it is by one environment variable, `NODE_EXTRA_CA_CERTS`, which is a
  path. Node appends it to the platform store, so GitHub's own hosts keep the image's roots, and the
  sandbox still carries no secret of Sentinel's in its environment;
- nothing writes the anchor into a host trust store, and the CA key never leaves the process that
  signed with it. A client without the anchor fails verification, which is what "the CA never leaves
  its sandbox" means on the wire —
  `a_client_without_the_sandbox_anchor_is_refused_and_one_with_it_is_not`.

## The name answers

A resolver per sandbox answers the two service hosts with the sandbox's endpoint address — `A`, TTL 0,
so nothing outlives the sandbox — and answers **`REFUSED`** for every other name. It has no upstream: a
resolver that forwarded would be the one path by which a job's bytes reach GitHub's storage, so
refusing is the whole design rather than an error path. An `AAAA` question for a service name is
answered empty, so a client falls back to the A record instead of reading a refusal as "no such host".

Every other GitHub host is resolved by GitHub's own answers, because the sandbox's resolver is asked
about these two names and nothing else.

## The boundary, and why the request never sets it

A cache archive or an artifact lands under a boundary of tenant, repository, trust and platform, and
each dimension comes from the **lease**, not from the request:

- the listener serves exactly one lease, so the tenant, repository, trust and platform are the ones the
  controller stated for that sandbox;
- the controller states them in **protocol 17**'s scope frame, as soon as a `workflow_job` delivery
  binds the job to the runner it registered — the first moment a fork is known. A sandbox that has not
  received one **refuses every cache and artifact call** (`403`, `refusal: "unscoped"`) rather than
  writing into a guessed scope;
- the client's key, version, run id, token and `workflow_run_backend_id` are the job's business and
  never authority. A job that names another run's backend id still writes its own run —
  `a_client_that_names_another_run_writes_its_own`.

Trust follows the job's provenance, one rule (`Trust::of_runner_job`): a job from a fork pool is
`pull_request`, any other runner-mode job is `protected`, because its content came from this
repository's own refs through GitHub's own admission. A fork job's cache write lands in a
`pull_request` scope and a trusted job's listener cannot read it, and the other way round —
`a_fork_job_never_writes_a_trusted_scope_and_a_trusted_job_never_reads_a_forks`.

The archive location a lookup hands back names the exact generation that was read, and the download
re-checks the seal's own boundary before serving a byte, so a URL moved to another sandbox's listener
is a refusal rather than another tenant's bytes.

## Refused, never forwarded

Anything outside the pinned surface is a refusal that says so, with `schema: "sentinel.actions/1"`,
the reason and `forwarded: false`:

| Call | Answer |
|---|---|
| a path or method the services do not have | `404`, `refusal: "not_implemented"` |
| a known path with a method it does not answer | `405`, `refusal: "method_not_implemented"` |
| `CONNECT` anywhere | `405`, `refusal: "tunnel_refused"` — a tunnel is a forward |
| any call before the boundary is stated | `403`, `refusal: "unscoped"` |

The endpoint has no outbound client at all: it holds a listener, the sandbox's store and the boundary,
and the resolver holds one socket and no upstream. That is why "never forwarded" is structural rather
than a policy branch — `an_unimplemented_call_is_refused_and_never_forwarded` and
`no_query_leaves_the_resolver_for_a_name_it_does_not_own` are the tests that pin it.

## What it stores

One store under the worker's data root, `actions/cache` and `actions/artifacts`, laid out so a moved
directory can never serve (the rule [cache](cache.md#the-boundary) states for native caches):

```text
cache/<repo>/<trust>/<platform>/<key16>/<version16>/gen-<unix_ms>-<rand>/{archive,manifest}
cache/<repo>/<trust>/<platform>/<key16>/<version16>/current
artifacts/<repo>/<trust>/<run>/<slug>-<digest8>/{blob,manifest}
```

- `key16`/`version16` are the first 8 bytes of the client's key and version digests, so two keys never
  share a directory and a slug collision is a `wrong_key` miss rather than wrong bytes.
- A cache archive is sealed by writing the manifest inside the generation and then moving `current`; a
  chunk is written where its `Content-Range` says, because the pinned client uploads several at once.
- An artifact body arrives as Azure blocks and is assembled in the order the block list names.
- Both manifests record the whole boundary. A lookup answers a hit only when every dimension matches
  the listener's, and every other case is a typed miss (`absent`, `corrupt`, `wrong_tenant`,
  `wrong_repo`, `wrong_trust`, `wrong_platform`, `wrong_key`, `wrong_version`).

Tenant quotas for `actions_cache` are not charged by this change; the store enforces per-archive
(10 GiB) and per-artifact (4 GiB) bounds and leaves reclamation to the cache store's own sweep.

## Operating it

A worker serves runner mode only when it states the image **and** the address its sandboxes reach the
endpoint on:

```toml
[runner]
image = "ghcr.io/rusticstack/sentinel-runner@sha256:0f2c…"
actions_address = "10.0.2.2"
```

`actions_address` is the host address as the sandbox's network spells it ([configuration](configuration.md#runner-image)).
A worker that states the image and no address **declines every runner lease**: a runner whose cache and
artifacts would silently go to GitHub's storage is not one this feature serves. Where the sandbox is
granted egress, the worker's own nftables refusals accept `tcp dport 443` to that one address ahead of
every drop, so the endpoint is reachable and nothing else about the host is.

One listener serves one boundary, so a worker hosting several runners needs several addresses: each
sandbox binds the first address of the block its worker can have (`actions_address`, then the next 15
in the last octet) and is told that one in its hosts entries. The address has to be one the worker can
bind **and** the sandbox can reach: on a pasta network that
is the gateway address the sandbox maps the host to, and a rootless worker needs
`CAP_NET_BIND_SERVICE` on the binary to bind 443 at all (`setcap cap_net_bind_service=+ep`). A bind
that fails is not a silent fallback: the worker starts no runner for that lease and reports it
`RunnerFailed`, so the operator sees the address rather than the traffic reappearing at GitHub.

## The fallback per client version

If a client version's protocol detail blocks transparent serving, a repository is never left without a
path: two drop-in actions do by name what the endpoint does by interception, and switching is a
one-line change per step.

```diff
-      uses: actions/cache@v4
+      uses: sentinel/cache@v1
```

```diff
-      uses: actions/upload-artifact@v4
+      uses: sentinel/upload-artifact@v1
```

They take the same inputs (`path`, `key`, `restore-keys` / `name`, `path`, `if-no-files-found`) and
speak the same tenant-scoped store through the controller's API rather than through DNS and a sandbox
CA, so a workflow that pins the fallback gets the same bytes on the same disk with no interception at
all. Neither action exists in this release; the two lines are the stated change so an operator is never
without one, and they are AR06's remaining leg.

## What this release verifies, and what it cannot

Unit and crate tests, which run on any Linux account:

- the whole cache save/restore round trip over the pinned client's wire shape, chunked `PATCH` included
  (`cache::tests::the_clients_save_and_restore_round_trip_through_the_service`);
- the whole artifact upload/download round trip: Twirp `CreateArtifact`, Azure block staging and block
  list, `FinalizeArtifact`, `ListArtifacts`, `GetSignedArtifactURL`, `GET`
  (`artifact::tests::the_artifact_services_upload_and_download_round_trip`);
- a real TLS handshake refused without the sandbox's anchor and served with it, over a real listener
  (`endpoint::tests::a_client_outside_the_sandbox_cannot_reach_the_endpoint_and_one_inside_can`);
- the fork/trust wall in both directions, and an unscoped sandbox serving nothing;
- DNS answers over UDP for both hosts, and `REFUSED` for every other name with a stub upstream that
  receives nothing;
- the plan a sandbox is built with: two `/etc/hosts` entries, one read-only anchor mount, one
  environment variable naming it, and the endpoint's accept rule ahead of the egress refusals.

What needs a privileged host or a real Actions runner, and is therefore **not** proven here:

- that rootless Podman honours the plan (the `--add-host` entries, the single-file anchor mount, and a
  read-only root filesystem that still mounts it), that a real `actions/runner` reaches
  `actions_address:443` from inside its network namespace, and which address pasta actually forwards
  to the host — AR03's sandbox suite on `reference-host` and `arm64-host`; the tests here bind the
  endpoint on loopback at an ephemeral port and speak the same protocols to it;
- the cache-hit and artifact-upload gate on the pilots' unmodified workflows, and the comparison of
  restore and upload times against GitHub's measured and Blacksmith's published figures: both need a
  real runner and a benchmark host;
- that nothing is written to GitHub's storage, read back through the repository's Actions cache and
  artifact APIs: that check needs a live GitHub App and a pilot repository;
- the scope frame arriving within one provisioning pass of a job binding: proven in process by the
  store query and the controller pass, not on a live session.

Two legs remain, stated rather than implied:

- **Reclamation for the cache.** This store has no sweep of its own: a `writing/` staging file from a
  sandbox that died stays until the sandbox directory's sweep or an operator removes it, and an entry
  nothing asked for again waits for its repository's cache tree to give way at the tenant's hard
  threshold ([below](#what-the-cache-is-charged-to)). A runner-mode cache entry is otherwise bounded only
  by the archive's own 10 GiB limit, which is the worker's budget, not the tenant's.
- **The fallback actions.** `sentinel/cache` and `sentinel/upload-artifact` are stated above as the
  one-line change they would be; neither exists in this release.

## What an artifact uploaded here becomes

What `upload-artifact` seals is published into the controller's own artifact store, so it is a tenant's
artifact rather than a file one host knows about (protocol 18, `RUNNER_ARTIFACTS_MIN`). At
`FinalizeArtifact` the sandbox's listener offers the artifact to its worker's link — the lease, the name,
the sealed length and the store's own BLAKE3 digest — streams the sealed blob, and answers the client
only once the controller committed the row:

- the row is `origin: runner` under the GitHub run and job the lease took, named by
  `runner_manifest_name`, with the deployment's default class, the repository's effective artifact
  retention (further narrowed by the class's maximum age in the insert trigger) and a charge against the
  repository quota and the tenant's hard threshold ([storage](storage.md#artifact-records),
  [retention](retention.md#artifact-classes-and-pins));
- it retires through the same artifact sweep, appears in `GET /tenants/{slug}/repos/{name}/runner-runs/{run}/artifacts`,
  in the run page's artifact browser, in the CLI and in MCP, and downloads as a ranged object or a
  short-lived link like any other artifact;
- **it fails closed.** A controller that refuses the publication — `quota_exceeded` at the tenant's hard
  threshold after its caches were evicted, `duplicate` for a name the job already holds, `too_large` at
  the repository's quota, a store fault — makes `FinalizeArtifact` answer `409` with that reason and
  removes the sealed copy from the worker's disk. The job's upload fails visibly; no artifact survives
  that the tenant holds no row for.

What is not here yet: the endpoint still answers a local `ListArtifacts`/download from its own disk, so a
later job of the same run reads back an earlier one on the same worker host, and the controller's row is
what makes it readable from anywhere else through the API.

## What the cache is charged to

A runner-mode `actions/cache` tree lives on the worker host, so the controller used to hold no figure for
it and the tenant's hard threshold could not see it. The worker now walks `actions/cache/<repo>` — one
directory per repository it serves, symlinks never followed — and reports the bytes it holds for each
repository of the tenant that caused them (protocol 19, `ACTIONS_ACCOUNTING_MIN`; at most
`MAX_ACTIONS_REPOS`, 64, repositories per frame). It reports when it attaches, when a job's attempt ends,
and after it has given entries up, so a figure is never older than the last thing that changed it.

The controller writes one row per `(worker, repository)` into `worker_actions_cache` and folds the
per-tenant sum into `tenant_usage.actions_cache_bytes` in the same writer transaction. Only a repository one
of that worker's runner leases ran is charged (one keyed probe of `runner_leases(worker_id, repo_id)`): the tree
holds nothing else, so a repository the worker never served is dropped from the report rather than charged to
its tenant. A report replaces
its own worker's rows and deletes the ones it no longer names: a worker that dropped a whole repository's
entries must read zero rather than its last figure, and two workers that hold the same repository add,
because the class is bytes on every host the tenant's jobs ran on. The class is one of the six
`GET /tenants/{slug}/storage` reports, and it is counted toward the tenant quota ([retention](retention.md#per-class-accounting)) —
which is what makes the threshold act on it.

At the hard threshold the answer to a report is `ActionsEvict` naming the tenant's repositories, and the
worker removes each repository's whole cache tree. A repository whose sandbox is still running is spared:
a live job's inputs are never deleted under it, and that repository's entries go at the next report, when
the attempt has ended. An eviction that removed nothing is not reported again, so a spared repository does not
turn into a report and the same answer back to back while its job runs. A revoked worker has its rows cleared
and its tenants re-folded in the revocation's own transaction, so a retired host gives its figures back
rather than holding them.

What no test here covers is the walk over a tree a real job filled: the report, the fold, the hard state
and the eviction are driven end to end over a real worker link
(`crates/sentinel-link/tests/runner_mode.rs`), and the tree itself is read by the same directory code the
spool and mirror sweeps use.
