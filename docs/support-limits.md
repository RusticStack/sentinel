# Support limits

What v0.1 supports, what exists without being supported, and what nobody has been able to check. This page is the list the [release notes](release-notes.md) point at; it is a draft until the release gates close, and nothing here is a release claim.

Four words are used with one meaning each:

| Word | Meaning |
|---|---|
| **Supported** | In the v0.1 support set: built, documented, and covered by the release gates |
| **Implemented, not supported** | Code and tests exist, but a release gate for it is open or it is outside the v0.1 scope |
| **Unverified** | Built and tested against a double or on one host; the real counterpart could not be reached. Each row names what is missing |
| **Not built** | No code path; refused or absent |

No figure on this page is an estimate. A measurement that does not exist is written **not measured**, with the wave of [TODO.md](../TODO.md) that produces it.

## Product limits

| Area | State | Limit |
|---|---|---|
| Native pipelines (`.sentinel.yml`) on Linux workers, rootless Podman, x86_64 and arm64 | Supported target | End-to-end release qualification is not recorded yet ([qualification](qualification.md)) |
| Controller and worker hosts | Linux only | `sentinel server`, `sentinel worker` and `sentinel admin` are built into the Linux binaries only ([configuration](configuration.md#host-local-administration)) |
| Windows | CLI only | The CLI is packaged for Windows x86_64. No Windows worker or Windows job execution exists. The Windows CLI has no smoke test on a Windows verification host (X2) |
| Linux microVMs (Firecracker) | Implemented, not supported | Needs a KVM host. The end-to-end gate (M04), network policy (M05) and snapshot restore (M06) are open; hosts without KVM keep rootless Podman ([executor](executor.md)) |
| GitHub Actions runner mode | Implemented in part, not supported | Outside the v0.1 scope. Intake, provisioning, the local cache and artifact endpoints, and the Linux runner image and sandbox (its egress gate is open) exist ([runner mode](runner-mode.md#what-this-release-verifies-and-what-it-cannot)); microVM runners, Windows runners, runner images with hosted-runner toolchains and every runner-mode measurement are open in the [backlog](backlog.md) |
| Fork pull requests | Not supported | Native intake ignores a pull request whose head repository is not the bound repository (`fork_pr`). In runner mode a fork pull request's job is refused (`runner_fork_pr`) unless the tenant opted in and a pool serves it ([runner mode](runner-mode.md#fork-pull-requests)). Rootless containers alone are not treated as a boundary against hostile code |
| Secrets on manual runs | Refused | A manual dispatch whose pipeline declares secrets, secret files or registry credentials is refused (`manual_run_secrets`); secrets reach only runs that name an authenticated delivery ([secrets](secrets.md#who-may-cause-a-delivery)) |
| Git sources | `https://` and `ssh://` remotes | A local path or a `file://` remote is not accepted ([fully local operation](deployment.md#fully-local-operation)) |
| GitHub Enterprise Server | File configuration only | One-click App setup always addresses github.com ([GitHub App](github-app.md#before-you-start)) |
| GitHub features without a public HTTPS origin | Not available | Webhook, Checks and GitHub sign-in need GitHub to reach the deployment ([GitHub ingress](deployment.md#github-ingress)) |
| Job network | Off by default | A job has no network unless the worker sets `job_network = "egress"` |
| Release signing | Not built | Archives carry SHA-256 sums and a manifest, no signature ([releasing](releasing.md#verifying-a-download)) |
| Web interface | Optional | The controller, CLI and MCP work without it. Its own limits are listed in [web interface](web-ui.md#known-limits) |
| Release qualification | Single host | A PASS does not cover multi-host enrollment, Tailcat, runner mode, microVM or Windows paths ([qualification](qualification.md#what-a-pass-does-not-show)) |

## Unverified against the real counterpart

These are the owner prerequisites of [TODO.md](../TODO.md#owner-prerequisites) that a session cannot supply. Each stays an unverified limit until the named thing exists; none is closed by a test against a double.

| Capability | What exists | Blocked by |
|---|---|---|
| Comparison with Blacksmith (B11) | The gate's definition and harness, no data | X1: Blacksmith benchmark access. No Blacksmith execution has been measured |
| Windows CLI | The packaged `sentinel.exe` | X2: a Windows verification host |
| One-click GitHub App setup on the real GitHub pages | The flow against a loopback GitHub double | X3: a registered App on a disposable account |
| Reading a collaborator's permission with `members:read` alone | Not determined | X3 |
| Where the pinned Tailcat helper comes from in the final enrollment flow | Operator-supplied helper; direct TLS is the default transport | X4: an owner decision on source and licence |
| Secrets for fork pull requests | Fork pull requests stay refused | X5: an owner decision on the policy |
| Destructive reliability scenarios and the relay link | Harness rehearsed against a fake only, which is not evidence | X6: approval, a disposable host, an operator-owned DERP |
| MCP with real clients | The stdio and HTTP transports ([MCP](mcp.md)) | X7: real MCP clients |
| Hosted S3 providers | Tests against S3-compatible services started locally ([S3](s3.md#verification)) | X7: hosted buckets |
| GitLab over TLS and Forgejo over SSH as generic Git sources | The generic Git path ([generic Git verification](generic-git-verification.md)) | X7: the two fixtures |
| CLI browser sign-in launching a desktop browser | The loopback flow with `--no-browser` and the device flow ([CLI](cli.md#authentication-and-profiles)) | X7: a desktop browser |
| Email delivery | The durable mail outbox ([admission](admission.md#email-identity-and-email-invitations)) | X7: a Resend key and domain |
| GitHub sign-in on real github.com | The sign-in flow and its tests ([GitHub sign-in](github-sign-in.md#verification)) | X7: a registered GitHub OAuth app |
| Tailcat NAT traversal | The pinned-helper integration ([worker link](worker-link.md#verification)) | X7: separate real networks |

## Not measured yet

The figures below do not exist. They are gaps, to be filled from committed records only; until then no document may quote a number for them.

| Wave | What is missing | Needs |
|---|---|---|
| 1 Verification gate | The full suites on the final tree on x86_64 and arm64 | `reference-host`, `arm64-host` |
| 2 Measurements | Latency budgets re-measured on the final tree (B03, B03a, B03b); the critical-path profile (B04, B04a); the cache matrix (B05: **no result exists**); retention defaults (R01); the backup drill at 100 GiB (R04); idle RSS and CPU (R06); the CI baseline on the real topology (F06) | A quiet `reference-host` |
| 3 KVM host | Everything about microVMs: detection, capacity, the end-to-end suite, network gate, snapshot restore, and overhead against rootless Podman (M01 to M06, M08); the completed same-hardware baseline (B01a) | `kvm-host` with nftables privileges |
| 4 Real fleet | Host management across three hosts (Q11 to Q13); placement by expected finish (Q03); Tailcat telemetry (Q06, Q07); the three-worker fleet and the reliability matrix (Q09, B09) | All three hosts; X4, X6 |
| 5 Pilots and Blacksmith | Pilot workflow confirmation and parity (B06, B07, B10); the sub-minute target (B08, **unmet** on the recorded baselines); the Blacksmith ratio (B11, **blocked by X1**) | Waves 2 to 4; X1 |

The pilot figures that do exist, with their sample counts and their limits, are in the [release notes](release-notes.md#measured-performance).

## Verification

This page is text. Each row's evidence is the document it links; the rows under "Unverified" and "Not measured yet" have none by definition. No test was run to write it.
