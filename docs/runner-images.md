# Runner images

Runner mode starts the official GitHub Actions runner in a sandbox ([runner mode](runner-mode.md)). The
runner image described [there](runner-mode.md#the-runner-image-and-its-update-policy) carries only what the
runner itself needs. This page is about the images a workflow written for GitHub's hosted runners
expects: an Ubuntu 24.04 image and a Windows Server 2025 image that carry a **published subset** of the
hosted images' toolchains, so `setup-go`, `setup-node`, `setup-python`, `setup-java` and
`dtolnay/rust-toolchain` find a version already on disk instead of downloading it.

It is a subset on purpose. GitHub's `ubuntu-24.04` image is tens of gigabytes of tools most jobs never
call; a worker pulls its image by digest and keeps it, so every tool in it is paid for on every host.
The subset is what the [pilot repositories](pilot-repositories.md) use, and it grows by a row in one file.

## The published subset

[`examples/runner/toolset.tsv`](../examples/runner/toolset.tsv) is the manifest both images are built
from: one row per tool, version, operating system and architecture, with the archive's URL and the
publisher's checksum. The table below is the same content, and
[`scripts/release/check-runner-toolset.sh`](../scripts/release/check-runner-toolset.sh) fails when the two
disagree in either direction, so this page cannot list a version an image does not carry.

| Tool | Version | Images | Checksum taken from |
|---|---|---|---|
| `node` | `24.22.3` | Ubuntu 24.04, Windows Server 2025 | nodejs.org `SHASUMS256.txt` |
| `node` | `22.23.5` | Ubuntu 24.04, Windows Server 2025 | nodejs.org `SHASUMS256.txt` |
| `go` | `1.27.4` | Ubuntu 24.04, Windows Server 2025 | go.dev's download index |
| `go` | `1.26.11` | Ubuntu 24.04, Windows Server 2025 | go.dev's download index |
| `python` | `3.13.18` | Ubuntu 24.04 | `actions/python-versions` release archive |
| `python` | `3.12.16` | Ubuntu 24.04 | `actions/python-versions` release archive |
| `temurin` | `17.0.21+100000002` | Ubuntu 24.04, Windows Server 2025 | Adoptium's release API |
| `temurin` | `21.0.13+100000002.0.LTS` | Ubuntu 24.04, Windows Server 2025 | Adoptium's release API |
| `temurin` | `25.0.5+100000002.0.LTS` | Ubuntu 24.04, Windows Server 2025 | Adoptium's release API |
| `maven` | `3.9.16` | Ubuntu 24.04, Windows Server 2025 | Apache's `.sha512` beside the archive |
| `rust` | `1.99.1` | Ubuntu 24.04, Windows Server 2025 | rustup's `rustup-init.sha256` (the version is the toolchain rustup then installs) |
| `runner` | `2.338.2` | Windows Server 2025 | `actions/runner` release archive |
| `git` | `2.56.1` | Windows Server 2025 | Git for Windows' MinGit release archive |

Both images also carry, outside the manifest:

- **Ubuntu 24.04** — everything the runner image has (`bash`, `ca-certificates`, `curl`, `git`, `gzip`,
  `jq`, `tar`, `unzip`) plus `build-essential` (gcc, g++, make), `file`, `libssl-dev`, `openssh-client`,
  `pkg-config`, `xz-utils`, `zip` and `zstd`, from Ubuntu's own archive at build time. Rust comes with
  `clippy` and `rustfmt`.
- **Windows Server 2025** — what the operating system has, plus MinGit and the runner. Rust is the
  `x86_64-pc-windows-gnu` host toolchain, which links by itself; the MSVC toolchain needs Visual Studio's
  build tools, which the image does not carry.

**Where a setup action finds them.** Toolchains sit in the tool cache `@actions/tool-cache` reads, at
`<cache>/<name>/<version>/<arch>` with a `<arch>.complete` marker beside each: `node`, `go`, `Python` and
`Java_Temurin-Hotspot_jdk` (a JDK's directory is its version with `+` written as `-`, as `setup-java`
names it). The cache is `/opt/hostedtoolcache` on Ubuntu and `C:\hostedtoolcache\windows` on Windows,
stated to jobs as `RUNNER_TOOL_CACHE` and `AGENT_TOOLSDIRECTORY`. The runner's own `.env` file carries
`GOROOT_<major>_<minor>_<ARCH>`, `JAVA_HOME_<major>_<ARCH>` and `JAVA_HOME`, as the hosted images do.

**Defaults without a setup action.** The newest pinned Node, Go and Python, JDK 17, Maven, and the pinned
Rust are on `PATH`. A setup action that selects another version puts it first.

**A version the image does not carry is downloaded by the setup action**, exactly as on a hosted runner
whose image lacks it; that is the setup action's own behavior and needs the job's egress. The image
decides only what resolves without a download.

## What the images leave out

A command the hosted image has and this one does not is not left to fail as a bare `command not found`.
Each name in [`examples/runner/absent.txt`](../examples/runner/absent.txt) (Ubuntu) and
[`examples/runner/windows/absent.txt`](../examples/runner/windows/absent.txt) (Windows) has a refusal
**last** on the job's `PATH`. A step that calls one fails with exit code 127 and an `::error` annotation
naming the command and this page, so the job's summary says what was missing. Because the refusal is
last, a step or action that installs the real tool takes its place without anything to undo.

- Ubuntu 24.04: `ansible`, `ant`, `aws`, `az`, `bazel`, `buildah`, `clang`, `cmake`, `composer`, `docker`, `docker-compose`, `dotnet`, `gcloud`, `gem`, `gh`, `gradle`, `helm`, `kotlin`, `kubectl`, `ninja`, `php`, `pnpm`, `podman`, `pwsh`, `ruby`, `sbt`, `skopeo`, `sudo`, `swift`, `terraform`, `yarn`.
- Windows Server 2025: `7z`, `aws`, `az`, `bazel`, `choco`, `cl`, `cmake`, `docker`, `dotnet`, `gcloud`, `gh`, `gradle`, `helm`, `kubectl`, `link`, `msbuild`, `ninja`, `nuget`, `php`, `pnpm`, `python`, `ruby`, `terraform`, `vcpkg`, `yarn`.

`pwsh` is deliberately not a refusal on Windows: the runner picks a `run:` step's default shell by looking for `pwsh` on `PATH` and falls back to Windows PowerShell only when there is none, so a shim there would fail every such step. A step that names `shell: pwsh` is not answered by this image at all.

Two of those are structural rather than a matter of size. `sudo` is absent because the runner is not
root and a rootless sandbox has no root to give. `docker` and `podman` are absent because a rootless
Podman sandbox cannot nest a container engine: `container:`, `services:` and Docker actions need the
microVM sandbox, which is backlog item AR04.

A list that names a command the image does carry fails the build, so the lists cannot drift into
refusing a tool that is there.

## Ubuntu 24.04

[`examples/Containerfile.runner-ubuntu-2404`](../examples/Containerfile.runner-ubuntu-2404) builds on the
runner image, which the builder names (`--build-arg RUNNER=…`, no default), so the runner version and its
checksum stay stated once.
[`examples/runner/install-toolset.sh`](../examples/runner/install-toolset.sh) checks every archive
against its row before unpacking it, and an architecture with no rows fails the build.

The build's last step is `sentinel-toolset check`, run as the runner's own uid: every pinned tool must be
present and report its pinned version, or no image is produced, and the failure names every tool that is
missing rather than the first. The same command is in the image for an operator:

```sh
podman run --rm --entrypoint sentinel-toolset <reference> list     # tool and version, one per line
podman run --rm --entrypoint sentinel-toolset <reference> check    # exit 1 naming what is missing
podman run --rm --entrypoint sentinel-toolset <reference> absent   # the refused commands
```

**Pinned by digest.** A worker states this image the way it states any runner image, by digest under
`[runner] image` ([configuration](configuration.md#runner-image)); a tag is refused.
[`scripts/release/publish-runner-image.sh`](../scripts/release/publish-runner-image.sh) builds, pushes and
prints that line:

```sh
RUNNER_IMAGE=ubuntu-2404 scripts/release/publish-runner-image.sh ghcr.io/rusticstack/sentinel-runner-ubuntu-2404
# a worker pins this line:
# image = "ghcr.io/rusticstack/sentinel-runner-ubuntu-2404@sha256:…"
```

`PUBLISH=0` builds and checks without pushing. Each architecture publishes its own digest.

**Rebuilt on a schedule.** [`.github/workflows/runner-image.yml`](../.github/workflows/runner-image.yml)
builds the amd64 image weekly, on every pull request that touches what it is made of, and on demand. It
checks the toolset, checks that a left-out command is refused by name, and checks this page against the
manifest. It publishes only when the repository variable `RUNNER_IMAGE_REPOSITORY` names where: a
scheduled or manual run on `main` then pushes the image and writes the digest line to the run's summary.
A rebuild moves the Ubuntu packages under the toolset; a pinned version moves only in a commit that also
moves its checksum and its row above. A new digest reaches a job only when an operator pins it.

## Windows Server 2025

A Windows job runs in a guest, not a container ([backlog](backlog.md) AR04), so the Windows image is a
guest disk and what this repository carries is what provisions it:
[`examples/runner/windows/provision.ps1`](../examples/runner/windows/provision.ps1) reads the `windows`
rows of the same manifest, checks each download against its checksum, and lays the runner under `-Root`
and the toolchains under `-ToolCache`. It writes the runner's `.env` and `.path` files, which the runner
gives every job, and changes nothing else on the machine: no registry key, no machine `PATH`, no service.
What it installed is listed in `sentinel-toolset.tsv` beside the runner.

[`examples/runner/windows/sentinel-runner.ps1`](../examples/runner/windows/sentinel-runner.ps1) is the
entry point, with the Linux one's contract: the just-in-time configuration arrives on standard input,
bounded at 131072 bytes, and an empty, oversized or multi-line input is refused without being echoed
([runner mode](runner-mode.md#the-configuration-is-a-credential)).

There is no scheduled rebuild for Windows: nothing boots a Windows guest yet, so there is no image to
rebuild and no digest to pin until the guest sandbox exists.

## What is verified, and what is not

- **Built and checked by CI**: the amd64 Ubuntu 24.04 image, on every change, with the toolset check
  and the refusal check above.
- **Not verified anywhere yet**: the arm64 image (its rows are pinned, no arm64 build has run); a real
  setup action resolving from the tool cache inside a runner sandbox without a download, which is this
  item's gate and needs a real just-in-time configuration on a verification host; the JDK directory
  names against `setup-java` itself; and `provision.ps1` on Windows Server 2025.
- The checksums for `python`, the Windows runner archive and MinGit were computed from the downloaded
  release archives, because those publishers state them only in release metadata; every other checksum
  is the publisher's own published value.
