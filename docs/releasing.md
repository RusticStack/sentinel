# Releasing and verifying Sentinel

How a Sentinel release is built, what it contains, and how anyone holding the archives checks them. This is task V01 in [TODO](../TODO.md). The systemd units shipped in the server and worker packages, and the release profile, are in [deployment](deployment.md).

## What a release contains

| Archive | Contents | Built as |
|---|---|---|
| `sentinel-<version>-<arch>-linux-server.tar.gz` | `bin/sentinel`, the server unit, the web unit, `server.toml`, the container examples (the web image example, `Containerfile.web`, builds from the `web/` directory of the source tag, not from the package: [deployment](deployment.md#the-web-interface)) | `-p sentinel --features server` |
| `sentinel-<version>-<arch>-linux-worker.tar.gz` | `bin/sentinel`, the worker unit, `worker.toml`; on x86_64 also `microvm/` (Firecracker, the guest kernel, the agent: [below](#microvm-assets)) | `-p sentinel --features worker` |
| `sentinel-<version>-<arch>-linux-cli.tar.gz` | `bin/sentinel` (`pipeline`, `api`, `auth`, `mcp`; no role) | `-p sentinel`, default features |
| `sentinel-agent-<version>-<arch>-linux-musl.tar.gz` | `bin/sentinel-agent`, the static guest `/init` of microVM jobs | `-p sentinel-agent --target <arch>-unknown-linux-musl` |
| `sentinel-<version>-x86_64-windows-cli.zip` | `bin\sentinel.exe` (CLI only; controllers and workers are Linux) | `-p sentinel`, default features |
| `SHA256SUMS` | the SHA-256 of every archive above, in `sha256sum` format | |
| `release-manifest.json` | the same digests as machine-readable data, plus the pinned helper digests ([below](#the-release-manifest)) | |

`<arch>` is `x86_64` or `aarch64`. Every archive has one top directory named like the archive, holding the `LICENSE`, the [third-party inventory](#dependency-and-license-inventory) and a `BUILD-INFO` file (package, version, commit, dirty flag, architecture, `rustc`). The role packages are separate binaries on purpose: a worker host carries no controller code and the reverse.

## Building

Needs the toolchain pinned in `rust-toolchain.toml` (rustup installs it on first use), a clean checkout of the release commit, and a `Cargo.lock` that already holds every dependency: all builds use `--locked`.

On each Linux architecture (an x86_64 host and an arm64 host; every host packages the architecture it runs on, there is no cross-compilation):

```sh
rustup target add "$(uname -m)-unknown-linux-musl"   # once, for the guest agent
scripts/release/package.sh build --out dist
```

`build` refuses a working tree with uncommitted changes to tracked files (`--allow-dirty` marks the package `dirty: true` in `BUILD-INFO`, for development), writes the four Linux archives, `SHA256SUMS` and `release-manifest.json`, and runs `verify` as its last step. `--skip-agent` leaves the agent out when the musl target is not installed (and with it the x86_64 worker's `microvm/`). On x86_64 `build` also needs the microVM inputs, see [microVM assets](#microvm-assets); `--skip-microvm` builds the worker without them, for development.

On Windows x86_64, from PowerShell:

```powershell
scripts\release\package.ps1 -Out dist
```

It builds the CLI and writes the zip. Copy every host's archives into one directory, then in the checkout of the same commit:

```sh
scripts/release/package.sh assemble --out dist   # rewrites SHA256SUMS and release-manifest.json over everything in dist
scripts/release/package.sh verify --out dist
```

`assemble` takes the commit and version from the checkout it runs in, so run it at the release commit; `verify` fails when an archive's `BUILD-INFO` names another commit.

## Verification record

`package.sh build` and `verify` ran clean from a clean checkout of the same commit on both Linux hosts: x86_64 (12 cores, with the pinned microVM inputs; the worker package carries `microvm/`) and aarch64 (2 vCPU, about 11 minutes of release builds). On aarch64 the worker package holds a `AArch64` binary, no `microvm/` and no Firecracker or kernel file, `worker --check` accepts a configuration, and the manifest lists `tailcat` for both architectures. `worker --check` on the x86_64 host reports `microvm=unavailable: no usable /dev/kvm` because that host has no KVM; a microVM run needs a KVM host. Digests of that build (the digests change with every commit, so re-run it for a release):

```
x86_64  cli     a6ba30e0f7fe4579590257d89347b4bc77cf6933fc231a75f04b3f5ee54f5241
x86_64  server  d6e879e8b2f6bf5b44d4a4dba3ed14bd4566c3263658728cdc4a0c067ecf048c
x86_64  worker  31d91ad6f2ec50409cab3b0f79751780cad2a5808e0252b095cee4fc7d5d1d2d
x86_64  agent   e50ed6de4bad3ebb6aac66caac345cb35d1f528d695eb283dd9b150eba578278
aarch64 cli     2590f88e46630316384d6346d4198ed45ba0e7615fcf7d4824a2b395db8eef18
aarch64 server  080bc7375c63c494a593618638e6f58c5353d9d3c84dad3b082c631a8e639540
aarch64 worker  ef878cee1ebe5bc9b832d3ca00d8ad919c229ac3153a55984057c1d92197761a
aarch64 agent   33d2b0d7954d2db699a52f2dc85215729243395cab9c937d926a27d17ac0ad2c
```

## Verifying a download

1. Fetch the archives you need and `SHA256SUMS` (and its signature, if the release has one) into one directory.
2. Check the signature first when there is one ([below](#signatures-optional)): whoever can replace an archive can replace the sums next to it.
3. Check the archives:

```sh
sha256sum --check --ignore-missing --strict SHA256SUMS      # Linux
shasum -a 256 --check --ignore-missing SHA256SUMS           # macOS
```

```powershell
(Get-FileHash .\sentinel-<version>-x86_64-windows-cli.zip -Algorithm SHA256).Hash.ToLower()   # compare with its line in SHA256SUMS
```

`--ignore-missing` lets you check only the archives you downloaded: every one that is present must match, and a listed file that is absent is not an error. Without it, every listed archive must be present.

With the repository, `scripts/release/package.sh verify --out <dir>` checks more: the sums, [the manifest](#the-release-manifest), that every archive is in both `SHA256SUMS` and `release-manifest.json` with the same digest, that every expected file is inside, that each archive's `BUILD-INFO` names the manifest's commit, that each Linux `bin/sentinel` runs (`--version`, so run it on a host of the archive's architecture) and that the agent has no program interpreter (it is static). The Windows zip is checked by content only.

### The release manifest

`release-manifest.json` is for programs, such as the worker bootstrap the controller generates (Q11), which pins an exact worker build and verifies its digest before installing. Its version is the `schema` string `sentinel.release/1`:

```json
{
  "schema": "sentinel.release/1",
  "version": "0.1.0-dev",
  "commit": "<40 hex digits>",
  "artifacts": [
    {"file": "sentinel-0.1.0-dev-x86_64-linux-worker.tar.gz", "kind": "worker", "os": "linux", "arch": "x86_64", "sha256": "<64 hex digits>", "bytes": 12345678}
  ],
  "helpers": [
    {"name": "firecracker", "version": "v1.17.0", "arch": "x86_64", "sha256": "<executable>", "license": "Apache-2.0", "source": "<url>", "archive_sha256": "<upstream archive>", "package": "worker", "path": "microvm/firecracker"},
    {"name": "kernel", "version": "6.18.52", "arch": "x86_64", "sha256": "<vmlinux>", "license": "GPL-2.0-only", "source": "<url>", "package": "worker", "path": "microvm/vmlinux"},
    {"name": "tailcat", "version": "v0.6.0", "arch": "x86_64", "sha256": "<executable>", "license": "BSD-3-Clause", "source": "<url>", "archive_sha256": "<upstream archive>"}
  ]
}
```

`artifacts`: `kind` is `server`, `worker`, `cli` or `agent`; `os` is `linux` or `windows`; `arch` is `x86_64` or `aarch64`. `helpers` are the pinned third-party programs ([bundled binaries](#bundled-binaries)): `sha256` is the digest of the executable itself. A helper with `package` and `path` is inside that package (`path` is relative to the archive's top directory), so a consumer can check it after unpacking; one without them is only named, and an installer downloads it from `source` and compares the executable with `sha256` (Tailcat, for Q11's script). The Firecracker and kernel entries are present only when the x86_64 worker in the set carries `microvm/`; Tailcat is always listed, for both architectures. A consumer ignores fields it does not know. The version string changes only when a field is removed or changes meaning ([compatibility](compatibility.md)); a consumer refuses a version it does not know rather than guessing. The manifest carries digests, not trust: it is as trustworthy as the channel it came from, so a consumer fetches it over the same authenticated channel as the controller itself, or checks a signature on `SHA256SUMS`.

`scripts/release/verify-manifest.py` is the reference verifier (Python 3, standard library only; `package.sh verify` runs it):

```sh
python3 -I scripts/release/verify-manifest.py dist/release-manifest.json --dir dist --pins scripts/release/pins.env
```

It rejects, and exits 1 after listing every problem found: a `schema` other than `sentinel.release/1`; an artifact that is missing from the directory, has another size or has another SHA-256; a bundled helper that is missing from its package or whose executable has another SHA-256; and, with `--pins`, any helper digest that is not the one in `scripts/release/pins.env`. `scripts/release/test-verify-manifest.sh` runs each rejection against a synthetic release.

### Signatures (optional)

Releases are not signed yet: no signing key exists. The checksum protects against a corrupted or partial download, not against a compromised download location. When the release process adds signing, the contract is a detached signature over `SHA256SUMS`, published beside it (for example `SHA256SUMS.minisig` or `SHA256SUMS.asc`), with the public key committed to this repository. Verification is then:

```sh
minisign -Vm SHA256SUMS -p sentinel-release.pub     # or: gpg --verify SHA256SUMS.asc SHA256SUMS
sha256sum --check --ignore-missing --strict SHA256SUMS
```

Every archive is covered by `SHA256SUMS`, and the manifest repeats the same digests, so one signature over `SHA256SUMS` covers the set.

## Reproducibility

The archives are deterministic for a given set of binaries: entries are sorted, timestamps are the commit's, ownership is numeric root, gzip is written with `-n`, and the zip uses the commit's timestamp and forward-slash entry names.

The binaries are not claimed to be reproducible. They are built with the pinned toolchain and `--locked` dependencies, but paths, the linker and the C toolchain used by build scripts (the bundled SQLite, `ring`) can leave a mark, and a bit-for-bit comparison of two builds has not been measured. `BUILD-INFO` records the commit and `rustc` so a rebuild can be compared on equal terms. Treat a digest as identifying a published file, not a source tree.

## microVM assets

The x86_64 worker package carries everything the Firecracker executor needs, in `microvm/`, laid out for the `[microvm]` keys of `examples/worker.toml`:

| File in the package | Installed to (`install.sh`) | `[microvm]` key |
|---|---|---|
| `microvm/firecracker` (v1.17.0, unmodified upstream executable) | `/usr/local/bin/firecracker` | `firecracker` |
| `microvm/sentinel-agent` (the static musl guest agent, the same build as the agent archive) | `/usr/local/bin/sentinel-agent` | `agent` |
| `microvm/vmlinux` (Linux 6.18.52 guest kernel) | `/var/lib/sentinel-microvm/vmlinux` | `kernel` |

Also in `microvm/`: `install.sh`, `SHA256SUMS` (the three files and `vmlinux.config`), `SOURCES.md` (licences and the kernel source offer), `vmlinux.config` and `vmlinux.build` (the kernel configuration and the compiler it was built with), `build-kernel.sh` (the script that built it) and `licenses/` (Firecracker's `LICENSE`, `NOTICE` and `THIRD-PARTY`). The arm64 worker has no `microvm/`: the guest kernel configuration is x86_64 only.

On a KVM host, after unpacking the worker archive:

```sh
sudo sentinel-0.1.0-x86_64-linux-worker/microvm/install.sh     # checks SHA256SUMS first, then installs the three files
sentinel worker --config /etc/sentinel/worker.toml --check      # prints "microvm=ready"
```

`install.sh` prints the `[microvm]` section to add; it never edits the configuration. `worker --check` appends `microvm=ready` when the section is present and everything works, or `microvm=unavailable: <every problem>`: each missing or non-executable file by path (`firecracker …: not an executable file; /var/lib/sentinel-microvm/vmlinux: no guest kernel; agent …`) and, when the files are fine, why `/dev/kvm` is not usable. Without a `[microvm]` section the message is absent and the worker runs containers only. The worker itself logs the same text as `runtime_selected` at start.

### Building the inputs

`build` takes Firecracker and the kernel from `--assets DIR` (default `<target dir>/release-assets`) and refuses any file whose SHA-256 is not the one in `scripts/release/pins.env`:

```sh
scripts/release/package.sh fetch-assets --assets assets            # downloads firecracker-v1.17.0-x86_64.tgz, checks it
bench/microvm/build-kernel.sh assets                                # writes vmlinux-6.18.52, .config and .build (needs podman)
scripts/release/package.sh build --out dist --assets assets
```

The Firecracker pin is the checksum Firecracker publishes beside its release archive (`firecracker-v1.17.0-x86_64.tgz.sha256.txt`); `fetch-assets` fails on any other bytes, and `build` checks the extracted executable against its own pin too. `build-kernel.sh` downloads the kernel tarball, verifies it against kernel.org's `sha256sums.asc`, applies Firecracker's CI guest configuration for that tag and builds in a throwaway container with a fixed build stamp (`KBUILD_BUILD_USER`, `KBUILD_BUILD_HOST`, `KBUILD_BUILD_TIMESTAMP`), so the same source, configuration and compiler version give the same bytes. The compiler comes from the builder image's package manager, so its version is recorded in `vmlinux-6.18.52.build` and a different compiler can produce a different digest; the pin names the build that was measured and shipped. Changing the kernel, Firecracker or the configuration means rebuilding, then updating `pins.env` in the same commit (the `KERNEL_SHA256` and `KERNEL_CONFIG_SHA256` lines are what `build-kernel.sh` printed and wrote).

### Kernel source offer

The kernel is GPL-2.0-only. Its corresponding source is the upstream tarball (URL and SHA-256 in `SOURCES.md` inside the package), the shipped `vmlinux.config` and the shipped `build-kernel.sh`, with a written offer in `SOURCES.md` to supply it on request for three years. No patches are applied. The same text is the offer referred to by the [inventory](#bundled-binaries).

## Dependency and license inventory

`THIRD-PARTY-LICENSES.md` lists every crate in the dependency graph of the release targets (Linux x86_64 and arm64, static musl, Windows x86_64; development-only dependencies excluded) with its license, followed by every distinct license text. It ships in every archive. [`cargo about`](https://github.com/EmbarkStudios/cargo-about) generates it from `about.toml` and `about.hbs`; do not edit it by hand.

The policy is `deny.toml`, for [`cargo deny`](https://github.com/EmbarkStudios/cargo-deny): permissive licenses only (MIT, Apache-2.0, BSD, ISC, Zlib, Unicode, CC0, MPL-2.0, CDLA-Permissive-2.0), no wildcard version requirements, and crates only from crates.io. A dependency under another license, or from a git source, fails the check until a person decides it is acceptable and adds it, with the reason, to both `deny.toml` and `about.toml`.

```sh
cargo licenses                              # the policy: bans, licenses, sources (needs cargo-deny)
scripts/release/check-inventory.sh          # the policy, and whether THIRD-PARTY-LICENSES.md is current (needs cargo-about too)
scripts/release/check-inventory.sh --write  # regenerate it after a dependency change, then commit it
```

Run `check-inventory.sh` whenever `Cargo.lock` changes. Security advisories are not part of it, because they need the advisory database from the network and change daily; run `cargo deny check advisories` before a release.

### Bundled binaries

The crate inventory above covers Rust code. The release also carries, or names for download, these programs. Their licences are fixed by `scripts/release/pins.env`; a new one is added there, in the manifest `helpers` and here together.

| Program | Where | Licence | Pinned by | Source |
|---|---|---|---|---|
| Firecracker v1.17.0 | x86_64 worker, `microvm/firecracker` | Apache-2.0 (`LICENSE`, `NOTICE` and `THIRD-PARTY` shipped in `microvm/licenses/`) | the upstream published checksum of the release archive and the digest of the executable | https://github.com/firecracker-microvm/firecracker/tree/v1.17.0 |
| Linux 6.18.52 guest kernel | x86_64 worker, `microvm/vmlinux` | GPL-2.0-only; source offer in [above](#kernel-source-offer) and `microvm/SOURCES.md` | digest of the built `vmlinux` and of its `.config` | https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.18.52.tar.xz |
| Sentinel guest agent (musl, static) | x86_64 worker `microvm/sentinel-agent`, and the agent archive | Sentinel's licence; Rust dependencies in `THIRD-PARTY-LICENSES.md` | the release build | this repository |
| Tailcat v0.6.0 | not packaged: the worker enrollment script (Q11) downloads it | BSD-3-Clause | digest of the executable and of the upstream archive, both architectures | https://github.com/tailscale/tailcat/releases/tag/v0.6.0 |

Produced by a documented command that fails on a disallowed licence: `cargo licenses` (policy) and `scripts/release/check-inventory.sh` (policy and current `THIRD-PARTY-LICENSES.md`), both runnable on the verification hosts with `cargo-deny` and `cargo-about` installed; `cargo deny check advisories` adds the security advisories before a release. Duplicate crate versions are reported as warnings by the `bans` check. The web (pnpm) inventory belongs to the web interface and is not part of this one.

Qualifying a release as a whole (install, upgrade, recovery, revocation, worker loss, secrets, caches, diagnostics, egress, compatibility) is `scripts/qualify/qualify.sh`; see [qualification](qualification.md).
