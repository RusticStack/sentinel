# Releasing and verifying Sentinel

How a Sentinel release is built, what it contains, and how anyone holding the archives checks them. This is task V01 in [TODO](../TODO.md). The systemd units shipped in the server and worker packages, and the release profile, are in [deployment](deployment.md).

## What a release contains

| Archive | Contents | Built as |
|---|---|---|
| `sentinel-<version>-<arch>-linux-server.tar.gz` | `bin/sentinel`, the server unit, the web unit, `server.toml` | `-p sentinel --features server` |
| `sentinel-<version>-<arch>-linux-worker.tar.gz` | `bin/sentinel`, the worker unit, `worker.toml` | `-p sentinel --features worker` |
| `sentinel-<version>-<arch>-linux-cli.tar.gz` | `bin/sentinel` (`pipeline`, `api`, `auth`, `mcp`; no role) | `-p sentinel`, default features |
| `sentinel-agent-<version>-<arch>-linux-musl.tar.gz` | `bin/sentinel-agent`, the static guest `/init` of microVM jobs | `-p sentinel-agent --target <arch>-unknown-linux-musl` |
| `sentinel-<version>-x86_64-windows-cli.zip` | `bin\sentinel.exe` (CLI only; controllers and workers are Linux) | `-p sentinel`, default features |
| `SHA256SUMS` | the SHA-256 of every archive above, in `sha256sum` format | |
| `release-manifest.json` | the same digests as machine-readable data | |

`<arch>` is `x86_64` or `aarch64`. Every archive has one top directory named like the archive, holding the `LICENSE`, the [third-party inventory](#dependency-and-license-inventory) and a `BUILD-INFO` file (package, version, commit, dirty flag, architecture, `rustc`). The role packages are separate binaries on purpose: a worker host carries no controller code and the reverse.

## Building

Needs the toolchain pinned in `rust-toolchain.toml` (rustup installs it on first use), a clean checkout of the release commit, and a `Cargo.lock` that already holds every dependency: all builds use `--locked`.

On each Linux architecture (an x86_64 host and an arm64 host; every host packages the architecture it runs on, there is no cross-compilation):

```sh
rustup target add "$(uname -m)-unknown-linux-musl"   # once, for the guest agent
scripts/release/package.sh build --out dist
```

`build` refuses a working tree with uncommitted changes to tracked files (`--allow-dirty` marks the package `dirty: true` in `BUILD-INFO`, for development), writes the four Linux archives, `SHA256SUMS` and `release-manifest.json`, and runs `verify` as its last step. `--skip-agent` leaves the agent out when the musl target is not installed.

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

With the repository, `scripts/release/package.sh verify --out <dir>` checks more: the sums, that every archive is in both `SHA256SUMS` and `release-manifest.json` with the same digest, that every expected file is inside, that each archive's `BUILD-INFO` names the manifest's commit, that each Linux `bin/sentinel` runs (`--version`, so run it on a host of the archive's architecture) and that the agent has no program interpreter (it is static). The Windows zip is checked by content only.

### The digest manifest

`release-manifest.json` is for programs, such as the worker bootstrap the controller generates (Q11), which pins an exact worker build and verifies its digest before installing:

```json
{
  "schema": 1,
  "version": "0.1.0-dev",
  "commit": "<40 hex digits>",
  "artifacts": [
    {"file": "sentinel-0.1.0-dev-x86_64-linux-worker.tar.gz", "kind": "worker", "os": "linux", "arch": "x86_64", "sha256": "<64 hex digits>", "bytes": 12345678}
  ]
}
```

`kind` is `server`, `worker`, `cli` or `agent`; `os` is `linux` or `windows`; `arch` is `x86_64` or `aarch64`. `schema` changes only when a field is removed or changes meaning; a consumer ignores fields it does not know. The manifest carries digests, not trust: it is as trustworthy as the channel it came from, so a consumer fetches it over the same authenticated channel as the controller itself, or checks a signature on `SHA256SUMS`.

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

## Dependency and license inventory

`THIRD-PARTY-LICENSES.md` lists every crate in the dependency graph of the release targets (Linux x86_64 and arm64, static musl, Windows x86_64; development-only dependencies excluded) with its license, followed by every distinct license text. It ships in every archive. [`cargo about`](https://github.com/EmbarkStudios/cargo-about) generates it from `about.toml` and `about.hbs`; do not edit it by hand.

The policy is `deny.toml`, for [`cargo deny`](https://github.com/EmbarkStudios/cargo-deny): permissive licenses only (MIT, Apache-2.0, BSD, ISC, Zlib, Unicode, CC0, MPL-2.0, CDLA-Permissive-2.0), no wildcard version requirements, and crates only from crates.io. A dependency under another license, or from a git source, fails the check until a person decides it is acceptable and adds it, with the reason, to both `deny.toml` and `about.toml`.

```sh
cargo licenses                              # the policy: bans, licenses, sources (needs cargo-deny)
scripts/release/check-inventory.sh          # the policy, and whether THIRD-PARTY-LICENSES.md is current (needs cargo-about too)
scripts/release/check-inventory.sh --write  # regenerate it after a dependency change, then commit it
```

Run `check-inventory.sh` whenever `Cargo.lock` changes. Security advisories are not part of it, because they need the advisory database from the network and change daily; run `cargo deny check advisories` before a release.
