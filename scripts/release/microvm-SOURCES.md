# Sources and licences of the microVM files

This directory of the Sentinel x86_64 worker package carries three programs that are not Sentinel's own code, and Sentinel's own guest agent.

| File | What it is | Licence | Source |
|---|---|---|---|
| `firecracker` | Firecracker v1.17.0, the virtual machine monitor, unmodified from the upstream release | Apache-2.0 (`licenses/firecracker-LICENSE`, `licenses/firecracker-NOTICE`, `licenses/firecracker-THIRD-PARTY`) | https://github.com/firecracker-microvm/firecracker/tree/v1.17.0 (release archive `firecracker-v1.17.0-x86_64.tgz`, SHA-256 `06094a1108ae9e82aa4c23a775aa92758f53f1175d422270d9d6162cb9ade558`, the checksum Firecracker publishes beside it) |
| `vmlinux` | the Linux 6.18.52 guest kernel, built with Firecracker's own CI guest configuration | GPL-2.0-only, with the Linux-syscall-note | see "Kernel source" below |
| `sentinel-agent` | the static guest agent that runs as the VM's `/init` | Sentinel's licence (`../LICENSE`); its Rust dependencies are in `../THIRD-PARTY-LICENSES.md` | this repository, `crates/sentinel-agent` |

## Kernel source

The kernel is GPL-2.0-only. The complete corresponding source for `vmlinux` is:

1. the upstream tarball https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.18.52.tar.xz (SHA-256 `2b69564f7d4fea0c859b1959ba33709ee6e9139bd100e30a853b57159a8221b8`, from kernel.org's `sha256sums.asc`), unmodified;
2. the build configuration `vmlinux.config`, in this directory, which is Firecracker's `resources/guest_configs/microvm-kernel-ci-x86_64-6.18.config` at tag v1.17.0 after `make olddefconfig`;
3. the build script `build-kernel.sh`, in this directory, which applies no patches.

Written offer: for at least three years after a release, anyone who received `vmlinux` from it may request the corresponding source, as one archive, from the project's issue tracker at https://github.com/RusticStack/sentinel/issues, and it will be supplied at no more than the cost of providing it. The three items above are normally enough to rebuild the kernel: `./build-kernel.sh <output directory>` (needs `podman` and network access) writes `vmlinux-6.18.52`, and with the same compiler version, which `vmlinux.build` records, it produces the digest in `SHA256SUMS` and the release manifest.

## Checking the files

`SHA256SUMS` lists the files that `install.sh` installs. The release manifest (`release-manifest.json`) carries the same digests under `helpers`; `scripts/release/verify-manifest.py` checks them.
