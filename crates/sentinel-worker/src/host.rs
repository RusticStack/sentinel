//! What the worker's host can run (plan 16.8, runtime selection).

use std::fmt;

/// Hardware virtualization as the worker account sees it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Virtualization {
    /// `/dev/kvm` opened read-write by this account and a throwaway VM created in it.
    pub kvm: bool,
    /// The host is itself a guest, so KVM here is nested virtualization.
    pub nested: bool,
}

/// Why KVM counts as absent; a device the account cannot use is absent.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Absent(pub String);

impl fmt::Display for Absent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Probes KVM the way a VMM would use it: open the device, check the stable API version, create a VM.
#[cfg(target_os = "linux")]
pub fn kvm() -> Result<(), Absent> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    // linux/kvm.h: _IO(KVMIO, 0x00) and _IO(KVMIO, 0x01); the API version has been 12 since Linux 2.6.22.
    const KVM_GET_API_VERSION: libc::c_ulong = 0xAE00;
    const KVM_CREATE_VM: libc::c_ulong = 0xAE01;
    const KVM_API_VERSION: libc::c_int = 12;

    let device = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .map_err(|e| Absent(format!("/dev/kvm: {e}")))?;
    // SAFETY: both ioctls take no argument pointer and only read the open descriptor.
    let version = unsafe { libc::ioctl(device.as_raw_fd(), KVM_GET_API_VERSION, 0) };
    if version != KVM_API_VERSION {
        return Err(Absent(format!(
            "/dev/kvm reports API version {version}, not {KVM_API_VERSION}"
        )));
    }
    // SAFETY: as above; a non-negative result is a new descriptor this function owns.
    let vm = unsafe { libc::ioctl(device.as_raw_fd(), KVM_CREATE_VM, 0) };
    if vm < 0 {
        return Err(Absent(format!(
            "KVM_CREATE_VM failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    // SAFETY: `vm` is a fresh descriptor returned by the kernel and owned by nothing else.
    drop(unsafe { OwnedFd::from_raw_fd(vm) });
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn kvm() -> Result<(), Absent> {
    Err(Absent("KVM is a Linux interface".into()))
}

/// Whether the CPU reports running under a hypervisor (CPUID leaf 1, ECX bit 31).
pub fn under_hypervisor() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        let leaf = std::arch::x86_64::__cpuid(1);
        leaf.ecx & (1 << 31) != 0
    }
    #[cfg(not(target_arch = "x86_64"))]
    {
        // arm64 has no architectural equivalent; the device tree or DMI would, and nesting there is out of scope.
        false
    }
}

/// Detects the host's virtualization; `Err` carries why KVM is absent, for the startup log.
pub fn detect() -> (Virtualization, Option<Absent>) {
    match kvm() {
        Ok(()) => (
            Virtualization {
                kvm: true,
                nested: under_hypervisor(),
            },
            None,
        ),
        Err(why) => (Virtualization::default(), Some(why)),
    }
}

/// The executors a worker can run jobs on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Isolation {
    Container,
    Microvm,
}

impl Isolation {
    pub const fn as_str(self) -> &'static str {
        match self {
            Isolation::Container => "container",
            Isolation::Microvm => "microvm",
        }
    }
}

/// The operator's `isolation` setting for a worker.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Preference {
    /// The plan's runtime-selection table: a microVM where KVM is usable and the microVM executor is set up,
    /// rootless Podman otherwise.
    #[default]
    Auto,
    Container,
    Microvm,
}

impl Preference {
    pub fn parse(text: &str) -> Option<Preference> {
        match text {
            "auto" => Some(Preference::Auto),
            "container" => Some(Preference::Container),
            "microvm" => Some(Preference::Microvm),
            _ => None,
        }
    }
}

/// What a Linux worker runs: the executors it offers and the default for jobs that state none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Selection {
    pub default: Isolation,
    pub microvm: bool,
    pub virtualization: Virtualization,
}

/// Applies the runtime-selection table. `microvm_ready` says whether the microVM executor is set up
/// (VMM, guest kernel); an explicit `microvm` preference without it is a configuration error.
pub fn select(
    preference: Preference,
    virtualization: Virtualization,
    absent: Option<&Absent>,
    microvm_ready: Result<(), String>,
) -> Result<Selection, String> {
    let microvm = match (&microvm_ready, virtualization.kvm) {
        (Ok(()), true) => Ok(()),
        (Err(why), _) => Err(why.clone()),
        (Ok(()), false) => {
            Err(absent.map_or_else(|| "KVM is not usable".to_owned(), |a| a.0.clone()))
        }
    };
    let default = match (preference, &microvm) {
        (Preference::Container, _) => Isolation::Container,
        (Preference::Microvm, Ok(())) | (Preference::Auto, Ok(())) => Isolation::Microvm,
        (Preference::Auto, Err(_)) => Isolation::Container,
        (Preference::Microvm, Err(why)) => {
            return Err(format!(
                "isolation = \"microvm\", but microVMs cannot run here: {why}"
            ));
        }
    };
    Ok(Selection {
        default,
        microvm: microvm.is_ok(),
        virtualization,
    })
}

/// What the worker states it can run; a job that states an OS or isolation is placed only where they match.
/// A Linux worker always offers containers; `kvm` and `kvm.nested` report the host, `isolation.microvm` only
/// that the microVM executor can actually run here.
pub fn capabilities(selection: &Selection) -> sentinel_protocol::negotiate::Capabilities {
    use sentinel_protocol::negotiate::Capabilities as C;
    let mut bits = C::OS_LINUX.union(C::ISOLATION_CONTAINER);
    if selection.virtualization.kvm {
        bits = bits.union(C::KVM);
    }
    if selection.virtualization.nested {
        bits = bits.union(C::KVM_NESTED);
    }
    if selection.microvm {
        bits = bits.union(C::ISOLATION_MICROVM);
    }
    bits
}

/// The one-line record `worker --check` prints for this host: detection, why KVM is absent when it is, the
/// default executor and the capability bits the worker would state.
pub fn report(selection: &Selection, absent: Option<&Absent>) -> String {
    let bits = capabilities(selection).runtime_names();
    let mut text = format!(
        "runtime: kvm={} nested={} default={} capabilities={}",
        selection.virtualization.kvm,
        selection.virtualization.nested,
        selection.default.as_str(),
        bits.join(",")
    );
    if let Some(why) = absent {
        text.push_str(&format!(" kvm_absent=\"{why}\""));
    }
    text
}

#[cfg(test)]
mod tests {
    use super::*;

    const KVM: Virtualization = Virtualization {
        kvm: true,
        nested: false,
    };

    #[test]
    fn auto_prefers_a_microvm_only_where_one_can_run() {
        let s = select(Preference::Auto, KVM, None, Ok(())).unwrap();
        assert_eq!((s.default, s.microvm), (Isolation::Microvm, true));
        let s = select(Preference::Auto, KVM, None, Err("no guest kernel".into())).unwrap();
        assert_eq!((s.default, s.microvm), (Isolation::Container, false));
        let none = Absent("/dev/kvm: No such file or directory".into());
        let s = select(
            Preference::Auto,
            Virtualization::default(),
            Some(&none),
            Ok(()),
        )
        .unwrap();
        assert_eq!((s.default, s.microvm), (Isolation::Container, false));
    }

    #[test]
    fn an_operator_override_wins_and_an_impossible_one_is_refused() {
        let s = select(Preference::Container, KVM, None, Ok(())).unwrap();
        assert_eq!(
            (s.default, s.microvm),
            (Isolation::Container, true),
            "still offered to jobs that ask"
        );
        let s = select(Preference::Microvm, KVM, None, Ok(())).unwrap();
        assert_eq!(s.default, Isolation::Microvm);
        let none = Absent("/dev/kvm: Permission denied".into());
        let error = select(
            Preference::Microvm,
            Virtualization::default(),
            Some(&none),
            Ok(()),
        )
        .unwrap_err();
        assert!(error.contains("Permission denied"), "{error}");
        let error = select(
            Preference::Microvm,
            KVM,
            None,
            Err("no guest kernel".into()),
        )
        .unwrap_err();
        assert!(error.contains("no guest kernel"), "{error}");
    }

    #[test]
    fn preferences_parse() {
        assert_eq!(Preference::parse("auto"), Some(Preference::Auto));
        assert_eq!(Preference::parse("microvm"), Some(Preference::Microvm));
        assert_eq!(Preference::parse("container"), Some(Preference::Container));
        assert_eq!(Preference::parse("vm"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn detection_agrees_with_the_device() {
        // On a host without KVM (reference-host) this must report absent with a reason; on kvm-host, usable.
        let (v, absent) = detect();
        eprintln!("detected: {v:?}, absent: {absent:?}");
        assert_eq!(v.kvm, absent.is_none());
        if std::env::var_os("SENTINEL_EXPECT_KVM").is_some_and(|v| v == "1") {
            assert!(
                v.kvm,
                "SENTINEL_EXPECT_KVM=1 on a host where KVM is absent: {absent:?}"
            );
        }
        if !std::path::Path::new("/dev/kvm").exists() {
            assert!(!v.kvm);
        }
    }

    fn names(selection: &Selection) -> Vec<&'static str> {
        capabilities(selection).runtime_names()
    }

    #[test]
    fn capability_bits_follow_detection_and_selection() {
        let nested = Virtualization {
            kvm: true,
            nested: true,
        };
        let s = select(Preference::Auto, KVM, None, Ok(())).unwrap();
        assert_eq!(
            names(&s),
            [
                "kvm",
                "isolation.container",
                "isolation.microvm",
                "os.linux"
            ]
        );
        let s = select(Preference::Auto, nested, None, Ok(())).unwrap();
        assert_eq!(
            names(&s),
            [
                "kvm",
                "kvm.nested",
                "isolation.container",
                "isolation.microvm",
                "os.linux"
            ]
        );
        // KVM without a usable microVM executor: the host bit is stated, the isolation is not.
        let s = select(Preference::Auto, KVM, None, Err("no guest kernel".into())).unwrap();
        assert_eq!(names(&s), ["kvm", "isolation.container", "os.linux"]);
        // No KVM: containers only, never a microVM bit.
        let none = Absent("/dev/kvm: No such file or directory".into());
        let s = select(
            Preference::Auto,
            Virtualization::default(),
            Some(&none),
            Ok(()),
        )
        .unwrap();
        assert_eq!(names(&s), ["isolation.container", "os.linux"]);
        assert!(!capabilities(&s).contains(sentinel_protocol::negotiate::Capabilities::KVM));
        // The windows and native bits are never stated by a Linux worker.
        for v in [KVM, nested, Virtualization::default()] {
            let s = select(Preference::Auto, v, None, Ok(())).unwrap();
            let bits = capabilities(&s);
            assert!(!bits.contains(sentinel_protocol::negotiate::Capabilities::OS_WINDOWS));
            assert!(!bits.contains(sentinel_protocol::negotiate::Capabilities::ISOLATION_NATIVE));
        }
    }

    #[test]
    fn a_container_override_still_offers_the_microvm_bit_where_one_can_run() {
        // The override changes the default for jobs that state none, not what the host offers.
        let s = select(Preference::Container, KVM, None, Ok(())).unwrap();
        assert_eq!(s.default, Isolation::Container);
        assert_eq!(
            names(&s),
            [
                "kvm",
                "isolation.container",
                "isolation.microvm",
                "os.linux"
            ]
        );
    }

    #[test]
    fn the_check_record_names_detection_default_and_bits() {
        let s = select(Preference::Auto, KVM, None, Ok(())).unwrap();
        assert_eq!(
            report(&s, None),
            "runtime: kvm=true nested=false default=microvm capabilities=kvm,isolation.container,isolation.microvm,os.linux"
        );
        let none = Absent("/dev/kvm: No such file or directory".into());
        let s = select(
            Preference::Auto,
            Virtualization::default(),
            Some(&none),
            Ok(()),
        )
        .unwrap();
        assert_eq!(
            report(&s, Some(&none)),
            "runtime: kvm=false nested=false default=container capabilities=isolation.container,os.linux kvm_absent=\"/dev/kvm: No such file or directory\""
        );
    }
}
