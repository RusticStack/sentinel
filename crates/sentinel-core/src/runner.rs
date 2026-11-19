//! GitHub Actions runner mode's vocabulary: the labels a workflow may name and the two
//! permissions the one App needs for it. A label Sentinel does not define is not ours;
//! a label naming a class the deployment does not serve is ours and refused.

use std::fmt;

/// The operating system and architecture a class runs, which is what tells the pools
/// that can serve it apart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RunnerOs {
    Ubuntu2404,
    Ubuntu2404Arm,
    Windows2025,
}

impl RunnerOs {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ubuntu2404 => "ubuntu-2404",
            Self::Ubuntu2404Arm => "ubuntu-2404-arm",
            Self::Windows2025 => "windows-2025",
        }
    }

    pub const fn is_windows(self) -> bool {
        matches!(self, Self::Windows2025)
    }

    pub const fn is_arm(self) -> bool {
        matches!(self, Self::Ubuntu2404Arm)
    }
}

/// Every Sentinel label starts here; nothing else in a `runs-on:` list is a demand.
pub const LABEL_PREFIX: &str = "sentinel-";

/// The largest vCPU count a label may name. The deployment's own class list decides
/// what it serves; this only bounds the number a label can claim.
pub const MAX_VCPUS: u16 = 128;

/// A resource class a job asks for: `sentinel-<n>vcpu-<os>` (plan 16.10). `n` CPUs
/// with the memory and disk the deployment gives that class.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct RunnerClass {
    pub vcpus: u16,
    pub os: RunnerOs,
}

impl RunnerClass {
    /// The class one label names, or `None` when the label is not a Sentinel label at
    /// all (another runner's, `self-hosted`, `linux`) or is not in the documented form.
    pub fn parse(label: &str) -> Option<Self> {
        let rest = label.strip_prefix(LABEL_PREFIX)?;
        let (vcpus, os) = rest.split_once("vcpu-")?;
        if vcpus.is_empty() || vcpus.len() > 3 || vcpus.starts_with('0') {
            return None;
        }
        let mut n: u16 = 0;
        for byte in vcpus.bytes() {
            if !byte.is_ascii_digit() {
                return None;
            }
            n = n * 10 + u16::from(byte - b'0');
        }
        if !(1..=MAX_VCPUS).contains(&n) {
            return None;
        }
        let os = match os {
            "ubuntu-2404" => RunnerOs::Ubuntu2404,
            "ubuntu-2404-arm" => RunnerOs::Ubuntu2404Arm,
            "windows-2025" => RunnerOs::Windows2025,
            _ => return None,
        };
        Some(Self { vcpus: n, os })
    }

    /// The class a job's whole label set names. `None` means no label is ours, so the
    /// job is another runner's and Sentinel ignores it; `Conflict` means the set names
    /// two of our classes, which no one runner can satisfy.
    pub fn of_labels<'a>(labels: impl IntoIterator<Item = &'a str>) -> Labelled {
        let mut found = None;
        for label in labels {
            let Some(class) = Self::parse(label) else {
                continue;
            };
            match found {
                None => found = Some(class),
                Some(first) if first == class => {}
                Some(_) => return Labelled::Conflict,
            }
        }
        match found {
            Some(class) => Labelled::Class(class),
            None => Labelled::None,
        }
    }
}

impl fmt::Display for RunnerClass {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{LABEL_PREFIX}{}vcpu-{}", self.vcpus, self.os.as_str())
    }
}

/// What a label set says about the class it wants.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Labelled {
    /// No label is a Sentinel label: not our job.
    None,
    Class(RunnerClass),
    /// More than one Sentinel class: no runner Sentinel provisions satisfies both.
    Conflict,
}

/// What runner mode needs beyond the base App, as a bitset so an installation snapshot
/// carries it in one column. `actions` read delivers `workflow_job`; registering a
/// runner needs organization self-hosted runners write, or repository administration
/// write where a personal namespace has no organization.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RunnerPermissions(u8);

impl RunnerPermissions {
    const ACTIONS: u8 = 0b01;
    const REGISTER: u8 = 0b10;

    pub const NONE: Self = Self(0);
    pub const ALL: Self = Self(0b11);

    /// The bits an installation snapshot states, or `None` for bits this build does not know.
    pub const fn from_bits(bits: u8) -> Option<Self> {
        if bits & !Self::ALL.0 == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    pub const fn bits(self) -> u8 {
        self.0
    }

    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    pub const fn grants(actions: bool, register: bool) -> Self {
        let mut bits = 0;
        if actions {
            bits |= Self::ACTIONS;
        }
        if register {
            bits |= Self::REGISTER;
        }
        Self(bits)
    }

    /// What is missing, named as GitHub's App settings name it. An installation of a
    /// personal namespace has no organization to register runners in, so it asks for
    /// repository administration write instead.
    pub const fn missing(self, personal: bool) -> &'static [&'static str] {
        const NONE: &[&str] = &[];
        const ACTIONS: &[&str] = &["actions"];
        const REGISTER: &[&str] = &["organization_self_hosted_runners"];
        const REGISTER_PERSONAL: &[&str] = &["administration"];
        const BOTH: &[&str] = &["actions", "organization_self_hosted_runners"];
        const BOTH_PERSONAL: &[&str] = &["actions", "administration"];
        let actions = self.contains(Self(Self::ACTIONS));
        let register = self.contains(Self(Self::REGISTER));
        match (actions, register, personal) {
            (true, true, _) => NONE,
            (false, false, false) => BOTH,
            (false, false, true) => BOTH_PERSONAL,
            (false, true, _) => ACTIONS,
            (true, false, false) => REGISTER,
            (true, false, true) => REGISTER_PERSONAL,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_documented_forms_are_sentinel_labels() {
        assert_eq!(
            RunnerClass::parse("sentinel-4vcpu-ubuntu-2404"),
            Some(RunnerClass {
                vcpus: 4,
                os: RunnerOs::Ubuntu2404
            })
        );
        assert_eq!(
            RunnerClass::parse("sentinel-16vcpu-windows-2025"),
            Some(RunnerClass {
                vcpus: 16,
                os: RunnerOs::Windows2025
            })
        );
        assert_eq!(
            RunnerClass::parse("sentinel-2vcpu-ubuntu-2404-arm").map(|c| c.os),
            Some(RunnerOs::Ubuntu2404Arm)
        );
        for other in [
            "ubuntu-latest",
            "self-hosted",
            "linux",
            "blacksmith-4vcpu-ubuntu-2404",
            "4vcpu-ubuntu-2404",
            "sentinel-ubuntu-2404",
            "sentinel-windows-2025",
            "sentinel-0vcpu-ubuntu-2404",
            "sentinel-04vcpu-ubuntu-2404",
            "sentinel-129vcpu-ubuntu-2404",
            "sentinel--2vcpu-ubuntu-2404",
            "sentinel-2vcpu-ubuntu-2204",
            "sentinel-2vcpu-ubuntu-2404-extra",
            "sentinel-+2vcpu-ubuntu-2404",
            "sentinel-2vcpu-Windows-2025",
            "SENTINEL-2vcpu-ubuntu-2404",
        ] {
            assert_eq!(RunnerClass::parse(other), None, "{other}");
        }
    }

    #[test]
    fn a_label_set_names_one_class_another_runner_or_a_conflict() {
        assert_eq!(
            RunnerClass::of_labels(["self-hosted", "sentinel-2vcpu-ubuntu-2404"]),
            Labelled::Class(RunnerClass {
                vcpus: 2,
                os: RunnerOs::Ubuntu2404
            })
        );
        assert_eq!(
            RunnerClass::of_labels(["sentinel-2vcpu-ubuntu-2404", "sentinel-2vcpu-ubuntu-2404"]),
            Labelled::Class(RunnerClass {
                vcpus: 2,
                os: RunnerOs::Ubuntu2404
            })
        );
        assert_eq!(
            RunnerClass::of_labels(["ubuntu-24.04", "linux"]),
            Labelled::None
        );
        assert_eq!(RunnerClass::of_labels(Vec::<&str>::new()), Labelled::None);
        assert_eq!(
            RunnerClass::of_labels(["sentinel-2vcpu-ubuntu-2404", "sentinel-8vcpu-windows-2025"]),
            Labelled::Conflict
        );
    }

    #[test]
    fn a_class_renders_as_the_label_it_came_from() {
        for label in [
            "sentinel-2vcpu-ubuntu-2404",
            "sentinel-64vcpu-windows-2025",
            "sentinel-1vcpu-ubuntu-2404-arm",
        ] {
            assert_eq!(RunnerClass::parse(label).unwrap().to_string(), label);
        }
    }

    #[test]
    fn the_missing_permissions_are_named_as_the_app_settings_name_them() {
        assert!(RunnerPermissions::ALL.missing(false).is_empty());
        assert!(RunnerPermissions::ALL.missing(true).is_empty());
        assert_eq!(RunnerPermissions::NONE.missing(false), BOTH_ORG);
        assert_eq!(RunnerPermissions::NONE.missing(true), BOTH_PERSONAL);
        assert_eq!(
            RunnerPermissions::grants(true, false).missing(false),
            REGISTER_ORG
        );
        assert_eq!(
            RunnerPermissions::grants(true, false).missing(true),
            REGISTER_PERSONAL
        );
        assert_eq!(
            RunnerPermissions::grants(false, true).missing(false),
            ACTIONS
        );
        assert_eq!(RunnerPermissions::from_bits(4), None);
        assert_eq!(
            RunnerPermissions::from_bits(3),
            Some(RunnerPermissions::ALL)
        );
        assert!(RunnerPermissions::ALL.contains(RunnerPermissions::grants(true, false)));
    }

    const ACTIONS: &[&str] = &["actions"];
    const REGISTER_ORG: &[&str] = &["organization_self_hosted_runners"];
    const REGISTER_PERSONAL: &[&str] = &["administration"];
    const BOTH_ORG: &[&str] = &["actions", "organization_self_hosted_runners"];
    const BOTH_PERSONAL: &[&str] = &["actions", "administration"];
}
