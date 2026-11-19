//! Label table version 1: the `runs-on:` labels a Sentinel runner class serves, the class
//! each one becomes, and why every other label keeps its job on GitHub's runners.
//!
//! A table version is a promise: the same labels map to the same classes and the same
//! stated changes until the version moves, which is a compatibility entry.

use sentinel_core::runner::{RunnerClass, RunnerOs};

pub const LABEL_TABLE_VERSION: u16 = 1;

/// GitHub's standard hosted runner size in vCPUs, which `ubuntu-latest` and `windows-latest`
/// name when they say nothing more.
const HOSTED_VCPUS: u16 = 4;

/// What a job's `runs-on:` becomes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Destination {
    /// The job runs on a Sentinel class.
    Class(ClassTarget),
    /// The job stays on GitHub's runners, for the stated reason.
    Keep(KeepReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClassTarget {
    pub class: RunnerClass,
    /// The stated difference between the label and the class, when the class is not
    /// exactly what the label asked for. Never silent: the preview shows it.
    pub change: Option<&'static str>,
    /// The job needs a Docker daemon, so only a class a Linux microVM guest serves runs it.
    pub requires_microvm: bool,
}

/// Why a job stays on GitHub's runners.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeepReason {
    /// A macOS label: Sentinel has no macOS class.
    MacOs,
    /// A GPU label: Sentinel has no GPU class.
    Gpu,
    /// The job needs a Docker daemon and no class this deployment serves can provide one.
    Docker,
    /// A `${{ }}` label the analyzer cannot resolve to a label set.
    Expression,
    /// No Sentinel class matches the label set.
    NoClass,
}

impl KeepReason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MacOs => "macos",
            Self::Gpu => "gpu",
            Self::Docker => "docker",
            Self::Expression => "expression",
            Self::NoClass => "no_class",
        }
    }

    /// The same reason as a sentence, for a preview that lists the jobs staying behind.
    pub const fn note(self) -> &'static str {
        match self {
            Self::MacOs => "Sentinel has no macOS class",
            Self::Gpu => "Sentinel has no GPU class",
            Self::Docker => "the job needs a Docker daemon no class of this deployment provides",
            Self::Expression => "a `${{ }}` label the analyzer cannot resolve to a label set",
            Self::NoClass => "no Sentinel class matches the label set",
        }
    }
}

/// What a job's `runs-on:` declares, before the table resolves it.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Declared {
    pub labels: Vec<String>,
    /// A named runner group: GitHub's own scaling concept, never a Sentinel class.
    pub group: Option<String>,
}

/// What the deployment's runner-mode classes can offer a job that needs a Docker daemon.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DockerHosts {
    /// Linux classes run in microVM guests, which can carry a daemon.
    MicrovmGuests,
    /// Only container workers exist, which cannot nest a daemon.
    ContainerOnly,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LabelTable {
    version: u16,
}

impl LabelTable {
    pub const V1: Self = Self {
        version: LABEL_TABLE_VERSION,
    };

    pub const fn version(self) -> u16 {
        self.version
    }

    /// The destination of one label set. `needs_docker` is the job's own fact: a
    /// `container:`, a `services:` entry or a `docker://` step.
    pub fn classify(
        self,
        declared: &Declared,
        needs_docker: bool,
        docker: DockerHosts,
    ) -> Destination {
        if declared.group.is_some() {
            return Destination::Keep(KeepReason::NoClass);
        }
        let mut found: Option<(RunnerClass, Option<&'static str>)> = None;
        let mut macos = false;
        let mut gpu = false;
        let mut expression = false;
        for label in &declared.labels {
            let entry = if label.contains("${{") {
                expression = true;
                continue;
            } else {
                entry(label)
            };
            match entry {
                Entry::Class { vcpus, os, change } => {
                    let class = RunnerClass { vcpus, os };
                    match found {
                        None => found = Some((class, change)),
                        Some((first, _)) if first == class => {}
                        // Two labels naming different classes satisfy no one runner.
                        Some(_) => return Destination::Keep(KeepReason::NoClass),
                    }
                }
                Entry::Keep(KeepReason::MacOs) => macos = true,
                Entry::Keep(KeepReason::Gpu) => gpu = true,
                Entry::Keep(_) => {}
            }
        }
        if let Some((class, change)) = found {
            if needs_docker {
                if docker == DockerHosts::ContainerOnly || class.os.is_windows() {
                    return Destination::Keep(KeepReason::Docker);
                }
                return Destination::Class(ClassTarget {
                    class,
                    change,
                    requires_microvm: true,
                });
            }
            return Destination::Class(ClassTarget {
                class,
                change,
                requires_microvm: false,
            });
        }
        if macos {
            return Destination::Keep(KeepReason::MacOs);
        }
        if gpu {
            return Destination::Keep(KeepReason::Gpu);
        }
        if expression {
            return Destination::Keep(KeepReason::Expression);
        }
        Destination::Keep(KeepReason::NoClass)
    }
}

enum Entry {
    Class {
        vcpus: u16,
        os: RunnerOs,
        change: Option<&'static str>,
    },
    Keep(KeepReason),
}

fn class_of(vcpus: u16, os: RunnerOs, change: Option<&'static str>) -> Option<Entry> {
    (1..=sentinel_core::runner::MAX_VCPUS)
        .contains(&vcpus)
        .then_some(Entry::Class { vcpus, os, change })
}

/// One label to its table entry. Ordered so a specific shape is read before a general one.
fn entry(label: &str) -> Entry {
    if let Some(class) = RunnerClass::parse(label) {
        return Entry::Class {
            vcpus: class.vcpus,
            os: class.os,
            change: None,
        };
    }
    if label.starts_with("macos") {
        return Entry::Keep(KeepReason::MacOs);
    }
    if label.contains("gpu") || label.starts_with("nvidia") {
        return Entry::Keep(KeepReason::Gpu);
    }
    blacksmith(label)
        .or_else(|| hosted(label))
        .unwrap_or(Entry::Keep(KeepReason::NoClass))
}

/// `blacksmith-<n>vcpu-<os>-<version>`, the labels the B11 reference runner names.
fn blacksmith(label: &str) -> Option<Entry> {
    let rest = label.strip_prefix("blacksmith-")?;
    let (vcpus, rest) = digits_vcpu(rest)?;
    let (os, version) = rest.split_once('-')?;
    let version = match version
        .strip_suffix("-arm")
        .or_else(|| version.strip_suffix("-arm64"))
    {
        Some(_) => return None,
        None => version,
    };
    match (os, version) {
        ("ubuntu", "2404") => class_of(vcpus, RunnerOs::Ubuntu2404, None),
        ("ubuntu", "2204") => class_of(
            vcpus,
            RunnerOs::Ubuntu2404,
            Some("the class runs Ubuntu 24.04, not 22.04"),
        ),
        ("ubuntu", "2004") => class_of(
            vcpus,
            RunnerOs::Ubuntu2404,
            Some("the class runs Ubuntu 24.04, not 20.04"),
        ),
        ("ubuntu-arm", _) | ("ubuntu-arm64", _) => None,
        ("windows", "2025") => class_of(vcpus, RunnerOs::Windows2025, None),
        ("windows", "2022") => class_of(
            vcpus,
            RunnerOs::Windows2025,
            Some("the class runs Windows Server 2025, not 2022"),
        ),
        ("windows", "2019") => class_of(
            vcpus,
            RunnerOs::Windows2025,
            Some("the class runs Windows Server 2025, not 2019"),
        ),
        _ => None,
    }
}

/// `ubuntu-latest`, `ubuntu-24.04`, `ubuntu-24.04-arm`, `ubuntu-24.04-16core`,
/// `windows-2025`, `windows-2022-8core`: GitHub's hosted and larger-runner labels.
fn hosted(label: &str) -> Option<Entry> {
    let (os, rest) = if let Some(rest) = label.strip_prefix("ubuntu-") {
        (RunnerOs::Ubuntu2404, rest)
    } else {
        (RunnerOs::Windows2025, label.strip_prefix("windows-")?)
    };
    let mut arm = false;
    let mut vcpus = None;
    let mut version = None;
    for part in rest.split('-') {
        if let Some(cores) = part
            .strip_suffix("core")
            .and_then(|n| n.parse::<u16>().ok())
            .filter(|n| *n > 0)
        {
            vcpus = Some(cores);
        } else if part == "arm" || part == "arm64" {
            arm = true;
        } else if version.is_none() {
            version = Some(part);
        } else {
            return None;
        }
    }
    let vcpus = vcpus.unwrap_or(HOSTED_VCPUS);
    let os = match (arm, os) {
        (false, os) => os,
        (true, RunnerOs::Ubuntu2404) => RunnerOs::Ubuntu2404Arm,
        (true, RunnerOs::Ubuntu2404Arm) => RunnerOs::Ubuntu2404Arm,
        (true, RunnerOs::Windows2025) => return None,
    };
    let change = match (os, version?) {
        (RunnerOs::Ubuntu2404 | RunnerOs::Ubuntu2404Arm, "24.04") => None,
        (RunnerOs::Ubuntu2404 | RunnerOs::Ubuntu2404Arm, "latest") => {
            Some("`latest` is pinned to Ubuntu 24.04")
        }
        (RunnerOs::Ubuntu2404 | RunnerOs::Ubuntu2404Arm, "22.04") => {
            Some("the class runs Ubuntu 24.04, not 22.04")
        }
        (RunnerOs::Ubuntu2404 | RunnerOs::Ubuntu2404Arm, "20.04") => {
            Some("the class runs Ubuntu 24.04, not 20.04")
        }
        (RunnerOs::Windows2025, "2025") => None,
        (RunnerOs::Windows2025, "latest") => Some("`latest` is pinned to Windows Server 2025"),
        (RunnerOs::Windows2025, "2022") => Some("the class runs Windows Server 2025, not 2022"),
        (RunnerOs::Windows2025, "2019") => Some("the class runs Windows Server 2025, not 2019"),
        _ => return None,
    };
    class_of(vcpus, os, change)
}

/// `2vcpu-` at the head of a Blacksmith label: the digits, then the rest after `vcpu-`.
fn digits_vcpu(label: &str) -> Option<(u16, &str)> {
    let (digits, rest) = label.split_once("vcpu-")?;
    if digits.is_empty() || digits.len() > 3 || digits.starts_with('0') {
        return None;
    }
    let vcpus = digits.parse::<u16>().ok()?;
    Some((vcpus, rest))
}
