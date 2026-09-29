//! Frozen benchmark contracts (B01, `sentinel.bench-contract/1`): what a
//! representative check is, on which host, with which sources, images,
//! tools, allocation and cold/warm/small-edit procedure. The runner measures
//! a contract lane only when the host and inputs match the contract, and
//! every record names the contract revision and digest it was taken under.
use std::{collections::BTreeMap, fs, path::Path};

use serde::{Deserialize, Serialize};

pub const FORMAT: &str = "sentinel.bench-contract/1";

#[derive(Deserialize)]
pub struct Contract {
    pub format: String,
    pub id: String,
    pub revision: u32,
    pub reference_host: ReferenceHost,
    pub allocation: Allocation,
    pub sources: Vec<SourcePin>,
    pub images: BTreeMap<String, String>,
    #[serde(default)]
    pub environment: BTreeMap<String, String>,
    pub freshness: Freshness,
    pub conditions: BTreeMap<String, Condition>,
    pub lanes: Vec<Lane>,
}

#[derive(Deserialize)]
pub struct ReferenceHost {
    pub cpu_model: String,
    pub cpus_online: usize,
    pub mem_total_kib_min: u64,
    pub podman: String,
}

#[derive(Deserialize)]
pub struct Allocation {
    pub total: Caps,
}

#[derive(Clone, Deserialize, Serialize)]
pub struct Caps {
    pub cpus: String,
    pub memory: String,
}

#[derive(Deserialize)]
pub struct SourcePin {
    pub name: String,
    pub commit: String,
    pub path: String,
}

#[derive(Deserialize)]
pub struct Freshness {
    pub max_record_age_days: u32,
}

#[derive(Deserialize)]
pub struct Condition {
    pub prepare: String,
    pub samples: u32,
}

#[derive(Deserialize)]
pub struct Lane {
    pub id: String,
    pub image: String,
    #[serde(default)]
    pub env: BTreeMap<String, String>,
    pub run: String,
}

/// What a record says about the contract it was taken under.
#[derive(Serialize)]
pub struct Stamp {
    pub id: String,
    pub revision: u32,
    pub blake3: String,
    pub lane: String,
    pub condition: String,
    pub max_record_age_days: u32,
    /// CPU pressure (`some`, avg60, percent) when sampling started.
    pub cpu_pressure_avg60: Option<f64>,
    pub sources: BTreeMap<String, String>,
    pub image: Option<String>,
}

/// Contract lane pressure bound: a contended start is not a baseline.
pub const MAX_START_PRESSURE: f64 = 5.0;

pub struct Loaded {
    pub contract: Contract,
    pub blake3: String,
}

pub fn load(path: &Path) -> Result<Loaded, String> {
    let bytes = fs::read(path).map_err(|e| format!("cannot read {}: {e}", path.display()))?;
    let contract: Contract = serde_json::from_slice(&bytes)
        .map_err(|e| format!("{} is not a bench contract: {e}", path.display()))?;
    if contract.format != FORMAT {
        return Err(format!(
            "{} is `{}`, not `{FORMAT}`",
            path.display(),
            contract.format
        ));
    }
    Ok(Loaded {
        contract,
        blake3: blake3::hash(&bytes).to_hex().to_string(),
    })
}

impl Contract {
    pub fn lane(&self, id: &str) -> Result<&Lane, String> {
        self.lanes.iter().find(|l| l.id == id).ok_or_else(|| {
            let ids: Vec<&str> = self.lanes.iter().map(|l| l.id.as_str()).collect();
            format!(
                "no lane `{id}` in contract {}; lanes: {}",
                self.id,
                ids.join(", ")
            )
        })
    }

    pub fn condition(&self, id: &str) -> Result<&Condition, String> {
        self.conditions
            .get(id)
            .ok_or_else(|| format!("no condition `{id}` in contract {}", self.id))
    }

    /// Replace `{root}` and `{commit:<source>}`. `{sample_nonce}` stays for
    /// the runner to fill in before each run.
    pub fn expand(&self, text: &str, root: &str) -> String {
        let mut out = text.replace("{root}", root);
        for source in &self.sources {
            out = out.replace(&format!("{{commit:{}}}", source.name), &source.commit);
        }
        out
    }

    /// The contract environment plus the lane's, expanded.
    pub fn env(&self, lane: &Lane, root: &str) -> BTreeMap<String, String> {
        let mut env: BTreeMap<String, String> = self
            .environment
            .iter()
            .map(|(k, v)| (k.clone(), self.expand(v, root)))
            .collect();
        for (k, v) in &lane.env {
            env.insert(k.clone(), self.expand(v, root));
        }
        env
    }
}

/// Everything that differs from the contract, in words; empty means the
/// host and inputs match and measuring may start.
pub fn drift(
    contract: &Contract,
    host: &crate::Host,
    podman: Option<&str>,
    image_digest: Option<&str>,
    lane: &Lane,
    root: &Path,
) -> Vec<String> {
    let mut out = Vec::new();
    let want = &contract.reference_host;
    if host.cpu_model.as_deref() != Some(want.cpu_model.as_str()) {
        out.push(format!(
            "cpu model {:?}, contract {:?}",
            host.cpu_model, want.cpu_model
        ));
    }
    if host.cpus_online != Some(want.cpus_online) {
        out.push(format!(
            "{:?} CPUs online, contract {}",
            host.cpus_online, want.cpus_online
        ));
    }
    if host
        .mem_total_kib
        .is_none_or(|m| m < want.mem_total_kib_min)
    {
        out.push(format!(
            "memory {:?} KiB, contract at least {}",
            host.mem_total_kib, want.mem_total_kib_min
        ));
    }
    if let Some(podman) = podman
        && podman != want.podman
    {
        out.push(format!("{podman:?}, contract {:?}", want.podman));
    }
    if let Some(pinned) = contract.images.get(&lane.image) {
        let want_digest = pinned.rsplit_once('@').map(|(_, d)| d);
        if image_digest.is_some() && image_digest != want_digest {
            out.push(format!(
                "image {} has digest {image_digest:?}, contract {want_digest:?}",
                lane.image
            ));
        }
    } else {
        out.push(format!(
            "lane image `{}` is not pinned in images",
            lane.image
        ));
    }
    for source in &contract.sources {
        let dir = root.join(&source.path);
        let at = crate::command_line(&[
            "git",
            "-C",
            &dir.display().to_string(),
            "rev-parse",
            &format!("{}^{{commit}}", source.commit),
        ]);
        if at.as_deref() != Some(source.commit.as_str()) {
            out.push(format!(
                "source {} at {} does not hold commit {}",
                source.name,
                dir.display(),
                source.commit
            ));
        }
    }
    out
}

/// `some avg60` of `/proc/pressure/cpu`, in percent.
pub fn cpu_pressure() -> Option<f64> {
    let text = fs::read_to_string("/proc/pressure/cpu").ok()?;
    let some = text.lines().find(|l| l.starts_with("some"))?;
    some.split_whitespace()
        .find_map(|f| f.strip_prefix("avg60="))?
        .parse()
        .ok()
}

/// A Podman memory size (`26g`, `512m`) as systemd reads it (`26G`, `512M`).
pub fn systemd_memory(memory: &str) -> String {
    memory.to_ascii_uppercase()
}

/// `--cpus 10` as a systemd `CPUQuota` (`1000%`).
pub fn cpu_quota(cpus: &str) -> Result<String, String> {
    let n: f64 = cpus
        .parse()
        .map_err(|_| format!("--cpus {cpus:?} is not a number"))?;
    if !n.is_finite() || n <= 0.0 {
        return Err("--cpus must be positive".into());
    }
    Ok(format!("{}%", (n * 100.0).round() as u64))
}

#[cfg(test)]
mod tests {
    use super::*;

    const CONTRACT: &str = include_str!("../../../bench/contracts/lockwell-ci.json");

    #[test]
    fn the_committed_contract_parses_and_expands() {
        let contract: Contract = serde_json::from_str(CONTRACT).unwrap();
        assert_eq!(contract.format, FORMAT);
        let lane = contract.lane("unit").unwrap();
        assert!(lane.run.contains("-count=1"));
        for lane in &contract.lanes {
            assert!(contract.images.contains_key(&lane.image), "{}", lane.id);
            assert!(
                contract.images[&lane.image].contains("@sha256:"),
                "images are pinned by digest"
            );
        }
        let edit = contract.condition("small-edit").unwrap();
        let a = contract.expand(&edit.prepare, "/b");
        assert!(
            a.contains("{sample_nonce}"),
            "the runner fills a fresh nonce into every sample's edit: {a}"
        );
        assert!(!a.contains("{root}") && !a.contains("{commit:"), "{a}");
        assert!(a.contains("cbe48fc712dc510ca77bfa4de7efe8101c7cc521"));
        let env = contract.env(lane, "/b");
        assert_eq!(env["GOTOOLCHAIN"], "local");
        assert_eq!(env["GOCACHE"], "/b/cache/gocache");
        assert!(contract.lane("nope").is_err());
    }

    #[test]
    fn caps_translate_to_systemd() {
        assert_eq!(cpu_quota("10").unwrap(), "1000%");
        assert_eq!(cpu_quota("1.5").unwrap(), "150%");
        assert!(cpu_quota("0").is_err());
        assert_eq!(systemd_memory("26g"), "26G");
    }
}
