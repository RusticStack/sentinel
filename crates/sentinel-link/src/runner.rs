//! Runner-mode provisioning on the controller (AR02): what one pass decides and what it holds
//! between passes.
//!
//! Three things make a running runner on this side. **Placement** leases a worker's capacity for
//! one unmet unit of demand of a label set, exactly as dispatch leases capacity for a pipeline job.
//! **Provisioning** asks the App for the job's just-in-time configuration as the lease requires it,
//! seals it, and delivers it once. **Reconciliation** covers what events cannot: a reached idle bound
//! retires a runner nobody handed work to, a registration that outlived its lease is removed at
//! GitHub, and a `queued` job whose delivery was lost is found in GitHub's own queue.
//!
//! The configuration is a credential. It is in memory only between the App's answer and the sealed
//! row, the wire frame is wiped after it is written, and nothing here formats it.

use std::{sync::Arc, time::Duration};

use sentinel_core::{RunnerClass, RunnerLeaseId, TenantId, UnixMillis};
use sentinel_github::runner::Scope;
use sentinel_store::runner_provision::{self, MAX_JIT_BYTES};

use crate::{
    Result,
    session::{self, Sender},
};

/// The largest encoded configuration a frame may carry; the session's bound is the same number.
pub const MAX_CONFIG_BYTES: usize = MAX_JIT_BYTES;
const _: () = assert!(MAX_CONFIG_BYTES == crate::session::MAX_RUNNER_CONFIG_BYTES);

/// How often the provisioning pass runs: fast enough that a queued job waits one placement round,
/// slow enough that an idle fleet costs nothing.
pub const PASS_INTERVAL: Duration = Duration::from_secs(1);

/// A runner that no job took within this bound is de-registered and its sandbox destroyed. It is
/// the row's guarantee — "no runner outlives its bound idle" — so it is a stated deployment
/// setting, not a constant nobody can see.
pub const DEFAULT_IDLE_MS: i64 = 120_000;

/// How often the reconciliation pass reads GitHub's queue for repositories whose deliveries may have
/// been lost. It is the outer half of the bound: a lost event is recovered within one interval plus
/// one pass.
pub const DEFAULT_RECONCILE_MS: i64 = 60_000;

/// The runner group a tenant's runners are registered in at the organization. GitHub's default
/// group is 1; a deployment whose runners must be grouped states its own id.
pub const DEFAULT_RUNNER_GROUP: u64 = 1;

/// The most leases one pass places on one worker: enough to fill a machine's room in one round
/// without a burst of queued jobs becoming a burst of frames.
pub const PLACES_PER_WORKER: usize = 4;

/// The most configurations one pass asks GitHub for.
pub const PROVISION_BATCH: u32 = 8;

/// The most registrations one pass removes.
pub const UNREGISTER_BATCH: u32 = 16;

/// The most repositories one reconciliation pass reads, the runs it lists of each, and the jobs it
/// reads of each run: the whole pass costs at most `RECONCILE_REPOS * (1 + RECONCILE_RUNS)` requests,
/// and the repositories it did not reach are the next pass's.
pub const RECONCILE_REPOS: u32 = 8;
pub const RECONCILE_RUNS: usize = 5;
pub const RECONCILE_JOBS: usize = 50;

/// What the deployment states about runner mode: the classes it serves, the group its runners join,
/// how long a runner may stay idle, and how often a reconciliation pass runs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    pub classes: Arc<[RunnerClass]>,
    pub runner_group: u64,
    pub idle_ms: i64,
    pub reconcile_ms: i64,
}

impl Policy {
    pub fn new(classes: Arc<[RunnerClass]>) -> Self {
        Self {
            classes,
            runner_group: DEFAULT_RUNNER_GROUP,
            idle_ms: DEFAULT_IDLE_MS,
            reconcile_ms: DEFAULT_RECONCILE_MS,
        }
    }

    /// The class a label names, when this deployment serves it.
    pub fn serves(&self, label: &str) -> Option<RunnerClass> {
        let class = RunnerClass::parse(label)?;
        self.classes.contains(&class).then_some(class)
    }
}

/// The label a class is registered and matched by, allocated once per offer.
pub fn class_label(lease: &runner_provision::Lease) -> &str {
    &lease.class
}

/// Where this repository's runners are registered. A personal namespace has no organization, so its
/// runners belong to the repository.
pub fn scope<'a>(remote: &'a str, login: &'a str, personal: bool) -> Option<Scope<'a>> {
    if personal {
        let (owner, repo) = github_owner_repo(remote)?;
        return Some(Scope::Repository { owner, repo });
    }
    Some(Scope::Organization(login))
}

/// `owner` and `repository` of an `https://github.com/owner/repository(.git)` remote. Anything else
/// (a self-hosted forge, another host, a credential in the URL) is not a GitHub repository this
/// build can register a runner for.
pub fn github_owner_repo(remote: &str) -> Option<(&str, &str)> {
    let rest = remote
        .strip_prefix("https://github.com/")
        .or_else(|| remote.strip_prefix("ssh://git@github.com/"))?;
    let rest = rest.strip_suffix(".git").unwrap_or(rest);
    let (owner, repo) = rest.split_once('/')?;
    let valid = |part: &str| {
        !part.is_empty()
            && part.len() <= 100
            && part != "."
            && part != ".."
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
    };
    (valid(owner) && valid(repo) && !repo.contains('/')).then_some((owner, repo))
}

/// The context a sealed configuration opens under: one lease, one repository, one tenant. A
/// ciphertext moved to any other row does not open.
pub fn seal_context(
    tenant: TenantId,
    repo: sentinel_core::RepoId,
    lease: RunnerLeaseId,
) -> Vec<u8> {
    let mut context = Vec::with_capacity(32 + 48);
    context.extend_from_slice(b"sentinel runner jit v1");
    context.extend_from_slice(tenant.as_bytes());
    context.extend_from_slice(repo.as_bytes());
    context.extend_from_slice(lease.as_bytes());
    context
}

/// Offer one runner lease to the worker that was given its capacity.
pub fn offer(sender: &Sender, lease: &runner_provision::Lease, until: UnixMillis) -> Result<()> {
    let vcpus = RunnerClass::parse(&lease.class).map_or(1, |class| class.vcpus);
    let (cpu, memory) = runner_provision::class_capacity(vcpus);
    let wire = crate::session::RunnerLeaseWire {
        lease: *lease.id.as_bytes(),
        class: class_label(lease).to_owned(),
        lease_until_ms: until.0,
        cpu_millis: u64::try_from(cpu).unwrap_or(0),
        memory_bytes: u64::try_from(memory).unwrap_or(0),
    };
    sender.send_bounded(
        &crate::session::ServerMessage::RunnerOffer(wire),
        session::DISPATCH_WRITE_BOUND,
    )
}

/// Deliver the configuration of one accepted lease. The frame is sensitive — its encode buffer is
/// wiped after it is written — and the plaintext this holds is wiped here whatever the send did.
pub fn deliver(sender: &Sender, lease: RunnerLeaseId, config: Vec<u8>) -> Result<()> {
    let message = crate::session::ServerMessage::RunnerConfig {
        lease: *lease.as_bytes(),
        config: sentinel_protocol::secrets::SecretBytes::new(config),
    };
    sender.send_sensitive(&message)
}

/// Tell one worker the boundary the job its lease took may read and write. Sent once the delivery
/// names the job, which is the first moment a fork is known; until then the sandbox serves nothing.
pub fn scope_lease(
    sender: &Sender,
    lease: RunnerLeaseId,
    tenant: TenantId,
    repo: sentinel_core::RepoId,
    trust: sentinel_protocol::cache::Trust,
    run: u64,
    job: u64,
) -> Result<()> {
    session::push(
        sender,
        &crate::session::ServerMessage::RunnerScope {
            lease: *lease.as_bytes(),
            scope: crate::session::RunnerScopeWire {
                tenant: *tenant.as_bytes(),
                repo: *repo.as_bytes(),
                trust: trust.to_u8(),
                run,
                job,
            },
        },
    )
}

/// Tell a worker which leases it no longer holds.
pub fn stop(sender: &Sender, leases: &[RunnerLeaseId]) -> Result<()> {
    session::push(
        sender,
        &crate::session::ServerMessage::RunnerStop {
            leases: leases.iter().map(|l| *l.as_bytes()).collect(),
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_github_remote_spells_the_owner_and_repository_and_nothing_else_does() {
        assert_eq!(
            github_owner_repo("https://github.com/acme/app.git"),
            Some(("acme", "app"))
        );
        assert_eq!(
            github_owner_repo("ssh://git@github.com/acme/app.git"),
            Some(("acme", "app"))
        );
        assert_eq!(
            github_owner_repo("https://github.com/acme/app"),
            Some(("acme", "app"))
        );
        for other in [
            "https://gitlab.com/acme/app.git",
            "https://github.com/acme",
            "https://github.com/acme/app/extra",
            "https://token@github.com/acme/app.git",
            "https://github.com/../app.git",
            "https://forge.example/acme/app.git",
        ] {
            assert_eq!(github_owner_repo(other), None, "{other}");
        }
    }

    #[test]
    fn a_personal_namespace_registers_at_the_repository_and_an_organization_at_itself() {
        assert_eq!(
            scope("https://github.com/acme/app.git", "acme", false),
            Some(Scope::Organization("acme"))
        );
        assert_eq!(
            scope("https://github.com/acme/app.git", "acme", true),
            Some(Scope::Repository {
                owner: "acme",
                repo: "app"
            })
        );
        assert_eq!(scope("https://gitlab.com/acme/app.git", "acme", true), None);
    }

    #[test]
    fn a_sealed_context_binds_its_tenant_repository_and_lease() {
        let (tenant, repo, lease) = (
            TenantId::new(),
            sentinel_core::RepoId::new(),
            RunnerLeaseId::new(),
        );
        let context = seal_context(tenant, repo, lease);
        assert_ne!(
            context,
            seal_context(tenant, repo, RunnerLeaseId::new()),
            "another lease"
        );
        assert_ne!(
            context,
            seal_context(TenantId::new(), repo, lease),
            "another tenant"
        );
    }

    #[test]
    fn a_policy_serves_only_the_classes_the_deployment_names() {
        let policy = Policy::new(Arc::from(vec![
            RunnerClass::parse("sentinel-4vcpu-ubuntu-2404").unwrap(),
        ]));
        assert!(policy.serves("sentinel-4vcpu-ubuntu-2404").is_some());
        assert!(policy.serves("sentinel-8vcpu-ubuntu-2404").is_none());
        assert!(policy.serves("ubuntu-latest").is_none());
    }
}
