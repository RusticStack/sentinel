//! Host-local runner-mode administration: what this deployment serves, whether a tenant offers to
//! run GitHub's jobs, and which App permissions the answer still waits on.

use std::fmt::Write as _;

use sentinel_core::TenantId;
use sentinel_store::{Store, lookup, registration::Authority, runner, switch::Switch};

use crate::{
    admin::{self, Error, fail},
    cli::{RunnerModeArgs, RunnerModeCommand},
};

pub fn run(args: &RunnerModeArgs) -> Result<(), Error> {
    match &args.command {
        RunnerModeCommand::Show { data, tenant } => {
            let store = admin::open(data, true)?;
            let tenant = resolve(&store, tenant)?;
            let enabled = store
                .read(move |c| runner::mode(c, tenant))
                .map_err(|error| fail(format!("cannot read the runner-mode switch: {error}")))?;
            let missing = store
                .read(move |c| runner::missing(c, tenant))
                .map_err(|error| fail(format!("cannot read the runner permissions: {error}")))?;
            let classes = crate::source_admin::load_runner_classes(&data.data_dir)
                .map_err(|_| fail("cannot load the runner class policy"))?;
            sentinel::outln!("tenant: {}", tenant);
            sentinel::outln!("runner mode: {}", if enabled { "on" } else { "off" });
            sentinel::outln!("{}", joined("classes", &classes));
            sentinel::outln!("{}", joined("missing", &missing));
        }
        RunnerModeCommand::Set {
            data,
            tenant,
            enabled,
        } => {
            let store = admin::open(data, true)?;
            let tenant = resolve(&store, tenant)?;
            let enabled = *enabled;
            match store
                .writer()
                .write(move |tx| runner::set_mode(tx, Authority::HostLocal, tenant, enabled))
                .map_err(|error| fail(format!("cannot change the runner-mode switch: {error}")))?
            {
                Switch::Set => sentinel::outln!(
                    "runner mode {} for {}",
                    if enabled { "on" } else { "off" },
                    tenant
                ),
                Switch::Unchanged => sentinel::outln!(
                    "runner mode {} for {} was already so",
                    if enabled { "on" } else { "off" },
                    tenant
                ),
                Switch::Missing(missing) => {
                    return Err(fail(format!(
                        "runner mode needs the GitHub App to grant {}; an owner approves the permission change on GitHub and the next installation snapshot records it",
                        missing.join(", ")
                    )));
                }
                Switch::NoInstallation => {
                    return Err(fail(
                        "the tenant has no GitHub App installation to register a runner through",
                    ));
                }
            }
        }
    }
    Ok(())
}

/// A tenant by slug or by its `tnt_` identifier, so an operator can name either.
fn resolve(store: &Store, named: &str) -> Result<TenantId, Error> {
    if let Ok(id) = named.parse::<TenantId>() {
        store
            .read(move |c| lookup::tenant_slug(c, id))
            .map_err(|_| fail("no active tenant with that identifier"))?;
        return Ok(id);
    }
    let slug = named.to_owned();
    store
        .read(move |c| lookup::tenant_by_slug(c, &slug))
        .map_err(|_| fail("no active tenant with that slug"))
}

fn joined<T: std::fmt::Display>(name: &str, values: &[T]) -> String {
    if values.is_empty() {
        return format!("{name}: none");
    }
    let mut text = String::with_capacity(name.len() + 2 + values.len() * 16);
    text.push_str(name);
    text.push_str(": ");
    for (index, value) in values.iter().enumerate() {
        if index > 0 {
            text.push_str(", ");
        }
        let _ = write!(text, "{value}");
    }
    text
}
