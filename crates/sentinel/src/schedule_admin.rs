//! `admin schedule`: configure, list and stop a repository's durable UTC schedule.
//!
//! The row is the schedule, so these commands work on a stopped controller exactly as `admin source
//! poll` does: the running controller's schedule lane picks up a change on its next pass, and no
//! in-memory timer has to be restarted.

use crate::{
    admin::{self, Error},
    cli::{ScheduleArgs, ScheduleCommand},
};
use sentinel_core::{RepoId, UnixMillis, UserId};
use sentinel_store::{
    registration::Authority,
    schedule::{self, Overlap, Spec},
};

fn fail(message: &str) -> Error {
    Error {
        message: message.into(),
    }
}

pub fn run(args: &ScheduleArgs) -> Result<(), Error> {
    let store = admin::open(&args.data, true)?;
    let actor: UserId = args.actor.parse().map_err(|_| fail("invalid actor ID"))?;
    let now = UnixMillis::now();
    let host = Authority::HostLocal;
    let repo = |s: &str| {
        s.parse::<RepoId>()
            .map_err(|_| fail("invalid repository ID"))
    };
    let refused = |_: sentinel_store::Error| {
        fail("schedule operation refused; check authority, the repository binding and the cron")
    };
    match &args.command {
        ScheduleCommand::Set {
            repo: r,
            cron,
            ref_name,
            overlap,
        } => {
            let repo = repo(r)?;
            let overlap = Overlap::parse(overlap)
                .ok_or_else(|| fail("overlap must be `skip` or `cancel`"))?;
            let spec = Spec {
                cron: cron.clone(),
                ref_name: ref_name.clone(),
                overlap,
            };
            let next = store
                .writer()
                .write(move |tx| schedule::configure(tx, host, Some(actor), repo, &spec, now))
                .map_err(refused)?;
            sentinel::outln!(
                "{}",
                serde_json::json!({
                    "repo": repo.to_string(),
                    "cron": cron,
                    "ref": ref_name,
                    "overlap": overlap.as_str(),
                    "next_at_ms": next
                })
            );
        }
        ScheduleCommand::Disable { repo: r } => {
            let repo = repo(r)?;
            store
                .writer()
                .write(move |tx| schedule::disable(tx, host, Some(actor), repo, now))
                .map_err(refused)?;
            sentinel::outln!(
                "{}",
                serde_json::json!({"repo": repo.to_string(), "enabled": false})
            );
        }
        ScheduleCommand::Show { repo: r, all } => {
            if *all {
                let rows = store.read(schedule::all).map_err(refused)?;
                let rows: Vec<_> = rows.iter().map(json).collect();
                sentinel::outln!("{}", serde_json::json!({"schedules": rows}));
            } else {
                let r = r
                    .as_deref()
                    .ok_or_else(|| fail("--repo or --all is required"))?;
                let repo = repo(r)?;
                let row = store
                    .read(move |c| schedule::of_repo(c, repo))
                    .map_err(refused)?;
                match row {
                    Some(row) => sentinel::outln!("{}", json(&row)),
                    None => sentinel::outln!(
                        "{}",
                        serde_json::json!({"repo": repo.to_string(), "schedule": null})
                    ),
                }
            }
        }
    }
    Ok(())
}

fn json(schedule: &schedule::Schedule) -> serde_json::Value {
    serde_json::json!({
        "repo": schedule.repo.to_string(),
        "tenant": schedule.tenant.to_string(),
        "cron": schedule.cron,
        "ref": schedule.ref_name,
        "overlap": schedule.overlap.as_str(),
        "enabled": schedule.enabled,
        "next_at_ms": schedule.next_at_ms,
        "last_at_ms": schedule.last_at_ms,
        "last_run": schedule.last_run_id.map(|r| r.to_string()),
        "updated_ms": schedule.updated_ms
    })
}
