//! `job cancel|rerun`, `workers list|drain|undrain` and `queue`.

use serde_json::{Map, Value, json};

use super::{List, segment, tenant, text};
use crate::client::{self, Client, Error, Output};

pub(super) fn job(client: &Client, output: Output, job: &str, rerun: bool) -> Result<(), Error> {
    let job = segment("job", job)?;
    let action = if rerun { "rerun" } else { "cancel" };
    let result = client.post(&format!("/api/v1/jobs/{job}/{action}"), &json!({}), None)?;
    client::emit(output, &result, || {
        if rerun {
            format!("{job}: {}\n", text(&result, "state"))
        } else {
            format!("{job}: cancellation {}\n", text(&result, "outcome"))
        }
    });
    Ok(())
}

/// Pools are the items: one NDJSON line per pool with its workers.
pub(super) fn workers(
    client: &Client,
    output: Output,
    tenant_flag: Option<String>,
) -> Result<(), Error> {
    let slug = tenant(client, tenant_flag)?;
    let view = client.get(&format!("/api/v1/workers?tenant={slug}"))?;
    let mut list = List::new(output);
    for pool in view["pools"].as_array().into_iter().flatten() {
        list.item(pool.clone(), || {
            let mut out = format!("pool {} ({})\n", text(pool, "name"), text(pool, "kind"));
            for worker in pool["workers"].as_array().into_iter().flatten() {
                out.push_str(&format!(
                    "  {} {} {} {}\n",
                    text(worker, "id"),
                    text(worker, "name"),
                    text(worker, "arch"),
                    if worker["connected"] == true {
                        "connected"
                    } else {
                        "offline"
                    }
                ));
            }
            out
        });
    }
    list.finish("pools", Map::new());
    Ok(())
}

pub(super) fn drain(
    client: &Client,
    output: Output,
    worker: &str,
    drain: bool,
) -> Result<(), Error> {
    let worker = segment("worker", worker)?;
    let action = if drain { "drain" } else { "undrain" };
    let result = client.post(
        &format!("/api/v1/workers/{worker}/{action}"),
        &json!({}),
        None,
    )?;
    client::emit(output, &result, || {
        format!(
            "{worker}: {}\n",
            if drain {
                "takes no new attempts"
            } else {
                "takes work again"
            }
        )
    });
    Ok(())
}

/// Waiting jobs are the items; the server bounds the list (at most 500)
/// and reports the total, which JSON keeps and text summarizes.
pub(super) fn queue(
    client: &Client,
    output: Output,
    tenant_flag: Option<String>,
    limit: Option<usize>,
) -> Result<(), Error> {
    let slug = tenant(client, tenant_flag)?;
    let limit = match limit {
        None => 100,
        Some(n) if (1..=500).contains(&n) => n,
        Some(_) => return Err(Error::usage("--limit must be 1..500")),
    };
    let view = client.get(&format!("/api/v1/queue?tenant={slug}&limit={limit}"))?;
    let jobs = view["jobs"].as_array().map_or(&[][..], Vec::as_slice);
    let mut list = List::new(output);
    for job in jobs {
        list.item(job.clone(), || {
            format!(
                "{} {:<12} {:>7} {}{}\n",
                text(job, "job"),
                text(job, "repo"),
                age_text(job["age_ms"].as_u64().unwrap_or(0)),
                text(&job["reason"], "code"),
                job["reason"]["detail"]
                    .as_str()
                    .map(|detail| format!(" ({detail})"))
                    .unwrap_or_default(),
            )
        });
    }
    if output == Output::Text && view["truncated"] == true {
        eprintln!(
            "{} of {} waiting jobs shown; raise --limit for the rest",
            jobs.len(),
            view["total"].as_u64().unwrap_or(0),
        );
    }
    let mut extra = Map::new();
    extra.insert("total".into(), view["total"].clone());
    extra.insert("truncated".into(), Value::Bool(view["truncated"] == true));
    list.finish("jobs", extra);
    Ok(())
}

/// A waiting age as a person reads it: seconds, then minutes, then hours.
fn age_text(age_ms: u64) -> String {
    let secs = age_ms / 1000;
    match secs {
        0..=59 => format!("{secs}s"),
        60..=3599 => format!("{}m{}s", secs / 60, secs % 60),
        _ => format!("{}h{}m", secs / 3600, (secs % 3600) / 60),
    }
}
