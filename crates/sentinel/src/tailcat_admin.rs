//! Node keys travel on standard input and output only, never argv or standard error.
//! A rotated key is listed beside the old one and committed only after a ping proves admission.

use std::path::Path;

use sentinel_core::WorkerId;
use sentinel_link::tailcat::{self, Admission, NodeKey, Role};

use crate::cli::{TailcatArgs, TailcatCommand, TailcatRole, TailcatRoleConfig};

/// Allow-list line limit: a nodekey (64 hex) and a worker id, with room for CRLF.
const LINE_CAP: u64 = 256;

pub fn run(args: &TailcatArgs) -> Result<(), String> {
    match &args.command {
        TailcatCommand::Rotate(target) => rotate(target),
        TailcatCommand::Commit(target) => commit(target),
        TailcatCommand::Abandon(target) => abandon(target),
        TailcatCommand::Allow { data } => {
            let admission = read_admission()?;
            let added = tailcat::admit(&data.data_dir, &admission).map_err(|e| e.to_string())?;
            eprintln!(
                "{} {}; the running controller admits it within 10 s",
                if added {
                    "listed a key for"
                } else {
                    "already listed a key for"
                },
                admission.worker
            );
            Ok(())
        }
        TailcatCommand::Retire { data } => {
            let keep = read_admission()?;
            let removed = tailcat::retire(&data.data_dir, &keep).map_err(|e| e.to_string())?;
            eprintln!(
                "removed {removed} other key(s) of {}; the running controller drops them within 10 s",
                keep.worker
            );
            Ok(())
        }
        TailcatCommand::Authorize { data, enrollment } => {
            let admission = read_admission()?;
            authorize(&data.data_dir, enrollment, &admission)?;
            eprintln!(
                "authorized a key for {} on that enrollment; the running controller admits it within 10 s and stops once the enrollment is spent, withdrawn or expired",
                admission.worker
            );
            Ok(())
        }
        TailcatCommand::Revoke { data, id } => {
            let worker: WorkerId = id
                .parse()
                .map_err(|_| "expected a wrk_ worker identifier".to_owned())?;
            let removed = tailcat::revoke(&data.data_dir, worker).map_err(|e| e.to_string())?;
            eprintln!(
                "removed {removed} key(s) of {worker} from the allow list; the running controller drops them within 10 s"
            );
            Ok(())
        }
    }
}

#[cfg(feature = "server")]
fn authorize(data_dir: &Path, enrollment: &str, admission: &Admission) -> Result<(), String> {
    use sentinel_core::{TokenId, UnixMillis};
    use sentinel_store::{auth::Authority, workers};

    let enrollment: TokenId = enrollment
        .parse()
        .map_err(|_| "expected a tok_ enrollment identifier".to_owned())?;
    let key = workers::parse_node_key(admission.key.expose())
        .ok_or_else(|| "the node key is not nodekey:<64 hex>".to_owned())?;
    let worker = admission.worker;
    let store = crate::admin::open(&crate::cli::DataDir::at(data_dir), true)
        .map_err(|error| error.message)?;
    store
        .writer()
        .write(move |tx| {
            workers::authorize_node_key(
                tx,
                Authority::HostLocal,
                enrollment,
                worker,
                key,
                UnixMillis::now(),
            )
        })
        .map_err(|error| match error {
            sentinel_store::Error::NotFound => "no enrollment with that identifier".to_owned(),
            sentinel_store::Error::Conflict => {
                "the enrollment is no longer pending, already has another key, or that key or worker identifier already belongs to a worker"
                    .to_owned()
            }
            sentinel_store::Error::InvalidInput(_) => {
                "that enrollment is for direct TLS and takes no node key".to_owned()
            }
            other => format!("cannot authorize the key: {other}"),
        })
}

#[cfg(not(feature = "server"))]
fn authorize(_data_dir: &Path, _enrollment: &str, _admission: &Admission) -> Result<(), String> {
    Err(
        "authorizing a key for an enrollment needs the controller's own build (--features server)"
            .to_owned(),
    )
}

struct Target {
    role: Role,
    setup: crate::service::TailcatSetup,
}

fn target(args: &TailcatRoleConfig) -> Result<Target, String> {
    let (role, name) = match args.role {
        TailcatRole::Server => (Role::Controller, "server"),
        TailcatRole::Worker => (Role::Worker, "worker"),
    };
    let setup = crate::service::tailcat_setup(name, args.config.clone(), args.data_dir.clone())
        .map_err(|error| error.message)?;
    Ok(Target { role, setup })
}

fn rotate(args: &TailcatRoleConfig) -> Result<(), String> {
    let Target { role, setup } = target(args)?;
    let worker = match role {
        Role::Worker => Some(worker_id(&setup.data_dir)?),
        Role::Controller => None,
    };
    let key = tailcat::stage_rotation(&setup.helper, &setup.data_dir, role)
        .map_err(|error| error.to_string())?;
    match worker {
        Some(worker) => {
            print_line(&key, worker);
            eprintln!(
                "staged a new worker node key; list the line above on the controller \
                 (`sentinel admin tailcat allow --data-dir <controller data dir>` reads it \
                 on standard input), then run `sentinel admin tailcat commit --role worker` here"
            );
        }
        None => eprintln!(
            "staged a new controller node key; the running controller serves it beside the \
             active one within 10 s and writes its address to {}; give that address to every \
             worker as tailcat_address, then run `sentinel admin tailcat commit --role server`",
            tailcat::staged_address_file(&setup.data_dir).display()
        ),
    }
    Ok(())
}

fn commit(args: &TailcatRoleConfig) -> Result<(), String> {
    let Target { role, setup } = target(args)?;
    let worker = match role {
        Role::Worker => Some(worker_id(&setup.data_dir)?),
        Role::Controller => None,
    };
    let committed = tailcat::commit_rotation(
        &setup.helper,
        &setup.data_dir,
        role,
        setup.controller.as_ref(),
    )
    .map_err(|error| error.to_string())?;
    match worker {
        Some(worker) => {
            print_line(&committed.key, worker);
            eprintln!(
                "committed; the running worker switches to the new key within one probe \
                 interval (30 s). Then make the line above the worker's only key on the \
                 controller: `sentinel admin tailcat retire --data-dir <controller data dir>` \
                 reads it on standard input"
            );
        }
        None => eprintln!(
            "committed; {} holds the new address and the running controller switches within \
             10 s; workers still dialing the old address lose their tunnel then",
            setup
                .data_dir
                .join("tailcat")
                .join(tailcat::ADDRESS_FILE)
                .display()
        ),
    }
    if !committed.previous_deleted {
        eprintln!(
            "warning: the previous private key could not be deleted; it is no longer used \
             (run commit again to retry)"
        );
    }
    Ok(())
}

fn abandon(args: &TailcatRoleConfig) -> Result<(), String> {
    let Target { role, setup } = target(args)?;
    let dropped = tailcat::abandon_rotation(&setup.helper, &setup.data_dir, role)
        .map_err(|error| error.to_string())?;
    eprintln!(
        "{}",
        if dropped {
            "dropped the staged key; the keys in use are unchanged"
        } else {
            "no key rotation was staged"
        }
    );
    Ok(())
}

fn print_line(key: &NodeKey, worker: WorkerId) {
    sentinel::outln!("{} {worker}", key.expose());
}

fn worker_id(data_dir: &Path) -> Result<WorkerId, String> {
    let text = sentinel::bounded::text(&data_dir.join("worker.id"), 4 << 10).map_err(|_| {
        "cannot read worker.id in the data directory; start the worker once so it has an id"
            .to_owned()
    })?;
    text.trim()
        .parse()
        .map_err(|_| "worker.id is not a wrk_ identifier".to_owned())
}

fn read_admission() -> Result<Admission, String> {
    let bytes = sentinel::bounded::read(std::io::stdin().lock(), LINE_CAP).map_err(|_| {
        "expected one `nodekey:<64 hex> wrk_<id>` line on standard input".to_owned()
    })?;
    let text = std::str::from_utf8(&bytes)
        .map_err(|_| "the line on standard input is not UTF-8".to_owned())?;
    let mut lines = text.lines().map(str::trim).filter(|line| !line.is_empty());
    let (Some(line), None) = (lines.next(), lines.next()) else {
        return Err(
            "expected exactly one `nodekey:<64 hex> wrk_<id>` line on standard input".to_owned(),
        );
    };
    let mut fields = line.split_whitespace();
    let (Some(key), Some(worker), None) = (fields.next(), fields.next(), fields.next()) else {
        return Err("the line on standard input is not `nodekey:<64 hex> wrk_<id>`".to_owned());
    };
    let key = NodeKey::parse(key)
        .ok_or_else(|| "the line on standard input does not start with a nodekey".to_owned())?;
    let worker = worker
        .parse()
        .map_err(|_| "the line on standard input does not name a wrk_ worker".to_owned())?;
    Ok(Admission { key, worker })
}
