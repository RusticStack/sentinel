//! `sentinel service-account create|allow|grant|grants|revoke` (O06): a
//! tenant administrator creates service principals, allows them
//! repositories, and issues grants whose refresh token goes to stdout once
//! (metadata to stderr) for `sentinel auth login --grant-file`.
//!
//! Every subcommand is one request through the shared [`Client`]; the
//! tenant is `--tenant`, else the profile's context (`sentinel context
//! use`). Path segments are checked locally so a name can never reshape the
//! request path.

use std::time::{SystemTime, UNIX_EPOCH};

use clap::{Args, Subcommand};
use serde_json::{Value, json};

use crate::client::{self, Client, ClientArgs, Output};

#[derive(Args, Debug)]
pub struct ServiceAccountArgs {
    #[command(flatten)]
    pub client: ClientArgs,
    #[command(subcommand)]
    pub command: ServiceAccountCommand,
}

#[derive(Subcommand, Debug)]
pub enum ServiceAccountCommand {
    /// Create a service principal in a tenant
    Create {
        /// Tenant slug (default: the profile's context)
        #[arg(long, value_name = "SLUG")]
        tenant: Option<String>,
        /// Display name
        #[arg(long)]
        name: String,
        /// reader or operator
        #[arg(long, default_value = "operator")]
        role: String,
    },
    /// Allow a service principal a repository (replaces its access there)
    Allow {
        /// Tenant slug (default: the profile's context)
        #[arg(long, value_name = "SLUG")]
        tenant: Option<String>,
        /// The service principal's usr_ identifier
        account: String,
        /// Repository name in the tenant
        #[arg(long)]
        repo: String,
        /// Comma-separated: read, run; empty withdraws access
        #[arg(long, default_value = "read,run")]
        access: String,
    },
    /// Issue a grant; only the refresh token goes to stdout
    Grant {
        /// Tenant slug (default: the profile's context)
        #[arg(long, value_name = "SLUG")]
        tenant: Option<String>,
        /// The service principal's usr_ identifier
        account: String,
        /// A label for the grant, shown in listings
        #[arg(long)]
        name: String,
        /// Space-separated scopes, e.g. "runs:read runs:write logs:read"
        #[arg(long)]
        scope: String,
        /// Narrow the grant to one repository of the tenant
        #[arg(long)]
        repo: Option<String>,
        /// Lifetime such as 30d, 12h or 90m; 1h to 90d (default 30d)
        #[arg(long, value_name = "DURATION")]
        expires_in: Option<String>,
    },
    /// List a service principal's grants as metadata
    Grants {
        /// Tenant slug (default: the profile's context)
        #[arg(long, value_name = "SLUG")]
        tenant: Option<String>,
        /// The service principal's usr_ identifier
        account: String,
    },
    /// Revoke a grant by its grt_ identifier
    Revoke {
        /// The grant's grt_ identifier
        grant: String,
    },
}

pub fn run(args: ServiceAccountArgs) -> Result<(), client::Error> {
    let output = args.client.output();
    // Arguments are checked before any connection is made.
    let request = Request::from(args.command)?;
    let client = Client::connect(&args.client)?;
    request.send(&client, output)
}

/// One validated request.
enum Request {
    Create {
        tenant: Option<String>,
        name: String,
        role: String,
    },
    Allow {
        tenant: Option<String>,
        account: String,
        repo: String,
        access: Vec<&'static str>,
    },
    Grant {
        tenant: Option<String>,
        account: String,
        body: Value,
    },
    Grants {
        tenant: Option<String>,
        account: String,
    },
    Revoke {
        grant: String,
    },
}

impl Request {
    fn from(command: ServiceAccountCommand) -> Result<Request, client::Error> {
        Ok(match command {
            ServiceAccountCommand::Create { tenant, name, role } => {
                if role != "reader" && role != "operator" {
                    return Err(client::Error::usage("--role is reader or operator"));
                }
                Request::Create {
                    tenant: tenant.map(segment_owned("tenant")).transpose()?,
                    name,
                    role,
                }
            }
            ServiceAccountCommand::Allow {
                tenant,
                account,
                repo,
                access,
            } => Request::Allow {
                tenant: tenant.map(segment_owned("tenant")).transpose()?,
                account: segment_owned("account")(account)?,
                repo: segment_owned("repository")(repo)?,
                access: parse_access(&access)?,
            },
            ServiceAccountCommand::Grant {
                tenant,
                account,
                name,
                scope,
                repo,
                expires_in,
            } => {
                let mut body = json!({ "name": name, "scope": scope });
                if let Some(repo) = repo {
                    body["repo"] = Value::String(segment_owned("repository")(repo)?);
                }
                if let Some(text) = expires_in {
                    body["expires_in_ms"] = Value::from(parse_duration(&text)?);
                }
                Request::Grant {
                    tenant: tenant.map(segment_owned("tenant")).transpose()?,
                    account: segment_owned("account")(account)?,
                    body,
                }
            }
            ServiceAccountCommand::Grants { tenant, account } => Request::Grants {
                tenant: tenant.map(segment_owned("tenant")).transpose()?,
                account: segment_owned("account")(account)?,
            },
            ServiceAccountCommand::Revoke { grant } => Request::Revoke {
                grant: segment_owned("grant")(grant)?,
            },
        })
    }

    fn send(self, client: &Client, output: Output) -> Result<(), client::Error> {
        match self {
            Request::Create { tenant, name, role } => {
                let path = format!("{}/service-accounts", accounts(client, tenant.as_deref())?);
                let created = client.post(&path, &json!({ "name": name, "role": role }), None)?;
                client::emit(output, &created, || {
                    format!(
                        "{}\t{}\t{}\n",
                        text(&created["user"]),
                        text(&created["name"]),
                        text(&created["role"])
                    )
                });
            }
            Request::Allow {
                tenant,
                account,
                repo,
                access,
            } => {
                let path = format!(
                    "{}/service-accounts/{account}/repos/{repo}",
                    accounts(client, tenant.as_deref())?
                );
                let allowed = client.put(&path, &json!({ "access": access }))?;
                client::emit(output, &allowed, || {
                    let access = allowed["access"]
                        .as_array()
                        .map(|a| {
                            a.iter()
                                .filter_map(Value::as_str)
                                .collect::<Vec<_>>()
                                .join(",")
                        })
                        .unwrap_or_default();
                    let access = if access.is_empty() {
                        "none".to_owned()
                    } else {
                        access
                    };
                    format!("{account} may {access} on {repo}\n")
                });
            }
            Request::Grant {
                tenant,
                account,
                body,
            } => {
                let path = format!(
                    "{}/service-accounts/{account}/grants",
                    accounts(client, tenant.as_deref())?
                );
                let issued = client.post(&path, &body, None)?;
                let Some(token) = issued["refresh_token"].as_str() else {
                    return Err(client::Error::remote("the server answered without a token"));
                };
                // Only the token on stdout, so `> file` captures exactly it.
                println!("{token}");
                let metadata = json!({
                    "grant": issued["grant"],
                    "account": account,
                    "scope": issued["scope"],
                    "expires_ms": issued["expires_ms"],
                });
                match output {
                    Output::Text => eprintln!(
                        "issued {} to {account}: scope \"{}\", expires {}; \
                         import it with: sentinel auth login --server {} --grant-file PATH",
                        text(&issued["grant"]),
                        text(&issued["scope"]),
                        when(&issued["expires_ms"]),
                        client.server()
                    ),
                    Output::Json | Output::Ndjson => eprintln!("{metadata}"),
                }
            }
            Request::Grants { tenant, account } => {
                let path = format!(
                    "{}/service-accounts/{account}/grants",
                    accounts(client, tenant.as_deref())?
                );
                let listed = client.get(&path)?;
                let items = listed["grants"].as_array().map_or(&[][..], Vec::as_slice);
                match output {
                    Output::Json => client::emit(output, &listed, String::new),
                    _ => {
                        for grant in items {
                            client::emit_item(output, grant, || grant_line(grant));
                        }
                    }
                }
            }
            Request::Revoke { grant } => {
                let revoked = client.delete(&format!("/api/v1/grants/{grant}"))?;
                client::emit(output, &revoked, || format!("revoked {grant}\n"));
            }
        }
        Ok(())
    }
}

/// `/api/v1/tenants/{slug}` for the explicit or the profile's tenant.
fn accounts(client: &Client, tenant: Option<&str>) -> Result<String, client::Error> {
    let tenant = match tenant {
        Some(tenant) => tenant,
        None => client.default_tenant().ok_or_else(|| {
            client::Error::usage(
                "name a tenant with --tenant, or set one: sentinel context use SLUG",
            )
        })?,
    };
    segment(tenant, "tenant")?;
    Ok(format!("/api/v1/tenants/{tenant}"))
}

/// A path segment: 1..=128 of `A-Z a-z 0-9 - . _ ~`, not `.` or `..`.
fn segment(value: &str, what: &str) -> Result<(), client::Error> {
    let valid = !value.is_empty()
        && value.len() <= 128
        && value != "."
        && value != ".."
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'));
    if valid {
        Ok(())
    } else {
        Err(client::Error::usage(format!("invalid {what}: {value:?}")))
    }
}

fn segment_owned(what: &'static str) -> impl Fn(String) -> Result<String, client::Error> {
    move |value| segment(&value, what).map(|()| value)
}

/// `read,run` as the API's access list; empty withdraws access.
fn parse_access(text: &str) -> Result<Vec<&'static str>, client::Error> {
    let mut access = Vec::with_capacity(2);
    for item in text.split(',').map(str::trim).filter(|s| !s.is_empty()) {
        let known = match item {
            "read" => "read",
            "run" => "run",
            _ => return Err(client::Error::usage("--access entries are read or run")),
        };
        if !access.contains(&known) {
            access.push(known);
        }
    }
    Ok(access)
}

/// `90m`, `12h`, `30d` (or `s`) as milliseconds. The server enforces the
/// 1 h..90 d bounds; this only refuses what is not a duration.
fn parse_duration(text: &str) -> Result<i64, client::Error> {
    let bad = || client::Error::usage(format!("invalid duration {text:?}; use e.g. 30d, 12h, 90m"));
    // Before the last character, not the last byte: a multibyte unit is a
    // usage error, never a panic.
    let split = text.char_indices().last().ok_or_else(bad)?.0;
    let (number, unit) = text.split_at(split);
    let unit_ms: i64 = match unit {
        "s" => 1_000,
        "m" => 60_000,
        "h" => 3_600_000,
        "d" => 86_400_000,
        _ => return Err(bad()),
    };
    let value: i64 = number.parse().map_err(|_| bad())?;
    if value <= 0 {
        return Err(bad());
    }
    value.checked_mul(unit_ms).ok_or_else(bad)
}

fn text(value: &Value) -> &str {
    value.as_str().unwrap_or("-")
}

/// A wall-clock millisecond timestamp relative to now, e.g. `in 29d`.
fn when(value: &Value) -> String {
    let Some(at) = value.as_i64() else {
        return "-".to_owned();
    };
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
    let (past, delta) = if at >= now {
        (false, at - now)
    } else {
        (true, now - at)
    };
    let span = match delta {
        d if d >= 86_400_000 => format!("{}d", d / 86_400_000),
        d if d >= 3_600_000 => format!("{}h", d / 3_600_000),
        d => format!("{}m", d / 60_000),
    };
    if past {
        format!("{span} ago")
    } else {
        format!("in {span}")
    }
}

fn grant_line(grant: &Value) -> String {
    let state = if grant["revoked"].as_bool() == Some(true) {
        "revoked".to_owned()
    } else {
        format!("expires {}", when(&grant["expires_ms"]))
    };
    format!(
        "{}\t{}\t{}\t{}\t{state}\n",
        text(&grant["id"]),
        text(&grant["name"]),
        grant["repo"].as_str().unwrap_or("*"),
        text(&grant["scope"]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_parse_with_a_unit_only() {
        assert_eq!(parse_duration("90m").unwrap(), 5_400_000);
        assert_eq!(parse_duration("12h").unwrap(), 43_200_000);
        assert_eq!(parse_duration("30d").unwrap(), 2_592_000_000);
        for bad in [
            "",
            "d",
            "30",
            "-1d",
            "0h",
            "1w",
            "1.5d",
            "99999999999999999d",
            // A multibyte unit is refused, never split inside a character.
            "30д",
            "é",
        ] {
            assert!(parse_duration(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn path_segments_and_access_are_checked_locally() {
        for ok in ["acme", "app.v2", "usr_0123", "a-b_c~d"] {
            assert!(segment(ok, "x").is_ok(), "{ok}");
        }
        for bad in ["", ".", "..", "a/b", "a?b", "a#b", "a%2F", "a b", "é"] {
            assert!(segment(bad, "x").is_err(), "{bad}");
        }
        assert_eq!(parse_access("read, run,read").unwrap(), ["read", "run"]);
        assert!(parse_access("").unwrap().is_empty());
        assert!(parse_access("write").is_err());
    }
}
