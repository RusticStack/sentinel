//! The CLI's side of the API (W08): a few commands for humans and agents
//! over the same routes the web page uses. Output is text by default and
//! JSON with `--json`; errors are the server's `sentinel.error/1` codes.
//!
//! The server and credential come from `--server`/`SENTINEL_SERVER` and
//! `--token`/`SENTINEL_TOKEN`; a token file (`--token-file`) keeps the
//! secret out of the process list.

use std::{fs, path::Path, time::Duration};

use serde_json::{Value, json};

use crate::cli::{ApiArgs, ApiCommand};

pub struct Error {
    pub message: String,
    pub code: u8,
}

fn usage(message: impl Into<String>) -> Error {
    Error {
        message: message.into(),
        code: 2,
    }
}

fn remote(message: impl Into<String>) -> Error {
    Error {
        message: message.into(),
        code: 1,
    }
}

struct Client {
    base: String,
    token: String,
    agent: ureq::Agent,
}

impl Client {
    fn from_args(args: &ApiArgs) -> Result<Client, Error> {
        let base = args
            .server
            .clone()
            .or_else(|| std::env::var("SENTINEL_SERVER").ok())
            .ok_or_else(|| usage("give --server URL or set SENTINEL_SERVER"))?;
        let token = match (&args.token_file, &args.token) {
            (Some(path), _) => read_token(path)?,
            (None, Some(token)) => token.clone(),
            (None, None) => std::env::var("SENTINEL_TOKEN")
                .map_err(|_| usage("give --token-file, --token or set SENTINEL_TOKEN"))?,
        };
        if sentinel_auth::token::parse(token.trim()).is_none() {
            return Err(usage("the credential is not a sntl_ token"));
        }
        let agent = ureq::Agent::new_with_config(
            ureq::Agent::config_builder()
                .http_status_as_error(false)
                .timeout_global(Some(Duration::from_secs(60)))
                .build(),
        );
        Ok(Client {
            base: base.trim_end_matches('/').to_owned(),
            token: token.trim().to_owned(),
            agent,
        })
    }

    fn call(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        key: Option<&str>,
    ) -> Result<(u16, Value), Error> {
        let url = format!("{}{path}", self.base);
        let auth = format!("Bearer {}", self.token);
        let response = match (method, body) {
            ("GET", _) => self.agent.get(&url).header("authorization", &auth).call(),
            ("POST", body) => {
                let mut request = self
                    .agent
                    .post(&url)
                    .header("authorization", &auth)
                    .header("content-type", "application/json");
                if let Some(key) = key {
                    request = request.header("idempotency-key", key);
                }
                request.send(
                    body.map(|b| b.to_string())
                        .unwrap_or_else(|| "{}".into())
                        .as_bytes(),
                )
            }
            _ => unreachable!(),
        }
        .map_err(|e| remote(format!("cannot reach {}: {e}", self.base)))?;
        let status = response.status().as_u16();
        let text = response
            .into_body()
            .read_to_string()
            .map_err(|e| remote(format!("cannot read the response: {e}")))?;
        let value = if text.is_empty() {
            Value::Null
        } else {
            serde_json::from_str(&text).map_err(|_| remote("the server did not answer JSON"))?
        };
        Ok((status, value))
    }

    /// A call that must succeed; a structured error becomes the exit.
    fn expect(
        &self,
        method: &str,
        path: &str,
        body: Option<&Value>,
        key: Option<&str>,
    ) -> Result<Value, Error> {
        let (status, value) = self.call(method, path, body, key)?;
        if (200..300).contains(&status) {
            return Ok(value);
        }
        let code = value["code"].as_str().unwrap_or("error");
        let message = value["message"].as_str().unwrap_or("");
        Err(Error {
            message: format!("{code}: {message}"),
            code: match code {
                "unauthenticated" | "forbidden" => 3,
                "not_found" => 4,
                _ => 1,
            },
        })
    }
}

fn read_token(path: &Path) -> Result<String, Error> {
    let text =
        fs::read_to_string(path).map_err(|e| usage(format!("cannot read the token file: {e}")))?;
    Ok(text.trim().to_owned())
}

pub fn run(args: ApiArgs) -> Result<(), Error> {
    let client = Client::from_args(&args)?;
    let json_out = args.json;
    let out = |value: Value, text: String| {
        if json_out {
            println!("{}", serde_json::to_string_pretty(&value).expect("json"));
        } else {
            print!("{text}");
        }
    };
    match &args.command {
        ApiCommand::Me => {
            let me = client.expect("GET", "/api/v1/me", None, None)?;
            out(
                me.clone(),
                format!(
                    "{} via {}{}\n",
                    me["user"],
                    me["via"],
                    if me["super_admin"] == true {
                        " (super admin)"
                    } else {
                        ""
                    }
                ),
            );
        }
        ApiCommand::Run {
            tenant,
            repo,
            pipeline,
            source,
            sha,
            r#ref,
            idempotency_key,
        } => {
            let text = fs::read_to_string(pipeline)
                .map_err(|e| usage(format!("cannot read the pipeline: {e}")))?;
            let body =
                json!({ "pipeline": text, "source": { "repo": source, "sha": sha, "ref": r#ref } });
            let run = client.expect(
                "POST",
                &format!("/api/v1/tenants/{tenant}/repos/{repo}/runs"),
                Some(&body),
                idempotency_key.as_deref(),
            )?;
            out(
                run.clone(),
                format!("{}\n{}", run["id"].as_str().unwrap_or(""), jobs_text(&run)),
            );
        }
        ApiCommand::Status { run } => {
            let view = client.expect("GET", &format!("/api/v1/runs/{run}"), None, None)?;
            out(
                view.clone(),
                format!(
                    "{} {}\n{}",
                    view["id"].as_str().unwrap_or(""),
                    view["state"].as_str().unwrap_or(""),
                    jobs_text(&view)
                ),
            );
        }
        ApiCommand::Runs {
            tenant,
            repo,
            limit,
        } => {
            let list = client.expect(
                "GET",
                &format!("/api/v1/tenants/{tenant}/repos/{repo}/runs?limit={limit}"),
                None,
                None,
            )?;
            let mut text = String::new();
            for run in list["runs"].as_array().into_iter().flatten() {
                text.push_str(&format!(
                    "{} {} {}\n",
                    run["id"].as_str().unwrap_or(""),
                    run["state"].as_str().unwrap_or(""),
                    run["sha"].as_str().unwrap_or("")
                ));
            }
            out(list.clone(), text);
        }
        ApiCommand::Cancel { run, job } => {
            let (path, label) = match (run, job) {
                (Some(run), None) => (format!("/api/v1/runs/{run}/cancel"), run.clone()),
                (None, Some(job)) => (format!("/api/v1/jobs/{job}/cancel"), job.clone()),
                _ => return Err(usage("give exactly one of --run or --job")),
            };
            let result = client.expect("POST", &path, Some(&json!({})), None)?;
            out(result.clone(), format!("{label}: cancellation recorded\n"));
        }
        ApiCommand::Rerun { job } => {
            let result = client.expect(
                "POST",
                &format!("/api/v1/jobs/{job}/rerun"),
                Some(&json!({})),
                None,
            )?;
            out(
                result.clone(),
                format!("{job}: {}\n", result["state"].as_str().unwrap_or("")),
            );
        }
        ApiCommand::Logs { attempt, follow } => {
            let mut after = 0u64;
            loop {
                let page = client.expect(
                    "GET",
                    &format!(
                        "/api/v1/attempts/{attempt}/logs?after={after}&wait={}",
                        u8::from(*follow)
                    ),
                    None,
                    None,
                )?;
                if json_out {
                    println!("{}", serde_json::to_string(&page).expect("json"));
                } else {
                    use std::io::Write;
                    for frame in page["frames"].as_array().into_iter().flatten() {
                        let text = frame["text"].as_str().unwrap_or("");
                        if frame["stream"] == "stderr" {
                            let _ = std::io::stderr().write_all(text.as_bytes());
                        } else {
                            let _ = std::io::stdout().write_all(text.as_bytes());
                        }
                    }
                    let _ = std::io::stdout().flush();
                }
                if let Some(last) = page["frames"].as_array().and_then(|f| f.last()) {
                    after = last["seq"].as_u64().unwrap_or(after);
                }
                if page["complete"] == true {
                    if !json_out {
                        for gap in page["gaps"].as_array().into_iter().flatten() {
                            eprintln!(
                                "[sentinel: frames {}-{} were lost on the worker]",
                                gap[0], gap[1]
                            );
                        }
                    }
                    return Ok(());
                }
                if !*follow {
                    if !json_out {
                        eprintln!("[sentinel: log incomplete; use --follow to wait for the rest]");
                    }
                    return Ok(());
                }
            }
        }
        ApiCommand::Workers { tenant } => {
            let view = client.expect(
                "GET",
                &format!("/api/v1/workers?tenant={tenant}"),
                None,
                None,
            )?;
            let mut text = String::new();
            for pool in view["pools"].as_array().into_iter().flatten() {
                text.push_str(&format!(
                    "pool {} ({})\n",
                    pool["name"].as_str().unwrap_or(""),
                    pool["kind"].as_str().unwrap_or("")
                ));
                for worker in pool["workers"].as_array().into_iter().flatten() {
                    text.push_str(&format!(
                        "  {} {} {} {}\n",
                        worker["id"].as_str().unwrap_or(""),
                        worker["name"].as_str().unwrap_or(""),
                        worker["arch"].as_str().unwrap_or(""),
                        if worker["connected"] == true {
                            "connected"
                        } else {
                            "offline"
                        }
                    ));
                }
            }
            out(view.clone(), text);
        }
    }
    Ok(())
}

fn jobs_text(run: &Value) -> String {
    let mut text = String::new();
    for job in run["jobs"].as_array().into_iter().flatten() {
        text.push_str(&format!(
            "  {:<24} {:<12} {}{}\n",
            job["name"].as_str().unwrap_or(""),
            job["state"].as_str().unwrap_or(""),
            job["failure_class"].as_str().unwrap_or(""),
            job["attempt"]
                .as_str()
                .map(|a| format!(" {a}"))
                .unwrap_or_default()
        ));
    }
    text
}
