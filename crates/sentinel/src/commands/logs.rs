//! `log show [--follow] [--step]` and `log search --text`.

use std::io::Write;

use serde_json::{Map, Value, json};

use super::{List, MAX_ITEMS, PAGE, busy_backoff, segment, text};
use crate::client::{Client, Error, Output};

/// Print an attempt's frames page by page. Text writes each frame's bytes
/// to the stream it came from (stdout or stderr), as the job wrote them;
/// NDJSON prints one `{seq, step, stream, text}` line per frame; JSON one
/// `{attempt, frames, complete, gaps}` document of at most 10,000 frames
/// (`next_after` continues a cut one). Without `--follow` the command ends
/// at the end of what is stored; with it, it parks until the log is
/// complete.
pub(super) fn show(
    client: &Client,
    output: Output,
    attempt: &str,
    follow: bool,
    step: Option<u32>,
) -> Result<(), Error> {
    let attempt = segment("attempt", attempt)?;
    let mut after = 0u64;
    let mut list = List::new(output);
    let mut shown = 0usize;
    let (complete, gaps) = loop {
        let mut path = format!("/api/v1/attempts/{attempt}/logs?after={after}&limit={PAGE}");
        if let Some(step) = step {
            path.push_str(&format!("&step={step}"));
        }
        if follow {
            path.push_str("&wait=1");
        }
        let page = match client.get(&path) {
            Ok(page) => page,
            Err(error) => match (follow, busy_backoff(&error)) {
                (true, Some(pause)) => {
                    std::thread::sleep(pause);
                    continue;
                }
                _ => return Err(error),
            },
        };
        let frames = page["frames"].as_array().map_or(&[][..], Vec::as_slice);
        for frame in frames {
            if output == Output::Json && shown >= MAX_ITEMS {
                break;
            }
            shown += 1;
            match output {
                Output::Text => {
                    let bytes = text(frame, "text").as_bytes();
                    let _ = if frame["stream"] == "stderr" {
                        std::io::stderr().write_all(bytes)
                    } else {
                        std::io::stdout().write_all(bytes)
                    };
                }
                _ => list.item(frame.clone(), String::new),
            }
            after = frame["seq"].as_u64().unwrap_or(after);
        }
        if output == Output::Text {
            let _ = std::io::stdout().flush();
        }
        let complete = page["complete"] == true;
        let capped = output == Output::Json && shown >= MAX_ITEMS;
        if complete || capped || (!follow && frames.len() < PAGE) {
            break (complete && !capped, page["gaps"].clone());
        }
    };
    if output == Output::Text {
        for gap in gaps.as_array().into_iter().flatten() {
            eprintln!(
                "[sentinel: frames {}-{} were lost on the worker]",
                gap[0], gap[1]
            );
        }
        if !complete {
            eprintln!("[sentinel: log incomplete; use --follow to wait for the rest]");
        }
    }
    let mut extra = Map::new();
    extra.insert("attempt".into(), Value::String(attempt.to_owned()));
    extra.insert("complete".into(), Value::Bool(complete));
    extra.insert("gaps".into(), gaps);
    extra.insert(
        "next_after".into(),
        if complete { Value::Null } else { json!(after) },
    );
    list.finish("frames", extra);
    Ok(())
}

/// Longest literal the server searches for, in bytes.
const MAX_TEXT: usize = 256;

/// Follow the server's bounded scans (`next_after`) until the log's end or
/// the match limit: each request scans at most 4 MiB, so a large log costs
/// several short requests rather than one long one.
pub(super) fn search(
    client: &Client,
    output: Output,
    attempt: &str,
    needle: &str,
    limit: Option<usize>,
) -> Result<(), Error> {
    let attempt = segment("attempt", attempt)?;
    if needle.is_empty() || needle.len() > MAX_TEXT {
        return Err(Error::usage(format!("--text must be 1..{MAX_TEXT} bytes")));
    }
    let cap = match limit {
        None => 100,
        Some(n) if (1..=MAX_ITEMS).contains(&n) => n,
        Some(_) => return Err(Error::usage(format!("--limit must be 1..{MAX_ITEMS}"))),
    };
    let query: String = form_urlencoded::byte_serialize(needle.as_bytes()).collect();
    let mut list = List::new(output);
    let mut shown = 0usize;
    let mut after = 0u64;
    // The server's scan state at `after` (hex), so a literal split across
    // two requests is still found, once.
    let mut carry = String::new();
    let (next, complete) = loop {
        let size = (cap - shown).min(PAGE);
        let resume = if carry.is_empty() { "" } else { "&carry=" };
        let page = client.get(&format!(
            "/api/v1/attempts/{attempt}/logs/search?q={query}&after={after}&limit={size}{resume}{carry}"
        ))?;
        for m in page["matches"].as_array().into_iter().flatten() {
            if shown >= cap {
                break;
            }
            shown += 1;
            list.item(m.clone(), || {
                format!(
                    "{} step {} {}: {}\n",
                    m["seq"],
                    m["step"],
                    text(m, "stream"),
                    text(m, "text")
                )
            });
            after = m["seq"].as_u64().unwrap_or(after);
        }
        let complete = page["complete"] == true;
        match page["next_after"].as_u64() {
            Some(next) if shown < cap => {
                after = next;
                carry.clear();
                // Hex from the server; anything else is dropped, not sent.
                if let Some(text) = page["next_carry"].as_str()
                    && text.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    carry.push_str(text);
                }
            }
            Some(next) => break (Some(next.max(after)), complete),
            None => break (None, complete),
        }
    };
    if output == Output::Text {
        if let Some(next) = next {
            eprintln!("[sentinel: more matches may follow sequence {next}; raise --limit]");
        } else if !complete {
            eprintln!("[sentinel: the log is still being written; later lines were not searched]");
        }
    }
    let mut extra = Map::new();
    extra.insert("attempt".into(), Value::String(attempt.to_owned()));
    extra.insert("next_after".into(), next.map_or(Value::Null, |n| json!(n)));
    extra.insert("complete".into(), Value::Bool(complete && next.is_none()));
    list.finish("matches", extra);
    Ok(())
}
