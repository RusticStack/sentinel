use std::io::Write;

use serde_json::{Map, Value, json};

use super::{List, MAX_ITEMS, PAGE, busy_backoff, segment, text};
use crate::client::{self, Client, Error, Output};

const MAX_JSON_TEXT: usize = 16 << 20;

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
    let mut held = 0usize;
    let mut capped = false;
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
            if output == Output::Json {
                let size = text(frame, "text").len();
                if shown >= MAX_ITEMS || (shown > 0 && held + size > MAX_JSON_TEXT) {
                    capped = true;
                    break;
                }
                held += size;
            }
            shown += 1;
            match output {
                Output::Text => {
                    let bytes = text(frame, "text").as_bytes();
                    if frame["stream"] == "stderr" {
                        let _ = std::io::stderr().write_all(bytes);
                    } else {
                        client::stdout_bytes(bytes);
                    }
                }
                _ => list.item(frame.clone(), String::new),
            }
            after = frame["seq"].as_u64().unwrap_or(after);
        }
        if output == Output::Text {
            client::stdout_flush();
        }
        let complete = page["complete"] == true;
        capped |= output == Output::Json && shown >= MAX_ITEMS;
        let more = page["next_after"].as_u64();
        if let Some(next) = more
            && !capped
        {
            after = after.max(next);
            continue;
        }
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

const MAX_TEXT: usize = 256;

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
    // The server's scan state at `after`, so a literal split across two requests is still found once.
    let mut carry = String::new();
    let (next, complete) = loop {
        let size = (cap - shown).min(PAGE);
        let resume = if carry.is_empty() { "" } else { "&carry=" };
        let page = client.get(&format!(
            "/api/v1/attempts/{attempt}/logs/search?q={query}&after={after}&limit={size}{resume}{carry}"
        ))?;
        // Matches past the cap are cut here; the resume point precedes that frame so a rerun sees them.
        let mut cut: Option<u64> = None;
        for m in page["matches"].as_array().into_iter().flatten() {
            if shown >= cap {
                cut = m["seq"].as_u64().map(|seq| seq.saturating_sub(1));
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
        if let Some(cut) = cut {
            break (Some(cut), false);
        }
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
