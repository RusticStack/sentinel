//! AI assistance policy (Part 22 Y01): the providers a deployment allows, set by a
//! platform administrator, and the opt-in and data policy a tenant's administrator
//! chooses. No route here reaches a provider: with no tenant opted in there is no
//! request to make, and the gate Y03 calls (`sentinel_store::ai::admit`) reads this
//! policy on every request, so a disable applies at once.
//!
//! Y02 adds the one route an AI process reads: the evidence bundle for an attempt
//! ([`context`]). It holds no provider and makes no call either; it exists so the process
//! that will call one never holds a log, a secret or a credential, only a bounded,
//! redacted document behind its own grant.
//!
//! Y03 adds the durable requests that process consumes ([`enqueue`], [`queued`], [`claim`],
//! [`complete`]) and the delegation each one mints: the requester's own identity capped to reads,
//! bound to that request and that attempt, ten minutes or the request's deadline at most.

use sentinel_core::{
    AiRequestId, AttemptId, UnixMillis,
    auth::{Permissions, Scopes},
};
use sentinel_protocol::{
    diagnostics::{Diagnostic, Severity, StepReference},
    error::{ApiError, ErrorCode},
    logs::Frame,
    patterns,
    redact::Redactor,
    summary::{AttemptSummary, StepOutcome},
};
use sentinel_store::{
    Error as StoreError, ai, auth as authz, dispatch, logs, lookup, secrets, status,
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::evidence::{LogScope, Reports, json_len, log_reports, looks_binary, step_outcome_name};

use super::{
    Reply, Route, admin, auth, body, err, id, identify, ok, parse, query_param, store_error,
    stream_name,
};
use crate::{State, http::Request};

pub(super) fn route(
    state: &State,
    request: &mut Request,
    method: &str,
    parts: &[&str],
    query: &str,
) -> Option<Route> {
    Some(match (method, parts) {
        ("GET", ["api", "v1", "admin", "ai"]) => deployment_policy(state, request),
        ("PUT", ["api", "v1", "admin", "ai"]) => set_deployment(state, request),
        ("GET", ["api", "v1", "tenants", slug, "ai"]) => tenant_policy(state, request, slug),
        ("PUT", ["api", "v1", "tenants", slug, "ai"]) => set_tenant(state, request, slug),
        ("GET", ["api", "v1", "attempts", attempt, "ai-context"]) => {
            context(state, request, attempt, query)
        }
        ("POST", ["api", "v1", "tenants", slug, "ai", "requests"]) => enqueue(state, request, slug),
        ("GET", ["api", "v1", "ai", "requests"]) => queued(state, request, query),
        ("GET", ["api", "v1", "ai", "requests", request_id]) => {
            require_request(state, request, request_id)
        }
        ("POST", ["api", "v1", "ai", "requests", request_id, "claim"]) => {
            claim(state, request, request_id)
        }
        ("POST", ["api", "v1", "ai", "requests", request_id, "complete"]) => {
            complete(state, request, request_id)
        }
        _ => return None,
    })
}

fn deployment_json(policy: ai::Deployment) -> Value {
    json!({
        "enabled": policy.enabled,
        "providers": policy.providers.list().map(ai::Provider::as_str).collect::<Vec<_>>(),
    })
}

fn tenant_json(policy: Option<ai::Tenant>, providers: ai::Providers) -> Value {
    json!({
        "enabled": policy.is_some_and(|p| p.enabled),
        "data_policy": policy.map(|p| p.data_policy.as_str()),
        "providers": providers.list().map(ai::Provider::as_str).collect::<Vec<_>>(),
    })
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DeploymentBody {
    enabled: bool,
    providers: Vec<String>,
}

fn deployment_policy(state: &State, request: &Request) -> Route {
    admin::platform(state, request, false)?;
    let policy = state.store.read(ai::deployment).map_err(store_error)?;
    ok(deployment_json(policy))
}

fn set_deployment(state: &State, request: &mut Request) -> Route {
    let who = admin::platform(state, request, true)?;
    let body: DeploymentBody = parse(&body(request)?)?;
    let mut providers = ai::Providers::NONE;
    for name in &body.providers {
        let provider = ai::Provider::parse(name).ok_or_else(|| unknown_provider(name))?;
        providers.insert(provider);
    }
    if body.enabled && providers.is_empty() {
        return Err(err(
            ErrorCode::InvalidRequest,
            "enabling AI needs at least one provider",
        ));
    }
    let policy = ai::Deployment {
        enabled: body.enabled,
        providers,
    };
    let authority = who.authority();
    state
        .store
        .writer()
        .write(move |tx| ai::set_deployment(tx, authority, policy, UnixMillis::now()))
        .map_err(store_error)?;
    ok(deployment_json(policy))
}

fn unknown_provider(name: &str) -> ApiError {
    err(ErrorCode::InvalidRequest, "unknown provider").with_detail("provider", name)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TenantBody {
    enabled: bool,
    data_policy: String,
}

fn tenant_policy(state: &State, request: &Request, slug: &str) -> Route {
    let who = admin::tenant_admin(state, request, false)?;
    let principal = who.principal;
    let slug = slug.to_owned();
    let (policy, providers) = state
        .store
        .read(move |c| {
            let tenant = authz::member_tenant_by_slug(c, principal, &slug)?;
            authz::require_tenant_admin(c, principal, tenant)?;
            Ok((ai::tenant(c, tenant)?, ai::effective(c, tenant)?.0))
        })
        .map_err(store_error)?;
    ok(tenant_json(policy, providers))
}

fn set_tenant(state: &State, request: &mut Request, slug: &str) -> Route {
    let who = admin::tenant_admin(state, request, true)?;
    let body: TenantBody = parse(&body(request)?)?;
    let data_policy = ai::DataPolicy::parse(&body.data_policy).ok_or_else(|| {
        err(
            ErrorCode::InvalidRequest,
            "data_policy must be local_only, zero_retention or provider_terms",
        )
        .with_detail("data_policy", body.data_policy.as_str())
    })?;
    let policy = ai::Tenant {
        enabled: body.enabled,
        data_policy,
    };
    let (principal, authority) = (who.principal, who.authority());
    let slug = slug.to_owned();
    let providers = state
        .store
        .writer()
        .write(move |tx| {
            let tenant = authz::member_tenant_by_slug(tx, principal, &slug)?;
            ai::set_tenant(tx, authority, tenant, policy, UnixMillis::now())?;
            Ok(ai::effective(tx, tenant)?.0)
        })
        .map_err(store_error)?;
    ok(tenant_json(Some(policy), providers))
}

/// The bundle's bound: the plan's 32 KiB, and the 64 KiB a caller may ask for.
const DEFAULT_BUNDLE_BYTES: usize = 32 << 10;
const MAX_BUNDLE_BYTES: usize = 64 << 10;
/// Below this a bundle cannot hold its own frame, so a smaller `budget` is refused, not served empty.
const MIN_BUNDLE_BYTES: usize = 1 << 10;
const BUNDLE_FRAMES: usize = 512;
const BUNDLE_SCAN_BYTES: u64 = 16 << 20;
const BUNDLE_PAGE_BYTES: u64 = 4 << 20;
/// Seed text taken from the newest frames; the bound then trims what does not fit.
const BUNDLE_TEXT_BYTES: usize = 128 << 10;
const MAX_BUNDLE_DIAGNOSTICS: usize = 20;
const DIAGNOSTIC_TEXT_BYTES: usize = 1024;
const MAX_BUNDLE_STEPS: usize = 8;

/// The AI evidence bundle (Y02): bounded, redacted, and readable only by a credential a deployment
/// granted `ai:context`. The controller builds it from what it already stored — the attempt's
/// redacted log and the diagnostics those frames parse into — and re-applies the attempt's
/// registered secret values and the credential-shaped scanners to every text field before serving
/// it, so a provider receives evidence and never a credential.
pub(super) fn context(state: &State, request: &Request, attempt: &str, query: &str) -> Route {
    let who = identify(state, request, false)?;
    let attempt: AttemptId = id(attempt, "attempt")?;
    // Two credentials may read a bundle: the AI service's own `ai:context` grant, and the
    // read-only delegation of a live request about this very attempt. The delegation is the
    // requester's own identity capped to reads, so it can read nothing the requester cannot, and
    // its binding ends the moment the request settles or its deadline passes.
    if !who.scopes.contains(Scopes::AI_CONTEXT) {
        let delegated = match who.credential {
            Some(token) => state
                .store
                .read(move |c| ai::delegates(c, token, attempt, UnixMillis::now()))
                .map_err(store_error)?,
            None => false,
        };
        if !delegated {
            auth::require_scope(&who, Scopes::AI_CONTEXT)?;
        }
    }
    let budget = match query_param(query, "budget") {
        None => DEFAULT_BUNDLE_BYTES,
        Some(value) => value
            .parse::<usize>()
            .ok()
            .filter(|size| (MIN_BUNDLE_BYTES..=MAX_BUNDLE_BYTES).contains(size))
            .ok_or_else(|| {
                err(
                    ErrorCode::InvalidRequest,
                    format!("budget must be {MIN_BUNDLE_BYTES}..{MAX_BUNDLE_BYTES} bytes"),
                )
            })?,
    };
    let principal = who.principal;
    let key = state.secret_key.clone();
    let found = state
        .store
        .read(move |c| {
            let job = lookup::attempt_job(c, attempt)?;
            let run = lookup::job_run(c, job)?;
            let repo = lookup::run_repo(c, run)?;
            let tenant = authz::require_repo(c, principal, repo, Permissions::READ)?;
            // The same reading Y03's request path makes: a tenant the deployment or its own
            // administrator has not opted in has no bundle at all.
            if !ai::permits(c, tenant)? {
                return Ok(None);
            }
            let summary = dispatch::attempt_summary(c, tenant, attempt)?;
            let status = status::attempt_job_status(c, tenant, attempt)?;
            let values = match key.as_deref() {
                Some(key) => secrets::attempt_values(c, key, attempt)?,
                None => secrets::Values::empty(),
            };
            Ok(Some((run, job, summary, status, values)))
        })
        .map_err(store_error)?;
    let Some((run, job, summary_bytes, status, values)) = found else {
        return Err(
            err(ErrorCode::Forbidden, "AI assistance is off for this tenant")
                .with_detail("ai", "off"),
        );
    };
    let summary = summary_bytes
        .as_deref()
        .map(AttemptSummary::decode)
        .transpose()
        .map_err(|_| err(ErrorCode::Internal, "stored summary unreadable"))?
        .unwrap_or_default();
    let step = summary
        .steps
        .iter()
        .find(|record| is_failed(record.outcome));
    let page = bundle_page(state, run, job, attempt, step.map(|record| record.index))?;
    let mut reports = Reports::default();
    log_reports(
        &mut reports,
        &page.frames,
        0,
        LogScope {
            run,
            job,
            attempt,
            step_index: step.map(|record| record.index),
            step_reference: step.map(|record| StepReference {
                index: record.index,
                key: Some(record.id.clone()),
            }),
            complete: page.complete && page.gaps.is_empty(),
        },
    );
    let mut scrub = Scrub::new(&values);
    let mut steps = Vec::with_capacity(summary.steps.len().min(MAX_BUNDLE_STEPS));
    let mut omitted_steps = 0u64;
    for primary in [true, false] {
        for record in &summary.steps {
            if is_failed(record.outcome) != primary {
                continue;
            }
            if steps.len() == MAX_BUNDLE_STEPS {
                omitted_steps = omitted_steps.saturating_add(1);
                continue;
            }
            steps.push(step_json(record, &mut scrub));
        }
    }
    let mut flat = Vec::new();
    for item in &mut reports.items {
        flat.append(&mut item.report.diagnostics);
    }
    // Failures and errors before warnings and informational records, each group in the order the
    // autopsy found it: a model reads the bundle, so its strongest evidence comes first.
    flat.sort_by_key(|diagnostic| !is_failure(diagnostic.severity));
    let mut omitted_diagnostics = reports.omitted;
    let mut diagnostics = Vec::with_capacity(MAX_BUNDLE_DIAGNOSTICS);
    for diagnostic in flat {
        if diagnostics.len() == MAX_BUNDLE_DIAGNOSTICS {
            omitted_diagnostics = omitted_diagnostics.saturating_add(1);
            continue;
        }
        let id = diagnostics.len() + 1;
        diagnostics.push(diagnostic_json(id, diagnostic, &mut scrub));
    }
    let mut frames = Vec::with_capacity(page.frames.len().min(64));
    let mut seeded = 0usize;
    for frame in page.frames.iter().rev() {
        if seeded >= BUNDLE_TEXT_BYTES {
            break;
        }
        seeded = seeded.saturating_add(frame.bytes.len());
        frames.push(frame_json(frame, &mut scrub));
    }
    frames.reverse();
    let omitted_log_frames = (page.frames.len() - frames.len()) as u64;
    let failed_step = step.map(|record| step_json(record, &mut scrub));
    let mut body = json!({
        "schema": "sentinel.ai-context/1",
        "attempt": attempt.to_string(),
        "run": run.to_string(),
        "job": job.to_string(),
        "authoritative": {
            "current_attempt": status.current,
            "job_state": status.state.map(|state| state.as_str()),
            "failure_class": status.failure_class.map(|class| class.as_str()),
        },
        "failed_step": failed_step,
        "steps": steps,
        "omitted_steps": omitted_steps,
        "diagnostics": diagnostics,
        "log": {
            "frames": frames,
            "complete": page.complete && page.gaps.is_empty(),
            "gaps": page.gaps.iter().take(sentinel_protocol::logs::MAX_GAPS).collect::<Vec<_>>(),
            "gaps_truncated": page.gaps.len() > sentinel_protocol::logs::MAX_GAPS,
            "scanned_frames": page.frames.len(),
        },
        "bounds": {
            "budget_bytes": budget,
            "bytes": 0,
            "truncated": omitted_log_frames > 0,
            "omitted_diagnostics": omitted_diagnostics,
            "omitted_log_frames": omitted_log_frames,
        },
        "redaction": {
            "values": scrub.registered,
            "value_rewrites": scrub.value_rewrites,
            "pattern_replacements": scrub.patterns.count(),
            "patterns": scrub.patterns.kinds().map(patterns::Kind::as_str).collect::<Vec<_>>(),
        },
    });
    fit_bundle(&mut body, budget);
    ok(body)
}

fn is_failed(outcome: StepOutcome) -> bool {
    matches!(
        outcome,
        StepOutcome::Failed { .. }
            | StepOutcome::Signaled { .. }
            | StepOutcome::OutOfMemory
            | StepOutcome::TimedOut
            | StepOutcome::Runtime
    )
}

fn is_failure(severity: Severity) -> bool {
    matches!(severity, Severity::Error | Severity::Failure)
}

/// The newest window of the failed step, or of the whole log when the attempt had no failed step:
/// the same pages the failure context reads, with a legacy flat log read as far back as it goes.
fn bundle_page(
    state: &State,
    run: sentinel_core::RunId,
    job: sentinel_core::JobId,
    attempt: AttemptId,
    step: Option<u32>,
) -> Result<logs::Tail, ApiError> {
    let page = logs::Page {
        limit: BUNDLE_FRAMES,
        bytes: BUNDLE_PAGE_BYTES,
        scan: BUNDLE_SCAN_BYTES,
    };
    state
        .logs
        .newest_page(run, job, attempt, page, step)
        .or_else(|error| match error {
            StoreError::NotFound => state.logs.tail_legacy_page(attempt, 0, page, step),
            other => Err(other),
        })
        .or_else(|error| match error {
            StoreError::NotFound => Ok(logs::Tail {
                frames: Vec::new(),
                complete: false,
                gaps: Vec::new(),
                next_after: None,
                step_done: false,
            }),
            other => Err(other),
        })
        .map_err(store_error)
}

/// One redaction pass over the bundle's text: the attempt's registered values first, then the
/// credential-shaped scanners. Both counts are what the bundle reports about itself.
struct Scrub {
    values: Redactor,
    registered: usize,
    value_rewrites: u64,
    patterns: patterns::Hits,
}

impl Scrub {
    fn new(values: &secrets::Values) -> Scrub {
        let mut redactor = Redactor::new();
        let mut registered = 0;
        for value in values.iter() {
            if redactor.register(value) {
                registered += 1;
            }
        }
        Scrub {
            values: redactor,
            registered,
            value_rewrites: 0,
            patterns: patterns::Hits::NONE,
        }
    }

    fn text(&mut self, text: &str) -> String {
        let bytes = self.values.redact_all(text.as_bytes());
        if bytes != text.as_bytes() {
            self.value_rewrites = self.value_rewrites.saturating_add(1);
        }
        let redacted = String::from_utf8(bytes)
            .unwrap_or_else(|error| String::from_utf8_lossy(error.as_bytes()).into_owned());
        patterns::redact_str(&redacted, &mut self.patterns)
    }
}

fn step_json(record: &sentinel_protocol::summary::StepRecord, scrub: &mut Scrub) -> Value {
    json!({
        "index": record.index,
        "id": scrub.text(&record.id),
        "outcome": step_outcome_name(record.outcome),
        "exit_code": match record.outcome {
            StepOutcome::Failed { code } => Some(code),
            _ => None,
        },
        "signal": match record.outcome {
            StepOutcome::Signaled { signal } => Some(signal),
            _ => None,
        },
        "duration_ns": record.duration_ns,
    })
}

/// A diagnostic keeps its first bytes: Go, Cargo and JUnit put the assertion at the start.
fn diagnostic_json(id: usize, diagnostic: Diagnostic, scrub: &mut Scrub) -> Value {
    let message = scrub.text(&sentinel_protocol::diagnostics::display_text(
        &diagnostic.message,
    ));
    let message = cut_end(message, DIAGNOSTIC_TEXT_BYTES);
    json!({
        "id": format!("diag-{id}"),
        "severity": diagnostic.severity,
        "failure_class": diagnostic.failure_class,
        "message": message,
        "code": diagnostic.code.as_deref().map(|code| scrub.text(code)),
        "step": diagnostic.step.map(|step| json!({
            "index": step.index,
            "key": step.key.as_deref().map(|key| scrub.text(key)),
        })),
        "source": diagnostic.source.map(|source| json!({
            "path": scrub.text(&source.path),
            "line": source.line,
            "column": source.column,
        })),
        "test": diagnostic.test.map(|test| json!({
            "name": scrub.text(&test.name),
            "package": test.package.as_deref().map(|package| scrub.text(package)),
            "class_name": test.class_name.as_deref().map(|name| scrub.text(name)),
        })),
        "evidence": diagnostic.evidence.iter().map(|reference| json!({
            "sequence": reference.start.sequence,
            "offset": reference.start.payload_offset,
            "end_sequence": reference.end.sequence,
            "end_offset": reference.end.payload_offset,
        })).collect::<Vec<_>>(),
    })
}

fn frame_json(frame: &Frame, scrub: &mut Scrub) -> Value {
    if looks_binary(&frame.bytes) {
        return json!({
            "sequence": frame.seq,
            "step": frame.step,
            "stream": stream_name(frame.stream),
            "binary": true,
            "bytes": frame.bytes.len(),
        });
    }
    let text = String::from_utf8_lossy(&frame.bytes);
    let text = scrub.text(&sentinel_protocol::diagnostics::display_text(&text));
    json!({
        "id": format!("log-{}", frame.seq),
        "sequence": frame.seq,
        "step": frame.step,
        "stream": stream_name(frame.stream),
        "text": text,
    })
}

/// The newest bytes of one value survive a cut; a cut never splits a character.
fn cut_start(text: &mut String, keep: usize) -> bool {
    if text.len() <= keep {
        return false;
    }
    let mut start = text.len() - keep;
    while !text.is_char_boundary(start) {
        start += 1;
    }
    text.replace_range(..start, "");
    true
}

/// The first bytes of one value survive a cut, where an assertion is.
fn cut_end(mut text: String, keep: usize) -> String {
    if text.len() <= keep {
        return text;
    }
    let mut end = keep;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text.truncate(end);
    text
}

/// Trims the assembled bundle to `budget`, oldest evidence first: the newest log bytes are what a
/// failure is usually explained by, so a frame loses its front before a whole frame is dropped, and
/// diagnostics go only after the log is gone. Every cut is stated in the body (`truncated`, `cut`,
/// `omitted_*`), so a consumer can tell a complete bundle from a shortened one.
fn fit_bundle(body: &mut Value, budget: usize) {
    loop {
        let size = json_len(body);
        if size <= budget {
            break;
        }
        let excess = size - budget;
        if body["bounds"]["truncated"] != Value::Bool(true) {
            body["bounds"]["truncated"] = Value::Bool(true);
        }
        let frames = body["log"]["frames"]
            .as_array_mut()
            .expect("the bundle always has a log");
        let Some(oldest) = frames.first_mut() else {
            if !shorten_diagnostic(body, excess) {
                break;
            }
            continue;
        };
        if let Some(text) = oldest
            .get("text")
            .and_then(Value::as_str)
            .filter(|text| !text.is_empty())
        {
            let mut kept = text.to_owned();
            let keep = kept.len().saturating_sub(excess.max(1));
            cut_start(&mut kept, keep);
            oldest["text"] = Value::String(kept);
            oldest["cut"] = Value::Bool(true);
            continue;
        }
        frames.remove(0);
        let omitted = body["bounds"]["omitted_log_frames"].as_u64().unwrap_or(0);
        body["bounds"]["omitted_log_frames"] = json!(omitted.saturating_add(1));
    }
    // Evidence alone cannot always fit: an attempt whose fixed frame is larger than a small
    // budget keeps its identity, its bound and what it redacted, and loses the evidence itself.
    if json_len(body) > budget {
        body["steps"] = json!([]);
        body["diagnostics"] = json!([]);
        body["failed_step"] = Value::Null;
        body["log"]["frames"] = json!([]);
        body["log"]["gaps"] = json!([]);
        body["bounds"]["truncated"] = Value::Bool(true);
    }
    // The reported size is the body's own size, so it counts its own digits: measure, write,
    // measure again until the figure and the body agree.
    loop {
        let size = json_len(body);
        if body["bounds"]["bytes"].as_u64() == Some(size as u64) {
            break;
        }
        body["bounds"]["bytes"] = json!(size);
    }
}

/// Shortens the last diagnostic's message from its end, then drops diagnostics oldest first.
fn shorten_diagnostic(body: &mut Value, excess: usize) -> bool {
    let Some(diagnostics) = body["diagnostics"].as_array_mut() else {
        return false;
    };
    let Some(last) = diagnostics.last_mut() else {
        return false;
    };
    if let Some(message) = last
        .get("message")
        .and_then(Value::as_str)
        .filter(|message| !message.is_empty())
    {
        let kept = cut_end(
            message.to_owned(),
            message.len().saturating_sub(excess.max(1)),
        );
        last["message"] = Value::String(kept);
        last["message_cut"] = Value::Bool(true);
        return true;
    }
    diagnostics.pop();
    let omitted = body["bounds"]["omitted_diagnostics"].as_u64().unwrap_or(0);
    body["bounds"]["omitted_diagnostics"] = json!(omitted.saturating_add(1));
    true
}

// ---------------------------------------------------------------------------------------------
// Durable requests (Y03): a member asks about one attempt, the AI service consumes the row through
// the API, and the row ends exactly once. The controller calls no provider and the AI process
// holds no log, no secret and no run.
// ---------------------------------------------------------------------------------------------

/// A page of queued requests. The service asks one poll at a time; a smaller page is a deliberate
/// cap, because a request that waits is a request that will expire.
const QUEUE_PAGE: u32 = 32;
const MAX_QUEUE_PAGE: u32 = 128;
/// How many expired rows one poll settles. Bounded like every other sweep in the controller.
const EXPIRE_PER_POLL: u32 = 32;

fn request_json(request: &ai::Request, with_result: bool) -> Value {
    let mut body = json!({
        "id": request.id.to_string(),
        "attempt": request.attempt.to_string(),
        "provider": request.provider.as_str(),
        "data_policy": request.data_policy.as_str(),
        "state": request.state.as_str(),
        "outcome": request.outcome.map(ai::Outcome::as_str),
        "reason": request.reason.as_deref().filter(|_| with_result),
        "created_ms": request.created.0,
        "deadline_ms": request.deadline.0,
    });
    if with_result {
        body["result"] = json!(request.result.as_deref());
    }
    body
}

fn ai_off() -> ApiError {
    err(ErrorCode::Forbidden, "AI assistance is off for this tenant").with_detail("ai", "off")
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestBody {
    attempt: String,
    provider: String,
}

/// A member asks for one AI request about one attempt. It is a durable row from here on: the
/// answer arrives through the request's own route, never in this response.
fn enqueue(state: &State, request: &mut Request, slug: &str) -> Route {
    let who = identify(state, request, true)?;
    // The requester must hold every read-only scope: the delegation minted for this request is
    // exactly that set, so a caller who holds less would get a credential wider than itself.
    auth::require_scope(&who, Scopes::READ_ONLY)?;
    let body: RequestBody = parse(&body(request)?)?;
    let attempt: AttemptId = id(&body.attempt, "attempt")?;
    let provider =
        ai::Provider::parse(&body.provider).ok_or_else(|| unknown_provider(&body.provider))?;
    let (principal, authority, scopes) = (who.principal, who.authority(), who.scopes);
    let slug = slug.to_owned();
    let row = state
        .store
        .writer()
        .write(move |tx| {
            let tenant = authz::member_tenant_by_slug(tx, principal, &slug)?;
            // The gate first, so a tenant that may send nothing is told that rather than told to
            // read a repository it may already read. `enqueue` reads it again and stores it, so
            // the row records the policy it was actually admitted under.
            ai::admit(tx, tenant, provider)?.ok_or(StoreError::Forbidden)?;
            let repo =
                lookup::run_repo(tx, lookup::job_run(tx, lookup::attempt_job(tx, attempt)?)?)?;
            ai::enqueue(
                tx,
                authority,
                tenant,
                repo,
                attempt,
                provider,
                scopes,
                UnixMillis::now(),
            )
        })
        .map_err(|error| match error {
            StoreError::Forbidden => ai_off(),
            other => store_error(other),
        })?;
    Ok(Reply::Json(201, request_json(&row, false), Vec::new()))
}

/// The oldest queued requests, and the sweep that ends the ones nobody answered in time. The
/// consumer's own poll is where expiry happens, so a controller with no AI process running has
/// nothing to schedule and a request can never outlive its deadline.
fn queued(state: &State, request: &Request, query: &str) -> Route {
    let who = identify(state, request, false)?;
    auth::require_scope(&who, Scopes::AI_CONTEXT)?;
    let limit = match query_param(query, "limit") {
        None => QUEUE_PAGE,
        Some(value) => value
            .parse::<u32>()
            .ok()
            .filter(|limit| (1..=MAX_QUEUE_PAGE).contains(limit))
            .ok_or_else(|| {
                err(
                    ErrorCode::InvalidRequest,
                    format!("limit must be 1..={MAX_QUEUE_PAGE}"),
                )
            })?,
    };
    let now = UnixMillis::now();
    state
        .store
        .writer()
        .write(move |tx| ai::sweep(tx, now, EXPIRE_PER_POLL))
        .map_err(store_error)?;
    let rows = state
        .store
        .read(move |c| ai::queued(c, limit))
        .map_err(store_error)?;
    // A full page may have more behind it; the service asks again for the next one.
    let truncated = rows.len() == limit as usize;
    let requests: Vec<Value> = rows.iter().map(|row| request_json(row, false)).collect();
    ok(json!({ "requests": requests, "truncated": truncated }))
}

/// One request, read by a member who can read its repository.
fn require_request(state: &State, request: &Request, request_id: &str) -> Route {
    let who = identify(state, request, false)?;
    auth::require_scope(&who, Scopes::RUNS_READ)?;
    let id: AiRequestId = id(request_id, "request")?;
    let principal = who.principal;
    // Authorized through the request's repository: a member of another tenant gets the same
    // `not_found` as for a request that does not exist.
    let row = state
        .store
        .read(move |c| {
            let row = ai::by_id(c, id)?;
            let tenant = authz::require_repo(c, principal, row.repo, Permissions::READ)?;
            ai::request(c, tenant, id)
        })
        .map_err(store_error)?;
    ok(request_json(&row, true))
}

fn claim(state: &State, request: &mut Request, request_id: &str) -> Route {
    let who = identify(state, request, true)?;
    auth::require_scope(&who, Scopes::AI_CONTEXT)?;
    let id: AiRequestId = id(request_id, "request")?;
    let claimed = state
        .store
        .writer()
        .write(move |tx| ai::claim(tx, id, UnixMillis::now()))
        .map_err(store_error)?;
    // Shown once, as every `sntl_` credential is: the controller holds only its digest.
    ok(json!({
        "request": request_json(&claimed.request, false),
        "evidence": format!("/api/v1/attempts/{}/ai-context", claimed.request.attempt),
        "token": {
            "access": sentinel_auth::token::format(&claimed.access),
            "expires_ms": claimed.expires.0,
            "scopes": Scopes::READ_ONLY.names().collect::<Vec<_>>(),
            "credential": claimed.token.to_string(),
        },
    }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteBody {
    outcome: String,
    text: Option<String>,
    reason: Option<String>,
}

/// The AI service settles a request: the answer, or the reason there is none. Exactly once, and
/// the delegation it read evidence with is revoked in the same write.
fn complete(state: &State, request: &mut Request, request_id: &str) -> Route {
    let who = identify(state, request, true)?;
    auth::require_scope(&who, Scopes::AI_CONTEXT)?;
    let id: AiRequestId = id(request_id, "request")?;
    let body: CompleteBody = parse(&body(request)?)?;
    let outcome = match body.outcome.as_str() {
        "completed" => ai::Outcome::Completed,
        "unavailable" => ai::Outcome::Unavailable,
        other => {
            return Err(err(
                ErrorCode::InvalidRequest,
                "outcome must be completed or unavailable",
            )
            .with_detail("outcome", other));
        }
    };
    let now = UnixMillis::now();
    let row = state
        .store
        .writer()
        .write(move |tx| {
            ai::settle(
                tx,
                id,
                outcome,
                body.text.as_deref(),
                body.reason.as_deref(),
                now,
            )
        })
        .map_err(store_error)?;
    ok(request_json(&row, true))
}
