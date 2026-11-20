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
//!
//! Y04 adds the one decision that stands between a claim and a provider call ([`reserve`]), the
//! tenant's budget policy and its month of usage ([`usage`]). A request whose maximum does not fit
//! is refused there and settled in the same write: nothing waits, and no provider is contacted.

use sentinel_core::{
    AiRequestId, AttemptId, TenantId, UnixMillis,
    auth::{Permissions, Scopes},
};
use sentinel_protocol::{
    analysis::{Analysis, Evidence as CitationTarget},
    diagnostics::{Diagnostic, Severity, StepReference},
    error::{ApiError, ErrorCode},
    logs::Frame,
    patterns,
    plan::{MAX_QUESTION_BYTES, Plan, Read as PlanRead},
    redact::Redactor,
    summary::{AttemptSummary, StepOutcome},
};
use sentinel_store::{
    Error as StoreError,
    ai::{self, Budgets},
    auth as authz, dispatch, history, logs, lookup, secrets, status,
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
        ("GET", ["api", "v1", "attempts", attempt, "ai-analysis"]) => {
            analysis(state, request, attempt)
        }
        ("POST", ["api", "v1", "tenants", slug, "ai", "requests"]) => enqueue(state, request, slug),
        ("GET", ["api", "v1", "ai", "requests"]) => queued(state, request, query),
        ("GET", ["api", "v1", "ai", "requests", request_id]) => {
            require_request(state, request, request_id)
        }
        ("POST", ["api", "v1", "ai", "requests", request_id, "claim"]) => {
            claim(state, request, request_id)
        }
        ("POST", ["api", "v1", "ai", "requests", request_id, "reserve"]) => {
            reserve(state, request, request_id)
        }
        ("POST", ["api", "v1", "ai", "requests", request_id, "plan"]) => {
            plan_reads(state, request, request_id)
        }
        ("GET", ["api", "v1", "tenants", slug, "ai", "usage"]) => usage(state, request, slug),
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
        "budgets": budgets_json(policy.map_or_else(Budgets::default, |p| p.budgets)),
        "auto_analysis": policy.is_some_and(|p| p.auto_analysis),
    })
}

fn budgets_json(budgets: ai::Budgets) -> Value {
    json!({
        "monthly_tokens": budgets.monthly_tokens,
        "monthly_cost_micros": budgets.monthly_cost_micros,
        "max_input_tokens": budgets.max_input_tokens,
        "max_output_tokens": budgets.max_output_tokens,
        "max_cost_micros": budgets.max_cost_micros,
        "concurrency": budgets.concurrency,
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
    /// Each field stated replaces what is stored; one left out keeps it, so a policy change never
    /// resets a budget by omission.
    budgets: Option<BudgetsBody>,
    /// Whether a failed job gets an analysis nobody asked for (Y05). Left out, it keeps what the
    /// tenant has, so stating a data policy never switches automatic analysis on or off.
    auto_analysis: Option<bool>,
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct BudgetsBody {
    monthly_tokens: Option<u64>,
    monthly_cost_micros: Option<u64>,
    max_input_tokens: Option<u64>,
    max_output_tokens: Option<u64>,
    max_cost_micros: Option<u64>,
    concurrency: Option<u32>,
}

impl BudgetsBody {
    /// Refuses a field the schema could not hold, naming it. A monthly field may be `0`, which is no
    /// budget at all; the per-request maxima are always positive.
    fn validate(&self) -> Result<(), ApiError> {
        for (value, name, positive) in [
            (self.monthly_tokens, "monthly_tokens", false),
            (self.monthly_cost_micros, "monthly_cost_micros", false),
            (self.max_input_tokens, "max_input_tokens", true),
            (self.max_output_tokens, "max_output_tokens", true),
            (self.max_cost_micros, "max_cost_micros", true),
        ] {
            let Some(value) = value else { continue };
            if i64::try_from(value).is_err() || (positive && value == 0) {
                return Err(err(
                    ErrorCode::InvalidRequest,
                    format!("budgets.{name} must be a whole number this deployment can hold"),
                )
                .with_detail("budget", name));
            }
        }
        if let Some(value) = self.concurrency
            && !(1..=ai::MAX_CONCURRENCY).contains(&value)
        {
            return Err(err(
                ErrorCode::InvalidRequest,
                format!("budgets.concurrency must be 1..={}", ai::MAX_CONCURRENCY),
            )
            .with_detail("budget", "concurrency"));
        }
        Ok(())
    }

    /// `current` with what the body states laid over it: a field left out keeps the stored value.
    fn over(self, current: ai::Budgets) -> ai::Budgets {
        ai::Budgets {
            monthly_tokens: self.monthly_tokens.unwrap_or(current.monthly_tokens),
            monthly_cost_micros: self
                .monthly_cost_micros
                .unwrap_or(current.monthly_cost_micros),
            max_input_tokens: self.max_input_tokens.unwrap_or(current.max_input_tokens),
            max_output_tokens: self.max_output_tokens.unwrap_or(current.max_output_tokens),
            max_cost_micros: self.max_cost_micros.unwrap_or(current.max_cost_micros),
            concurrency: self.concurrency.unwrap_or(current.concurrency),
        }
    }
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
    let stated = body.budgets.unwrap_or_default();
    stated.validate()?;
    let (principal, authority) = (who.principal, who.authority());
    let slug = slug.to_owned();
    let (policy, providers) = state
        .store
        .writer()
        .write(move |tx| {
            let tenant = authz::member_tenant_by_slug(tx, principal, &slug)?;
            let current = ai::tenant(tx, tenant)?;
            let policy = ai::Tenant {
                enabled: body.enabled,
                data_policy,
                budgets: stated.over(current.map_or_else(ai::Budgets::default, |row| row.budgets)),
                auto_analysis: body
                    .auto_analysis
                    .unwrap_or_else(|| current.is_some_and(|row| row.auto_analysis)),
            };
            ai::set_tenant(tx, authority, tenant, policy, UnixMillis::now())?;
            Ok((policy, ai::effective(tx, tenant)?.0))
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
                    format!("budget must be {MIN_BUNDLE_BYTES}..={MAX_BUNDLE_BYTES} bytes"),
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
            Ok((tenant, repo))
        })
        .map_err(store_error)?;
    let (tenant, repo) = found;
    ok(bundle(
        state,
        tenant,
        repo,
        attempt,
        budget,
        key.as_deref(),
    )?)
}

/// One attempt's evidence bundle, built from what the controller already stored: the deterministic
/// summary, the diagnostics its stored frames parse into, and the newest frames of the failed step,
/// re-redacted and trimmed to `budget`. It is the one builder both readers use — the bundle route,
/// and a log-search plan's context read — so an answer cites a document the controller would also
/// have served on its own, and `repo` is the repository the caller was authorized against: an
/// attempt of another repository is `not_found`, never evidence.
fn bundle(
    state: &State,
    tenant: TenantId,
    repo: sentinel_core::RepoId,
    attempt: AttemptId,
    budget: usize,
    key: Option<&sentinel_auth::sealed::Key>,
) -> Result<Value, ApiError> {
    let found = state
        .store
        .read(move |c| {
            let job = lookup::attempt_job(c, attempt)?;
            let run = lookup::job_run(c, job)?;
            if lookup::run_repo(c, run)? != repo {
                return Ok(None);
            }
            // The same reading Y03's request path makes: a tenant the deployment or its own
            // administrator has not opted in has no bundle at all.
            if !ai::permits(c, tenant)? {
                return Ok(None);
            }
            let summary = dispatch::attempt_summary(c, tenant, attempt)?;
            let status = status::attempt_job_status(c, tenant, attempt)?;
            let values = match key {
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
    let evidence = attempt_evidence(state, run, job, attempt, &summary)?;
    let step = summary
        .steps
        .iter()
        .find(|record| is_failed(record.outcome));
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
    let mut omitted_diagnostics = evidence.omitted_diagnostics;
    let mut diagnostics = Vec::with_capacity(MAX_BUNDLE_DIAGNOSTICS);
    for diagnostic in evidence.diagnostics {
        if diagnostics.len() == MAX_BUNDLE_DIAGNOSTICS {
            omitted_diagnostics = omitted_diagnostics.saturating_add(1);
            continue;
        }
        let id = diagnostics.len() + 1;
        diagnostics.push(diagnostic_json(id, diagnostic, &mut scrub));
    }
    let page = evidence.page;
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
    Ok(body)
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

/// One attempt's stored evidence, as the bundle identifies it: the newest window of the failed step,
/// and the diagnostics those frames parse into, failures and errors before warnings and informational
/// records — each group in the order the autopsy found it, so a model reads its strongest evidence
/// first. The bundle numbers that list `diag-1` .. `diag-n`, and a citation check reads the same list,
/// so an analysis can only cite evidence the bundle could have shown it.
struct Evidence {
    page: logs::Tail,
    /// In bundle order, before the bundle's own 20-diagnostic cap.
    diagnostics: Vec<Diagnostic>,
    omitted_diagnostics: u64,
}

fn attempt_evidence(
    state: &State,
    run: sentinel_core::RunId,
    job: sentinel_core::JobId,
    attempt: AttemptId,
    summary: &AttemptSummary,
) -> Result<Evidence, ApiError> {
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
    let mut diagnostics = Vec::new();
    for item in &mut reports.items {
        diagnostics.append(&mut item.report.diagnostics);
    }
    diagnostics.sort_by_key(|diagnostic| !is_failure(diagnostic.severity));
    Ok(Evidence {
        page,
        diagnostics,
        omitted_diagnostics: reports.omitted,
    })
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
// Failure analysis (Y05): the answer a request settled with, decoded and checked before it is shown.
// A citation that does not resolve is dropped, and an analysis whose every citation was dropped is
// not shown at all — a claim nobody can check must not look like a finding. Nothing here writes
// anything a run, a job, a check or a GitHub delivery reads.
// ---------------------------------------------------------------------------------------------

/// One cited attempt's stored evidence, as the citation check reads it: the frames the bundle could
/// have shown, by sequence and step, each diagnostic the bundle numbers, and when the log expires.
struct Cited {
    run: sentinel_core::RunId,
    steps: std::collections::BTreeMap<u64, u32>,
    /// The step and the first evidence sequence of `diag-1` .. `diag-20`, in the bundle's order.
    diagnostics: Vec<(Option<u32>, Option<u64>)>,
    /// What the attempt's log has left: nothing resolves into a log retention removed.
    retention: ai::Retention,
}

/// One attempt an analysis cites, located in the repository the request was made about.
struct Located {
    run: sentinel_core::RunId,
    job: sentinel_core::JobId,
    /// The attempt's terminal summary, from which the evidence page's failed step is read.
    summary: Option<Vec<u8>>,
    /// What the attempt's log has left: a citation into a log retention removed never resolves.
    retention: ai::Retention,
}

/// Where a cited attempt is, or nothing when the reader could not open it: another repository's
/// attempt is not found, so an analysis can never cite evidence its reader has no access to.
fn locate(
    conn: &sentinel_store::Connection,
    tenant: TenantId,
    repo: sentinel_core::RepoId,
    attempt: AttemptId,
) -> sentinel_store::Result<Option<Located>> {
    let job = match lookup::attempt_job(conn, attempt) {
        Ok(job) => job,
        Err(StoreError::NotFound) => return Ok(None),
        Err(error) => return Err(error),
    };
    let run = lookup::job_run(conn, job)?;
    if lookup::run_repo(conn, run)? != repo {
        return Ok(None);
    }
    let summary = match dispatch::attempt_summary(conn, tenant, attempt) {
        Ok(summary) => summary,
        Err(StoreError::NotFound) => None,
        Err(error) => return Err(error),
    };
    let retention = ai::retention(conn, attempt)?.unwrap_or(ai::Retention {
        expires: None,
        expired: true,
    });
    Ok(Some(Located {
        run,
        job,
        summary,
        retention,
    }))
}

/// The analysis one attempt has, decoded against `sentinel.ai-analysis/1`, with every citation
/// resolved against the evidence the controller stored and labelled inference. `present: false` is
/// the whole of every other answer: no analysis, one still being produced, AI off for the tenant, or
/// an analysis whose every citation was dropped.
///
/// It is advisory and nothing else reads it: no run's state, no job's state, no failure class and no
/// check publication is computed from this body, which is why serving it cannot change a conclusion.
fn analysis(state: &State, request: &Request, attempt: &str) -> Route {
    let who = identify(state, request, false)?;
    auth::require_scope(&who, Scopes::LOGS_READ)?;
    let attempt: AttemptId = id(attempt, "attempt")?;
    let principal = who.principal;
    let now = UnixMillis::now();
    let (repo, tenant, permits, answer) = state
        .store
        .read(move |c| {
            let repo = lookup::run_repo(c, lookup::job_run(c, lookup::attempt_job(c, attempt)?)?)?;
            let tenant = authz::require_repo(c, principal, repo, Permissions::READ)?;
            Ok((
                repo,
                tenant,
                ai::permits(c, tenant)?,
                ai::answer(c, attempt, now)?,
            ))
        })
        .map_err(store_error)?;
    if !permits {
        return ok(json!({ "present": false, "reason": "off" }));
    }
    let (document, reused, settled, origin) = match answer {
        ai::Answer::Analysis {
            document,
            reused,
            settled,
            origin,
        } => (document, reused, settled, origin),
        ai::Answer::Pending => return ok(json!({ "present": false, "reason": "pending" })),
        ai::Answer::None => return ok(json!({ "present": false, "reason": "none" })),
    };
    let document = Analysis::decode(document.as_bytes())
        .map_err(|_| err(ErrorCode::Internal, "stored analysis unreadable"))?;
    let resolved = resolve(state, tenant, repo, &document)?;
    let (claims, dropped, expires) = (resolved.claims, resolved.dropped, resolved.expires);
    if claims.is_empty() {
        return ok(json!({
            "present": false,
            "reason": "dropped",
            "dropped_citations": dropped,
        }));
    }
    ok(json!({
        "present": true,
        "schema": sentinel_protocol::analysis::ANALYSIS_SCHEMA,
        "inference": true,
        "attempt": attempt.to_string(),
        "origin": origin.as_str(),
        "reused": reused,
        "summary": document.summary,
        "claims": claims,
        "dropped_citations": dropped,
        "settled_ms": settled.0,
        "expires_ms": expires.map(|until| until.0),
    }))
}

/// Every claim of `document` whose citations resolve against the evidence this repository still
/// stores, each citation naming the attempt, run, step and sequence it points at. A citation into
/// another repository's attempt, a frame the attempt does not hold, a diagnostic the bundle does not
/// number, or a log retention has removed resolves to nothing and is counted in `dropped`; a claim
/// left with no citation is dropped with it. The one reader both an attempt's analysis and a
/// log-search answer are served by, so the two cannot disagree about what resolves.
struct Resolution {
    claims: Vec<Value>,
    dropped: u64,
    expires: Option<UnixMillis>,
}

fn resolve(
    state: &State,
    tenant: TenantId,
    repo: sentinel_core::RepoId,
    document: &Analysis,
) -> Result<Resolution, ApiError> {
    let mut wanted: Vec<AttemptId> = Vec::with_capacity(MAX_CITED_ATTEMPTS);
    for claim in &document.claims {
        for citation in &claim.citations {
            if !wanted.contains(&citation.attempt) && wanted.len() < MAX_CITED_ATTEMPTS {
                wanted.push(citation.attempt);
            }
        }
    }
    let located = state
        .store
        .read(move |c| {
            let mut found = Vec::with_capacity(wanted.len());
            for cited in wanted {
                found.push((cited, locate(c, tenant, repo, cited)?));
            }
            Ok(found)
        })
        .map_err(store_error)?;
    let mut found: Vec<(AttemptId, Cited)> = Vec::with_capacity(located.len());
    for (cited, located) in located {
        let Some(located) = located else {
            continue;
        };
        let summary = located
            .summary
            .as_deref()
            .map(AttemptSummary::decode)
            .transpose()
            .map_err(|_| err(ErrorCode::Internal, "stored summary unreadable"))?
            .unwrap_or_default();
        let evidence = attempt_evidence(state, located.run, located.job, cited, &summary)?;
        let mut steps = std::collections::BTreeMap::new();
        for frame in &evidence.page.frames {
            steps.insert(frame.seq, frame.step);
        }
        let diagnostics = evidence
            .diagnostics
            .iter()
            .take(MAX_BUNDLE_DIAGNOSTICS)
            .map(|diagnostic| {
                let first = diagnostic.evidence.first();
                (
                    diagnostic
                        .step
                        .as_ref()
                        .map(|step| step.index)
                        .or_else(|| first.map(|reference| reference.step_index)),
                    first.map(|reference| reference.start.sequence),
                )
            })
            .collect();
        found.push((
            cited,
            Cited {
                run: located.run,
                steps,
                diagnostics,
                retention: located.retention,
            },
        ));
    }
    let mut dropped = 0u64;
    let mut expires: Option<UnixMillis> = None;
    let mut claims = Vec::with_capacity(document.claims.len());
    for claim in &document.claims {
        let mut citations = Vec::with_capacity(claim.citations.len());
        for citation in &claim.citations {
            let Some((_, target)) = found.iter().find(|(cited, _)| *cited == citation.attempt)
            else {
                dropped = dropped.saturating_add(1);
                continue;
            };
            let (step, sequence) = match citation.evidence {
                CitationTarget::Log { sequence } => match target.steps.get(&sequence) {
                    Some(step) => (Some(*step), Some(sequence)),
                    None => {
                        dropped = dropped.saturating_add(1);
                        continue;
                    }
                },
                CitationTarget::Diagnostic { id } => {
                    match target.diagnostics.get(usize::from(id) - 1) {
                        Some((step, sequence)) => (*step, *sequence),
                        None => {
                            dropped = dropped.saturating_add(1);
                            continue;
                        }
                    }
                }
            };
            // Evidence the retention removed resolves to nothing, so the citation goes with it.
            if target.retention.expired {
                dropped = dropped.saturating_add(1);
                continue;
            }
            if let Some(until) = target.retention.expires {
                expires = Some(expires.map_or(until, |seen| UnixMillis(seen.0.min(until.0))));
            }
            citations.push(json!({
                "attempt": citation.attempt.to_string(),
                "run": target.run.to_string(),
                "evidence": citation.evidence.id(),
                "step": step,
                "sequence": sequence,
            }));
        }
        if !citations.is_empty() {
            claims.push(json!({ "text": claim.text, "citations": citations }));
        }
    }
    Ok(Resolution {
        claims,
        dropped,
        expires,
    })
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
/// How many automatic requests one poll writes. Bounded like the expiry sweep, so a controller that
/// was away for a while catches up over several polls rather than in one write.
const AUTOMATIC_PER_POLL: u32 = 8;
/// How many distinct attempts one analysis may cite and have resolved. A model reads one attempt's
/// bundle and a reused answer describes the one it was computed from, so this is a bound on the
/// reading a single page view may do, never on what a model may write.
const MAX_CITED_ATTEMPTS: usize = 4;

fn request_json(request: &ai::Request, with_result: bool) -> Value {
    let mut body = json!({
        "id": request.id.to_string(),
        "attempt": request.attempt.to_string(),
        "provider": request.provider.as_str(),
        "data_policy": request.data_policy.as_str(),
        "origin": request.origin.as_str(),
        "kind": request.kind.as_str(),
        "question": request.question.as_deref(),
        "state": request.state.as_str(),
        "outcome": request.outcome.map(ai::Outcome::as_str),
        "reused": request.reused,
        "reason": request.reason.as_deref().filter(|_| with_result),
        "created_ms": request.created.0,
        "deadline_ms": request.deadline.0,
    });
    if with_result {
        // The stored document is the one the controller decoded, so it parses back into the same
        // object a client sent; a row that does not is corruption, never an answer.
        body["analysis"] = request
            .analysis
            .as_deref()
            .and_then(|document| serde_json::from_str(document).ok())
            .unwrap_or(Value::Null);
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
    /// The member's question (Y07). With one, the row is a log-search request whose answer comes
    /// from a bounded plan of reads; without one it is a failure analysis of `attempt`.
    question: Option<String>,
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
    let question = match body.question {
        None => None,
        Some(question) => {
            // A question becomes a plan of log reads, so asking one is asking to read logs.
            auth::require_scope(&who, Scopes::LOGS_READ)?;
            let question = question.trim();
            if question.is_empty() || question.len() > MAX_QUESTION_BYTES {
                return Err(err(
                    ErrorCode::InvalidRequest,
                    format!("question must be 1..{MAX_QUESTION_BYTES} bytes"),
                ));
            }
            Some(question.to_owned())
        }
    };
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
                question.as_deref(),
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
        .write(move |tx| {
            ai::sweep(tx, now, EXPIRE_PER_POLL)?;
            // The same poll is where a failed job a tenant asked to have analysed becomes a request.
            // Nothing else in the controller writes one: no run, job, attempt, dispatch, log
            // acknowledgement or check publication is on this path.
            ai::enqueue_automatic(tx, now, AUTOMATIC_PER_POLL)?;
            Ok(())
        })
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
    let mut body = request_json(&row, true);
    if row.kind != ai::Kind::Search {
        return ok(body);
    }
    // A log-search answer is served as the lines it links, resolved against what the repository's
    // logs hold now: a line retention removed is not a line the answer still points at, and an
    // answer whose every claim dropped is not shown at all.
    auth::require_scope(&who, Scopes::LOGS_READ)?;
    let Some(document) = row.analysis.as_deref() else {
        body["present"] = json!(false);
        body["reason"] = json!(row.reason.as_deref().or(Some("none")));
        return ok(body);
    };
    let document = Analysis::decode(document.as_bytes())
        .map_err(|_| err(ErrorCode::Internal, "stored analysis unreadable"))?;
    let resolved = resolve(state, row.tenant, row.repo, &document)?;
    if resolved.claims.is_empty() {
        body["present"] = json!(false);
        body["reason"] = json!("dropped");
        body["dropped_citations"] = json!(resolved.dropped);
        return ok(body);
    }
    body["present"] = json!(true);
    body["inference"] = json!(true);
    body["schema"] = json!(sentinel_protocol::analysis::ANALYSIS_SCHEMA);
    body["summary"] = json!(document.summary);
    body["claims"] = json!(resolved.claims);
    body["dropped_citations"] = json!(resolved.dropped);
    body["expires_ms"] = json!(resolved.expires.map(|until| until.0));
    ok(body)
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
    /// The model's answer, as `sentinel.ai-analysis/1` states it (Y05). It is decoded here before
    /// anything is stored: an answer that does not decode is refused, never kept as text.
    analysis: Option<Value>,
    reason: Option<String>,
    /// What the provider reported. A component left out settles at the reservation's maximum; it is
    /// absent because the provider did not report it, never because it was free.
    usage: Option<UsageBody>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UsageBody {
    input_tokens: Option<u64>,
    output_tokens: Option<u64>,
    cost_micros: Option<u64>,
}

impl UsageBody {
    const fn usage(&self) -> ai::Usage {
        ai::Usage {
            input_tokens: self.input_tokens,
            output_tokens: self.output_tokens,
            cost_micros: self.cost_micros,
        }
    }
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
    let mut analysis = match (outcome, body.analysis) {
        (ai::Outcome::Completed, Some(answer)) => Some(stored(&answer)?),
        (ai::Outcome::Completed, None) => None,
        (ai::Outcome::Unavailable, _) => None,
    };
    let mut reason = body.reason;
    // Y07's gate, where the answer is stored: a log-search answer is accepted only when at least one
    // claim cites evidence this repository still holds. An answer that resolves to nothing ends the
    // request `unavailable` with the reason instead, so no reader can ever be shown one — the
    // citations it wrote are checked against the lines the plan was executed from.
    let mut outcome = outcome;
    if outcome == ai::Outcome::Completed {
        let (tenant, repo, kind) = state
            .store
            .read(move |c| ai::by_id(c, id).map(|row| (row.tenant, row.repo, row.kind)))
            .map_err(store_error)?;
        if kind == ai::Kind::Search {
            let cited = match analysis.as_deref() {
                Some(document) => {
                    let document = Analysis::decode(document.as_bytes())
                        .map_err(|_| err(ErrorCode::Internal, "stored analysis unreadable"))?;
                    !resolve(state, tenant, repo, &document)?.claims.is_empty()
                }
                None => false,
            };
            if !cited {
                outcome = ai::Outcome::Unavailable;
                analysis = None;
                reason = Some(
                    "citation: no claim cites evidence this repository's logs hold".to_owned(),
                );
            }
        }
    }
    let now = UnixMillis::now();
    let usage = body.usage.map(|usage| usage.usage());
    let row = state
        .store
        .writer()
        .write(move |tx| {
            ai::settle(
                tx,
                id,
                outcome,
                analysis.as_deref(),
                reason.as_deref(),
                now,
                usage,
            )
        })
        .map_err(store_error)?;
    ok(request_json(&row, true))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReserveBody {
    /// The prompt's estimated tokens: what the model will be sent, counted conservatively.
    input_tokens: u64,
    /// The output cap the provider will be asked for.
    output_tokens: u64,
    /// The two of them priced at this model's rate, in millionths of the deployment's currency.
    cost_micros: u64,
    /// The digest of the exact evidence bundle the model will read, as 64 lower-case hex digits.
    digest: String,
    /// The failure's signature, stable across reruns of the same failure.
    fingerprint: String,
    prompt_version: String,
    model: String,
}

/// A 32-byte digest from its 64 lower-case hex digits.
fn hex32(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (at, pair) in text.as_bytes().chunks_exact(2).enumerate() {
        let high = (pair[0] as char).to_digit(16)?;
        let low = (pair[1] as char).to_digit(16)?;
        if pair[0].is_ascii_uppercase() || pair[1].is_ascii_uppercase() {
            return None;
        }
        out[at] = (high * 16 + low) as u8;
    }
    Some(out)
}

/// The pre-call decision (Y04): hold this request's maximum, answer it from an analysis the ledger
/// already paid for, or refuse it — immediately, in this one write, with the row settled and the
/// reason on it. A refused request is never queued and no provider is contacted for it.
fn reserve(state: &State, request: &mut Request, request_id: &str) -> Route {
    let who = identify(state, request, true)?;
    auth::require_scope(&who, Scopes::AI_CONTEXT)?;
    let id: AiRequestId = id(request_id, "request")?;
    let body: ReserveBody = parse(&body(request)?)?;
    let evidence = hex32(&body.digest).ok_or_else(|| bad_digest("digest"))?;
    let fingerprint = hex32(&body.fingerprint).ok_or_else(|| bad_digest("fingerprint"))?;
    let asked = ai::Reservation {
        input_tokens: body.input_tokens,
        output_tokens: body.output_tokens,
        cost_micros: body.cost_micros,
        digest: evidence,
        fingerprint,
        prompt_version: body.prompt_version,
        model: body.model,
    };
    let now = UnixMillis::now();
    let (admitted, row) = state
        .store
        .writer()
        .write(move |tx| Ok((ai::reserve(tx, id, &asked, now)?, ai::by_id(tx, id)?)))
        .map_err(store_error)?;
    ok(match admitted {
        ai::Admitted::Reserved { expires } => json!({
            "state": "reserved",
            "expires_ms": expires.0,
            "request": request_json(&row, false),
        }),
        ai::Admitted::Reused { analysis, by } => json!({
            "state": "reused",
            "by": by.as_str(),
            "analysis": serde_json::from_str(&analysis).unwrap_or(Value::Null),
            "request": request_json(&row, false),
        }),
        ai::Admitted::Refused { reason } => json!({
            "state": "refused",
            "reason": reason,
            "request": request_json(&row, false),
        }),
    })
}

// ---------------------------------------------------------------------------------------------
// The log-search assistant (Y07): a question becomes a bounded plan of reads the controller already
// serves, executed here under the requester's own authority, and the model sees only the result.
// Nothing in this path can reach a line the person who asked could not, and the plan's reads, bytes
// and matches are all bounded before any of them runs.
// ---------------------------------------------------------------------------------------------

/// What one context read inside a plan may spend. Smaller than a standalone bundle because a plan
/// holds up to [`MAX_PLAN_READS`] of them and the whole document is bounded below.
const PLAN_CONTEXT_BYTES: usize = 8 << 10;
/// The largest plan result document the controller serves a model.
const MAX_PLAN_RESULT_BYTES: usize = 64 << 10;
/// Attempts one plan's searches look at, however small their logs: a missing or expired log still
/// costs a lookup, and a plan is a question, never a crawl of a repository's history.
const MAX_PLAN_TARGETS: usize = 256;

/// Executes a `sentinel.ai-plan/1` under the requester's authority and answers the bounded result
/// document a model reads instead of a log. The plan is refused — and the request settled in the
/// same write — when it names a read this build cannot execute, a read the requester cannot perform,
/// a scan beyond the plan's byte bound or a result larger than the document bound. Refusal is
/// immediate and never truncated: a silently shortened answer would be a claim nobody can check.
fn plan_reads(state: &State, request: &mut Request, request_id: &str) -> Route {
    let who = identify(state, request, false)?;
    let id: AiRequestId = id(request_id, "request")?;
    // Two credentials may execute a plan: the AI service's own `ai:context` grant, and the live
    // delegation of that very request. The delegation is the requester's own identity capped to
    // reads, so executing under it can read nothing the requester could not.
    let token = if who.scopes.contains(Scopes::AI_CONTEXT) {
        None
    } else {
        let token = who.credential.ok_or_else(|| {
            err(
                ErrorCode::Forbidden,
                "this request's delegation is required",
            )
        })?;
        Some(token)
    };
    let row = state
        .store
        .read(move |c| {
            let row = ai::by_id(c, id)?;
            if !ai::executing(c, id, token, UnixMillis::now())? {
                return Err(StoreError::Conflict);
            }
            Ok(row)
        })
        .map_err(store_error)?;
    if row.kind != ai::Kind::Search {
        return Err(err(
            ErrorCode::InvalidRequest,
            "this request is a failure analysis, not a log search",
        ));
    }
    let plan = match Plan::decode(&body(request)?) {
        Ok(plan) => plan,
        Err(error) => {
            return refused_plan(state, id, error.reason(), error.field());
        }
    };
    // The requester's own authority, re-read now: a request whose requester lost the repository, or
    // whose tenant turned AI off, is refused rather than answered from what it could read before.
    let requester = sentinel_core::auth::Principal::new(
        row.requester,
        Permissions::READ,
        Some(row.tenant),
        Some(row.repo),
    );
    let (tenant, repo) = (row.tenant, row.repo);
    state
        .store
        .read(move |c| {
            if !ai::permits(c, tenant)? {
                return Err(StoreError::Forbidden);
            }
            authz::require_repo(c, requester, repo, Permissions::READ)?;
            Ok(())
        })
        .map_err(|error| match error {
            StoreError::Forbidden => {
                err(ErrorCode::Forbidden, "AI assistance is off for this tenant")
                    .with_detail("ai", "off")
            }
            other => store_error(other),
        })?;
    let key = state.secret_key.clone();
    let mut reads = Vec::with_capacity(plan.reads.len());
    let mut scanned = 0u64;
    let mut targets = 0usize;
    let mut patterns = patterns::Hits::NONE;
    for (at, read) in plan.reads.iter().enumerate() {
        match read {
            PlanRead::Search {
                needle,
                runs,
                limit,
            } => {
                let found = search_read(
                    state,
                    tenant,
                    repo,
                    needle,
                    *runs,
                    *limit,
                    &mut scanned,
                    &mut targets,
                    &mut patterns,
                )?;
                if found.exhausted {
                    return refused_plan(
                        state,
                        id,
                        "bounds: the plan's searches exceed the log bytes it may scan",
                        "plan",
                    );
                }
                reads.push(found.read);
            }
            PlanRead::Context { attempt } => {
                let owned = state
                    .store
                    .read(move |c| {
                        let run = lookup::job_run(c, lookup::attempt_job(c, *attempt)?)?;
                        Ok(lookup::run_repo(c, run)? == repo)
                    })
                    .map_err(store_error)?;
                if !owned {
                    return refused_plan(
                        state,
                        id,
                        "plan: a read names an attempt this repository does not hold",
                        format!("plan[{}]", at + 1).as_str(),
                    );
                }
                let bundle = bundle(
                    state,
                    tenant,
                    repo,
                    *attempt,
                    PLAN_CONTEXT_BYTES,
                    key.as_deref(),
                )
                .map_err(|error| match error.code {
                    // The bundle's own refusal is the plan read's: an attempt whose tenant may
                    // send nothing has no context to read.
                    ErrorCode::Forbidden => {
                        err(ErrorCode::Forbidden, "AI assistance is off for this tenant")
                            .with_detail("ai", "off")
                    }
                    _ => error,
                })?;
                reads.push(
                    json!({ "kind": "context", "attempt": attempt.to_string(), "bundle": bundle }),
                );
            }
        }
    }
    let mut body = json!({
        "schema": "sentinel.ai-search/1",
        "request": id.to_string(),
        "question": row.question,
        "reads": reads,
        "bounds": {
            "reads": plan.reads.len(),
            "scanned_bytes": scanned,
            "attempts": targets,
            "bytes": 0,
            "redaction": {
                "pattern_replacements": patterns.count(),
                "patterns": patterns.kinds().map(patterns::Kind::as_str).collect::<Vec<_>>(),
            },
        },
    });
    let size = json_len(&body);
    if size > MAX_PLAN_RESULT_BYTES {
        return refused_plan(
            state,
            id,
            format!("bounds: the plan's results exceed {MAX_PLAN_RESULT_BYTES} bytes").as_str(),
            "plan",
        );
    }
    body["bounds"]["bytes"] = json!(size);
    let row = state
        .store
        .read(move |c| ai::by_id(c, id))
        .map_err(store_error)?;
    ok(json!({ "state": "ready", "results": body, "request": request_json(&row, false) }))
}

/// One literal search of a plan: the newest `runs` runs of the repository, every attempt's log in
/// them, at most `limit` matching lines, spending only what the plan's scan bound has left. It is
/// the cross-run search's own read path, without a resume cursor, because a plan is one bounded
/// question rather than a page a client walks; `patterns` counts what the credential scanners
/// rewrote, since a model reads these lines next.
struct Found {
    read: Value,
    /// Whether a target went unsearched because the plan's scan bound was spent.
    exhausted: bool,
}

#[allow(clippy::too_many_arguments)]
fn search_read(
    state: &State,
    tenant: TenantId,
    repo: sentinel_core::RepoId,
    needle: &str,
    runs: u16,
    limit: u16,
    scanned: &mut u64,
    targets: &mut usize,
    patterns: &mut patterns::Hits,
) -> Result<Found, ApiError> {
    let window = state
        .store
        .read(move |c| history::search_runs(c, tenant, repo, None, runs))
        .map_err(store_error)?;
    let mut lines = Vec::with_capacity(usize::from(limit));
    let mut truncated = false;
    let mut exhausted = false;
    let (mut expired, mut missing) = (0u32, 0u32);
    'runs: for run in &window {
        let candidates = state
            .store
            .read(move |c| history::log_targets(c, tenant, *run, None))
            .map_err(store_error)?;
        for target in candidates {
            if lines.len() >= usize::from(limit) {
                truncated = true;
                break 'runs;
            }
            if *scanned >= logs::SEARCH_SCAN_BYTES || *targets >= MAX_PLAN_TARGETS {
                exhausted = *scanned >= logs::SEARCH_SCAN_BYTES;
                truncated = true;
                break 'runs;
            }
            *targets += 1;
            if target.expired_ms.is_some() {
                expired += 1;
                continue;
            }
            let query = logs::SearchQuery {
                needle: needle.as_bytes(),
                after: 0,
                limit: usize::from(limit) - lines.len(),
                budget: logs::SEARCH_SCAN_BYTES - *scanned,
                carry: None,
            };
            let found = match state
                .logs
                .search(*run, target.job, target.attempt, query)
                .or_else(|error| match error {
                    StoreError::NotFound => state.logs.search_legacy(target.attempt, query),
                    other => Err(other),
                }) {
                Ok(found) => found,
                Err(StoreError::NotFound) => {
                    missing += 1;
                    continue;
                }
                Err(error) => return Err(store_error(error)),
            };
            *scanned += found.scanned;
            for matched in &found.matches {
                let text = String::from_utf8_lossy(&matched.text).into_owned();
                lines.push(json!({
                    "attempt": target.attempt.to_string(),
                    "run": run.to_string(),
                    "job": target.name,
                    "evidence": format!("log-{}", matched.seq),
                    "sequence": matched.seq,
                    "step": matched.step,
                    "stream": stream_name(matched.stream),
                    "text": patterns::redact_str(&text, patterns),
                }));
            }
            if found.next_after.is_some() {
                truncated = true;
                break 'runs;
            }
        }
    }
    Ok(Found {
        read: json!({
            "kind": "search",
            "q": needle,
            "runs": window.len(),
            "lines": lines,
            "truncated": truncated,
            "expired_attempts": expired,
            "missing_logs": missing,
        }),
        exhausted,
    })
}

/// Ends a request the plan cannot answer, in the write that refuses it, and answers the same shape
/// `reserve` does: nothing waits, and the AI process has no second call to make.
fn refused_plan(state: &State, id: AiRequestId, reason: &str, field: &str) -> Route {
    let reason = reason.to_owned();
    let sent = reason.clone();
    let row = state
        .store
        .writer()
        .write(move |tx| {
            ai::settle(
                tx,
                id,
                ai::Outcome::Unavailable,
                None,
                Some(&sent),
                UnixMillis::now(),
                None,
            )
        })
        .map_err(store_error)?;
    ok(json!({
        "state": "refused",
        "reason": reason,
        "field": field,
        "request": request_json(&row, true),
    }))
}

/// The one document the store keeps for an answer: the model's object decoded against
/// `sentinel.ai-analysis/1` and re-encoded, so what is stored is exactly what every reader decodes.
/// A refusal names the field and never echoes the text, which may have come from a log.
fn stored(answer: &Value) -> Result<String, ApiError> {
    let bytes = serde_json::to_vec(answer).map_err(|_| {
        err(
            ErrorCode::InvalidRequest,
            "analysis must be a JSON document",
        )
    })?;
    let analysis = Analysis::decode(&bytes).map_err(|error| {
        err(ErrorCode::InvalidRequest, error.reason()).with_detail("field", error.field())
    })?;
    Ok(analysis.encode())
}

fn bad_digest(field: &'static str) -> ApiError {
    err(
        ErrorCode::InvalidRequest,
        format!("{field} must be 64 lower-case hex digits"),
    )
    .with_detail("field", field)
}

/// What one tenant's AI month holds: the budget it was given, what it has been charged, what live
/// reservations are holding, and how many of its requests are in flight.
fn usage(state: &State, request: &Request, slug: &str) -> Route {
    let who = admin::tenant_admin(state, request, false)?;
    let principal = who.principal;
    let slug = slug.to_owned();
    let (budgets, month) = state
        .store
        .read(move |c| {
            let tenant = authz::member_tenant_by_slug(c, principal, &slug)?;
            authz::require_tenant_admin(c, principal, tenant)?;
            Ok((
                ai::tenant(c, tenant)?.map_or_else(Budgets::default, |row| row.budgets),
                ai::month(c, tenant, UnixMillis::now())?,
            ))
        })
        .map_err(store_error)?;
    let spend = |spend: ai::Spend| {
        json!({
            "input_tokens": spend.input_tokens,
            "output_tokens": spend.output_tokens,
            "cost_micros": spend.cost_micros,
        })
    };
    ok(json!({
        "month": format!("{:04}-{:02}", month.month / 100, month.month % 100),
        "budget": budgets_json(budgets),
        "settled": spend(month.settled),
        "reserved": spend(month.reserved),
        "in_flight": month.in_flight,
    }))
}
