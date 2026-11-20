//! AI assistance policy, its durable request queue and its budget (Part 22 Y01, Y03, Y04). Nothing
//! here talks to a provider: the first half decides whether a request may be made at all, the
//! second stores each one as a row that `sentinel-ai` consumes through the API, and the third holds
//! the maximum a request may cost — and reuses an analysis that was already paid for.
//!
//! Two administrators must agree before one can be. A platform administrator allows
//! AI for the deployment and names the providers it may use; a tenant administrator
//! then opts that tenant in under a data policy. Off is the default on both sides, so
//! a fresh deployment and an upgraded one have nothing to switch on. There is no
//! cache: [`admit`] reads the policy per request, so a disable applies to the next
//! request that would have been made, and nothing is left queued to expire.
//!
//! Y04's budget is the same shape. [`reserve`] is one writer transaction that decides, before any
//! provider is contacted, whether this request is already answered (an analysis for its evidence
//! digest or its failure fingerprint), whether it fits the tenant's monthly ledger, its
//! per-request caps and its concurrency limit, and what it holds if it does. A refusal and a reuse
//! settle the request in that same commit, so a refused request is never queued and a reused one
//! costs nothing.
//!
//! Y05 adds the answer's shape and where it comes from: a settled request carries one
//! `sentinel.ai-analysis/1` document, a cached analysis expires with the log it cites rather than
//! with the cache's own bound, and a tenant that asks for one gets a request for every job that
//! ended failed — written by [`enqueue_automatic`], which the AI process's own poll runs, so no
//! attempt, dispatch, log acknowledgement or check publication is ever on that path.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_auth::secret::Secret;
use sentinel_core::{
    AiRequestId, AttemptId, RepoId, TenantId, TokenId, UnixMillis, UserId,
    auth::{Permissions, Scopes},
};

use crate::{
    Error, Result,
    auth::{Authority, require_repo, require_tenant_admin},
    local_auth::{Event, audit},
};

/// The providers this deployment can speak to, in the order the allow-list lists
/// them. Bit `n` of `deployment_policy.ai_providers` is `Provider::ALL[n]`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Provider {
    /// An OpenAI-compatible endpoint on loopback or a private network: Ollama, vLLM, a LiteLLM gateway.
    Local = 0,
    /// The default hosted provider: one key for many models, zero data retention enforced per request.
    OpenRouter = 1,
    Anthropic = 2,
    OpenAi = 3,
}

impl Provider {
    pub const ALL: [Provider; 4] = [Self::Local, Self::OpenRouter, Self::Anthropic, Self::OpenAi];

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Local => "local",
            Self::OpenRouter => "openrouter",
            Self::Anthropic => "anthropic",
            Self::OpenAi => "openai",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        Self::ALL
            .into_iter()
            .find(|provider| provider.as_str() == text)
    }

    const fn mask(self) -> i64 {
        1 << self as u8
    }

    /// Whether every byte of a request stays inside the operator's own network.
    const fn stays_local(self) -> bool {
        matches!(self, Self::Local)
    }
}

/// A set of providers, as the deployment's allow-list is stored and returned.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Providers(i64);

impl Providers {
    pub const NONE: Self = Self(0);

    pub fn insert(&mut self, provider: Provider) {
        self.0 |= provider.mask();
    }

    pub const fn contains(self, provider: Provider) -> bool {
        self.0 & provider.mask() != 0
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }

    /// In the providers' own order, so two readings of one policy print alike.
    pub fn list(self) -> impl Iterator<Item = Provider> {
        Provider::ALL
            .into_iter()
            .filter(move |provider| self.contains(*provider))
    }

    fn from_bits(bits: i64) -> Result<Self> {
        let known = Provider::ALL.iter().fold(0, |all, p| all | p.mask());
        if bits < 0 || bits & !known != 0 {
            return Err(Error::Corrupt("deployment_policy.ai_providers"));
        }
        Ok(Self(bits))
    }
}

/// What a tenant's opt-in commits to on the provider's side ([ai](../docs/ai.md)).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum DataPolicy {
    /// Only an allow-listed endpoint inside the operator's own network.
    LocalOnly = 0,
    /// Only providers that keep neither the prompt nor the answer after the response.
    ZeroRetention = 1,
    /// The provider's own terms, which the operator accepts for this tenant.
    ProviderTerms = 2,
}

impl DataPolicy {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalOnly => "local_only",
            Self::ZeroRetention => "zero_retention",
            Self::ProviderTerms => "provider_terms",
        }
    }

    pub fn parse(text: &str) -> Option<Self> {
        [Self::LocalOnly, Self::ZeroRetention, Self::ProviderTerms]
            .into_iter()
            .find(|policy| policy.as_str() == text)
    }

    fn from_code(code: i64) -> Option<Self> {
        Some(match code {
            0 => Self::LocalOnly,
            1 => Self::ZeroRetention,
            2 => Self::ProviderTerms,
            _ => return None,
        })
    }

    /// Whether a request to `provider` is within this policy. `zero_retention` allows
    /// every allow-listed provider because the retention it demands is a property of
    /// the request Y03 sends (`provider.zdr`, `data_collection: deny`), refused there
    /// for a provider that cannot honor it; `local_only` is a property of the provider
    /// the controller knows, so it is enforced here.
    pub const fn allows(self, provider: Provider) -> bool {
        match self {
            Self::LocalOnly => provider.stays_local(),
            Self::ZeroRetention | Self::ProviderTerms => true,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Deployment {
    pub enabled: bool,
    pub providers: Providers,
}

pub fn deployment(conn: &Connection) -> Result<Deployment> {
    let (enabled, providers) = conn
        .prepare_cached("SELECT ai_enabled, ai_providers FROM deployment_policy WHERE id = 1")?
        .query_row([], |r| Ok((r.get::<_, bool>(0)?, r.get::<_, i64>(1)?)))?;
    Ok(Deployment {
        enabled,
        providers: Providers::from_bits(providers)?,
    })
}

/// A platform administrator's decision, stepped up like every other deployment policy.
pub fn set_deployment(
    tx: &Transaction<'_>,
    authority: Authority,
    policy: Deployment,
    now: UnixMillis,
) -> Result<()> {
    authority.require_privileged(tx)?;
    let bits = policy.providers.list().fold(0, |bits, p| bits | p.mask());
    tx.prepare_cached(
        "UPDATE deployment_policy SET ai_enabled = ?1, ai_providers = ?2,
         updated_ms = ?3, updated_by = ?4 WHERE id = 1",
    )?
    .execute(params![
        policy.enabled,
        bits,
        now.0,
        authority.actor().as_ref().map(UserId::as_bytes)
    ])?;
    let mut detail = String::from(if policy.enabled { "ai=on" } else { "ai=off" });
    detail.push_str(" providers=");
    for (at, provider) in policy.providers.list().enumerate() {
        if at > 0 {
            detail.push(',');
        }
        detail.push_str(provider.as_str());
    }
    // A disable takes the queue with it, and a withdrawn provider takes its queued requests: the
    // next request that would have been made is refused, and nothing is left waiting to expire.
    if policy.enabled {
        drop_providers(tx, policy.providers)?;
    } else {
        drop_requests(tx, None, now)?;
    }
    audit(
        tx,
        Event::AiPolicyChanged,
        authority.actor(),
        None,
        authority.host_local(),
        Some(&detail),
    )
}

/// How many of one tenant's requests may hold a reservation at once. The column's own bound, so a
/// policy that states more is refused rather than stored.
pub const MAX_CONCURRENCY: u32 = 64;

/// A tenant's AI budget: what one calendar month may spend, what one request may take, and how many
/// of its requests may be in flight at once. `0` in either monthly field is no budget at all, the
/// way `tenant_quota_bytes` of `0` is no quota; the per-request maxima are always positive, because
/// a request with no maximum would reserve nothing and could spend anything.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Budgets {
    pub monthly_tokens: u64,
    pub monthly_cost_micros: u64,
    pub max_input_tokens: u64,
    pub max_output_tokens: u64,
    pub max_cost_micros: u64,
    pub concurrency: u32,
}

impl Budgets {
    /// What an upgraded tenant gets and what `PUT /tenants/{slug}/ai` fills in when it states none:
    /// no monthly ceiling, a 32,000-token prompt (a 64 KiB bundle is far inside it), 4,096 output
    /// tokens (an answer is 8 KiB at most) and two requests in flight.
    pub const DEFAULT: Self = Self {
        monthly_tokens: 0,
        monthly_cost_micros: 0,
        max_input_tokens: 32_000,
        max_output_tokens: 4_096,
        max_cost_micros: 100_000,
        concurrency: 2,
    };

    /// Why this request is past the per-request maxima, as the sentence a refused request carries.
    /// Reading it allocates only on the refusal path.
    fn refusal(self, request: &Reservation) -> Option<String> {
        if request.input_tokens > self.max_input_tokens {
            return Some(format!(
                "per_request: a prompt of {} tokens is over the tenant's limit of {}",
                request.input_tokens, self.max_input_tokens
            ));
        }
        if request.output_tokens > self.max_output_tokens {
            return Some(format!(
                "per_request: an output of {} tokens is over the tenant's limit of {}",
                request.output_tokens, self.max_output_tokens
            ));
        }
        if request.cost_micros > self.max_cost_micros {
            return Some(format!(
                "per_request: a request of {} micros is over the tenant's limit of {}",
                request.cost_micros, self.max_cost_micros
            ));
        }
        None
    }
}

impl Default for Budgets {
    fn default() -> Self {
        Self::DEFAULT
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Tenant {
    pub enabled: bool,
    pub data_policy: DataPolicy,
    pub budgets: Budgets,
    /// Whether a failed job gets an analysis nobody asked for (Y05). Off in every fresh deployment
    /// and every upgraded one, and read by the sweep that writes those requests.
    pub auto_analysis: bool,
}

/// `None` until the tenant's administrator opts in: no row is off. The budget is part of the same
/// row, so one reading answers both and a reservation needs no second statement to find it.
pub fn tenant(conn: &Connection, tenant: TenantId) -> Result<Option<Tenant>> {
    let row = conn
        .prepare_cached(
            "SELECT enabled, data_policy, monthly_tokens, monthly_cost_micros, input_tokens_cap,
                output_tokens_cap, cost_micros_cap, concurrency, auto_analysis
             FROM tenant_ai WHERE tenant_id = ?1",
        )?
        .query_row([tenant.as_bytes()], |r| {
            Ok((
                r.get::<_, bool>(0)?,
                r.get::<_, i64>(1)?,
                budgets_at(r, 2)?,
                r.get::<_, bool>(8)?,
            ))
        })
        .optional()?;
    let (enabled, code, budgets, auto_analysis) = match row {
        Some(row) => row,
        None => return Ok(None),
    };
    Ok(Some(Tenant {
        enabled,
        data_policy: DataPolicy::from_code(code).ok_or(Error::Corrupt("tenant_ai.data_policy"))?,
        budgets,
        auto_analysis,
    }))
}

/// The six budget columns that start at `at`, as one value a policy route and a reservation share.
fn budgets_at(row: &rusqlite::Row<'_>, at: usize) -> rusqlite::Result<Budgets> {
    Ok(Budgets {
        monthly_tokens: nonzero(row.get::<_, i64>(at)?),
        monthly_cost_micros: nonzero(row.get::<_, i64>(at + 1)?),
        max_input_tokens: nonzero(row.get::<_, i64>(at + 2)?),
        max_output_tokens: nonzero(row.get::<_, i64>(at + 3)?),
        max_cost_micros: nonzero(row.get::<_, i64>(at + 4)?),
        concurrency: u32::try_from(row.get::<_, i64>(at + 5)?).unwrap_or(u32::MAX),
    })
}

/// A constraint already refuses a negative count; this keeps the conversion out of every reader.
const fn nonzero(value: i64) -> u64 {
    if value < 0 { 0 } else { value as u64 }
}

/// A tenant administrator's decision, refused without a live step-up. Disabling is
/// this one transaction: the request queue Y03 adds is deleted from here, in the same
/// commit that turns the tenant off.
pub fn set_tenant(
    tx: &Transaction<'_>,
    authority: Authority,
    tenant: TenantId,
    policy: Tenant,
    now: UnixMillis,
) -> Result<()> {
    let principal = authority.principal().ok_or(Error::Forbidden)?;
    require_tenant_admin(tx, principal, tenant)?;
    authority.require_fresh(tx)?;
    if policy.enabled {
        let deployment = deployment(tx)?;
        if !deployment.enabled || deployment.providers.is_empty() {
            return Err(Error::Forbidden);
        }
    }
    let budgets = policy.budgets;
    let too_large = |value: u64| i64::try_from(value).is_err();
    if [
        budgets.monthly_tokens,
        budgets.monthly_cost_micros,
        budgets.max_input_tokens,
        budgets.max_output_tokens,
        budgets.max_cost_micros,
    ]
    .into_iter()
    .any(too_large)
    {
        return Err(Error::InvalidInput("ai budget"));
    }
    if budgets.max_input_tokens == 0
        || budgets.max_output_tokens == 0
        || budgets.max_cost_micros == 0
        || !(1..=MAX_CONCURRENCY).contains(&budgets.concurrency)
    {
        return Err(Error::InvalidInput("ai budget"));
    }
    tx.prepare_cached(
        "INSERT INTO tenant_ai(tenant_id, enabled, data_policy, monthly_tokens, monthly_cost_micros,
            input_tokens_cap, output_tokens_cap, cost_micros_cap, concurrency, updated_ms,
            updated_by, auto_analysis)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)
         ON CONFLICT(tenant_id) DO UPDATE SET enabled = ?2, data_policy = ?3,
            monthly_tokens = ?4, monthly_cost_micros = ?5, input_tokens_cap = ?6,
            output_tokens_cap = ?7, cost_micros_cap = ?8, concurrency = ?9, updated_ms = ?10,
            updated_by = ?11, auto_analysis = ?12",
    )?
    .execute(params![
        tenant.as_bytes(),
        policy.enabled,
        policy.data_policy as u8,
        i64::try_from(budgets.monthly_tokens).map_err(|_| Error::InvalidInput("ai budget"))?,
        i64::try_from(budgets.monthly_cost_micros)
            .map_err(|_| Error::InvalidInput("ai budget"))?,
        i64::try_from(budgets.max_input_tokens)
            .map_err(|_| Error::InvalidInput("ai budget"))?,
        i64::try_from(budgets.max_output_tokens)
            .map_err(|_| Error::InvalidInput("ai budget"))?,
        i64::try_from(budgets.max_cost_micros)
            .map_err(|_| Error::InvalidInput("ai budget"))?,
        i64::from(budgets.concurrency),
        now.0,
        principal.user.as_bytes(),
        policy.auto_analysis
    ])?;
    if !policy.enabled {
        drop_requests(tx, Some(tenant), now)?;
    }
    // The budget is what an operator has to be able to see changed, so it is in the row's own
    // detail: monthly tokens and cost, the per-request maxima and the concurrency limit.
    let detail = format!(
        "tenant={tenant} ai={} data_policy={} monthly_tokens={} monthly_cost_micros={} \
         max_input_tokens={} max_output_tokens={} max_cost_micros={} concurrency={} \
         auto_analysis={}",
        if policy.enabled { "on" } else { "off" },
        policy.data_policy.as_str(),
        budgets.monthly_tokens,
        budgets.monthly_cost_micros,
        budgets.max_input_tokens,
        budgets.max_output_tokens,
        budgets.max_cost_micros,
        budgets.concurrency,
        if policy.auto_analysis { "on" } else { "off" }
    );
    audit(
        tx,
        Event::TenantAiPolicyChanged,
        Some(principal.user),
        None,
        false,
        Some(&detail),
    )
}

/// What `tenant` may use right now, and under which data policy; `NONE` and `None` while
/// either side is off. One statement for both rows, because the deployment's allow-list
/// and the tenant's opt-in decide together.
pub fn effective(conn: &Connection, tenant: TenantId) -> Result<(Providers, Option<DataPolicy>)> {
    let (enabled, providers, tenant_enabled, code) = conn
        .prepare_cached(
            "SELECT p.ai_enabled, p.ai_providers, t.enabled, t.data_policy
             FROM deployment_policy p LEFT JOIN tenant_ai t ON t.tenant_id = ?1
             WHERE p.id = 1",
        )?
        .query_row([tenant.as_bytes()], |r| {
            Ok((
                r.get::<_, bool>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, Option<bool>>(2)?,
                r.get::<_, Option<i64>>(3)?,
            ))
        })?;
    if !enabled || tenant_enabled != Some(true) {
        return Ok((Providers::NONE, None));
    }
    let code = code.ok_or(Error::Corrupt("tenant_ai.data_policy"))?;
    let data_policy = DataPolicy::from_code(code).ok_or(Error::Corrupt("tenant_ai.data_policy"))?;
    let mut allowed = Providers::NONE;
    for provider in Providers::from_bits(providers)?.list() {
        if data_policy.allows(provider) {
            allowed.insert(provider);
        }
    }
    Ok((allowed, Some(data_policy)))
}

/// The gate the evidence bundle passes (Y02): whether `tenant` may have one at all, which is
/// whether [`admit`] would admit any allow-listed provider. It reads the policy the same way and
/// caches nothing, so a disable refuses the next bundle; the bundle names no provider because it
/// is built before a request picks one, and a tenant with none allowed has no bundle to build.
pub fn permits(conn: &Connection, tenant: TenantId) -> Result<bool> {
    let (providers, policy) = effective(conn, tenant)?;
    Ok(policy.is_some() && !providers.is_empty())
}

/// The single gate every AI request passes: `Some(policy)` is what a request for
/// `provider` on `tenant`'s behalf may be made under, `None` is no request at all.
pub fn admit(
    conn: &Connection,
    tenant: TenantId,
    provider: Provider,
) -> Result<Option<DataPolicy>> {
    let (providers, policy) = effective(conn, tenant)?;
    Ok(policy.filter(|_| providers.contains(provider)))
}

// ---------------------------------------------------------------------------------------------
// Durable requests (Y03). The controller never calls a provider: it writes a row, and the AI
// process consumes it through the API. A row is the whole contract — who asked, about which
// attempt, under which data policy, by when it must be answered, and what the answer was.
// ---------------------------------------------------------------------------------------------

/// How long a request may stay unanswered. Its deadline is also the ceiling on its delegation, so
/// nothing a request minted outlives the request itself.
pub const REQUEST_LIFETIME_MS: i64 = 10 * 60 * 1000;
/// A delegation's own lifetime: the plan's ten minutes, shortened to the request's deadline.
pub const DELEGATION_MS: i64 = 10 * 60 * 1000;
/// How long a claim holds a row before the sweep may settle it as unavailable.
pub const CLAIM_LEASE_MS: i64 = 60 * 1000;
/// The answer's bound, which is also `sentinel.ai-analysis/1`'s: an analysis is stored whole or not
/// at all, never truncated, because a citation cut off the end is a claim nobody can check.
pub const MAX_RESULT_BYTES: usize = 8 << 10;
/// The bound on a stated reason, which is a sentence, never a payload.
pub const MAX_REASON_BYTES: usize = 512;
/// The delegation credentials are named `ai-delegate:<request>`: an operator sees what they are.
const DELEGATION_NAME_PREFIX: &str = "ai-delegate:";

/// Where a request is in its life. It moves forward only.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum State {
    Queued = 1,
    Claimed = 2,
    Settled = 3,
}

impl State {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Queued => "queued",
            Self::Claimed => "claimed",
            Self::Settled => "settled",
        }
    }

    fn from_code(code: i64) -> Option<Self> {
        Some(match code {
            1 => Self::Queued,
            2 => Self::Claimed,
            3 => Self::Settled,
            _ => return None,
        })
    }
}

/// How a request ended. There is no third answer and no partial one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Outcome {
    Unavailable = 1,
    Completed = 2,
}

impl Outcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unavailable => "unavailable",
            Self::Completed => "completed",
        }
    }

    fn from_code(code: i64) -> Option<Self> {
        Some(match code {
            1 => Self::Unavailable,
            2 => Self::Completed,
            _ => return None,
        })
    }
}

/// Who asked for a request (Y05): a member, or the controller for a failed job a tenant asked to
/// have analysed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Origin {
    Member = 1,
    Automatic = 2,
}

impl Origin {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Member => "member",
            Self::Automatic => "automatic",
        }
    }

    fn from_code(code: i64) -> Option<Self> {
        Some(match code {
            1 => Self::Member,
            2 => Self::Automatic,
            _ => return None,
        })
    }
}

/// One durable request, as every reader of it sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request {
    pub id: AiRequestId,
    pub tenant: TenantId,
    pub repo: RepoId,
    pub attempt: AttemptId,
    pub requester: UserId,
    pub provider: Provider,
    pub data_policy: DataPolicy,
    pub origin: Origin,
    pub state: State,
    pub outcome: Option<Outcome>,
    pub reason: Option<String>,
    /// The settled answer: `sentinel.ai-analysis/1`'s stored document (Y05), or nothing.
    pub analysis: Option<String>,
    /// Whether the answer was an analysis the ledger already paid for (Y04), rather than one this
    /// request's own provider call produced. It is a property of the answer, not of its text.
    pub reused: bool,
    pub created: UnixMillis,
    pub deadline: UnixMillis,
}
const REQUEST_COLUMNS: &str = "id, tenant_id, repo_id, attempt_id, requester_id, provider,
     data_policy, origin, state_code, outcome, reason, result, reused, created_ms, deadline_ms";

/// One row's bytes, as the store holds them. Decoded once, outside the query closure.
type Raw = (
    [u8; 16],
    [u8; 16],
    [u8; 16],
    [u8; 16],
    [u8; 16],
    i64,
    i64,
    i64,
    i64,
    Option<i64>,
    Option<String>,
    Option<String>,
    bool,
    i64,
    i64,
);

fn raw(row: &rusqlite::Row<'_>) -> rusqlite::Result<Raw> {
    Ok((
        row.get(0)?,
        row.get(1)?,
        row.get(2)?,
        row.get(3)?,
        row.get(4)?,
        row.get(5)?,
        row.get(6)?,
        row.get(7)?,
        row.get(8)?,
        row.get(9)?,
        row.get(10)?,
        row.get(11)?,
        row.get(12)?,
        row.get(13)?,
        row.get(14)?,
    ))
}

fn decode(raw: Raw) -> Result<Request> {
    let (
        id,
        tenant,
        repo,
        attempt,
        requester,
        provider,
        policy,
        origin,
        state,
        outcome,
        reason,
        analysis,
        reused,
        created,
        deadline,
    ) = raw;
    Ok(Request {
        id: AiRequestId::from_bytes(id).map_err(|_| Error::Corrupt("ai_requests.id"))?,
        tenant: TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?,
        repo: RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))?,
        attempt: AttemptId::from_bytes(attempt).map_err(|_| Error::Corrupt("attempt_id"))?,
        requester: UserId::from_bytes(requester).map_err(|_| Error::Corrupt("requester_id"))?,
        provider: Provider::ALL
            .get(usize::try_from(provider).unwrap_or(usize::MAX))
            .copied()
            .ok_or(Error::Corrupt("ai_requests.provider"))?,
        data_policy: DataPolicy::from_code(policy)
            .ok_or(Error::Corrupt("ai_requests.data_policy"))?,
        origin: Origin::from_code(origin).ok_or(Error::Corrupt("ai_requests.origin"))?,
        state: State::from_code(state).ok_or(Error::Corrupt("ai_requests.state_code"))?,
        outcome: match outcome {
            None => None,
            Some(code) => {
                Some(Outcome::from_code(code).ok_or(Error::Corrupt("ai_requests.outcome"))?)
            }
        },
        reason,
        analysis,
        reused,
        created: UnixMillis(created),
        deadline: UnixMillis(deadline),
    })
}

/// One request by id, for the service that consumes it.
pub fn by_id(conn: &Connection, id: AiRequestId) -> Result<Request> {
    let raw = conn
        .prepare_cached(&format!(
            "SELECT {REQUEST_COLUMNS} FROM ai_requests WHERE id = ?1"
        ))?
        .query_row(params![id.as_bytes()], raw)
        .optional()?
        .ok_or(Error::NotFound)?;
    decode(raw)
}

/// One request by id within a tenant. A row of another tenant is simply not found, as everywhere
/// else in the store.
pub fn request(conn: &Connection, tenant: TenantId, id: AiRequestId) -> Result<Request> {
    let raw = conn
        .prepare_cached(&format!(
            "SELECT {REQUEST_COLUMNS} FROM ai_requests WHERE id = ?1 AND tenant_id = ?2"
        ))?
        .query_row(params![id.as_bytes(), tenant.as_bytes()], raw)
        .optional()?
        .ok_or(Error::NotFound)?;
    decode(raw)
}

/// A member's request about one attempt. It is refused unless the requester can read the
/// repository, the tenant's policy admits `provider` right now, and the requester holds every
/// read-only scope — which is what makes the delegation minted at claim time a subset of their
/// own set rather than a substitute for it.
#[allow(clippy::too_many_arguments)]
pub fn enqueue(
    tx: &Transaction<'_>,
    authority: Authority,
    tenant: TenantId,
    repo: RepoId,
    attempt: AttemptId,
    provider: Provider,
    requester_scopes: Scopes,
    now: UnixMillis,
) -> Result<Request> {
    let principal = authority.principal().ok_or(Error::Forbidden)?;
    require_repo(tx, principal, repo, Permissions::READ)?;
    if !requester_scopes.contains(Scopes::READ_ONLY) {
        return Err(Error::Forbidden);
    }
    let data_policy = admit(tx, tenant, provider)?.ok_or(Error::Forbidden)?;
    let owned: bool = tx
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM attempts a JOIN jobs j ON j.id = a.job_id
                JOIN runs r ON r.id = j.run_id
              WHERE a.id = ?1 AND r.repo_id = ?2 AND r.tenant_id = ?3)",
        )?
        .query_row(
            params![attempt.as_bytes(), repo.as_bytes(), tenant.as_bytes()],
            |r| r.get(0),
        )?;
    if !owned {
        return Err(Error::NotFound);
    }
    let id = AiRequestId::new();
    let deadline = now.0.saturating_add(REQUEST_LIFETIME_MS);
    tx.prepare_cached(
        "INSERT INTO ai_requests(id, tenant_id, repo_id, attempt_id, requester_id,
            requester_scopes, provider, data_policy, created_ms, deadline_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
    )?
    .execute(params![
        id.as_bytes(),
        tenant.as_bytes(),
        repo.as_bytes(),
        attempt.as_bytes(),
        principal.user.as_bytes(),
        requester_scopes.bits(),
        provider as u8,
        data_policy as u8,
        now.0,
        deadline
    ])?;
    Ok(Request {
        id,
        tenant,
        repo,
        attempt,
        requester: principal.user,
        provider,
        data_policy,
        origin: Origin::Member,
        state: State::Queued,
        outcome: None,
        reason: None,
        analysis: None,
        reused: false,
        created: now,
        deadline: UnixMillis(deadline),
    })
}

/// How long after a job's failure an automatic request may still be written. The sweep runs on every
/// poll, so this only bounds a controller that never polled through the failure — it never turns a
/// tenant's backlog of old failures into a bill the moment the switch is turned on.
pub const AUTOMATIC_WINDOW_MS: i64 = REQUEST_LIFETIME_MS;

/// Writes the automatic requests a tenant asked for: one per failed attempt of a job that ended
/// `failed` — Sentinel has no advisory job, so every job is a required one — inside the window, for a
/// tenant that turned automatic analysis on and whose policy still admits a provider. The requester is
/// the administrator whose decision turned it on, so the delegation minted at claim reads exactly what
/// they could.
///
/// Idempotent by the one automatic row an attempt may have, so a sweep that runs twice writes once.
/// The provider is the first the deployment allows that the tenant's data policy permits, in the
/// providers' own order, so two sweeps over one policy choose alike.
pub fn enqueue_automatic(tx: &Transaction<'_>, now: UnixMillis, limit: u32) -> Result<usize> {
    let (enabled, bits) = tx
        .prepare_cached("SELECT ai_enabled, ai_providers FROM deployment_policy WHERE id = 1")?
        .query_row([], |r| Ok((r.get::<_, bool>(0)?, r.get::<_, i64>(1)?)))?;
    if !enabled {
        return Ok(0);
    }
    let providers = Providers::from_bits(bits)?;
    let mut found = Vec::new();
    let mut statement = tx.prepare_cached(
        "SELECT j.tenant_id, r.repo_id, a.id, t.data_policy, t.updated_by
           FROM jobs j
           JOIN runs r ON r.id = j.run_id
           JOIN attempts a ON a.job_id = j.id AND a.fence = (
                SELECT MAX(fence) FROM attempts WHERE job_id = j.id)
           JOIN tenant_ai t ON t.tenant_id = j.tenant_id
          WHERE j.state_code = 20
            AND t.enabled = 1 AND t.auto_analysis = 1 AND t.updated_by IS NOT NULL
            AND j.terminal_ms >= ?1
          ORDER BY j.terminal_ms, j.id
          LIMIT ?2",
    )?;
    let mut rows = statement.query(params![
        now.0.saturating_sub(AUTOMATIC_WINDOW_MS),
        i64::from(limit)
    ])?;
    while let Some(row) = rows.next()? {
        found.push((
            row.get::<_, [u8; 16]>(0)?,
            row.get::<_, [u8; 16]>(1)?,
            row.get::<_, [u8; 16]>(2)?,
            row.get::<_, i64>(3)?,
            row.get::<_, [u8; 16]>(4)?,
        ));
    }
    drop(rows);
    drop(statement);
    let mut written = 0;
    for (tenant, repo, attempt, policy, requester) in found {
        let Some(policy) = DataPolicy::from_code(policy) else {
            return Err(Error::Corrupt("tenant_ai.data_policy"));
        };
        let Some(provider) = providers.list().find(|p| policy.allows(*p)) else {
            continue;
        };
        let (tenant, repo, attempt, requester) = (
            TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?,
            RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))?,
            AttemptId::from_bytes(attempt).map_err(|_| Error::Corrupt("attempt_id"))?,
            UserId::from_bytes(requester).map_err(|_| Error::Corrupt("requester_id"))?,
        );
        let id = AiRequestId::new();
        written += tx
            .prepare_cached(
                "INSERT OR IGNORE INTO ai_requests(id, tenant_id, repo_id, attempt_id,
                    requester_id, requester_scopes, provider, data_policy, origin, created_ms,
                    deadline_ms)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 2, ?9, ?10)",
            )?
            .execute(params![
                id.as_bytes(),
                tenant.as_bytes(),
                repo.as_bytes(),
                attempt.as_bytes(),
                requester.as_bytes(),
                Scopes::READ_ONLY.bits(),
                provider as u8,
                policy as u8,
                now.0,
                now.0.saturating_add(REQUEST_LIFETIME_MS)
            ])?;
    }
    Ok(written)
}

/// The oldest queued requests: what the AI process consumes, one page at a time.
pub fn queued(conn: &Connection, limit: u32) -> Result<Vec<Request>> {
    let mut statement = conn.prepare_cached(&format!(
        "SELECT {REQUEST_COLUMNS} FROM ai_requests WHERE state_code = 1
         ORDER BY created_ms, id LIMIT ?1"
    ))?;
    let mut rows = statement.query([i64::from(limit)])?;
    let mut found = Vec::with_capacity(limit as usize);
    while let Some(row) = rows.next()? {
        found.push(decode(raw(row)?)?);
    }
    Ok(found)
}

/// The analysis an attempt has (Y05), as the route that serves it reads it: none, one still being
/// produced, or the settled document of the newest answered request about this attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    /// Nobody has asked about this attempt, and the controller was not asked to.
    None,
    /// A request is queued or claimed: an answer may still arrive before its deadline.
    Pending,
    Analysis {
        /// `sentinel.ai-analysis/1`'s document, exactly as it was decoded and stored.
        document: String,
        /// Whether the ledger already paid for it, so it may describe an earlier attempt.
        reused: bool,
        settled: UnixMillis,
        origin: Origin,
    },
}

/// The newest answered request about one attempt, or the fact that one is still in flight. Both are
/// index probes: the newest settled answer first, because a request asked twice is answered twice.
pub fn answer(conn: &Connection, attempt: AttemptId, now: UnixMillis) -> Result<Answer> {
    let settled = conn
        .prepare_cached(
            "SELECT result, reused, settled_ms, origin FROM ai_requests
              WHERE attempt_id = ?1 AND state_code = 3 AND outcome = 2 AND result IS NOT NULL
              ORDER BY settled_ms DESC, id DESC LIMIT 1",
        )?
        .query_row(params![attempt.as_bytes()], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, bool>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
            ))
        })
        .optional()?;
    if let Some((document, reused, settled, origin)) = settled {
        return Ok(Answer::Analysis {
            document,
            reused,
            settled: UnixMillis(settled),
            origin: Origin::from_code(origin).ok_or(Error::Corrupt("ai_requests.origin"))?,
        });
    }
    let pending: bool = conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM ai_requests
              WHERE attempt_id = ?1 AND state_code != 3 AND deadline_ms > ?2)",
        )?
        .query_row(params![attempt.as_bytes(), now.0], |r| r.get(0))?;
    Ok(if pending {
        Answer::Pending
    } else {
        Answer::None
    })
}

/// What an attempt's stored evidence has left: the log retention it was written under, and whether
/// retention has already removed it. A citation resolves only while `expired` is false, and an
/// analysis expires no later than `expires` — so nothing it cites outlives the log itself.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Retention {
    /// When the log expires. `None` while no retention is recorded for the attempt, which is not the
    /// same as gone: an analysis then keeps the cache's own bound.
    pub expires: Option<UnixMillis>,
    /// Whether retention removed the log, which makes every citation into it drop.
    pub expired: bool,
}

/// `None` for an attempt the store does not know.
pub fn retention(conn: &Connection, attempt: AttemptId) -> Result<Option<Retention>> {
    let row = conn
        .prepare_cached("SELECT log_expires_ms, log_expired_ms FROM attempts WHERE id = ?1")?
        .query_row(params![attempt.as_bytes()], |r| {
            Ok((r.get::<_, Option<i64>>(0)?, r.get::<_, Option<i64>>(1)?))
        })
        .optional()?;
    Ok(row.map(|(expires, expired)| Retention {
        expires: expires.map(UnixMillis),
        expired: expired.is_some(),
    }))
}

/// A claim: the row's lease, and the delegation that reads its evidence.
pub struct Claimed {
    pub request: Request,
    /// The `api_tokens` row the delegation is; naming it is what binds the credential to the request.
    pub token: TokenId,
    pub access: Secret,
    pub expires: UnixMillis,
}

/// Claims one request for the AI process: `queued` becomes `claimed` in the same transaction that
/// mints the delegation, so a request is never claimed without the credential that reads it and
/// never read without a claim.
pub fn claim(tx: &Transaction<'_>, id: AiRequestId, now: UnixMillis) -> Result<Claimed> {
    let (bits, requester, repo, deadline, state, tenant) = tx
        .prepare_cached(
            "SELECT requester_scopes, requester_id, repo_id, deadline_ms, state_code, tenant_id
             FROM ai_requests WHERE id = ?1",
        )?
        .query_row(params![id.as_bytes()], |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, [u8; 16]>(1)?,
                r.get::<_, [u8; 16]>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, [u8; 16]>(5)?,
            ))
        })
        .optional()?
        .ok_or(Error::NotFound)?;
    if State::from_code(state) != Some(State::Queued) || deadline <= now.0 {
        return Err(Error::Conflict);
    }
    let tenant = TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?;
    let scopes =
        Scopes::from_bits(u32::try_from(bits).map_err(|_| Error::Corrupt("requester_scopes"))?)
            .ok_or(Error::Corrupt("requester_scopes"))?
            .intersect(Scopes::READ_ONLY);
    if scopes.is_empty() {
        return Err(Error::Forbidden);
    }
    let lifetime = DELEGATION_MS.min(deadline - now.0);
    let name = format!("{DELEGATION_NAME_PREFIX}{id}");
    let granted = crate::tokens::insert(
        tx,
        &crate::tokens::Grant {
            user: UserId::from_bytes(requester).map_err(|_| Error::Corrupt("requester_id"))?,
            name: &name,
            permissions: Permissions::READ,
            tenant: Some(tenant),
            repo: Some(RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))?),
            lifetime_ms: lifetime,
        },
        now,
    )?;
    let lease = deadline.min(now.0.saturating_add(CLAIM_LEASE_MS));
    let claimed = tx
        .prepare_cached(
            "UPDATE ai_requests SET state_code = 2, claimed_ms = ?2, lease_until_ms = ?3,
                delegation_id = ?4
              WHERE id = ?1 AND state_code = 1",
        )?
        .execute(params![id.as_bytes(), now.0, lease, granted.id.as_bytes()])?;
    if claimed == 0 {
        // Lost to another claim between the read and the write: the delegation minted above has no
        // request to belong to, so it is revoked here rather than left to expire.
        tx.prepare_cached(
            "UPDATE api_tokens SET revoked_ms = ?2 WHERE id = ?1 AND revoked_ms IS NULL",
        )?
        .execute(params![granted.id.as_bytes(), now.0])?;
        return Err(Error::Conflict);
    }
    Ok(Claimed {
        request: by_id(tx, id)?,
        token: granted.id,
        access: granted.secret,
        expires: granted.expires,
    })
}

/// Settles a request exactly once: the answer, or the reason there is none. Its delegation is
/// revoked and its reservation released in the same transaction, so nothing survives a request that
/// has ended and no budget is held by a request nobody can settle again. `usage` is what the
/// provider reported; a component it did not report settles at the reservation's maximum.
pub fn settle(
    tx: &Transaction<'_>,
    id: AiRequestId,
    outcome: Outcome,
    analysis: Option<&str>,
    reason: Option<&str>,
    now: UnixMillis,
    usage: Option<Usage>,
) -> Result<Request> {
    // The document was decoded before it reached here; the store holds it within the bound its column
    // states, because an analysis is stored only when the whole of it is.
    if analysis.is_some_and(|a| a.is_empty() || a.len() > MAX_RESULT_BYTES) {
        return Err(Error::InvalidInput("ai request analysis"));
    }
    if reason.is_some_and(|r| r.is_empty() || r.len() > MAX_REASON_BYTES) {
        return Err(Error::InvalidInput("ai request reason"));
    }
    let (outcome, analysis, reason) = match outcome {
        Outcome::Completed => (outcome, analysis, None),
        Outcome::Unavailable => (outcome, None, reason.or(Some("unavailable"))),
    };
    close(
        tx,
        id,
        Ending {
            outcome,
            analysis,
            reason,
            reused: false,
            usage,
        },
        now,
    )?;
    by_id(tx, id)
}

/// How a request ends and what it is charged, as one value the two writers of a settlement share.
struct Ending<'a> {
    outcome: Outcome,
    /// `sentinel.ai-analysis/1`'s document, as the cache holds it and the row publishes it.
    analysis: Option<&'a str>,
    reason: Option<&'a str>,
    /// Whether the answer was an analysis the cache already held, which the row states.
    reused: bool,
    usage: Option<Usage>,
}

/// Ends one request in one write: the row, its delegation, its reservation and what the ledger
/// charges for it. A request that was never reserved (a reuse, a refusal, a policy that stopped it)
/// charges nothing.
fn close(tx: &Transaction<'_>, id: AiRequestId, ending: Ending<'_>, now: UnixMillis) -> Result<()> {
    let Ending {
        outcome,
        analysis,
        reason,
        reused,
        usage,
    } = ending;
    let settled = tx
        .prepare_cached(
            "UPDATE ai_requests SET state_code = 3, outcome = ?2, result = ?3, reason = ?4,
                settled_ms = ?5, reused = ?6
              WHERE id = ?1 AND state_code != 3",
        )?
        .execute(params![
            id.as_bytes(),
            outcome as u8,
            analysis,
            reason,
            now.0,
            reused
        ])?;
    if settled == 0 {
        return Err(Error::Conflict);
    }
    tx.prepare_cached(
        "UPDATE api_tokens SET revoked_ms = ?1
          WHERE revoked_ms IS NULL AND id IN (
              SELECT delegation_id FROM ai_requests WHERE id = ?2 AND delegation_id IS NOT NULL)",
    )?
    .execute(params![now.0, id.as_bytes()])?;
    release(tx, id, analysis, now, usage)
}

/// Whether `token` is the live delegation of the request about `attempt`: the check the evidence
/// route makes when the presented credential holds no `ai:context` grant. One index probe, and a
/// settled or expired request ends it.
pub fn delegates(
    conn: &Connection,
    token: TokenId,
    attempt: AttemptId,
    now: UnixMillis,
) -> Result<bool> {
    let live: bool = conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM ai_requests
              WHERE delegation_id = ?1 AND attempt_id = ?2 AND state_code = 2
                AND settled_ms IS NULL AND deadline_ms > ?3)",
        )?
        .query_row(params![token.as_bytes(), attempt.as_bytes(), now.0], |r| {
            r.get(0)
        })?;
    Ok(live)
}

/// Settles every request past its deadline as `unavailable`, up to `limit`, and returns how many.
/// A provider outage, a disabled tenant and a killed AI process all end this way; nothing waits.
/// The reservations those requests held are deleted first, in this same write, so a killed AI
/// process never holds a tenant's budget past the deadline it was allowed; expired analyses are
/// pruned here too, which is the one clock the AI queue needs.
pub fn sweep(tx: &Transaction<'_>, now: UnixMillis, limit: u32) -> Result<usize> {
    tx.prepare_cached(
        "DELETE FROM ai_analyses WHERE (tenant_id, digest, prompt_version, model) IN (
            SELECT tenant_id, digest, prompt_version, model FROM ai_analyses
             WHERE expires_ms <= ?1 LIMIT ?2)",
    )?
    .execute(params![now.0, i64::from(limit)])?;
    tx.prepare_cached(
        "DELETE FROM ai_reservations WHERE request_id IN (
            SELECT id FROM ai_requests
             WHERE state_code != 3 AND deadline_ms <= ?1 ORDER BY deadline_ms LIMIT ?2)",
    )?
    .execute(params![now.0, i64::from(limit)])?;
    let swept = tx
        .prepare_cached(
            "UPDATE ai_requests SET state_code = 3, outcome = 1, reason = 'the request deadline passed',
                settled_ms = ?1, lease_until_ms = NULL
              WHERE id IN (SELECT id FROM ai_requests
                            WHERE state_code != 3 AND deadline_ms <= ?1
                            ORDER BY deadline_ms LIMIT ?2)",
        )?
        .execute(params![now.0, i64::from(limit)])?;
    if swept == 0 {
        return Ok(0);
    }
    tx.prepare_cached(
        "UPDATE api_tokens SET revoked_ms = ?1
          WHERE revoked_ms IS NULL AND id IN (
              SELECT delegation_id FROM ai_requests
               WHERE delegation_id IS NOT NULL AND state_code = 3 AND deadline_ms <= ?1)",
    )?
    .execute([now.0])?;
    Ok(swept)
}

// ---------------------------------------------------------------------------------------------
// Budgets, the ledger and the analysis cache (Y04). The controller still calls no provider: one
// writer transaction answers whether the request already has an answer, whether it fits, and what
// it holds if it does. A reuse and a refusal end the row in that same commit, so neither is ever
// left queued, and a reservation is released by the same write that ends its request or by its own
// expiry, so a killed AI process cannot hold a tenant's budget.
// ---------------------------------------------------------------------------------------------

/// How long an analysis is kept for reuse. Past this the logs it cites have usually aged out of
/// retention, so the sweep that expires requests prunes it here rather than holding it forever.
pub const ANALYSIS_TTL_MS: i64 = 30 * 24 * 60 * 60 * 1000;

/// Why an analysis was reused, which is what the row records next to it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reuse {
    /// The same evidence: one attempt asked about twice.
    Evidence,
    /// The same failure on a later run: normalized failed step, test identities and error lines.
    Fingerprint,
}

impl Reuse {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Evidence => "evidence",
            Self::Fingerprint => "fingerprint",
        }
    }
}

/// What the AI process asks to hold for one claimed request: its maxima, and the key its answer is
/// published under. The maxima are computed where the model and its price are configured, and the
/// controller decides whether they fit; it never guesses a price of its own.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reservation {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_micros: u64,
    /// The digest of the exact evidence bundle the model will read.
    pub digest: [u8; 32],
    /// The failure's signature, stable across reruns of the same failure.
    pub fingerprint: [u8; 32],
    pub prompt_version: String,
    pub model: String,
}

/// What a reservation did, decided in one write and never reconsidered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Admitted {
    /// The maxima are held until `expires`: the provider may be contacted.
    Reserved { expires: UnixMillis },
    /// This question or this failure was already answered; the request is settled with that answer,
    /// the `sentinel.ai-analysis/1` document the cache holds.
    Reused { analysis: String, by: Reuse },
    /// It does not fit. The request is settled `unavailable` carrying `reason`, and nothing is held.
    Refused { reason: String },
}

/// What a provider reported for one request. A count it did not report is `None`, never zero: an
/// unreported component settles at the reservation's maximum, because nothing can say it was free.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    pub input_tokens: Option<u64>,
    pub output_tokens: Option<u64>,
    pub cost_micros: Option<u64>,
}

/// Tokens and cost, as a ledger row holds them.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Spend {
    pub input_tokens: u64,
    pub output_tokens: u64,
    pub cost_micros: u64,
}

impl Spend {
    /// What a monthly token limit is compared against: a token is a token, whichever side of the
    /// call it was counted on.
    pub const fn tokens(self) -> u64 {
        self.input_tokens.saturating_add(self.output_tokens)
    }
}

/// One tenant's calendar month: what it was charged, what live reservations hold, and how many of
/// its requests are in flight.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Month {
    /// `YYYYMM`, UTC.
    pub month: i64,
    pub settled: Spend,
    pub reserved: Spend,
    pub in_flight: u32,
}

/// The UTC calendar month `ms` falls in, as `YYYYMM`: the ledger's key, so a month costs one
/// integer comparison and one row per tenant, and no date arithmetic runs on the request path.
pub const fn month_of(ms: i64) -> i64 {
    // Howard Hinnant's civil-from-days, shifted so day 0 is 1970-01-01.
    let days = ms.div_euclid(86_400_000) + 719_468;
    let era = days.div_euclid(146_097);
    let doe = days - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + if month <= 2 { 1 } else { 0 };
    year * 100 + month
}

/// The decision that stands between a claimed request and a provider call, in one transaction: an
/// answer the ledger already paid for, then the tenant's per-request caps, its concurrency limit and
/// its monthly budget — and, only if all of those pass, the reservation that holds the maximum.
///
/// The cache is read first because a reused answer costs nothing: neither a cap, nor a request
/// already in flight, nor an exhausted budget may refuse it. Everything after it is a refusal
/// before the call, never a queue.
pub fn reserve(
    tx: &Transaction<'_>,
    id: AiRequestId,
    asked: &Reservation,
    now: UnixMillis,
) -> Result<Admitted> {
    if asked.input_tokens == 0
        || [asked.input_tokens, asked.output_tokens, asked.cost_micros]
            .into_iter()
            .any(|value| i64::try_from(value).is_err())
        || asked.prompt_version.is_empty()
        || asked.prompt_version.len() > 64
        || asked.model.is_empty()
        || asked.model.len() > 128
    {
        return Err(Error::InvalidInput("ai reservation"));
    }
    let (tenant, state, deadline) = tx
        .prepare_cached("SELECT tenant_id, state_code, deadline_ms FROM ai_requests WHERE id = ?1")?
        .query_row(params![id.as_bytes()], |r| {
            Ok((
                r.get::<_, [u8; 16]>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
            ))
        })
        .optional()?
        .ok_or(Error::NotFound)?;
    if State::from_code(state) != Some(State::Claimed) || deadline <= now.0 {
        return Err(Error::Conflict);
    }
    let tenant = TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?;
    if let Some((analysis, by)) = cached(tx, tenant, asked, now)? {
        close(
            tx,
            id,
            Ending {
                outcome: Outcome::Completed,
                analysis: Some(&analysis),
                reason: None,
                reused: true,
                usage: None,
            },
            now,
        )?;
        return Ok(Admitted::Reused { analysis, by });
    }
    let budgets = budgets(tx, tenant)?;
    if let Some(reason) = budgets.refusal(asked) {
        return refuse(tx, id, &reason, now);
    }
    let in_flight = in_flight(tx, tenant, now)?;
    if in_flight >= budgets.concurrency {
        return refuse(
            tx,
            id,
            &format!(
                "concurrency: {in_flight} requests are in flight and the tenant's limit is {}",
                budgets.concurrency
            ),
            now,
        );
    }
    let month = month_of(now.0);
    let (settled, reserved) = spend(tx, tenant, month, now)?;
    let tokens = asked.input_tokens.saturating_add(asked.output_tokens);
    if budgets.monthly_tokens > 0 {
        let used = settled.tokens().saturating_add(reserved.tokens());
        if used.saturating_add(tokens) > budgets.monthly_tokens {
            return refuse(
                tx,
                id,
                &format!(
                    "budget: the month has spent or holds {used} tokens of {} and this request asks for {tokens}",
                    budgets.monthly_tokens
                ),
                now,
            );
        }
    }
    if budgets.monthly_cost_micros > 0 {
        let used = settled.cost_micros.saturating_add(reserved.cost_micros);
        if used.saturating_add(asked.cost_micros) > budgets.monthly_cost_micros {
            return refuse(
                tx,
                id,
                &format!(
                    "budget: the month has spent or holds {used} micros of {} and this request asks for {}",
                    budgets.monthly_cost_micros, asked.cost_micros
                ),
                now,
            );
        }
    }
    tx.prepare_cached(
        "INSERT INTO ai_reservations(request_id, tenant_id, month, input_tokens, output_tokens,
            cost_micros, digest, fingerprint, prompt_version, model, created_ms, expires_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
    )?
    .execute(params![
        id.as_bytes(),
        tenant.as_bytes(),
        month,
        i64::try_from(asked.input_tokens).map_err(|_| Error::InvalidInput("ai reservation"))?,
        i64::try_from(asked.output_tokens).map_err(|_| Error::InvalidInput("ai reservation"))?,
        i64::try_from(asked.cost_micros).map_err(|_| Error::InvalidInput("ai reservation"))?,
        asked.digest.as_slice(),
        asked.fingerprint.as_slice(),
        asked.prompt_version,
        asked.model,
        now.0,
        deadline,
    ])?;
    Ok(Admitted::Reserved {
        expires: UnixMillis(deadline),
    })
}

/// Refuses one request and ends it in the same write: the reason is on the row, nothing is held, and
/// the caller has nothing left to settle.
fn refuse(
    tx: &Transaction<'_>,
    id: AiRequestId,
    reason: &str,
    now: UnixMillis,
) -> Result<Admitted> {
    let reason = &reason[..reason.len().min(MAX_REASON_BYTES)];
    close(
        tx,
        id,
        Ending {
            outcome: Outcome::Unavailable,
            analysis: None,
            reason: Some(reason),
            reused: false,
            usage: None,
        },
        now,
    )?;
    Ok(Admitted::Refused {
        reason: reason.to_owned(),
    })
}

/// The answer this question already has: its exact evidence first, then the same failure on an
/// earlier run. One key probe each, and the second takes the newest.
fn cached(
    conn: &Connection,
    tenant: TenantId,
    asked: &Reservation,
    now: UnixMillis,
) -> Result<Option<(String, Reuse)>> {
    let exact = conn
        .prepare_cached(
            "SELECT text FROM ai_analyses
              WHERE tenant_id = ?1 AND digest = ?2 AND prompt_version = ?3 AND model = ?4
                AND expires_ms > ?5",
        )?
        .query_row(
            params![
                tenant.as_bytes(),
                asked.digest.as_slice(),
                asked.prompt_version,
                asked.model,
                now.0
            ],
            |r| r.get::<_, String>(0),
        )
        .optional()?;
    if let Some(text) = exact {
        return Ok(Some((text, Reuse::Evidence)));
    }
    let same = conn
        .prepare_cached(
            "SELECT text FROM ai_analyses
              WHERE tenant_id = ?1 AND fingerprint = ?2 AND prompt_version = ?3 AND model = ?4
                AND expires_ms > ?5
              ORDER BY created_ms DESC LIMIT 1",
        )?
        .query_row(
            params![
                tenant.as_bytes(),
                asked.fingerprint.as_slice(),
                asked.prompt_version,
                asked.model,
                now.0
            ],
            |r| r.get::<_, String>(0),
        )
        .optional()?;
    Ok(same.map(|text| (text, Reuse::Fingerprint)))
}

/// The tenant's budget as its policy row holds it. A request that reached here was admitted, so the
/// row exists; one that does not is a tenant that opted out between the claim and the reservation.
fn budgets(conn: &Connection, tenant: TenantId) -> Result<Budgets> {
    conn.prepare_cached(
        "SELECT monthly_tokens, monthly_cost_micros, input_tokens_cap, output_tokens_cap,
            cost_micros_cap, concurrency
          FROM tenant_ai WHERE tenant_id = ?1",
    )?
    .query_row([tenant.as_bytes()], |r| budgets_at(r, 0))
    .optional()?
    .ok_or(Error::Forbidden)
}

/// How many of the tenant's reservations are still live: the concurrency limit's one read.
fn in_flight(conn: &Connection, tenant: TenantId, now: UnixMillis) -> Result<u32> {
    let live: i64 = conn
        .prepare_cached(
            "SELECT COUNT(*) FROM ai_reservations WHERE tenant_id = ?1 AND expires_ms > ?2",
        )?
        .query_row(params![tenant.as_bytes(), now.0], |r| r.get(0))?;
    Ok(u32::try_from(live).unwrap_or(u32::MAX))
}

/// The month's charged and held totals: what the budget is compared against.
fn spend(
    conn: &Connection,
    tenant: TenantId,
    month: i64,
    now: UnixMillis,
) -> Result<(Spend, Spend)> {
    let settled = conn
        .prepare_cached(
            "SELECT input_tokens, output_tokens, cost_micros FROM ai_ledger
              WHERE tenant_id = ?1 AND month = ?2",
        )?
        .query_row(params![tenant.as_bytes(), month], |r| {
            Ok(Spend {
                input_tokens: nonzero(r.get(0)?),
                output_tokens: nonzero(r.get(1)?),
                cost_micros: nonzero(r.get(2)?),
            })
        })
        .optional()?
        .unwrap_or_default();
    let reserved = conn
        .prepare_cached(
            "SELECT COALESCE(SUM(input_tokens), 0), COALESCE(SUM(output_tokens), 0),
                COALESCE(SUM(cost_micros), 0)
              FROM ai_reservations WHERE tenant_id = ?1 AND month = ?2 AND expires_ms > ?3",
        )?
        .query_row(params![tenant.as_bytes(), month, now.0], |r| {
            Ok(Spend {
                input_tokens: nonzero(r.get(0)?),
                output_tokens: nonzero(r.get(1)?),
                cost_micros: nonzero(r.get(2)?),
            })
        })?;
    Ok((settled, reserved))
}

/// One tenant's month, for the route that reports it.
pub fn month(conn: &Connection, tenant: TenantId, now: UnixMillis) -> Result<Month> {
    let month = month_of(now.0);
    let (settled, reserved) = spend(conn, tenant, month, now)?;
    Ok(Month {
        month,
        settled,
        reserved,
        in_flight: in_flight(conn, tenant, now)?,
    })
}

/// Releases the reservation a request holds and charges the ledger what it used. A request that
/// never reserved — a reuse, a refusal, one a policy stopped — has nothing to release and charges
/// nothing. A completed answer is published under the key the reservation named, in this same write.
fn release(
    tx: &Transaction<'_>,
    id: AiRequestId,
    analysis: Option<&str>,
    now: UnixMillis,
    usage: Option<Usage>,
) -> Result<()> {
    let held = tx
        .prepare_cached(
            "SELECT tenant_id, month, input_tokens, output_tokens, cost_micros, digest, fingerprint,
                prompt_version, model
              FROM ai_reservations WHERE request_id = ?1",
        )?
        .query_row(params![id.as_bytes()], |r| {
            Ok((
                r.get::<_, [u8; 16]>(0)?,
                r.get::<_, i64>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, i64>(3)?,
                r.get::<_, i64>(4)?,
                r.get::<_, [u8; 32]>(5)?,
                r.get::<_, [u8; 32]>(6)?,
                r.get::<_, String>(7)?,
                r.get::<_, String>(8)?,
            ))
        })
        .optional()?;
    let Some((tenant, month, input, output, cost, digest, fingerprint, version, model)) = held
    else {
        return Ok(());
    };
    tx.prepare_cached("DELETE FROM ai_reservations WHERE request_id = ?1")?
        .execute(params![id.as_bytes()])?;
    let usage = usage.unwrap_or_default();
    tx.prepare_cached(
        "INSERT INTO ai_ledger(tenant_id, month, input_tokens, output_tokens, cost_micros)
         VALUES (?1, ?2, ?3, ?4, ?5)
         ON CONFLICT(tenant_id, month) DO UPDATE SET
            input_tokens = ai_ledger.input_tokens + excluded.input_tokens,
            output_tokens = ai_ledger.output_tokens + excluded.output_tokens,
            cost_micros = ai_ledger.cost_micros + excluded.cost_micros",
    )?
    .execute(params![
        tenant.as_slice(),
        month,
        charged(usage.input_tokens, input),
        charged(usage.output_tokens, output),
        charged(usage.cost_micros, cost)
    ])?;
    if let Some(analysis) = analysis.filter(|analysis| !analysis.is_empty())
        && let Some(expires) = evidence_expiry(tx, id, now)?
    {
        tx.prepare_cached(
            "INSERT INTO ai_analyses(tenant_id, digest, prompt_version, model, fingerprint, text,
                created_ms, expires_ms)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
             ON CONFLICT(tenant_id, digest, prompt_version, model) DO UPDATE SET
                fingerprint = excluded.fingerprint, text = excluded.text,
                created_ms = excluded.created_ms, expires_ms = excluded.expires_ms",
        )?
        .execute(params![
            tenant.as_slice(),
            digest.as_slice(),
            version,
            model,
            fingerprint.as_slice(),
            analysis,
            now.0,
            expires.0
        ])?;
    }
    Ok(())
}

/// When the analysis of `id` stops being servable: with the logs of the attempt it was computed from
/// (Y05), or with the cache's own 30-day bound, whichever is first. Nothing an analysis cites outlives
/// its evidence, so a reused answer can never cite a log the tenant no longer holds. `None` when the
/// evidence is already gone, which is a document there is no point caching.
fn evidence_expiry(
    tx: &Transaction<'_>,
    id: AiRequestId,
    now: UnixMillis,
) -> Result<Option<UnixMillis>> {
    let found = tx
        .prepare_cached(
            "SELECT a.log_expires_ms, a.log_expired_ms FROM ai_requests q
               JOIN attempts a ON a.id = q.attempt_id
              WHERE q.id = ?1",
        )?
        .query_row(params![id.as_bytes()], |r| {
            Ok((r.get::<_, Option<i64>>(0)?, r.get::<_, Option<i64>>(1)?))
        })
        .optional()?;
    let Some((expires, expired)) = found else {
        return Ok(None);
    };
    if expired.is_some() {
        return Ok(None);
    }
    let ttl = now.0.saturating_add(ANALYSIS_TTL_MS);
    Ok(expires.map_or(Some(UnixMillis(ttl)), |expires| {
        Some(UnixMillis(expires.min(ttl))).filter(|at| at.0 > now.0)
    }))
}

/// What one component settles at: what the provider reported, or the reservation's maximum when it
/// reported nothing. Never more than was held, so a call cannot spend past what it reserved.
fn charged(reported: Option<u64>, reserved: i64) -> i64 {
    match reported {
        None => reserved,
        Some(value) => i64::try_from(value).map_or(reserved, |value| value.min(reserved)),
    }
}

/// A policy change's queue: queued requests naming a provider the allow-list no longer holds are
/// deleted, because they could never be admitted again. A claimed request keeps its lease and its
/// own deadline ends it.
fn drop_providers(tx: &Transaction<'_>, providers: Providers) -> Result<usize> {
    let mut allowed = Vec::with_capacity(Provider::ALL.len());
    for provider in providers.list() {
        allowed.push(provider as u8);
    }
    let mut kept = String::with_capacity(allowed.len() * 2);
    for (at, _) in allowed.iter().enumerate() {
        if at > 0 {
            kept.push(',');
        }
        kept.push('?');
    }
    let sql = if allowed.is_empty() {
        "DELETE FROM ai_requests WHERE state_code = 1".to_owned()
    } else {
        format!("DELETE FROM ai_requests WHERE state_code = 1 AND provider NOT IN ({kept})")
    };
    let deleted = tx
        .prepare_cached(&sql)?
        .execute(rusqlite::params_from_iter(allowed))?;
    Ok(deleted)
}

/// A disable's first act (Y01's promise, kept by Y03): every request of `tenant` is deleted, and
/// the delegations it minted are revoked, in the same transaction that turns its AI off. The whole
/// deployment's disable passes `None`.
pub fn drop_requests(
    tx: &Transaction<'_>,
    tenant: Option<TenantId>,
    now: UnixMillis,
) -> Result<usize> {
    let deleted = match tenant {
        Some(tenant) => {
            tx.prepare_cached(
                "UPDATE api_tokens SET revoked_ms = ?1
                  WHERE revoked_ms IS NULL AND id IN (
                      SELECT delegation_id FROM ai_requests
                       WHERE delegation_id IS NOT NULL AND tenant_id = ?2)",
            )?
            .execute(params![now.0, tenant.as_bytes()])?;
            // The reservations name requests, so they go first; the analyses are the tenant's own
            // paid-for answers, and a tenant that is off keeps neither.
            tx.prepare_cached("DELETE FROM ai_reservations WHERE tenant_id = ?1")?
                .execute(params![tenant.as_bytes()])?;
            tx.prepare_cached("DELETE FROM ai_analyses WHERE tenant_id = ?1")?
                .execute(params![tenant.as_bytes()])?;
            tx.prepare_cached("DELETE FROM ai_requests WHERE tenant_id = ?1")?
                .execute(params![tenant.as_bytes()])?
        }
        None => {
            tx.prepare_cached(
                "UPDATE api_tokens SET revoked_ms = ?1
                  WHERE revoked_ms IS NULL AND id IN (
                      SELECT delegation_id FROM ai_requests WHERE delegation_id IS NOT NULL)",
            )?
            .execute([now.0])?;
            tx.prepare_cached("DELETE FROM ai_reservations")?
                .execute([])?;
            tx.prepare_cached("DELETE FROM ai_analyses")?.execute([])?;
            tx.prepare_cached("DELETE FROM ai_requests")?.execute([])?
        }
    };
    Ok(deleted)
}
