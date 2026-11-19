//! Acceptance commits before the sender is acknowledged. A delivery's tenant comes from its repository row,
//! never from the caller, and every caller authenticates before reaching this module.

use rusqlite::{Connection, OptionalExtension, Transaction, params};
use sentinel_auth::secret::Secret;
use sentinel_core::{DeliveryId, RepoId, TenantId, UnixMillis, UserId};

use crate::registration::Authority;
use crate::{Error, Result, sources};

pub const MAX_PENDING_PER_REPO: i64 = 1024;
pub const MAX_ATTEMPTS: u32 = 8;
const BASE_BACKOFF_MS: i64 = 1_000;
const MAX_BACKOFF_MS: i64 = 5 * 60 * 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Pending,
    Ready,
    Ignored,
    Failed,
    Dispatched,
}

impl State {
    pub const fn code(self) -> i64 {
        match self {
            Self::Pending => 0,
            Self::Ready => 1,
            Self::Ignored => 2,
            Self::Failed => 3,
            Self::Dispatched => 4,
        }
    }

    const fn decode(code: i64) -> Option<Self> {
        Some(match code {
            0 => Self::Pending,
            1 => Self::Ready,
            2 => Self::Ignored,
            3 => Self::Failed,
            4 => Self::Dispatched,
            _ => return None,
        })
    }

    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Ready => "ready",
            Self::Ignored => "ignored",
            Self::Failed => "failed",
            Self::Dispatched => "dispatched",
        }
    }

    pub const fn is_open(self) -> bool {
        matches!(self, Self::Pending | Self::Ready)
    }

    pub fn parse(text: &str) -> Option<Self> {
        Some(match text {
            "pending" => Self::Pending,
            "ready" => Self::Ready,
            "ignored" => Self::Ignored,
            "failed" => Self::Failed,
            "dispatched" => Self::Dispatched,
            _ => return None,
        })
    }
}

#[derive(Clone, Debug)]
pub struct Delivery {
    pub id: DeliveryId,
    pub tenant: TenantId,
    pub repo: RepoId,
    pub provider: String,
    pub external_id: String,
    pub event: String,
    pub ref_name: Option<String>,
    pub old_sha: Option<String>,
    pub new_sha: Option<String>,
    pub state: State,
    pub reason: Option<String>,
    pub attempts: u32,
    pub received: UnixMillis,
    pub settled: Option<UnixMillis>,
    pub run: Option<sentinel_core::RunId>,
}

/// How the caller proved a delivery's origin before handing it over. The adapter that verified it names the level;
/// the store records it with the delivery and the secret gate reads it back, so a run's provenance cannot claim it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Authentication {
    /// No inbound authentication: a ref transition the controller observed itself (polling).
    Observed = 0,
    /// The repository's generic hook secret was presented.
    HookToken = 1,
    /// The forge's webhook signature verified.
    SignedWebhook = 2,
}

pub struct NewDelivery<'a> {
    pub authentication: Authentication,
    pub provider: &'a str,
    pub external_id: &'a str,
    pub event: &'a str,
    pub ref_name: &'a str,
    pub old_sha: &'a str,
    pub new_sha: &'a str,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Accepted {
    Fresh(DeliveryId),
    Duplicate(DeliveryId),
}

impl Accepted {
    pub const fn id(self) -> DeliveryId {
        match self {
            Self::Fresh(id) | Self::Duplicate(id) => id,
        }
    }
    pub const fn duplicate(self) -> bool {
        matches!(self, Self::Duplicate(_))
    }
}

fn check(delivery: &NewDelivery<'_>) -> Result<()> {
    if delivery.provider.is_empty()
        || delivery.provider.len() > 32
        || delivery.event.is_empty()
        || delivery.event.len() > 64
        || !sentinel_protocol::intake::valid_delivery_id(delivery.external_id)
        || !sentinel_protocol::intake::valid_ref(delivery.ref_name)
        || !sentinel_protocol::intake::valid_sha(delivery.old_sha)
        || !sentinel_protocol::intake::valid_sha(delivery.new_sha)
    {
        return Err(Error::InvalidInput("delivery"));
    }
    Ok(())
}

#[derive(Debug)]
pub struct PrTerms<'a> {
    pub number: u64,
    pub action: &'a str,
    pub draft: bool,
    pub head_ref: &'a str,
    pub head_sha: &'a str,
    pub head_repo: u64,
    pub base_ref: &'a str,
    pub base_sha: &'a str,
    pub merge_sha: Option<&'a str>,
}

fn check_pr(pr: &PrTerms<'_>) -> Result<()> {
    let invalid = pr.number == 0
        || pr.number > i64::MAX as u64
        || pr.action.is_empty()
        || pr.action.len() > 32
        || !valid_branch_name(pr.head_ref)
        || !valid_branch_name(pr.base_ref)
        || !sentinel_protocol::intake::valid_sha(pr.head_sha)
        || !sentinel_protocol::intake::valid_sha(pr.base_sha)
        || pr
            .merge_sha
            .is_some_and(|s| !sentinel_protocol::intake::valid_sha(s))
        || pr.head_repo == 0
        || pr.head_repo > i64::MAX as u64;
    if invalid {
        return Err(Error::InvalidInput("pull request"));
    }
    Ok(())
}

fn valid_branch_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 512
        && !name.starts_with('/')
        && !name.ends_with('/')
        && !name.contains("//")
        && !name.contains("..")
        && !name
            .bytes()
            .any(|b| b <= 32 || b == 127 || b"~^:?*[\\".contains(&b))
}

/// A merge-queue delivery's terms: the pair of commits GitHub merged into its
/// queue branch, and the branch the required checks belong to. The queue branch
/// identifies the group — GitHub names it for the base commit it was built on —
/// so a redelivery of the same group matches on both.
#[derive(Debug)]
pub struct MergeTerms<'a> {
    pub action: &'a str,
    pub head_ref: &'a str,
    pub head_sha: &'a str,
    pub base_ref: &'a str,
    pub base_sha: &'a str,
    pub head_repo: u64,
    pub reason: Option<&'a str>,
}

fn check_merge(merge: &MergeTerms<'_>) -> Result<()> {
    let invalid = merge.action.is_empty()
        || merge.action.len() > 32
        || !merge.head_ref.starts_with("refs/heads/")
        || !valid_branch_name(merge.head_ref)
        || !valid_branch_name(merge.base_ref)
        || !sentinel_protocol::intake::valid_sha(merge.head_sha)
        || !sentinel_protocol::intake::valid_sha(merge.base_sha)
        || merge.head_repo == 0
        || merge.head_repo > i64::MAX as u64
        || merge
            .reason
            .is_some_and(|r| r.is_empty() || r.len() > 64 || r.bytes().any(|b| b < 32 || b == 127));
    if invalid {
        return Err(Error::InvalidInput("merge group"));
    }
    Ok(())
}

pub fn accept(
    tx: &Transaction<'_>,
    repo: RepoId,
    delivery: &NewDelivery<'_>,
    pr: Option<&PrTerms<'_>>,
    now: UnixMillis,
) -> Result<Accepted> {
    accept_with_terms(tx, repo, delivery, pr, None, now)
}

pub fn accept_merge_group(
    tx: &Transaction<'_>,
    repo: RepoId,
    delivery: &NewDelivery<'_>,
    merge: &MergeTerms<'_>,
    now: UnixMillis,
) -> Result<Accepted> {
    accept_with_terms(tx, repo, delivery, None, Some(merge), now)
}

/// One delivery with either its pull-request or its merge-group terms (never both).
pub fn accept_with_terms(
    tx: &Transaction<'_>,
    repo: RepoId,
    delivery: &NewDelivery<'_>,
    pr: Option<&PrTerms<'_>>,
    merge: Option<&MergeTerms<'_>>,
    now: UnixMillis,
) -> Result<Accepted> {
    check(delivery)?;
    if let Some(pr) = pr {
        check_pr(pr)?;
    }
    if let Some(merge) = merge {
        check_merge(merge)?;
    }
    let tenant = sources::repo_tenant(tx, repo)?;
    let metadata = sources::load_metadata(tx, repo).map_err(|e| match e {
        Error::NotFound => Error::Forbidden,
        other => other,
    })?;
    if metadata.revoked {
        return Err(Error::Forbidden);
    }
    if let Some(existing) = find(tx, tenant, repo, delivery.provider, delivery.external_id)? {
        if existing.ref_name.as_deref() == Some(delivery.ref_name)
            && existing.old_sha.as_deref() == Some(delivery.old_sha)
            && existing.new_sha.as_deref() == Some(delivery.new_sha)
            && existing.event == delivery.event
        {
            return Ok(Accepted::Duplicate(existing.id));
        }
        return Err(Error::Conflict);
    }
    let pending: i64 = tx
        .prepare_cached(
            "SELECT count(*) FROM webhook_deliveries WHERE repo_id = ?1 AND state IN (0, 1)",
        )?
        .query_row([repo.as_bytes()], |r| r.get(0))?;
    if pending >= MAX_PENDING_PER_REPO {
        return Err(Error::Overloaded);
    }
    let id = DeliveryId::new();
    tx.execute(
        "INSERT INTO webhook_deliveries(id, tenant_id, repo_id, provider, external_id,
            event, ref_name, old_sha, new_sha, state, received_ms, authentication)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 0, ?10, ?11)",
        params![
            id.as_bytes(),
            tenant.as_bytes(),
            repo.as_bytes(),
            delivery.provider,
            delivery.external_id,
            delivery.event,
            delivery.ref_name,
            delivery.old_sha,
            delivery.new_sha,
            now.0,
            delivery.authentication as i64
        ],
    )?;
    if let Some(pr) = pr {
        tx.execute(
            "INSERT INTO pr_deliveries(delivery_id, tenant_id, repo_id, number, action, draft,
                head_ref, head_sha, head_repo_id, base_ref, base_sha, merge_sha)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12)",
            params![
                id.as_bytes(),
                tenant.as_bytes(),
                repo.as_bytes(),
                pr.number as i64,
                pr.action,
                pr.draft,
                pr.head_ref,
                pr.head_sha,
                pr.head_repo as i64,
                pr.base_ref,
                pr.base_sha,
                pr.merge_sha
            ],
        )?;
    }
    if let Some(merge) = merge {
        tx.execute(
            "INSERT INTO merge_deliveries(delivery_id, tenant_id, repo_id, action, head_ref,
                head_sha, base_ref, base_sha, head_repo_id, reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            params![
                id.as_bytes(),
                tenant.as_bytes(),
                repo.as_bytes(),
                merge.action,
                merge.head_ref,
                merge.head_sha,
                merge.base_ref,
                merge.base_sha,
                merge.head_repo as i64,
                merge.reason
            ],
        )?;
    }
    Ok(Accepted::Fresh(id))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrDelivery {
    pub number: u64,
    pub action: String,
    pub draft: bool,
    pub head_ref: String,
    pub head_sha: String,
    pub head_repo: u64,
    pub base_ref: String,
    pub base_sha: String,
    pub merge_sha: Option<String>,
}

pub fn pr_for(conn: &Connection, delivery: DeliveryId) -> Result<Option<PrDelivery>> {
    type Row = (
        i64,
        String,
        bool,
        String,
        String,
        i64,
        String,
        String,
        Option<String>,
    );
    let row: Option<Row> = conn
        .prepare_cached(
            "SELECT number, action, draft, head_ref, head_sha, head_repo_id, base_ref, base_sha,
                    merge_sha
             FROM pr_deliveries WHERE delivery_id = ?1",
        )?
        .query_row([delivery.as_bytes()], |r| {
            Ok((
                r.get(0)?,
                r.get(1)?,
                r.get(2)?,
                r.get(3)?,
                r.get(4)?,
                r.get(5)?,
                r.get(6)?,
                r.get(7)?,
                r.get(8)?,
            ))
        })
        .optional()?;
    let Some((number, action, draft, head_ref, head_sha, head_repo, base_ref, base_sha, merge_sha)) =
        row
    else {
        return Ok(None);
    };
    Ok(Some(PrDelivery {
        number: u64::try_from(number).map_err(|_| Error::Corrupt("pull request number"))?,
        action,
        draft,
        head_ref,
        head_sha,
        head_repo: u64::try_from(head_repo).map_err(|_| Error::Corrupt("head repository"))?,
        base_ref,
        base_sha,
        merge_sha,
    }))
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MergeDelivery {
    pub action: String,
    pub head_ref: String,
    pub head_sha: String,
    pub base_ref: String,
    pub base_sha: String,
    pub head_repo: u64,
    pub reason: Option<String>,
}

type MergeRow = (String, String, String, String, String, i64, Option<String>);

const MERGE_COLUMNS: &str = "m.action, m.head_ref, m.head_sha, m.base_ref, m.base_sha, \
    m.head_repo_id, m.reason";

fn map_merge(r: &rusqlite::Row<'_>) -> rusqlite::Result<MergeRow> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
        r.get(6)?,
    ))
}

fn decode_merge(row: MergeRow) -> Result<MergeDelivery> {
    let (action, head_ref, head_sha, base_ref, base_sha, head_repo, reason) = row;
    Ok(MergeDelivery {
        action,
        head_ref,
        head_sha,
        base_ref,
        base_sha,
        head_repo: u64::try_from(head_repo).map_err(|_| Error::Corrupt("head repository"))?,
        reason,
    })
}

pub fn merge_for(conn: &Connection, delivery: DeliveryId) -> Result<Option<MergeDelivery>> {
    let row: Option<MergeRow> = conn
        .prepare_cached(&format!(
            "SELECT {MERGE_COLUMNS} FROM merge_deliveries m WHERE m.delivery_id = ?1"
        ))?
        .query_row([delivery.as_bytes()], map_merge)
        .optional()?;
    row.map(decode_merge).transpose()
}

/// What a merge group's recorded deliveries say about one of them, in one
/// statement: the run the group produced (one group produces one run, so this is
/// both the answer to a redelivery and the run a destroyed action cancels),
/// whether a delivery accepted before it is still waiting (this one is its
/// duplicate, whoever reaches the lane first), and whether the group has already
/// gone away without a run — a destroyed or merged action settles any delivery of
/// it that arrives afterwards.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MergeGroupState {
    pub run: Option<sentinel_core::RunId>,
    pub earlier_open: bool,
    pub gone: bool,
}

pub fn merge_group_state(
    conn: &Connection,
    delivery: &Delivery,
    head_ref: &str,
    base_sha: &str,
) -> Result<MergeGroupState> {
    let (tenant, repo, id) = (delivery.tenant, delivery.repo, delivery.id);
    let run: Option<[u8; 16]> = conn
        .prepare_cached(
            "SELECT d.run_id FROM webhook_deliveries d
             JOIN merge_deliveries m ON m.delivery_id = d.id
             WHERE d.tenant_id = ?1 AND d.repo_id = ?2 AND m.head_ref = ?3 AND m.base_sha = ?4
               AND d.state = 4
             ORDER BY d.received_ms DESC, d.id DESC LIMIT 1",
        )?
        .query_row(
            params![tenant.as_bytes(), repo.as_bytes(), head_ref, base_sha],
            |r| r.get(0),
        )
        .optional()?;
    let (earlier_open, gone): (bool, bool) = conn
        .prepare_cached(
            "SELECT
               EXISTS(SELECT 1 FROM webhook_deliveries d
                      JOIN merge_deliveries m ON m.delivery_id = d.id
                      WHERE d.tenant_id = ?1 AND d.repo_id = ?2 AND m.head_ref = ?3
                        AND m.base_sha = ?4 AND d.state IN (0, 1) AND d.id <> ?5
                        AND (d.received_ms < ?6 OR (d.received_ms = ?6 AND d.id < ?5))),
               EXISTS(SELECT 1 FROM webhook_deliveries d
                      JOIN merge_deliveries m ON m.delivery_id = d.id
                      WHERE d.tenant_id = ?1 AND d.repo_id = ?2 AND m.head_ref = ?3
                        AND m.base_sha = ?4 AND d.id <> ?5 AND d.reason IN ('merge_group_destroyed',
                        'merge_group_merged'))",
        )?
        .query_row(
            params![
                tenant.as_bytes(),
                repo.as_bytes(),
                head_ref,
                base_sha,
                id.as_bytes(),
                delivery.received.0
            ],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
    Ok(MergeGroupState {
        run: match run {
            Some(bytes) => Some(
                sentinel_core::RunId::from_bytes(bytes).map_err(|_| Error::Corrupt("run_id"))?,
            ),
            None => None,
        },
        earlier_open,
        gone,
    })
}

/// Close a merge group: cancel the run it produced, settle every delivery of it
/// still waiting and settle this one, all in the caller's transaction, so a group
/// cannot be cancelled and dispatched at the same time. Returns the reason this
/// delivery settled with — `merge_group_destroyed` when a run had to be cancelled,
/// `merge_group_merged` when the group went away before anything ran.
pub fn destroy_merge_group(
    tx: &Transaction<'_>,
    delivery: &Delivery,
    head_ref: &str,
    base_sha: &str,
    now: UnixMillis,
) -> Result<&'static str> {
    let state = merge_group_state(tx, delivery, head_ref, base_sha)?;
    if let Some(run) = state.run {
        crate::dispatch::cancel_run(tx, delivery.tenant, run, now)?;
    }
    let mut stmt = tx.prepare_cached(
        "SELECT d.id FROM webhook_deliveries d
         JOIN merge_deliveries m ON m.delivery_id = d.id
         WHERE d.tenant_id = ?1 AND d.repo_id = ?2 AND m.head_ref = ?3 AND m.base_sha = ?4
           AND d.state IN (0, 1) AND d.id <> ?5
         ORDER BY d.received_ms, d.id LIMIT 64",
    )?;
    let open = stmt
        .query_map(
            params![
                delivery.tenant.as_bytes(),
                delivery.repo.as_bytes(),
                head_ref,
                base_sha,
                delivery.id.as_bytes()
            ],
            |r| r.get::<_, [u8; 16]>(0),
        )?
        .collect::<std::result::Result<Vec<_>, _>>()?;
    drop(stmt);
    for bytes in open {
        let open = DeliveryId::from_bytes(bytes).map_err(|_| Error::Corrupt("delivery id"))?;
        match settle(tx, open, Resolution::Ignored("merge_group_merged"), now) {
            Ok(()) | Err(Error::Conflict) => {}
            Err(e) => return Err(e),
        }
    }
    let reason = if state.run.is_some() {
        "merge_group_destroyed"
    } else {
        "merge_group_merged"
    };
    settle(tx, delivery.id, Resolution::Ignored(reason), now)?;
    Ok(reason)
}

fn find(
    conn: &Connection,
    tenant: TenantId,
    repo: RepoId,
    provider: &str,
    external_id: &str,
) -> Result<Option<Delivery>> {
    let row = conn
        .prepare_cached(
            "SELECT id FROM webhook_deliveries
             WHERE tenant_id = ?1 AND repo_id = ?2 AND provider = ?3 AND external_id = ?4",
        )?
        .query_row(
            params![tenant.as_bytes(), repo.as_bytes(), provider, external_id],
            |r| r.get::<_, [u8; 16]>(0),
        )
        .optional()?;
    match row {
        Some(bytes) => {
            let id = DeliveryId::from_bytes(bytes).map_err(|_| Error::Corrupt("delivery id"))?;
            get(conn, id).map(Some)
        }
        None => Ok(None),
    }
}

pub fn authenticate(conn: &Connection, presented: &Secret) -> Result<Option<(TenantId, RepoId)>> {
    let row = conn
        .prepare_cached(
            "SELECT t.tenant_id, t.repo_id FROM source_intake_tokens t
             JOIN tenants n ON n.id = t.tenant_id AND n.active = 1
             WHERE t.token_digest = ?1",
        )?
        .query_row([presented.digest().0], |r| {
            Ok((r.get::<_, [u8; 16]>(0)?, r.get::<_, [u8; 16]>(1)?))
        })
        .optional()?;
    let Some((tenant, repo)) = row else {
        return Ok(None);
    };
    Ok(Some((
        TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?,
        RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))?,
    )))
}

pub fn hook_token_text(secret: &Secret) -> String {
    let mut text = String::with_capacity(
        sentinel_protocol::intake::HOOK_TOKEN_PREFIX.len() + Secret::TEXT_LEN,
    );
    text.push_str(sentinel_protocol::intake::HOOK_TOKEN_PREFIX);
    secret.expose(&mut text);
    text
}

pub fn hook_token_parse(text: &str) -> Option<Secret> {
    Secret::parse(text.strip_prefix(sentinel_protocol::intake::HOOK_TOKEN_PREFIX)?)
}

pub fn issue_token(
    tx: &Transaction<'_>,
    authority: Authority,
    repo: RepoId,
    now: UnixMillis,
) -> Result<Secret> {
    let tenant = tenant_admin_of(tx, authority, repo)?;
    if sources::load_metadata(tx, repo)?.revoked {
        return Err(Error::NotFound);
    }
    let secret = Secret::generate();
    tx.execute(
        "DELETE FROM source_intake_tokens WHERE repo_id = ?1",
        [repo.as_bytes()],
    )?;
    tx.execute(
        "INSERT INTO source_intake_tokens(token_digest, repo_id, tenant_id, created_ms)
         VALUES (?1, ?2, ?3, ?4)",
        params![secret.digest().0, repo.as_bytes(), tenant.as_bytes(), now.0],
    )?;
    audit(tx, tenant, repo, authority.actor(), "hook-token", now)?;
    Ok(secret)
}

pub fn revoke_token(
    tx: &Transaction<'_>,
    authority: Authority,
    repo: RepoId,
    now: UnixMillis,
) -> Result<()> {
    let tenant = tenant_admin_of(tx, authority, repo)?;
    let removed = tx.execute(
        "DELETE FROM source_intake_tokens WHERE repo_id = ?1",
        [repo.as_bytes()],
    )?;
    if removed == 0 {
        return Err(Error::NotFound);
    }
    audit(
        tx,
        tenant,
        repo,
        authority.actor(),
        "hook-token-revoked",
        now,
    )
}

fn tenant_admin_of(tx: &Transaction<'_>, authority: Authority, repo: RepoId) -> Result<TenantId> {
    match authority.principal() {
        Some(principal) => {
            let tenant = crate::auth::require_repo(
                tx,
                principal,
                repo,
                sentinel_core::auth::Permissions::READ,
            )?;
            crate::auth::require_tenant_admin(tx, principal, tenant)?;
            Ok(tenant)
        }
        None => sources::repo_tenant(tx, repo),
    }
}

pub fn token_issued(conn: &Connection, repo: RepoId) -> Result<Option<UnixMillis>> {
    Ok(conn
        .prepare_cached("SELECT created_ms FROM source_intake_tokens WHERE repo_id = ?1")?
        .query_row([repo.as_bytes()], |r| r.get::<_, i64>(0))
        .optional()?
        .map(UnixMillis))
}

pub fn github_target(
    conn: &Connection,
    installation_external_id: &str,
    forge_repo_id: i64,
) -> Result<(TenantId, RepoId)> {
    let row = conn
        .prepare_cached(
            "SELECT b.tenant_id, b.repo_id FROM source_bindings b
             JOIN installations i ON i.id = b.installation_id
                AND i.tenant_id = b.tenant_id AND i.provider = 'github'
                AND i.external_id = ?1 AND i.suspended = 0
             JOIN tenants t ON t.id = b.tenant_id AND t.active = 1
             WHERE b.forge_repo_id = ?2 AND b.revoked = 0",
        )?
        .query_row(params![installation_external_id, forge_repo_id], |r| {
            Ok((r.get::<_, [u8; 16]>(0)?, r.get::<_, [u8; 16]>(1)?))
        })
        .optional()?;
    let Some((tenant, repo)) = row else {
        return Err(Error::NotFound);
    };
    Ok((
        TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?,
        RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))?,
    ))
}

const COLUMNS: &str = "id, tenant_id, repo_id, provider, external_id, event, ref_name, old_sha, \
    new_sha, state, reason, attempts, received_ms, settled_ms, run_id";

type Fields = (
    [u8; 16],
    [u8; 16],
    [u8; 16],
    String,
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
    i64,
    Option<String>,
    i64,
    i64,
    Option<i64>,
    Option<[u8; 16]>,
);

fn map_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Fields> {
    Ok((
        r.get(0)?,
        r.get(1)?,
        r.get(2)?,
        r.get(3)?,
        r.get(4)?,
        r.get(5)?,
        r.get(6)?,
        r.get(7)?,
        r.get(8)?,
        r.get(9)?,
        r.get(10)?,
        r.get(11)?,
        r.get(12)?,
        r.get(13)?,
        r.get(14)?,
    ))
}

fn decode(row: Fields) -> Result<Delivery> {
    let (
        id,
        tenant,
        repo,
        provider,
        external_id,
        event,
        ref_name,
        old_sha,
        new_sha,
        state,
        reason,
        attempts,
        received,
        settled,
        run,
    ) = row;
    Ok(Delivery {
        id: DeliveryId::from_bytes(id).map_err(|_| Error::Corrupt("delivery id"))?,
        tenant: TenantId::from_bytes(tenant).map_err(|_| Error::Corrupt("tenant_id"))?,
        repo: RepoId::from_bytes(repo).map_err(|_| Error::Corrupt("repo_id"))?,
        provider,
        external_id,
        event,
        ref_name,
        old_sha,
        new_sha,
        state: State::decode(state).ok_or(Error::Corrupt("delivery state"))?,
        reason,
        attempts: u32::try_from(attempts).map_err(|_| Error::Corrupt("delivery attempts"))?,
        received: UnixMillis(received),
        settled: settled.map(UnixMillis),
        run: match run {
            Some(bytes) => Some(
                sentinel_core::RunId::from_bytes(bytes).map_err(|_| Error::Corrupt("run_id"))?,
            ),
            None => None,
        },
    })
}

pub fn get(conn: &Connection, id: DeliveryId) -> Result<Delivery> {
    let row = conn
        .prepare_cached(&format!(
            "SELECT {COLUMNS} FROM webhook_deliveries WHERE id = ?1"
        ))?
        .query_row([id.as_bytes()], map_row)
        .optional()?
        .ok_or(Error::NotFound)?;
    decode(row)
}

pub fn list(
    conn: &Connection,
    tenant: TenantId,
    repo: RepoId,
    state: Option<State>,
    limit: u16,
) -> Result<Vec<Delivery>> {
    if !(1..=100).contains(&limit) {
        return Err(Error::InvalidInput("page size"));
    }
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT {COLUMNS} FROM webhook_deliveries
         WHERE tenant_id = ?1 AND repo_id = ?2 AND (?3 IS NULL OR state = ?3)
         ORDER BY received_ms DESC, id LIMIT ?4"
    ))?;
    let rows = stmt.query_map(
        params![
            tenant.as_bytes(),
            repo.as_bytes(),
            state.map(State::code),
            limit
        ],
        map_row,
    )?;
    rows.map(|row| decode(row?)).collect()
}

pub fn last_dispatched(
    conn: &Connection,
    tenant: TenantId,
    repo: RepoId,
    ref_name: &str,
    pull_request: bool,
) -> Result<Option<Delivery>> {
    let row = conn
        .prepare_cached(&format!(
            "SELECT {COLUMNS} FROM webhook_deliveries
             WHERE tenant_id = ?1 AND repo_id = ?2 AND ref_name = ?3 AND state = 4
             AND (event = 'pull_request') = ?4
             ORDER BY settled_ms DESC, id DESC LIMIT 1"
        ))?
        .query_row(
            params![
                tenant.as_bytes(),
                repo.as_bytes(),
                ref_name,
                i64::from(pull_request)
            ],
            map_row,
        )
        .optional()?;
    row.map(decode).transpose()
}

pub fn due(conn: &Connection, state: State, now: UnixMillis, limit: u16) -> Result<Vec<Delivery>> {
    if !state.is_open() {
        return Ok(Vec::new());
    }
    // The literal IN (0, 1) lets SQLite pick the partial deliveries_open index; a bound state alone does not.
    let mut stmt = conn.prepare_cached(&format!(
        "SELECT {COLUMNS} FROM webhook_deliveries
         WHERE state IN (0, 1) AND state = ?1
           AND (next_attempt_ms IS NULL OR next_attempt_ms <= ?2)
         ORDER BY received_ms, id LIMIT ?3"
    ))?;
    let rows = stmt.query_map(params![state.code(), now.0, limit], map_row)?;
    rows.map(|row| decode(row?)).collect()
}

pub fn any_due(conn: &Connection, state: State, now: UnixMillis) -> Result<bool> {
    if !state.is_open() {
        return Ok(false);
    }
    Ok(conn
        .prepare_cached(
            "SELECT EXISTS(SELECT 1 FROM webhook_deliveries
               WHERE state IN (0, 1) AND state = ?1
                 AND (next_attempt_ms IS NULL OR next_attempt_ms <= ?2))",
        )?
        .query_row(params![state.code(), now.0], |r| r.get(0))?)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Resolution {
    Ready,
    Ignored(&'static str),
    Failed(&'static str),
}

impl Resolution {
    pub fn describe(self) -> String {
        match self {
            Self::Ready => "ready".into(),
            Self::Ignored(reason) => format!("ignored:{reason}"),
            Self::Failed(reason) => format!("failed:{reason}"),
        }
    }
}

pub fn validate(conn: &Connection, delivery: &Delivery) -> Result<Resolution> {
    // Only NotFound is a verdict; any other error is a store fault and must not settle the delivery.
    match sources::repo_tenant(conn, delivery.repo) {
        Ok(_) => {}
        Err(Error::NotFound) => return Ok(Resolution::Failed("tenant_suspended")),
        Err(e) => return Err(e),
    }
    let metadata = match sources::load_metadata(conn, delivery.repo) {
        Ok(metadata) => metadata,
        Err(Error::NotFound) => return Ok(Resolution::Failed("binding_revoked")),
        Err(e) => return Err(e),
    };
    if metadata.revoked {
        return Ok(Resolution::Failed("binding_revoked"));
    }
    // A runner-mode job names its own commit and carries no ref, so no binding ref gates
    // it: what decides it is the tenant's switch and the installation's permissions, at
    // resolution, where a refusal is visible and never retried.
    if delivery.event == crate::runner::EVENT {
        return Ok(Resolution::Ready);
    }
    let (Some(ref_name), Some(new_sha)) = (&delivery.ref_name, &delivery.new_sha) else {
        return Ok(Resolution::Ignored("no_ref"));
    };
    if sentinel_protocol::intake::is_zero_sha(new_sha) {
        return Ok(Resolution::Ignored("ref_deleted"));
    }
    // A merge group's ref is GitHub's own queue branch, which names the group and
    // the base commit it was built on; no binding can list it, so the base branch it
    // targets is what the binding gates (checked before this, as for any delivery).
    if delivery.event != "merge_group" && !metadata.binding.allows(ref_name) {
        return Ok(Resolution::Failed("ref_not_allowed"));
    }
    Ok(Resolution::Ready)
}

pub fn settle(
    tx: &Transaction<'_>,
    id: DeliveryId,
    resolution: Resolution,
    now: UnixMillis,
) -> Result<()> {
    let (state, reason) = match resolution {
        Resolution::Ready => (State::Ready, None),
        Resolution::Ignored(reason) => (State::Ignored, Some(reason)),
        Resolution::Failed(reason) => (State::Failed, Some(reason)),
    };
    let changed = tx.execute(
        "UPDATE webhook_deliveries SET state = ?2, reason = ?3, settled_ms = ?4
         WHERE id = ?1 AND state IN (0, 1)",
        params![id.as_bytes(), state.code(), reason, now.0],
    )?;
    if changed != 1 {
        return Err(Error::Conflict);
    }
    if let Some(reason) = reason {
        crate::checks::record_delivery(tx, id, reason, now)?;
    }
    Ok(())
}

pub fn settle_dispatched(
    tx: &Transaction<'_>,
    id: DeliveryId,
    run: sentinel_core::RunId,
    now: UnixMillis,
) -> Result<()> {
    let changed = tx.execute(
        "UPDATE webhook_deliveries SET state = 4, reason = NULL, settled_ms = ?2, run_id = ?3
         WHERE id = ?1 AND state = 1",
        params![id.as_bytes(), now.0, run.as_bytes()],
    )?;
    if changed != 1 {
        return Err(Error::Conflict);
    }
    Ok(())
}

/// A delivery that produced a runner-mode job. GitHub orchestrates that job, so the delivery
/// dispatches no run of Sentinel's own — and `dispatched` is defined by having one, which the
/// table's check enforces — so it settles `ignored:runner_job`: nothing is owed, nothing
/// retries, and the job row is the durable record it produced.
pub fn settle_runner(tx: &Transaction<'_>, id: DeliveryId, now: UnixMillis) -> Result<()> {
    settle(tx, id, Resolution::Ignored("runner_job"), now)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Retry {
    Scheduled { attempts: u32, next_attempt_ms: i64 },
    Exhausted,
}

pub fn retry(
    tx: &Transaction<'_>,
    id: DeliveryId,
    now: UnixMillis,
    exhausted: Resolution,
) -> Result<Retry> {
    debug_assert!(
        !matches!(exhausted, Resolution::Ready),
        "an exhausted retry must settle"
    );
    let attempts: i64 = tx
        .prepare_cached(
            "SELECT attempts FROM webhook_deliveries WHERE id = ?1 AND state IN (0, 1)",
        )?
        .query_row([id.as_bytes()], |r| r.get(0))
        .optional()?
        .ok_or(Error::Conflict)?;
    let next = u32::try_from(attempts.saturating_add(1)).unwrap_or(u32::MAX);
    if next >= MAX_ATTEMPTS {
        settle(tx, id, exhausted, now)?;
        return Ok(Retry::Exhausted);
    }
    let next_attempt_ms = now.0.saturating_add(backoff_ms(next));
    let changed = tx.execute(
        "UPDATE webhook_deliveries SET attempts = ?2, next_attempt_ms = ?3
         WHERE id = ?1 AND state IN (0, 1)",
        params![id.as_bytes(), next as i64, next_attempt_ms],
    )?;
    if changed != 1 {
        return Err(Error::Conflict);
    }
    Ok(Retry::Scheduled {
        attempts: next,
        next_attempt_ms,
    })
}

pub fn backoff_ms(attempts: u32) -> i64 {
    BASE_BACKOFF_MS
        .saturating_mul(1i64 << attempts.min(20))
        .min(MAX_BACKOFF_MS)
}

pub fn resolve_due(
    tx: &Transaction<'_>,
    now: UnixMillis,
    limit: u16,
) -> Result<Vec<(DeliveryId, Resolution)>> {
    let due = due(tx, State::Pending, now, limit)?;
    let mut settled = Vec::with_capacity(due.len());
    for delivery in due {
        tx.execute_batch("SAVEPOINT resolve_one")?;
        let attempt = validate(tx, &delivery).and_then(|resolution| {
            settle(tx, delivery.id, resolution, now)?;
            Ok(resolution)
        });
        match attempt {
            Ok(resolution) => {
                tx.execute_batch("RELEASE resolve_one")?;
                settled.push((delivery.id, resolution));
            }
            Err(Error::Sqlite(e)) if !is_row_fault(&e) => return Err(Error::Sqlite(e)),
            Err(_) => {
                tx.execute_batch("ROLLBACK TO resolve_one; RELEASE resolve_one")?;
                let exhausted = Resolution::Failed("resolution_attempts");
                if retry(tx, delivery.id, now, exhausted)? == Retry::Exhausted {
                    settled.push((delivery.id, exhausted));
                }
            }
        }
    }
    Ok(settled)
}

fn is_row_fault(error: &rusqlite::Error) -> bool {
    match error {
        rusqlite::Error::SqliteFailure(failure, _) => matches!(
            failure.code,
            rusqlite::ErrorCode::ConstraintViolation | rusqlite::ErrorCode::TypeMismatch
        ),
        _ => true,
    }
}

pub fn dispatch(
    tx: &Transaction<'_>,
    delivery: &Delivery,
    spec: &sentinel_pipeline::RunSpec,
    images: &[(String, String)],
    provenance: &crate::provenance::Provenance,
    now: UnixMillis,
) -> Result<sentinel_core::RunId> {
    if delivery.state != State::Ready {
        return Err(Error::Conflict);
    }
    if images.len() != spec.pipeline.jobs.len() {
        return Err(Error::InvalidInput("resolved images"));
    }
    let run = sentinel_core::RunId::new();
    let jobs = crate::runs::create_run(tx, delivery.tenant, delivery.repo, run, spec, now)?;
    for (job, (digest, platform)) in jobs.iter().zip(images) {
        crate::runs::resolve_image(tx, delivery.tenant, *job, digest, platform)?;
    }
    crate::provenance::insert(tx, provenance, run, now)?;
    crate::runs::apply_concurrency(tx, delivery.tenant, run, now)?;
    crate::dispatch::release_dependents(tx, delivery.tenant, run, now)?;
    crate::checks::record_run(tx, delivery.tenant, run, now)?;
    settle_dispatched(tx, delivery.id, run, now)?;
    Ok(run)
}

pub fn purge_settled(tx: &Transaction<'_>, before: UnixMillis, limit: u32) -> Result<usize> {
    Ok(tx.execute(
        "DELETE FROM webhook_deliveries WHERE id IN (
            SELECT id FROM webhook_deliveries
             WHERE state NOT IN (0, 1) AND run_id IS NULL AND settled_ms <= ?1
               AND NOT EXISTS (SELECT 1 FROM check_publications p
                               WHERE p.delivery_id = webhook_deliveries.id)
            ORDER BY settled_ms LIMIT ?2)",
        params![before.0, limit],
    )?)
}

pub(crate) fn audit(
    tx: &Transaction<'_>,
    tenant: TenantId,
    repo: RepoId,
    actor: Option<UserId>,
    action: &str,
    now: UnixMillis,
) -> Result<()> {
    let version = sources::load_metadata(tx, repo)
        .map(|m| m.version)
        .unwrap_or(1) as i64;
    tx.execute(
        "INSERT INTO source_audit(tenant_id, repo_id, version, actor, action, at_ms)
         VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![
            tenant.as_bytes(),
            repo.as_bytes(),
            version,
            actor.map(|a| *a.as_bytes()),
            action,
            now.0
        ],
    )?;
    Ok(())
}
