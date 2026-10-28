//! One-click GitHub App setup: GitHub's manifest flow, the App put in force without a restart,
//! and installations bound to tenants ([GitHub App](../../../docs/github-app.md)).
//!
//! The browser returns from GitHub to sentinel-web pages, which call these routes same-origin
//! with the session cookie and the CSRF header. Only the controller talks to GitHub; no response,
//! error or audit row ever carries the App's private key, client secret or webhook secret.

use std::{
    fmt,
    sync::{Arc, OnceLock},
};

use sentinel_auth::secret::Secret;
use sentinel_core::{SessionId, TenantId, UnixMillis, UserId};
use sentinel_github::{
    app::{Answer, App, Current, Described, OrgRole},
    http::Client,
    manifest::{self, Owner, Unreachable},
    oauth::Endpoints,
};
use sentinel_protocol::error::{ApiError, ErrorCode};
use sentinel_store::{
    Error as StoreError, auth as authz,
    github_app::{self as stored, Purpose, Refusal},
};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    Outbound, State,
    auth::{Identity, Via},
    http::Request,
    routes::{Route, body_limit, err, identify, ok, parse, store_error},
};

const MAX_BODY_BYTES: usize = 4 << 10;
/// One answer for every refused state, so a caller never learns which case applied.
const STATE_REFUSED: &str = "this GitHub setup link is not valid any more (used, expired or started elsewhere); start again";

/// Where the App in force came from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AppSource {
    /// `github-app.json`, `github-webhook.json` or `github-sign-in.json` in the data directory.
    Files,
    /// The manifest flow, stored sealed in the database.
    Manifest,
}

impl AppSource {
    const fn as_str(self) -> &'static str {
        match self {
            AppSource::Files => "files",
            AppSource::Manifest => "manifest",
        }
    }
}

/// What a completed conversion hands the controller's other components.
pub struct Activation {
    pub app: Arc<App>,
    pub app_id: u64,
    pub slug: String,
}

pub type OnActivate = Arc<dyn Fn(&Activation) + Send + Sync>;

/// The API's part of the GitHub App configuration.
#[derive(Clone)]
pub struct GithubAppSetup {
    /// GitHub's web origin (`https://github.com`) and REST API base (`https://api.github.com`).
    pub web_url: String,
    pub api_url: String,
    /// Where sign-in through the App's OAuth client goes.
    pub sign_in_endpoints: Endpoints,
    /// The App in force, shared with the controller's other components.
    pub current: Current,
    /// Where the App in force at start came from; `Files` also when only some files exist.
    pub source: Option<AppSource>,
    /// Called once, after the API's own holders are set, when a conversion puts an App in force.
    pub on_activate: Option<OnActivate>,
}

impl Default for GithubAppSetup {
    fn default() -> Self {
        GithubAppSetup {
            web_url: "https://github.com".into(),
            api_url: "https://api.github.com".into(),
            sign_in_endpoints: Endpoints::github(),
            current: Current::default(),
            source: None,
            on_activate: None,
        }
    }
}

impl fmt::Debug for GithubAppSetup {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GithubAppSetup")
            .field("web_url", &self.web_url)
            .field("api_url", &self.api_url)
            .field("configured", &self.current.get().is_some())
            .field("source", &self.source)
            .finish_non_exhaustive()
    }
}

pub(crate) struct Runtime {
    setup: GithubAppSetup,
    public_url: Option<String>,
    reachable: Result<(), Unreachable>,
    source: OnceLock<AppSource>,
    described: OnceLock<Described>,
    http: Client,
    calls: Outbound,
}

impl Runtime {
    pub(crate) fn new(setup: GithubAppSetup, public_url: Option<&str>) -> Runtime {
        let source = setup.source.map(OnceLock::from).unwrap_or_default();
        Runtime {
            reachable: manifest::reachability(public_url),
            public_url: public_url.map(str::to_owned),
            setup,
            source,
            described: OnceLock::new(),
            http: Client::new(),
            calls: Outbound::default(),
        }
    }

    fn webhook_url(&self) -> Option<String> {
        self.public_url
            .as_deref()
            .map(|url| format!("{url}{}", manifest::WEBHOOK_PATH))
    }

    /// Why a new App cannot be created now, if it cannot.
    fn create_refusal(&self, state: &State) -> Result<Option<&'static str>, ApiError> {
        if self.source.get() == Some(&AppSource::Files) {
            return Ok(Some("files"));
        }
        if self.setup.current.get().is_some()
            || state
                .store
                .read(stored::facts)
                .map_err(store_error)?
                .is_some()
        {
            return Ok(Some("configured"));
        }
        Ok(match self.public_url.as_deref() {
            None => Some("no_public_url"),
            Some(url) if !manifest::is_origin(url) => Some("public_url_has_path"),
            Some(_) if state.secret_key.is_none() => Some("no_master_key"),
            Some(_) => None,
        })
    }

    /// The App's public facts: from the store for a manifest App, from GitHub (once, then
    /// cached) for a file-configured one when `fetch` allows an outbound call.
    fn described(&self, state: &State, fetch: bool) -> Result<Option<Described>, ApiError> {
        if let Some(found) = self.described.get() {
            return Ok(Some(found.clone()));
        }
        if let Some(facts) = state.store.read(stored::facts).map_err(store_error)? {
            let found = Described {
                id: facts.app_id,
                slug: facts.slug,
                name: facts.name,
                html_url: facts.html_url,
                owner: facts.owner,
            };
            let _ = self.described.set(found.clone());
            return Ok(Some(found));
        }
        let Some(app) = self.setup.current.get() else {
            return Ok(None);
        };
        if !fetch {
            return Ok(None);
        }
        let _slot = self.calls.take().ok_or_else(busy)?;
        let found = app.describe(UnixMillis::now().0).map_err(|_| {
            err(
                ErrorCode::UpstreamFailed,
                "GitHub did not describe the configured App; retry shortly",
            )
        })?;
        let _ = self.described.set(found.clone());
        Ok(Some(found))
    }
}

fn busy() -> ApiError {
    err(
        ErrorCode::RateLimited,
        "another GitHub request is in flight; retry shortly",
    )
    .with_detail("retry_after_ms", 2000)
}

fn app_json(app: &Described) -> Value {
    json!({
        "id": app.id,
        "slug": app.slug,
        "name": app.name,
        "html_url": app.html_url,
        "owner": app.owner,
    })
}

pub(crate) fn route(
    state: &State,
    request: &mut Request,
    method: &str,
    parts: &[&str],
) -> Option<Route> {
    Some(match (method, parts) {
        ("GET", ["api", "v1", "github", "app"]) => view(state, request),
        ("POST", ["api", "v1", "github", "app", "manifest"]) => create_manifest(state, request),
        ("POST", ["api", "v1", "github", "app", "conversion"]) => convert(state, request),
        ("POST", ["api", "v1", "github", "app", "installation"]) => install(state, request),
        ("POST", ["api", "v1", "tenants", slug, "github", "installation-url"]) => {
            installation_url(state, request, slug)
        }
        _ => return None,
    })
}

fn is_platform(state: &State, who: &Identity) -> Result<bool, ApiError> {
    if !who.super_admin {
        return Ok(false);
    }
    let authority = who.authority();
    match state.store.read(move |c| authority.require_platform(c)) {
        Ok(()) => Ok(true),
        Err(StoreError::Forbidden) => Ok(false),
        Err(other) => Err(store_error(other)),
    }
}

/// Everyone signed in sees whether an App is configured and its public facts; only a platform
/// administrator also sees the public URL, the webhook URL and whether a new App may be made.
fn view(state: &State, request: &mut Request) -> Route {
    let who = identify(state, request, false)?;
    let runtime = &state.github_app;
    let platform = is_platform(state, &who)?;
    let configured = runtime.setup.current.get().is_some();
    let described = runtime.described(state, false)?;
    let source = runtime.source.get().copied().or(if described.is_some() {
        Some(AppSource::Manifest)
    } else {
        None
    });
    let app = match (&described, runtime.setup.current.get()) {
        (Some(found), _) => app_json(found),
        (None, Some(app)) => json!({
            "id": app.id(), "slug": null, "name": null, "html_url": null, "owner": null,
        }),
        (None, None) => Value::Null,
    };
    let install_url = described
        .as_ref()
        .map(|found| manifest::install_url(&runtime.setup.web_url, &found.slug, None));
    let refusal = if platform {
        runtime.create_refusal(state)?
    } else {
        Some("forbidden")
    };
    ok(json!({
        "configured": configured,
        "source": source.map(AppSource::as_str),
        "app": app,
        "public_url": if platform { json!(runtime.public_url) } else { Value::Null },
        "webhook_url": if platform { json!(runtime.webhook_url()) } else { Value::Null },
        "webhook_reachable": runtime.reachable.is_ok(),
        "reason": runtime.reachable.err().map(Unreachable::as_str),
        "can_create": refusal.is_none(),
        "create_refusal": if platform { json!(refusal) } else { Value::Null },
        "install_url": install_url,
    }))
}

/// A browser session's identity and the session it is: the states are bound to both.
fn session_identity(state: &State, request: &Request) -> Result<(Identity, SessionId), ApiError> {
    let who = identify(state, request, true)?;
    if who.via != Via::Session {
        return Err(err(
            ErrorCode::InvalidRequest,
            "only a browser session does this",
        ));
    }
    let session = who
        .authority()
        .created_session()
        .ok_or_else(|| err(ErrorCode::Unauthenticated, "sign in again"))?;
    Ok((who, session))
}

fn require_platform(state: &State, who: &Identity) -> Result<(), ApiError> {
    if is_platform(state, who)? {
        Ok(())
    } else {
        Err(err(
            ErrorCode::Forbidden,
            "only a platform administrator configures the GitHub App",
        ))
    }
}

fn refused_to_create(reason: &'static str) -> ApiError {
    let message = match reason {
        "files" => {
            "this deployment's GitHub App is configured by files in the data directory; remove them to use one-click setup"
        }
        "configured" => "a GitHub App is already configured",
        "no_public_url" => "set the controller's public_url first: GitHub returns to it",
        "public_url_has_path" => {
            "one-click setup needs the web interface at the root of public_url, without a path"
        }
        _ => {
            "create master.key (sentinel admin key create) first: the App's credentials are sealed with it"
        }
    };
    err(ErrorCode::Conflict, message).with_detail("reason", reason)
}

#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
enum OwnerBody {
    User,
    Organization { login: String },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestBody {
    owner: OwnerBody,
    #[serde(default)]
    public: bool,
}

fn state_text(secret: &Secret) -> String {
    let mut text = String::with_capacity(Secret::TEXT_LEN);
    secret.expose(&mut text);
    text
}

fn random_suffix() -> String {
    let secret = Secret::generate();
    state_text(&secret)[..6].to_owned()
}

fn create_manifest(state: &State, request: &mut Request) -> Route {
    let (who, session) = session_identity(state, request)?;
    require_platform(state, &who)?;
    let runtime = &state.github_app;
    if let Some(reason) = runtime.create_refusal(state)? {
        return Err(refused_to_create(reason));
    }
    let body: ManifestBody = parse(&body_limit(request, MAX_BODY_BYTES)?)?;
    let owner = match &body.owner {
        OwnerBody::User => Owner::User,
        OwnerBody::Organization { login } => Owner::Organization(login),
    };
    if !owner.valid() {
        return Err(err(
            ErrorCode::InvalidRequest,
            "owner.login must be a GitHub organization login",
        ));
    }
    let public_url = runtime.public_url.as_deref().unwrap_or_default();
    let (authority, user, now) = (who.authority(), who.user, UnixMillis::now());
    let (secret, expires, instance) = state
        .store
        .writer()
        .write(move |tx| {
            authority.require_privileged(tx)?;
            let (secret, expires) = stored::mint(tx, Purpose::Manifest, user, session, None, now)?;
            let instance = sentinel_store::setup::instance(tx)?.map(|(name, _)| name);
            Ok((secret, expires, instance))
        })
        .map_err(store_error)?;
    let state_value = state_text(&secret);
    let name = manifest::name_for(instance.as_deref(), &random_suffix());
    let text = manifest::manifest(&manifest::Request {
        name: &name,
        public_url,
        hook_active: runtime.reachable.is_ok(),
        public: body.public,
    });
    ok(json!({
        "action_url": manifest::action_url(&runtime.setup.web_url, &owner, &state_value),
        "manifest": text,
        "state": state_value,
        "expires_ms": expires.0,
    }))
}

/// Spends a state in its own transaction; a refusal is audited there and answered uniformly.
fn spend(
    state: &State,
    purpose: Purpose,
    text: &str,
    user: UserId,
    session: SessionId,
) -> Result<Option<TenantId>, ApiError> {
    let presented = Secret::parse(text.trim());
    let now = UnixMillis::now();
    let outcome = state
        .store
        .writer()
        .write(move |tx| {
            let outcome = match &presented {
                Some(secret) => stored::spend(tx, purpose, secret, user, session, now)?,
                None => Err(Refusal::Unknown),
            };
            if let Err(refusal) = outcome {
                stored::audit_refusal(tx, purpose, refusal, user, now)?;
            }
            Ok(outcome)
        })
        .map_err(store_error)?;
    outcome
        .map(|spent| spent.tenant)
        .map_err(|_| err(ErrorCode::NotFound, STATE_REFUSED))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConversionBody {
    code: String,
    state: String,
    /// Optional: mint the installation link for this tenant in the same answer.
    #[serde(default)]
    tenant: Option<String>,
    #[serde(default)]
    reason: Option<String>,
}

fn upstream(message: &'static str) -> ApiError {
    err(ErrorCode::UpstreamFailed, message)
}

fn convert(state: &State, request: &mut Request) -> Route {
    let (who, session) = session_identity(state, request)?;
    require_platform(state, &who)?;
    let body: ConversionBody = parse(&body_limit(request, MAX_BODY_BYTES)?)?;
    if !manifest::valid_code(&body.code) {
        return Err(err(ErrorCode::InvalidRequest, "malformed code"));
    }
    let runtime = &state.github_app;
    if let Some(reason) = runtime.create_refusal(state)? {
        return Err(refused_to_create(reason));
    }
    let key = state
        .secret_key
        .clone()
        .ok_or_else(|| refused_to_create("no_master_key"))?;
    // Taken before the state is spent, so a busy answer never burns it.
    let _slot = runtime.calls.take().ok_or_else(busy)?;
    spend(state, Purpose::Manifest, &body.state, who.user, session)?;
    let converted = manifest::convert(&runtime.http, &runtime.setup.api_url, &body.code)
        .map_err(|_| {
            upstream(
                "GitHub did not complete the App registration; if GitHub created the App, delete it in its settings and start again",
            )
        })?;
    let app = App::new(converted.id, &converted.pem)
        .and_then(|app| app.with_endpoint(&runtime.setup.api_url))
        .map_err(|_| {
            upstream(
                "GitHub returned a private key Sentinel cannot use; delete the new App on GitHub and start again",
            )
        })?;
    let (user, now) = (who.user, UnixMillis::now());
    let sealed = stored::seal(
        &key,
        converted.id,
        &converted.pem,
        &converted.client_secret,
        converted.webhook_secret.as_deref(),
    );
    let public = stored::Public {
        app_id: converted.id,
        slug: converted.slug.clone(),
        name: converted.name.clone(),
        owner: converted.owner.clone(),
        owner_id: converted.owner_id,
        html_url: converted.html_url.clone(),
        client_id: converted.client_id.clone(),
    };
    let stored_app = state
        .store
        .writer()
        .write(move |tx| stored::store(tx, &public, &sealed, user, now));
    stored_app.map_err(|error| match error {
        StoreError::Conflict => err(
            ErrorCode::Conflict,
            "a GitHub App was configured meanwhile; delete the App just created on GitHub",
        )
        .with_detail("reason", "configured"),
        other => store_error(other),
    })?;
    let described = Described {
        id: converted.id,
        slug: converted.slug.clone(),
        name: converted.name.clone(),
        html_url: converted.html_url.clone(),
        owner: converted.owner.clone(),
    };
    activate(state, &converted, Arc::new(app), &described);
    let install = match body.tenant.as_deref() {
        Some(slug) => mint_install(state, &who, session, slug, body.reason.as_deref())?.0,
        None => manifest::install_url(&runtime.setup.web_url, &described.slug, None),
    };
    ok(json!({ "app": app_json(&described), "install_url": install }))
}

/// Puts a converted App in force in this process: the shared holder (installation tokens,
/// checks, intake, membership), the webhook secret and sign-in through the App's OAuth client.
fn activate(state: &State, converted: &manifest::Converted, app: Arc<App>, described: &Described) {
    let runtime = &state.github_app;
    runtime.setup.current.set(Arc::clone(&app));
    if let Some(secret) = &converted.webhook_secret {
        let _ = state
            .github_webhook_secret
            .set(Arc::from(secret.as_bytes()));
    }
    if state.github.get().is_none()
        && let Ok(github) = crate::github::Github::new(
            crate::GithubSignIn {
                client_id: converted.client_id.clone(),
                client_secret: converted.client_secret.clone(),
                endpoints: runtime.setup.sign_in_endpoints.clone(),
            },
            &state.oauth.issuer,
        )
    {
        let _ = state.github.set(github);
    }
    let _ = runtime.described.set(described.clone());
    let _ = runtime.source.set(AppSource::Manifest);
    if let Some(on_activate) = &runtime.setup.on_activate {
        on_activate(&Activation {
            app,
            app_id: described.id,
            slug: described.slug.clone(),
        });
    }
}

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
struct InstallationUrlBody {
    #[serde(default)]
    reason: Option<String>,
}

/// Mints an installation state for `slug`: that tenant's administrator, or a platform
/// administrator acting under the platform-override rule (fresh step-up and a reason).
fn mint_install(
    state: &State,
    who: &Identity,
    session: SessionId,
    slug: &str,
    reason: Option<&str>,
) -> Result<(String, UnixMillis), ApiError> {
    let runtime = &state.github_app;
    if runtime.setup.current.get().is_none() {
        return Err(err(ErrorCode::Conflict, "no GitHub App is configured")
            .with_detail("reason", "not_configured"));
    }
    let described = runtime
        .described(state, true)?
        .ok_or_else(|| upstream("the configured App's slug is unknown"))?;
    let (authority, principal, user, now) =
        (who.authority(), who.principal, who.user, UnixMillis::now());
    let (slug, reason) = (slug.to_owned(), reason.map(str::to_owned));
    let (secret, expires) = state
        .store
        .writer()
        .write(move |tx| {
            let tenant = authz::member_tenant_by_slug(tx, principal, &slug)?;
            authority.require_tenant_access_change(tx, tenant, false, reason.as_deref())?;
            stored::mint(tx, Purpose::Install, user, session, Some(tenant), now)
        })
        .map_err(|error| match error {
            StoreError::InvalidInput("reason") => err(
                ErrorCode::InvalidRequest,
                "a platform administrator acting in a tenant they do not administer gives a reason",
            ),
            other => store_error(other),
        })?;
    let text = state_text(&secret);
    Ok((
        manifest::install_url(&runtime.setup.web_url, &described.slug, Some(&text)),
        expires,
    ))
}

fn installation_url(state: &State, request: &mut Request, slug: &str) -> Route {
    let (who, session) = session_identity(state, request)?;
    let bytes = body_limit(request, MAX_BODY_BYTES)?;
    let body: InstallationUrlBody = if bytes.iter().all(u8::is_ascii_whitespace) {
        InstallationUrlBody::default()
    } else {
        parse(&bytes)?
    };
    let (url, expires) = mint_install(state, &who, session, slug, body.reason.as_deref())?;
    ok(json!({ "install_url": url, "expires_ms": expires.0 }))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct InstallationBody {
    installation_id: u64,
    state: String,
    setup_action: String,
}

fn forbidden(message: &'static str, reason: &'static str) -> ApiError {
    err(ErrorCode::Forbidden, message).with_detail("reason", reason)
}

/// GitHub's redirect names an installation, but anyone can type that URL: the installation is
/// believed only after the App itself reads it, and bound only for a person GitHub shows to be
/// that account, or an owner of that organization (a platform administrator excepted).
fn install(state: &State, request: &mut Request) -> Route {
    let (who, session) = session_identity(state, request)?;
    let body: InstallationBody = parse(&body_limit(request, MAX_BODY_BYTES)?)?;
    if !matches!(body.setup_action.as_str(), "install" | "update") {
        return Err(err(
            ErrorCode::InvalidRequest,
            "setup_action must be install or update; an installation GitHub holds for an owner's approval is bound once approved",
        ));
    }
    if body.installation_id == 0 || body.installation_id > i64::MAX as u64 {
        return Err(err(ErrorCode::InvalidRequest, "malformed installation_id"));
    }
    let runtime = &state.github_app;
    let app = runtime.setup.current.get().cloned().ok_or_else(|| {
        err(ErrorCode::Conflict, "no GitHub App is configured")
            .with_detail("reason", "not_configured")
    })?;
    let _slot = runtime.calls.take().ok_or_else(busy)?;
    let tenant = spend(state, Purpose::Install, &body.state, who.user, session)?
        .ok_or_else(|| err(ErrorCode::NotFound, STATE_REFUSED))?;
    let now = UnixMillis::now();
    let installed = match app.installation_status(body.installation_id, now.0) {
        Ok(Some(installed)) => installed,
        Ok(None) => {
            return Err(forbidden(
                "that installation does not belong to this GitHub App",
                "foreign_installation",
            ));
        }
        Err(_) => {
            return Err(upstream(
                "GitHub did not confirm the installation; start again",
            ));
        }
    };
    if !is_platform(state, &who)? {
        prove_account(state, &app, &installed, who.user, now)?;
    }
    let (principal, observed) = (
        who.principal,
        (
            installed.id,
            installed.account_id,
            installed.login.clone(),
            installed.personal,
            installed.suspended,
            installed.permissions_valid,
        ),
    );
    let slug = state
        .store
        .writer()
        .write(move |tx| {
            stored::bind(
                tx,
                principal,
                tenant,
                &stored::Observed {
                    external_id: observed.0,
                    account_id: observed.1,
                    login: &observed.2,
                    personal: observed.3,
                    suspended: observed.4,
                    permissions_valid: observed.5,
                },
                now,
            )?;
            Ok(tx.query_row(
                "SELECT slug FROM tenants WHERE id = ?1",
                [tenant.as_bytes()],
                |r| r.get::<_, String>(0),
            )?)
        })
        .map_err(|error| match error {
            StoreError::Conflict => err(
                ErrorCode::Conflict,
                "that installation is bound to another organization; unbind it there first",
            )
            .with_detail("reason", "bound_elsewhere"),
            StoreError::Forbidden => forbidden(
                "this installation cannot be bound to that tenant: an organization's installation belongs to an organization tenant administered by you",
                "tenant_mismatch",
            ),
            other => store_error(other),
        })?;
    ok(json!({ "tenant": slug, "account": installed.login }))
}

/// The person binding must be the installation's account, or an owner of its organization,
/// by the immutable numeric id of their linked GitHub identity.
fn prove_account(
    state: &State,
    app: &App,
    installed: &sentinel_github::app::Installation,
    user: UserId,
    now: UnixMillis,
) -> Result<(), ApiError> {
    let linked = state
        .store
        .read(|c| stored::linked_github_id(c, user))
        .map_err(store_error)?
        .ok_or_else(|| {
            forbidden(
                "link your GitHub account to Sentinel first: binding proves you control the installation's account",
                "link_github",
            )
        })?;
    if installed.personal {
        return if installed.account_id == linked {
            Ok(())
        } else {
            Err(forbidden(
                "that installation belongs to another GitHub account",
                "cross_account",
            ))
        };
    }
    let token = app.membership_token(installed, now.0).map_err(|_| {
        upstream("GitHub refused a membership token; the App needs the organization permission Members: read")
    })?;
    let login = match app.user_login(&token, linked) {
        Answer::Known(login) => login,
        Answer::Absent => {
            return Err(forbidden(
                "your linked GitHub account no longer exists",
                "cross_account",
            ));
        }
        Answer::Unknown { .. } => return Err(upstream("GitHub did not answer; retry shortly")),
    };
    match app.org_membership(
        &token,
        &installed.login,
        installed.account_id,
        linked,
        &login,
    ) {
        Answer::Known(OrgRole::Owner) => Ok(()),
        Answer::Known(OrgRole::Member) | Answer::Absent => Err(forbidden(
            "only an owner of that GitHub organization binds its installation",
            "not_org_owner",
        )),
        Answer::Unknown { .. } => Err(upstream("GitHub did not answer; retry shortly")),
    }
}
