//! Bounded OAuth client registration and Client ID Metadata Document support.
//!
//! Registered OAuth clients are not Sentinel users. Remote MCP registrations
//! are public clients, limited to MCP scopes and exact redirect URIs.

use std::{
    borrow::Cow,
    collections::{HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Mutex, OnceLock},
    time::{Duration, Instant},
};

use sentinel_auth::{oauth as forms, secret::Secret};
use sentinel_core::{
    UnixMillis,
    auth::{Audience, Scopes},
};
use sentinel_protocol::oauth::{
    GRANT_AUTHORIZATION_CODE, GRANT_DEVICE_CODE, GRANT_REFRESH_TOKEN, OAuthErrorCode,
};
use sentinel_store::oauth::{
    self as grants, McpClientSpec, McpRegistrationError, McpRegistrationKind,
};
use serde::Deserialize;
use serde_json::json;
use ureq::unversioned::{
    resolver::{DefaultResolver, ResolvedSocketAddrs, Resolver},
    transport::{DefaultConnector, NextTimeout},
};
use url::{Host, Url};

use super::{Budget, admit, error, error_status, no_cache};
use crate::{
    State,
    http::Request,
    routes::{self, Reply, Route},
};

const MAX_CLIENT_ID_BYTES: usize = 2048;
const MAX_METADATA_BYTES: u64 = 64 << 10;
const MAX_METADATA_HEADERS: usize = 16 << 10;
const MAX_REDIRECT_URIS: usize = 16;
const MAX_METADATA_CACHE_ENTRIES: usize = 256;
const DEFAULT_METADATA_TTL: Duration = Duration::from_secs(60);
const MAX_METADATA_TTL: Duration = Duration::from_secs(60 * 60);

#[derive(Default)]
pub(crate) struct MetadataCache {
    entries: Mutex<HashMap<String, Instant>>,
}

impl MetadataCache {
    fn is_fresh(&self, url: &str, now: Instant) -> bool {
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match entries.get(url).copied() {
            Some(expires) if expires > now => true,
            Some(_) => {
                entries.remove(url);
                false
            }
            None => false,
        }
    }

    fn insert(&self, url: String, ttl: Duration, now: Instant) {
        if ttl.is_zero() {
            return;
        }
        let expires = now + ttl.min(MAX_METADATA_TTL);
        let mut entries = self
            .entries
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        entries.retain(|_, expiry| *expiry > now);
        if entries.len() >= MAX_METADATA_CACHE_ENTRIES
            && !entries.contains_key(&url)
            && let Some(oldest) = entries
                .iter()
                .min_by_key(|(_, expiry)| **expiry)
                .map(|(url, _)| url.clone())
        {
            entries.remove(&oldest);
        }
        entries.insert(url, expires);
    }
}

/// Turn an externally presented CIMD URL into its stable, fixed-size database
/// key. Other OAuth client identifiers already have the database's 64-byte
/// bound and pass through unchanged.
pub(crate) fn internal_id(client_id: &str) -> Option<Cow<'_, str>> {
    if client_id.starts_with("https://") {
        let url = metadata_url(client_id)?;
        Some(Cow::Owned(metadata_internal_id(&url)))
    } else if !client_id.is_empty() && client_id.len() <= 64 {
        Some(Cow::Borrowed(client_id))
    } else {
        None
    }
}

fn metadata_url(value: &str) -> Option<String> {
    if value.len() > MAX_CLIENT_ID_BYTES {
        return None;
    }
    let url = Url::parse(value).ok()?;
    if url.as_str() != value
        || url.scheme() != "https"
        || url.path() == "/"
        || url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
        || url.port().is_some()
    {
        return None;
    }
    let Host::Domain(host) = url.host()? else {
        return None;
    };
    let host = host.to_ascii_lowercase();
    if host.ends_with('.')
        || !host.contains('.')
        || [
            "localhost",
            "local",
            "internal",
            "test",
            "example",
            "invalid",
            "onion",
        ]
        .contains(&host.as_str())
        || [
            ".localhost",
            ".local",
            ".internal",
            ".test",
            ".example",
            ".invalid",
            ".onion",
        ]
        .iter()
        .any(|suffix| host.ends_with(suffix))
        || host == "home.arpa"
        || host.ends_with(".home.arpa")
    {
        return None;
    }
    Some(value.to_owned())
}

fn metadata_internal_id(url: &str) -> String {
    let digest = blake3::hash(url.as_bytes());
    let mut id = String::with_capacity(64);
    id.push_str("c_");
    for byte in &digest.as_bytes()[..31] {
        use std::fmt::Write as _;
        let _ = write!(id, "{byte:02x}");
    }
    id
}

fn random_client_id() -> String {
    let random = Secret::generate();
    let mut hex = String::with_capacity(Secret::TEXT_LEN);
    random.expose(&mut hex);
    let mut id = String::with_capacity(64);
    id.push_str("m_");
    id.push_str(&hex[..62]);
    id
}

#[derive(Debug, Deserialize)]
struct ClientMetadata {
    client_id: String,
    client_name: String,
    redirect_uris: Vec<String>,
    grant_types: Option<Vec<String>>,
    response_types: Option<Vec<String>>,
    token_endpoint_auth_method: Option<String>,
    scope: Option<String>,
}

#[derive(Debug, Deserialize)]
struct RegistrationRequest {
    redirect_uris: Vec<String>,
    client_name: Option<String>,
    response_types: Option<Vec<String>>,
    grant_types: Option<Vec<String>>,
    token_endpoint_auth_method: Option<String>,
    scope: Option<String>,
    client_id: Option<String>,
    client_secret: Option<String>,
}

fn parse_scope(value: Option<&str>) -> Option<Scopes> {
    match value {
        None => Some(Scopes::MCP),
        Some(value) => Scopes::parse(value)
            .ok()
            .filter(|scopes| !scopes.is_empty() && Scopes::MCP.contains(*scopes)),
    }
}

/// What every registered client is actually given, whatever it declared
/// (RFC 7591 §3.2.1 lets the server replace requested values): the code
/// grant, and refresh tokens, which every code exchange returns.
const EFFECTIVE_GRANT_TYPES: [&str; 2] = [GRANT_AUTHORIZATION_CODE, GRANT_REFRESH_TOKEN];

/// Whether declared registration metadata describes a public
/// authorization-code client. Omitted `grant_types` is RFC 7591's default
/// (`authorization_code`). A declared list must include the code grant and
/// may name only grants this server advertises; one it will not issue to a
/// registered client (the device grant) is intersected away rather than
/// refused, because clients commonly echo `grant_types_supported`.
fn validate_protocol_fields(
    grant_types: Option<&[String]>,
    response_types: Option<&[String]>,
    token_endpoint_auth_method: Option<&str>,
) -> bool {
    let distinct = |values: &[String]| {
        !values
            .iter()
            .enumerate()
            .any(|(index, value)| values[..index].contains(value))
    };
    if token_endpoint_auth_method.is_some_and(|method| method != "none") {
        return false;
    }
    if response_types.is_some_and(|types| {
        types.is_empty() || types.iter().any(|value| value != "code") || !distinct(types)
    }) {
        return false;
    }
    grant_types.is_none_or(|types| {
        types.iter().any(|value| value == GRANT_AUTHORIZATION_CODE)
            && types.iter().all(|value| {
                matches!(
                    value.as_str(),
                    GRANT_AUTHORIZATION_CODE | GRANT_REFRESH_TOKEN | GRANT_DEVICE_CODE
                )
            })
            && distinct(types)
    })
}

/// A redirect URI a registration may declare: an HTTPS URI on a domain, or
/// an HTTP loopback URI (`127.0.0.1`, `[::1]` or `localhost`, any port;
/// RFC 8252 §7.3/§8.3) in the exact shape [`forms::loopback_redirect_key`]
/// stores and matches. No userinfo, query or fragment.
fn valid_redirect_uri(value: &str) -> bool {
    if value.is_empty() || value.len() > 512 {
        return false;
    }
    if value.starts_with("http://") {
        return forms::loopback_redirect_key(value).is_some();
    }
    let Ok(url) = Url::parse(value) else {
        return false;
    };
    if url.username() != ""
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return false;
    }
    matches!((url.scheme(), url.host()), ("https", Some(Host::Domain(_))))
}

fn valid_redirects(uris: &[String]) -> bool {
    if uris.is_empty() || uris.len() > MAX_REDIRECT_URIS {
        return false;
    }
    let mut unique = HashSet::with_capacity(uris.len());
    uris.iter()
        .all(|uri| valid_redirect_uri(uri) && unique.insert(uri))
}

#[derive(Debug, Default)]
struct PublicResolver {
    system: DefaultResolver,
}

impl Resolver for PublicResolver {
    fn resolve(
        &self,
        uri: &ureq::http::Uri,
        config: &ureq::config::Config,
        timeout: NextTimeout,
    ) -> Result<ResolvedSocketAddrs, ureq::Error> {
        let addresses = self.system.resolve(uri, config, timeout)?;
        if addresses.is_empty() || addresses.iter().any(|addr| !public_ip(addr.ip())) {
            return Err(ureq::Error::HostNotFound);
        }
        // Return the vetted socket addresses themselves. The connector does
        // not perform another DNS lookup, preventing rebinding between check
        // and connect.
        Ok(addresses)
    }
}

fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => public_ipv4(ip),
        IpAddr::V6(ip) => public_ipv6(ip),
    }
}

fn public_ipv4(ip: Ipv4Addr) -> bool {
    let [a, b, c, d] = ip.octets();
    !(ip.is_private()
        || ip.is_loopback()
        || ip.is_link_local()
        || ip.is_multicast()
        || ip.is_broadcast()
        || ip.is_unspecified()
        || a == 0
        || a >= 240
        || (a == 100 && (64..=127).contains(&b))
        || (a == 192 && b == 0 && c == 0)
        || (a == 192 && b == 0 && c == 2)
        || (a == 192 && b == 88 && c == 99)
        || (a == 198 && b == 18)
        || (a == 198 && b == 19)
        || (a == 198 && b == 51 && c == 100)
        || (a == 203 && b == 0 && c == 113)
        || (a == 255 && b == 255 && c == 255 && d == 255))
}

fn public_ipv6(ip: Ipv6Addr) -> bool {
    let [a, b, ..] = ip.segments();
    // Permit only global-unicast 2000::/3, excluding protocol assignments,
    // documentation and 6to4. This also rejects mapped IPv4 addresses.
    a & 0xe000 == 0x2000
        && !(a == 0x2001 && b < 0x0200)
        && !(a == 0x2001 && b == 0x0db8)
        && a != 0x2002
        && a != 0x3fff
        && !ip.is_unspecified()
        && !ip.is_loopback()
}

/// Whole-request bound of one metadata fetch, DNS included. A fetch holds a
/// handler permit this long at most, under the deployment's shared
/// [`crate::OUTBOUND`] budget; a request past the budget is told to retry.
const METADATA_TIMEOUT: Duration = Duration::from_secs(2);

/// The one metadata agent: its TLS configuration and root store are built
/// once, and it may reuse a connection to the same host.
fn metadata_agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| {
        let config = ureq::Agent::config_builder()
            .https_only(true)
            .proxy(None)
            .max_redirects(0)
            .max_response_header_size(MAX_METADATA_HEADERS)
            .timeout_global(Some(METADATA_TIMEOUT))
            .timeout_resolve(Some(Duration::from_secs(1)))
            .http_status_as_error(false)
            .user_agent(concat!("sentinel/", env!("CARGO_PKG_VERSION")))
            .build();
        ureq::Agent::with_parts(
            config,
            DefaultConnector::default(),
            PublicResolver::default(),
        )
    })
}

fn cache_ttl(header: Option<&str>) -> Option<Duration> {
    let Some(header) = header else {
        return Some(DEFAULT_METADATA_TTL);
    };
    let mut no_cache = false;
    let mut max_age = None;
    for directive in header.split(',').map(str::trim) {
        if directive.eq_ignore_ascii_case("no-store") {
            return None;
        }
        if directive.eq_ignore_ascii_case("no-cache") {
            no_cache = true;
        }
        if let Some((name, value)) = directive.split_once('=')
            && name.trim().eq_ignore_ascii_case("max-age")
            && let Ok(seconds) = value.trim().trim_matches('"').parse::<u64>()
        {
            let ttl = Duration::from_secs(seconds).min(MAX_METADATA_TTL);
            max_age = Some(max_age.map_or(ttl, |current: Duration| current.min(ttl)));
        }
    }
    if no_cache {
        Some(Duration::ZERO)
    } else {
        Some(max_age.unwrap_or(DEFAULT_METADATA_TTL))
    }
}

fn fetch_metadata(url: &str) -> Option<(ClientMetadata, Option<Duration>)> {
    let mut response = metadata_agent()
        .get(url)
        .header("accept", "application/json")
        .call()
        .ok()?;
    if response.status().as_u16() != 200 {
        return None;
    }
    let media_type = response
        .headers()
        .get("content-type")?
        .to_str()
        .ok()?
        .split(';')
        .next()?
        .trim();
    if !media_type.eq_ignore_ascii_case("application/json")
        || response
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok())
            .is_some_and(|length| length > MAX_METADATA_BYTES)
    {
        return None;
    }
    let cache = response
        .headers()
        .get("cache-control")
        .and_then(|v| v.to_str().ok());
    let ttl = cache_ttl(cache);
    let bytes = response
        .body_mut()
        .with_config()
        .limit(MAX_METADATA_BYTES)
        .read_to_vec()
        .ok()?;
    let metadata = serde_json::from_slice(&bytes).ok()?;
    Some((metadata, ttl))
}

fn metadata_scopes(metadata: &ClientMetadata, url: &str) -> Option<Scopes> {
    if metadata.client_id != url
        || metadata.client_name.trim().is_empty()
        || metadata.client_name.len() > 128
        || metadata.client_name.chars().any(char::is_control)
        || !valid_redirects(&metadata.redirect_uris)
        || !validate_protocol_fields(
            metadata.grant_types.as_deref(),
            metadata.response_types.as_deref(),
            metadata.token_endpoint_auth_method.as_deref(),
        )
    {
        return None;
    }
    parse_scope(metadata.scope.as_deref())
}

/// A busy page that tells the browser when to try again.
fn busy(message: &str) -> Reply {
    let mut reply = super::html::error_page(503, message);
    if let Reply::Html(_, _, headers) = &mut reply {
        headers.push(routes::header("retry-after", "2"));
    }
    reply
}

/// The registrant digest of this request's client address.
fn registrant(state: &State, request: &Request) -> [u8; 16] {
    grants::registrant_digest(super::client_of(state, request))
}

/// Resolve a normal registered id locally or fetch and validate a CIMD URL.
/// The cache only avoids repeated network reads; disabled clients and current
/// database policy are checked on every request.
///
/// Callers fetch only for a signed-in account ([`super::code`]): an
/// anonymous request never makes this server call out. A fetch also passes
/// the per-client metadata budget and takes a [`crate::OUTBOUND`] slot, so
/// however many accounts ask at once, at most that many handler permits
/// wait on third-party hosts.
pub(crate) fn resolve(
    state: &State,
    request: &Request,
    external_id: &str,
) -> Result<grants::Client, Reply> {
    if !external_id.starts_with("https://") {
        let Some(id) = internal_id(external_id) else {
            return Err(super::html::error_page(
                400,
                "The client identifier is invalid.",
            ));
        };
        let client = state
            .store
            .read(|connection| grants::client(connection, id.as_ref()))
            .map_err(|error| match error {
                sentinel_store::Error::NotFound => {
                    super::html::error_page(400, "The client is not registered.")
                }
                other => super::store_failure(other),
            })?;
        // A CIMD client is only ever addressed by its metadata URL: its
        // internal `c_…` key would skip the document's freshness check and
        // keep serving withdrawn redirects.
        if client.display_id != client.id {
            return Err(super::html::error_page(
                400,
                "The client is not registered.",
            ));
        }
        return Ok(client);
    }
    let Some(url) = metadata_url(external_id) else {
        return Err(super::html::error_page(
            400,
            "The client metadata URL is not allowed.",
        ));
    };
    let policy = state
        .store
        .read(grants::client_registration)
        .map_err(super::store_failure)?;
    if !policy.metadata() {
        return Err(super::html::error_page(
            400,
            "This deployment does not accept client metadata documents.",
        ));
    }
    let id = metadata_internal_id(&url);
    let now = Instant::now();
    if state.oauth.client_metadata.is_fresh(&url, now) {
        return state
            .store
            .read(|connection| grants::client(connection, &id))
            .map_err(|error| match error {
                sentinel_store::Error::NotFound => {
                    super::html::error_page(400, "The client metadata is no longer available.")
                }
                other => super::store_failure(other),
            });
    }
    admit(state, request, Budget::Metadata)?;
    let Some(_slot) = state.outbound.take() else {
        return Err(busy(
            "Sentinel is checking another application's details. Try again in a moment.",
        ));
    };
    let Some((metadata, ttl)) = fetch_metadata(&url) else {
        return Err(super::html::error_page(
            400,
            "The client's metadata could not be retrieved.",
        ));
    };
    let Some(max_scopes) = metadata_scopes(&metadata, &url) else {
        return Err(super::html::error_page(
            400,
            "The client's metadata is invalid or requests an unsupported redirect.",
        ));
    };
    let redirects: Vec<&str> = metadata.redirect_uris.iter().map(String::as_str).collect();
    let spec = McpClientSpec {
        id: &id,
        name: &metadata.client_name,
        max_scopes,
        kind: McpRegistrationKind::Metadata,
        metadata_url: Some(&url),
    };
    match grants::register_mcp_client_from(
        &state.store,
        &spec,
        &redirects,
        Some(registrant(state, request)),
        UnixMillis::now(),
    ) {
        Ok(()) => {}
        Err(McpRegistrationError::Capacity | McpRegistrationError::Registrant) => {
            return Err(busy(
                "This deployment cannot register another application right now.",
            ));
        }
        Err(McpRegistrationError::Store(sentinel_store::Error::NotFound)) => {
            return Err(super::html::error_page(
                400,
                "This client has been disabled.",
            ));
        }
        Err(McpRegistrationError::Store(sentinel_store::Error::InvalidInput(_))) => {
            return Err(super::html::error_page(
                400,
                "The client's metadata is invalid or requests an unsupported redirect.",
            ));
        }
        Err(McpRegistrationError::Store(error)) => return Err(super::store_failure(error)),
    }
    if let Some(ttl) = ttl {
        state.oauth.client_metadata.insert(url.clone(), ttl, now);
    }
    Ok(grants::Client {
        id,
        display_id: url,
        name: metadata.client_name,
        first_party: false,
        loopback: false,
        redirect_path: None,
        device: false,
        max_scopes,
        resource: Audience::Mcp,
        registered: true,
    })
}

fn registration_error(code: OAuthErrorCode, description: &str) -> Route {
    Ok(error(code, description))
}

/// RFC 7591 Dynamic Client Registration for public MCP clients only, while
/// the deployment's policy allows it.
pub(crate) fn register(state: &State, request: &mut Request) -> Route {
    if let Err(reply) = admit(state, request, Budget::Registration) {
        return Ok(reply);
    }
    let policy = match state.store.read(grants::client_registration) {
        Ok(policy) => policy,
        Err(e) => return Ok(super::store_failure(e)),
    };
    if !policy.dynamic() {
        return Ok(error_status(
            403,
            OAuthErrorCode::AccessDenied,
            "dynamic client registration is disabled on this deployment",
        ));
    }
    let is_json = routes::header_value(request, "content-type").is_some_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|media| media.trim().eq_ignore_ascii_case("application/json"))
    });
    if !is_json {
        return registration_error(
            OAuthErrorCode::InvalidRequest,
            "Content-Type must be application/json",
        );
    }
    let bytes = match routes::body_limit(request, 16 << 10) {
        Ok(bytes) => bytes,
        Err(error) if error.code == sentinel_protocol::error::ErrorCode::PayloadTooLarge => {
            return Ok(error_status(
                413,
                OAuthErrorCode::InvalidClientMetadata,
                "client metadata exceeds the configured limit",
            ));
        }
        Err(_) => {
            return registration_error(
                OAuthErrorCode::InvalidClientMetadata,
                "client metadata is invalid",
            );
        }
    };
    let registration: RegistrationRequest = match serde_json::from_slice(&bytes) {
        Ok(registration) => registration,
        Err(_) => {
            return registration_error(
                OAuthErrorCode::InvalidClientMetadata,
                "client metadata is invalid",
            );
        }
    };
    if registration.client_id.is_some() || registration.client_secret.is_some() {
        return registration_error(
            OAuthErrorCode::InvalidClientMetadata,
            "client_id and client_secret are assigned by Sentinel",
        );
    }
    if !valid_redirects(&registration.redirect_uris) {
        return registration_error(
            OAuthErrorCode::InvalidRedirectUri,
            "redirect_uris must contain exact HTTPS or HTTP loopback URIs",
        );
    }
    if !validate_protocol_fields(
        registration.grant_types.as_deref(),
        registration.response_types.as_deref(),
        registration.token_endpoint_auth_method.as_deref(),
    ) {
        return registration_error(
            OAuthErrorCode::InvalidClientMetadata,
            "only public authorization-code clients with PKCE are supported",
        );
    }
    let name = registration
        .client_name
        .unwrap_or_else(|| "MCP client".to_owned());
    if name.trim().is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
        return registration_error(
            OAuthErrorCode::InvalidClientMetadata,
            "client_name must be nonempty, bounded and control-free",
        );
    }
    let Some(max_scopes) = parse_scope(registration.scope.as_deref()) else {
        return registration_error(
            OAuthErrorCode::InvalidClientMetadata,
            "scope contains an unsupported MCP permission",
        );
    };
    let registered_scope = registration.scope.as_ref().map(|_| max_scopes.to_names());
    let id = random_client_id();
    let redirects: Vec<&str> = registration
        .redirect_uris
        .iter()
        .map(String::as_str)
        .collect();
    let spec = McpClientSpec {
        id: &id,
        name: &name,
        max_scopes,
        kind: McpRegistrationKind::Dynamic,
        metadata_url: None,
    };
    match grants::register_mcp_client_from(
        &state.store,
        &spec,
        &redirects,
        Some(registrant(state, request)),
        UnixMillis::now(),
    ) {
        Ok(()) => {}
        Err(McpRegistrationError::Capacity) => {
            return Ok(error(
                OAuthErrorCode::TemporarilyUnavailable,
                "MCP client registration capacity reached",
            ));
        }
        Err(McpRegistrationError::Registrant) => {
            return Ok(error_status(
                429,
                OAuthErrorCode::TemporarilyUnavailable,
                "this address holds its share of client registrations",
            ));
        }
        Err(McpRegistrationError::Store(sentinel_store::Error::InvalidInput("client_name"))) => {
            return registration_error(
                OAuthErrorCode::InvalidClientMetadata,
                "client_name is reserved for a client of this deployment",
            );
        }
        Err(McpRegistrationError::Store(
            e @ (sentinel_store::Error::WriterUnavailable
            | sentinel_store::Error::Overloaded
            | sentinel_store::Error::WriteAmbiguous),
        )) => return Ok(super::store_failure(e)),
        Err(McpRegistrationError::Store(_)) => {
            return registration_error(
                OAuthErrorCode::InvalidClientMetadata,
                "client metadata is invalid",
            );
        }
    }
    let issued_at = u64::try_from(UnixMillis::now().0.max(0) / 1000).unwrap_or(0);
    let mut response = json!({
        "client_id": id,
        "client_id_issued_at": issued_at,
        "client_name": name,
        "redirect_uris": registration.redirect_uris,
        "grant_types": EFFECTIVE_GRANT_TYPES,
        "response_types": ["code"],
        "token_endpoint_auth_method": "none",
    });
    if let Some(scope) = registered_scope {
        response["scope"] = json!(scope);
    }
    Ok(Reply::Json(201, response, no_cache()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cimd_urls_are_canonical_https_documents_on_public_hosts() {
        assert_eq!(
            metadata_url("https://client.example.org/oauth/mcp.json").as_deref(),
            Some("https://client.example.org/oauth/mcp.json")
        );
        for denied in [
            "http://client.example.org/oauth/mcp.json",
            "https://client.example",
            "https://user@client.example.org/oauth/mcp.json",
            "https://client.example.org:444/oauth/mcp.json",
            "https://client.example.org/oauth/mcp.json?x=1",
            "https://client.example.org/oauth/mcp.json#frag",
            "https://127.0.0.1/oauth/mcp.json",
            "https://client.local/oauth/mcp.json",
            "https://localhost./oauth/mcp.json",
            "https://client.local./oauth/mcp.json",
            "https://example/oauth/mcp.json",
        ] {
            assert!(metadata_url(denied).is_none(), "{denied}");
            if denied.starts_with("https://") {
                assert!(internal_id(denied).is_none(), "{denied}");
            }
        }
        let url = "https://client.example.org/oauth/mcp.json";
        assert_eq!(internal_id(url).unwrap(), metadata_internal_id(url));
        assert_eq!(metadata_internal_id(url).len(), 64);
    }

    #[test]
    fn redirects_are_exact_public_https_or_loopback_uris() {
        for accepted in [
            "http://127.0.0.1:33418",
            "http://127.0.0.1/callback",
            "http://[::1]:33418/callback",
            "http://localhost",
            "http://localhost:33418/",
            "https://vscode.dev/redirect",
            "https://claude.ai/api/mcp/auth_callback",
        ] {
            assert!(valid_redirect_uri(accepted), "{accepted}");
        }
        for denied in [
            "http://client.example/callback",
            "http://localhost.client.example/callback",
            "http://127.0.0.1:33418/callback?x=1",
            "https://user@client.example/callback",
            "https://client.example/callback?next=other",
            "https://client.example/callback#fragment",
            "file:///tmp/callback",
        ] {
            assert!(!valid_redirect_uri(denied), "{denied}");
        }
        assert!(!valid_redirects(&[
            "https://vscode.dev/redirect".to_owned(),
            "https://vscode.dev/redirect".to_owned(),
        ]));
    }

    #[test]
    fn network_filter_rejects_reserved_addresses_and_pins_public_only() {
        for ip in [
            "127.0.0.1",
            "10.1.2.3",
            "100.64.0.1",
            "192.0.2.4",
            "198.18.0.1",
            "203.0.113.2",
            "::1",
            "fc00::1",
            "fe80::1",
            "2001:db8::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(!public_ip(ip.parse().unwrap()), "{ip}");
        }
        assert!(public_ip("8.8.8.8".parse().unwrap()));
        assert!(public_ip("2001:4860:4860::8888".parse().unwrap()));
    }

    #[test]
    fn metadata_cache_directives_are_case_insensitive_and_conservative() {
        assert_eq!(cache_ttl(None), Some(DEFAULT_METADATA_TTL));
        assert_eq!(cache_ttl(Some("MAX-AGE=90")), Some(Duration::from_secs(90)));
        assert_eq!(
            cache_ttl(Some("max-age=9000, Max-Age=45")),
            Some(Duration::from_secs(45))
        );
        assert_eq!(
            cache_ttl(Some("no-cache, max-age=45")),
            Some(Duration::ZERO)
        );
        assert_eq!(cache_ttl(Some("max-age=45, NO-STORE")), None);
        assert_eq!(
            cache_ttl(Some("max-age=invalid")),
            Some(DEFAULT_METADATA_TTL)
        );
    }

    /// P11-3 / P09S-5: RFC 7591 defaults and echoed advertised grants are
    /// accepted; anything not a public code-flow client is still refused.
    #[test]
    fn registered_clients_must_declare_only_supported_grants_and_responses() {
        let owned = |values: &[&str]| values.iter().map(|v| (*v).to_owned()).collect::<Vec<_>>();
        let code = owned(&["code"]);
        let accepts = |grants: Option<&[&str]>| {
            let grants = grants.map(owned);
            validate_protocol_fields(grants.as_deref(), Some(&code), Some("none"))
        };
        assert!(accepts(None), "omitted grant_types is authorization_code");
        assert!(accepts(Some(&["authorization_code"])));
        assert!(accepts(Some(&["authorization_code", "refresh_token"])));
        assert!(accepts(Some(&[
            "authorization_code",
            "refresh_token",
            "urn:ietf:params:oauth:grant-type:device_code"
        ])));
        assert!(!accepts(Some(&["refresh_token"])));
        assert!(!accepts(Some(&[])));
        assert!(!accepts(Some(&[
            "authorization_code",
            "client_credentials"
        ])));
        assert!(!accepts(Some(&["authorization_code", "implicit"])));
        assert!(!accepts(Some(&[
            "authorization_code",
            "authorization_code"
        ])));
        assert!(validate_protocol_fields(None, None, None));
        assert!(!validate_protocol_fields(
            None,
            Some(&owned(&["token"])),
            None
        ));
        assert!(!validate_protocol_fields(
            None,
            None,
            Some("client_secret_basic")
        ));
    }

    #[test]
    fn cimd_metadata_has_an_exact_identity_and_only_mcp_scope_ceiling() {
        let valid = ClientMetadata {
            client_id: "https://client.example.org/oauth/mcp.json".into(),
            client_name: "Example MCP client".into(),
            redirect_uris: vec!["https://client.example.org/callback".into()],
            grant_types: Some(vec!["authorization_code".into(), "refresh_token".into()]),
            response_types: Some(vec!["code".into()]),
            token_endpoint_auth_method: Some("none".into()),
            scope: Some("runs:read logs:read".into()),
        };
        assert_eq!(
            metadata_scopes(&valid, &valid.client_id),
            Some(Scopes::RUNS_READ.union(Scopes::LOGS_READ))
        );
        assert!(metadata_scopes(&valid, "https://different.example/client.json").is_none());
        let mut privileged = valid;
        privileged.scope = Some("platform:admin".into());
        assert!(metadata_scopes(&privileged, &privileged.client_id).is_none());
    }

    #[test]
    fn cache_expiry_and_capacity_are_hard_bounded() {
        let cache = MetadataCache::default();
        let now = Instant::now();
        for index in 0..(MAX_METADATA_CACHE_ENTRIES + 20) {
            cache.insert(
                format!("https://client{index}.example/metadata.json"),
                Duration::from_secs(20),
                now,
            );
        }
        assert_eq!(
            cache
                .entries
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .len(),
            MAX_METADATA_CACHE_ENTRIES
        );
        cache.insert(
            "https://short.example/m.json".into(),
            Duration::from_secs(1),
            now,
        );
        assert!(cache.is_fresh("https://short.example/m.json", now));
        assert!(!cache.is_fresh("https://short.example/m.json", now + Duration::from_secs(2)));
    }
}
