//! GitHub's App manifest flow: the manifest Sentinel asks GitHub to register, and the one-time
//! conversion of the code GitHub hands back into the App's identity and credentials.
//!
//! The permissions and events are exactly what the controller uses today; a feature that needs
//! more asks for them only when a tenant turns it on.

use std::{fmt, net::IpAddr};

use serde_json::{Value, json};

use crate::{
    Error, Result,
    app::{valid_login, valid_page, valid_slug, valid_text},
    http::Client,
};

/// What each permission is for: `checks` publishes check runs, `contents` reads a repository
/// at a revision (source tokens, reconciliation), `metadata` is GitHub's mandatory baseline and
/// what the per-repository collaborator read needs, `pull_requests` is required to receive
/// `pull_request` events, and the organization permission `members` reads membership for
/// GitHub-backed organizations. Sign-in reads only the account's numeric id and asks no scope.
pub const PERMISSIONS: [(&str, &str); 5] = [
    ("checks", "write"),
    ("contents", "read"),
    ("metadata", "read"),
    ("pull_requests", "read"),
    ("members", "read"),
];

/// The events the webhook route acts on. `installation` and `installation_repositories` are
/// delivered to every App without a subscription.
pub const EVENTS: [&str; 9] = [
    "push",
    "pull_request",
    "check_run",
    "check_suite",
    "repository",
    "organization",
    "membership",
    "member",
    "team",
];

/// The controller's GitHub webhook route, relative to `public_url`.
pub const WEBHOOK_PATH: &str = "/api/v1/hooks/github";
/// The sentinel-web pages GitHub sends the browser back to.
pub const CREATED_PATH: &str = "/setup/github/created";
pub const INSTALLED_PATH: &str = "/setup/github/installed";
/// The sign-in callback the App's OAuth client must allow.
pub const CALLBACK_PATH: &str = "/auth/github/callback";

/// GitHub's limit on an App name.
pub const MAX_NAME: usize = 34;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Owner<'a> {
    User,
    Organization(&'a str),
}

impl Owner<'_> {
    pub fn valid(&self) -> bool {
        match self {
            Owner::User => true,
            Owner::Organization(login) => valid_login(login) && login.len() <= 39,
        }
    }
}

/// Why GitHub cannot deliver webhooks to the configured public URL.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unreachable {
    NoPublicUrl,
    NotHttps,
    PrivateAddress,
    TailnetOnly,
    SingleLabelHost,
}

impl Unreachable {
    pub const fn as_str(self) -> &'static str {
        match self {
            Unreachable::NoPublicUrl => "no_public_url",
            Unreachable::NotHttps => "not_https",
            Unreachable::PrivateAddress => "private_address",
            Unreachable::TailnetOnly => "tailnet_only",
            Unreachable::SingleLabelHost => "single_label_host",
        }
    }
}

/// The host of an absolute URL: no scheme, userinfo, port or path; IPv6 without brackets.
fn host_of(url: &str) -> Option<&str> {
    let rest = url.split_once("://")?.1;
    let authority = rest.split(['/', '?', '#']).next()?;
    let authority = authority.rsplit_once('@').map_or(authority, |(_, h)| h);
    if let Some(v6) = authority.strip_prefix('[') {
        return v6.split_once(']').map(|(host, _)| host);
    }
    Some(authority.split(':').next().unwrap_or(authority))
}

fn classify_ip(ip: IpAddr) -> std::result::Result<(), Unreachable> {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            if a == 100 && (64..128).contains(&b) {
                return Err(Unreachable::TailnetOnly);
            }
            if v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_unspecified()
                || v4.is_broadcast()
                || a == 0
            {
                return Err(Unreachable::PrivateAddress);
            }
            Ok(())
        }
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                return classify_ip(IpAddr::V4(v4));
            }
            let s = v6.segments();
            if s[0] == 0xfd7a && s[1] == 0x115c && s[2] == 0xa1e0 {
                return Err(Unreachable::TailnetOnly);
            }
            if v6.is_loopback()
                || v6.is_unspecified()
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xffc0) == 0xfe80
            {
                return Err(Unreachable::PrivateAddress);
            }
            Ok(())
        }
    }
}

/// Whether GitHub, on the internet, can deliver to `{public_url}/api/v1/hooks/github`. Judged
/// from the URL alone: it never resolves a name, so a public name that points at a private
/// address is not caught here (GitHub's delivery log shows that one).
pub fn reachability(public_url: Option<&str>) -> std::result::Result<(), Unreachable> {
    let url = public_url.ok_or(Unreachable::NoPublicUrl)?;
    if !url.starts_with("https://") {
        return Err(Unreachable::NotHttps);
    }
    let host = host_of(url)
        .filter(|h| !h.is_empty())
        .ok_or(Unreachable::SingleLabelHost)?;
    if let Ok(ip) = host.parse::<IpAddr>() {
        return classify_ip(ip);
    }
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    if host == "localhost"
        || [".localhost", ".local", ".internal", ".home.arpa", ".lan"]
            .iter()
            .any(|suffix| host.ends_with(suffix))
    {
        return Err(Unreachable::PrivateAddress);
    }
    if host == "ts.net" || host.ends_with(".ts.net") {
        return Err(Unreachable::TailnetOnly);
    }
    if !host.contains('.') {
        return Err(Unreachable::SingleLabelHost);
    }
    Ok(())
}

/// `public_url` with no path: the pages GitHub returns to are served at the origin's root.
pub fn is_origin(public_url: &str) -> bool {
    public_url
        .split_once("://")
        .is_some_and(|(_, rest)| !rest.contains('/'))
}

/// At most 34 characters: the instance name's letters, digits and spaces (or `Sentinel`), then a
/// short random suffix, because App names are unique across GitHub.
pub fn name_for(instance: Option<&str>, suffix: &str) -> String {
    let mut base: String = instance
        .unwrap_or_default()
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { ' ' })
        .collect::<String>()
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    if base.is_empty() {
        base.push_str("Sentinel");
    }
    let room = MAX_NAME - 1 - suffix.len().min(MAX_NAME - 2);
    base.truncate(room);
    let mut name = base.trim_end().to_owned();
    name.push(' ');
    name.push_str(&suffix[..suffix.len().min(MAX_NAME - 2)]);
    name
}

pub struct Request<'a> {
    pub name: &'a str,
    pub public_url: &'a str,
    /// Only a webhook GitHub can reach is active, and only an active one subscribes to events.
    pub hook_active: bool,
    pub public: bool,
}

/// The manifest text for the form field named `manifest`.
pub fn manifest(request: &Request<'_>) -> String {
    let base = request.public_url.trim_end_matches('/');
    let permissions: serde_json::Map<String, Value> = PERMISSIONS
        .iter()
        .map(|(k, v)| ((*k).to_owned(), Value::from(*v)))
        .collect();
    let mut value = json!({
        "name": request.name,
        "url": base,
        "description": "Sentinel CI",
        "hook_attributes": {
            "url": format!("{base}{WEBHOOK_PATH}"),
            "active": request.hook_active,
        },
        "redirect_url": format!("{base}{CREATED_PATH}"),
        "callback_urls": [format!("{base}{CALLBACK_PATH}")],
        "setup_url": format!("{base}{INSTALLED_PATH}"),
        "setup_on_update": true,
        "request_oauth_on_install": false,
        "public": request.public,
        "default_permissions": permissions,
    });
    if request.hook_active {
        value["default_events"] = json!(EVENTS);
    }
    value.to_string()
}

fn push_query_value(out: &mut String, value: &str) {
    out.extend(form_url_encode(value));
}

fn form_url_encode(value: &str) -> impl Iterator<Item = char> + '_ {
    value.bytes().flat_map(|b| {
        let mut chunk = [None, None, None];
        if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
            chunk[0] = Some(b as char);
        } else {
            const HEX: &[u8; 16] = b"0123456789ABCDEF";
            chunk[0] = Some('%');
            chunk[1] = Some(HEX[usize::from(b >> 4)] as char);
            chunk[2] = Some(HEX[usize::from(b & 15)] as char);
        }
        chunk.into_iter().flatten()
    })
}

/// Where the browser posts the manifest form: the account's or the organization's new-App page.
pub fn action_url(web: &str, owner: &Owner<'_>, state: &str) -> String {
    let web = web.trim_end_matches('/');
    let mut out = match owner {
        Owner::User => format!("{web}/settings/apps/new?state="),
        Owner::Organization(org) => format!("{web}/organizations/{org}/settings/apps/new?state="),
    };
    push_query_value(&mut out, state);
    out
}

/// The App's installation page; with a state, GitHub returns it to the setup URL.
pub fn install_url(web: &str, slug: &str, state: Option<&str>) -> String {
    let mut out = format!(
        "{}/apps/{slug}/installations/new",
        web.trim_end_matches('/')
    );
    if let Some(state) = state {
        out.push_str("?state=");
        push_query_value(&mut out, state);
    }
    out
}

/// A code GitHub hands back: a short opaque token. Anything else never reaches a URL path.
pub fn valid_code(code: &str) -> bool {
    !code.is_empty()
        && code.len() <= 128
        && code
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// What one conversion returns. The private key, client secret and webhook secret are never
/// printed (`Debug` names only the public facts) and are wiped when this is dropped.
pub struct Converted {
    pub id: u64,
    pub slug: String,
    pub name: String,
    pub owner: String,
    pub owner_id: u64,
    pub html_url: String,
    pub client_id: String,
    pub client_secret: String,
    pub webhook_secret: Option<String>,
    pub pem: String,
}

impl fmt::Debug for Converted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Converted")
            .field("id", &self.id)
            .field("slug", &self.slug)
            .field("owner", &self.owner)
            .field("client_id", &self.client_id)
            .finish_non_exhaustive()
    }
}

impl Drop for Converted {
    fn drop(&mut self) {
        sentinel_auth::secret::wipe_string(&mut self.client_secret);
        sentinel_auth::secret::wipe_string(&mut self.pem);
        if let Some(secret) = &mut self.webhook_secret {
            sentinel_auth::secret::wipe_string(secret);
        }
    }
}

fn take_string(object: &mut serde_json::Map<String, Value>, key: &str) -> Option<String> {
    match object.remove(key) {
        Some(Value::String(text)) => Some(text),
        _ => None,
    }
}

fn printable(text: &str, range: std::ops::RangeInclusive<usize>) -> bool {
    range.contains(&text.len()) && text.bytes().all(|b| (0x20..0x7f).contains(&b))
}

fn wipe_all(object: &mut serde_json::Map<String, Value>) {
    for key in ["pem", "client_secret", "webhook_secret"] {
        if let Some(mut text) = take_string(object, key) {
            sentinel_auth::secret::wipe_string(&mut text);
        }
    }
}

/// `POST {api}/app-manifests/{code}/conversions`: unauthenticated, valid once and for an hour.
/// A refusal reports GitHub's status only, never its body.
pub fn convert(http: &Client, api: &str, code: &str) -> Result<Converted> {
    if !valid_code(code) {
        return Err(Error::Config("manifest code"));
    }
    let reply = http.post_anonymous(&format!(
        "{}/app-manifests/{code}/conversions",
        api.trim_end_matches('/')
    ))?;
    let mut body = reply.body;
    let Some(object) = body.as_object_mut() else {
        return Err(Error::Transport(format!("status {}", reply.status)));
    };
    if !matches!(reply.status, 200 | 201) {
        wipe_all(object);
        return Err(Error::Transport(format!("status {}", reply.status)));
    }
    let parsed = parse_conversion(object);
    wipe_all(object);
    parsed
}

fn parse_conversion(object: &mut serde_json::Map<String, Value>) -> Result<Converted> {
    let described = crate::app::parse_described(&Value::Object(
        object
            .iter()
            .filter(|(k, _)| matches!(k.as_str(), "id" | "slug" | "name" | "html_url" | "owner"))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect(),
    ))?;
    let owner_id = object
        .get("owner")
        .and_then(|o| o["id"].as_u64())
        .filter(|id| *id > 0)
        .ok_or(Error::Response("app owner"))?;
    let client_id = object
        .get("client_id")
        .and_then(Value::as_str)
        .filter(|s| printable(s, 1..=128) && !s.contains(' '))
        .ok_or(Error::Response("client id"))?
        .to_owned();
    let client_secret =
        take_string(object, "client_secret").ok_or(Error::Response("client secret"))?;
    let pem = take_string(object, "pem").ok_or(Error::Response("private key"))?;
    let webhook_secret = take_string(object, "webhook_secret");
    let converted = Converted {
        id: described.id,
        slug: described.slug,
        name: described.name,
        owner: described.owner,
        owner_id,
        html_url: described.html_url,
        client_id,
        client_secret,
        webhook_secret,
        pem,
    };
    if !printable(&converted.client_secret, 1..=256)
        || converted.pem.len() > 16 * 1024
        || converted
            .webhook_secret
            .as_deref()
            .is_some_and(|s| !printable(s, 16..=256))
        || !valid_slug(&converted.slug)
        || !valid_text(&converted.name, 100)
        || !valid_page(&converted.html_url)
    {
        return Err(Error::Response("app credentials"));
    }
    Ok(converted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reachability_names_why_github_cannot_deliver() {
        let r = |url: Option<&str>| reachability(url).err().map(Unreachable::as_str);
        assert_eq!(r(Some("https://ci.example.com")), None);
        assert_eq!(r(Some("https://ci.example.com:8443")), None);
        assert_eq!(r(Some("https://203.0.113.9")), None);
        assert_eq!(r(None), Some("no_public_url"));
        assert_eq!(r(Some("http://127.0.0.1:8080")), Some("not_https"));
        for private in [
            "https://localhost",
            "https://ci.localhost",
            "https://10.0.0.4",
            "https://192.168.1.2:443",
            "https://172.20.0.1",
            "https://169.254.1.1",
            "https://[::1]",
            "https://[fe80::1]",
            "https://[fd00::1]",
            "https://[::ffff:10.0.0.1]",
            "https://printer.local",
            "https://ci.corp.internal",
            "https://0.0.0.0",
        ] {
            assert_eq!(r(Some(private)), Some("private_address"), "{private}");
        }
        for tailnet in [
            "https://ci.tail1234.ts.net",
            "https://100.101.102.103",
            "https://[fd7a:115c:a1e0::1]",
        ] {
            assert_eq!(r(Some(tailnet)), Some("tailnet_only"), "{tailnet}");
        }
        assert_eq!(r(Some("https://ci")), Some("single_label_host"));
        assert_eq!(r(Some("https://ci:443/x")), Some("single_label_host"));
    }

    #[test]
    fn the_manifest_asks_for_exactly_the_permissions_in_use() {
        let text = manifest(&Request {
            name: "Acme 1a2b3c",
            public_url: "https://ci.example.com",
            hook_active: true,
            public: false,
        });
        let v: Value = serde_json::from_str(&text).unwrap();
        assert_eq!(
            v["hook_attributes"],
            json!({"url":"https://ci.example.com/api/v1/hooks/github","active":true})
        );
        assert_eq!(
            v["redirect_url"],
            "https://ci.example.com/setup/github/created"
        );
        assert_eq!(
            v["setup_url"],
            "https://ci.example.com/setup/github/installed"
        );
        assert_eq!(
            v["callback_urls"],
            json!(["https://ci.example.com/auth/github/callback"])
        );
        assert_eq!(v["public"], false);
        assert_eq!(v["setup_on_update"], true);
        assert_eq!(
            v["default_permissions"],
            json!({"checks":"write","contents":"read","metadata":"read","pull_requests":"read","members":"read"})
        );
        assert_eq!(v["default_events"].as_array().unwrap().len(), EVENTS.len());
        let inactive: Value = serde_json::from_str(&manifest(&Request {
            name: "x",
            public_url: "https://ci.example.com",
            hook_active: false,
            public: false,
        }))
        .unwrap();
        assert_eq!(inactive["hook_attributes"]["active"], false);
        assert!(inactive.get("default_events").is_none());
    }

    #[test]
    fn names_fit_githubs_limit_and_urls_carry_the_state_as_one_value() {
        let suffix = "a1b2c3";
        assert_eq!(name_for(None, suffix), "Sentinel a1b2c3");
        assert_eq!(name_for(Some("  Acme / CI!  "), suffix), "Acme CI a1b2c3");
        let long = name_for(Some(&"x".repeat(80)), suffix);
        assert!(
            long.len() <= MAX_NAME && long.ends_with(" a1b2c3"),
            "{long}"
        );
        assert_eq!(
            action_url("https://github.com", &Owner::User, "s+1"),
            "https://github.com/settings/apps/new?state=s%2B1"
        );
        assert_eq!(
            action_url("https://github.com/", &Owner::Organization("acme"), "s"),
            "https://github.com/organizations/acme/settings/apps/new?state=s"
        );
        assert_eq!(
            install_url("https://github.com", "acme-ci", Some("t")),
            "https://github.com/apps/acme-ci/installations/new?state=t"
        );
        assert!(!Owner::Organization("a/b").valid());
        assert!(!Owner::Organization("").valid());
        assert!(valid_code("0123abcdef"));
        assert!(!valid_code("../x"));
        assert!(!valid_code(""));
        assert!(is_origin("https://ci.example.com"));
        assert!(!is_origin("https://ci.example.com/sentinel"));
    }

    #[test]
    fn a_conversion_never_prints_its_secrets() {
        let mut object = json!({
            "id": 7, "slug": "acme-ci", "name": "Acme CI", "html_url": "https://github.com/apps/acme-ci",
            "owner": {"login": "acme", "id": 99}, "client_id": "Iv1.abc",
            "client_secret": "client-secret-canary", "webhook_secret": "webhook-secret-canary-0123",
            "pem": "pem-canary"
        });
        let converted = parse_conversion(object.as_object_mut().unwrap()).unwrap();
        let printed = format!("{converted:?}");
        assert!(!printed.contains("canary"), "{printed}");
        assert_eq!(converted.owner_id, 99);
        let mut short = json!({
            "id": 7, "slug": "acme-ci", "name": "Acme CI", "html_url": "https://github.com/apps/acme-ci",
            "owner": {"login": "acme", "id": 99}, "client_id": "Iv1.abc",
            "client_secret": "s", "webhook_secret": "short", "pem": "p"
        });
        let error = parse_conversion(short.as_object_mut().unwrap()).unwrap_err();
        assert!(!error.to_string().contains("short"));
    }
}
