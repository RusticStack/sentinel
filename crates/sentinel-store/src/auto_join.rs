//! Operator-configured email-domain auto-join (`SENTINEL_AUTO_JOIN_DOMAINS`).
//!
//! The operator maps mail domains to app-created organizations. A person whose
//! **verified** address is in a listed domain joins that organization as its
//! lowest role (a reader), the first such person to an organization that does
//! not exist yet creates it and administers it, and the join is audited. The
//! setting is trusted because the operator set it: there is no DNS proof, and
//! nothing here is reachable from a request.
//!
//! Safety rules, each enforced in exactly one place:
//!
//! - Only a verified address counts; a claim never does (the join statement
//!   reads `email_verified_ms`).
//! - A domain matches exactly: both sides are in the one canonical form of
//!   [`crate::email::normalize_domain`] (lower case, punycode), and the match is
//!   a key equality, never a suffix or a subdomain test.
//! - An organization whose membership GitHub confirms (a bound GitHub App
//!   installation, or `membership_source = 1`) is never joined, and neither is
//!   a personal namespace or a suspended tenant. Checked when the rules are
//!   recorded at start (the entry is dropped and reported by index) and again
//!   in the joining transaction, because a tenant can be converted later.
//! - Only an admitted, active account joins; a domain match never bypasses
//!   the deployment's registration approval.
//! - Removing a domain stops new joins and removes nobody.
//!
//! The parsed rules are written to `auto_join_domains` at every controller
//! start, like the mail settings, so the transactions that verify an address
//! or open a session (including the host-local CLI's) read them with one key
//! probe and no configuration plumbing. Joining is one idempotent statement
//! sequence inside the caller's transaction on the single writer: two accounts
//! verifying at once are serialized, so an organization is created once.

use rusqlite::{OptionalExtension, Transaction, params};
use sentinel_core::{
    TenantId, UnixMillis, UserId,
    auth::{Namespace, Role},
};

use crate::{
    Error, Result, Store,
    auth::{NamespaceKind, insert_namespace},
    email::normalize_domain,
    local_auth::{Event, audit},
};

/// Entries read from the setting; past this the rest are ignored (one entry
/// is reported). Bounds the table and the startup work.
pub const MAX_ENTRIES: usize = 1_024;

/// Why an entry produces no rule. Never carries the entry's text: a
/// configuration value may hold something secret-like.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    /// Not `domain` or `domain=slug`.
    Shape,
    /// The domain is not a registrable domain after IDN normalization.
    Domain,
    /// The organization name is not a valid slug (lower case letters, digits
    /// and hyphens, at most 63, no hyphen at either end), or the name derived
    /// from a bare domain is not one.
    Slug,
    /// The domain already appeared in an earlier entry.
    Duplicate,
    /// A derived name collides with another entry's: two different domains
    /// would silently share one organization.
    SlugCollision,
    /// Past [`MAX_ENTRIES`].
    TooMany,
    /// The organization is GitHub-backed: its members come from GitHub only.
    GithubBacked,
    /// The name belongs to a personal namespace.
    PersonalNamespace,
    /// The organization is suspended.
    Suspended,
}

impl Reason {
    pub const fn as_str(self) -> &'static str {
        match self {
            Reason::Shape => "not `domain` or `domain=organization`",
            Reason::Domain => "not a valid mail domain",
            Reason::Slug => "not a valid organization name",
            Reason::Duplicate => "domain listed earlier",
            Reason::SlugCollision => "organization name already taken by another entry's domain",
            Reason::TooMany => "too many entries",
            Reason::GithubBacked => "organization is GitHub-backed",
            Reason::PersonalNamespace => "name is a personal namespace",
            Reason::Suspended => "organization is suspended",
        }
    }
}

/// An entry that produced no rule: its 1-based position among the setting's
/// entries and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ignored {
    pub index: usize,
    pub reason: Reason,
}

/// One validated rule.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    /// 1-based position in the setting, for diagnostics.
    pub index: usize,
    /// Canonical (punycode, lower case) mail domain.
    pub domain: String,
    /// The organization its members join.
    pub slug: String,
}

/// The validated, immutable rule set: at most one rule per domain.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Rules {
    rules: Vec<Rule>,
}

impl Rules {
    pub fn iter(&self) -> impl Iterator<Item = &Rule> {
        self.rules.iter()
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The organization a canonical `domain` joins.
    pub fn slug_for(&self, domain: &str) -> Option<&str> {
        self.rules
            .iter()
            .find(|rule| rule.domain == domain)
            .map(|rule| rule.slug.as_str())
    }
}

/// The result of reading the setting: the rules that stand and the entries
/// that were dropped.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    pub rules: Rules,
    pub ignored: Vec<Ignored>,
}

/// Parse `SENTINEL_AUTO_JOIN_DOMAINS`: entries separated by commas or white
/// space, each `domain=organization` or a bare `domain`, which names an
/// organization after the domain with every dot a hyphen (`example.com` is
/// `example-com`). Every defect drops that entry alone and is reported by
/// position; the controller still starts, and no value is echoed.
pub fn parse(text: &str) -> Parsed {
    let mut parsed = Parsed::default();
    // slug -> whether the first entry to take it derived it from a bare domain.
    let mut taken: Vec<(String, bool)> = Vec::new();
    let entries = text
        .split(|c: char| c == ',' || c.is_ascii_whitespace())
        .filter(|entry| !entry.is_empty());
    for (position, entry) in entries.enumerate() {
        let index = position + 1;
        if index > MAX_ENTRIES {
            parsed.ignored.push(Ignored {
                index,
                reason: Reason::TooMany,
            });
            break;
        }
        match entry_rule(entry, index, &parsed.rules, &taken) {
            Ok((rule, bare)) => {
                if !taken.iter().any(|(slug, _)| *slug == rule.slug) {
                    taken.push((rule.slug.clone(), bare));
                }
                parsed.rules.rules.push(rule);
            }
            Err(reason) => parsed.ignored.push(Ignored { index, reason }),
        }
    }
    parsed
}

fn entry_rule(
    entry: &str,
    index: usize,
    so_far: &Rules,
    taken: &[(String, bool)],
) -> std::result::Result<(Rule, bool), Reason> {
    let (domain, named) = match entry.split_once('=') {
        Some((domain, slug)) => (domain, Some(slug)),
        None => (entry, None),
    };
    if domain.is_empty() || named.is_some_and(str::is_empty) {
        return Err(Reason::Shape);
    }
    let domain = normalize_domain(domain).map_err(|_| Reason::Domain)?;
    let bare = named.is_none();
    let slug = match named {
        Some(slug) => slug.to_owned(),
        None => domain.replace('.', "-"),
    };
    if Namespace::parse(&slug).is_none() {
        return Err(Reason::Slug);
    }
    if so_far.rules.iter().any(|rule| rule.domain == domain) {
        return Err(Reason::Duplicate);
    }
    // Two explicit entries may share an organization on purpose (several
    // domains of one company); a name *derived* from a domain may not be
    // shared with a different domain, or `a.b.com` and `a-b.com` would merge.
    if taken
        .iter()
        .any(|(other, other_bare)| *other == slug && (bare || *other_bare))
    {
        return Err(Reason::SlugCollision);
    }
    Ok((
        Rule {
            index,
            domain,
            slug,
        },
        bare,
    ))
}

/// What a name resolves to, for deciding whether it may be joined.
enum Target {
    /// No such tenant: the first match creates it.
    Absent,
    /// An active, app-created organization.
    Open(TenantId),
    Refused(Reason),
}

fn target(tx: &Transaction<'_>, slug: &str) -> Result<Target> {
    let row: Option<([u8; 16], i64, bool, i64, bool)> = tx
        .prepare_cached(
            "SELECT t.id, t.kind, t.active = 1, t.membership_source,
                    EXISTS(SELECT 1 FROM installations i
                           WHERE i.tenant_id = t.id AND i.provider = 'github')
             FROM tenants t WHERE t.slug = ?1",
        )?
        .query_row([slug], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
        })
        .optional()?;
    let Some((id, kind, active, source, installed)) = row else {
        return Ok(Target::Absent);
    };
    Ok(if kind != 0 {
        Target::Refused(Reason::PersonalNamespace)
    } else if source != 0 || installed {
        Target::Refused(Reason::GithubBacked)
    } else if !active {
        Target::Refused(Reason::Suspended)
    } else {
        Target::Open(TenantId::from_bytes(id).map_err(|_| Error::Corrupt("tenant_id"))?)
    })
}

/// Record the rules that stand for this run, replacing the previous run's.
/// Called by the controller at start. A rule whose organization is already
/// GitHub-backed, personal or suspended is not recorded and is returned for
/// the caller to warn about by index; everything else is recorded, including
/// organizations that do not exist yet. Idempotent: a restart changes nothing
/// for anyone who already joined.
pub fn set_rules(store: &Store, rules: &Rules) -> Result<Vec<Ignored>> {
    let rules = rules.clone();
    store.writer().write(move |tx| {
        tx.execute("DELETE FROM auto_join_domains", [])?;
        let mut refused = Vec::new();
        for rule in rules.iter() {
            if let Target::Refused(reason) = target(tx, &rule.slug)? {
                refused.push(Ignored {
                    index: rule.index,
                    reason,
                });
                continue;
            }
            tx.execute(
                "INSERT INTO auto_join_domains(domain, slug) VALUES (?1, ?2)",
                params![rule.domain, rule.slug],
            )?;
        }
        Ok(refused)
    })
}

/// The lowest role: what a domain match grants.
const JOINED_ROLE: Role = Role::Reader;

/// Join `user` to the organization their verified address's domain maps to,
/// if any, inside the caller's transaction. `None` when nothing applies:
/// no rules, an unverified address, an account that is not admitted and
/// active, a domain with no rule, or an organization that may not be joined.
/// Idempotent: an existing membership keeps its role and is not audited
/// again. Never fails a caller's transaction for a policy refusal.
pub(crate) fn apply(
    tx: &Transaction<'_>,
    user: UserId,
    now: UnixMillis,
) -> Result<Option<TenantId>> {
    // One key probe on the (usually empty) rule table; the address is
    // already canonical, so the domain is whatever follows the one `@`.
    let slug: Option<String> = tx
        .prepare_cached(
            "SELECT j.slug FROM users u
             JOIN auto_join_domains j ON j.domain = substr(u.email, instr(u.email, '@') + 1)
             WHERE u.id = ?1 AND u.kind = 0 AND u.active = 1 AND u.status = 1
               AND u.email_verified_ms IS NOT NULL",
        )?
        .query_row([user.as_bytes()], |r| r.get(0))
        .optional()?;
    let Some(slug) = slug else {
        return Ok(None);
    };
    match target(tx, &slug)? {
        Target::Refused(_) => Ok(None),
        Target::Open(tenant) => {
            let added = tx
                .prepare_cached(
                    "INSERT INTO memberships(tenant_id, user_id, role) VALUES (?1, ?2, ?3)
                     ON CONFLICT(tenant_id, user_id) DO NOTHING",
                )?
                .execute(params![
                    tenant.as_bytes(),
                    user.as_bytes(),
                    JOINED_ROLE as u8
                ])?;
            if added == 1 {
                audit(
                    tx,
                    Event::DomainAutoJoined,
                    None,
                    Some(user),
                    false,
                    Some(&format!("{slug} reader")),
                )?;
            }
            Ok(Some(tenant))
        }
        Target::Absent => {
            let Some(name) = Namespace::parse(&slug) else {
                return Ok(None);
            };
            let tenant = TenantId::new();
            insert_namespace(tx, tenant, name, NamespaceKind::Organization, now)?;
            tx.execute(
                "INSERT INTO memberships(tenant_id, user_id, role) VALUES (?1, ?2, ?3)",
                params![tenant.as_bytes(), user.as_bytes(), Role::TenantAdmin as u8],
            )?;
            audit(
                tx,
                Event::NamespaceCreated,
                None,
                Some(user),
                false,
                Some(&slug),
            )?;
            audit(
                tx,
                Event::DomainAutoJoined,
                None,
                Some(user),
                false,
                Some(&format!("{slug} admin")),
            )?;
            Ok(Some(tenant))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pairs(parsed: &Parsed) -> Vec<(&str, &str)> {
        parsed
            .rules
            .iter()
            .map(|r| (r.domain.as_str(), r.slug.as_str()))
            .collect()
    }

    #[test]
    fn entries_are_domains_with_an_optional_organization() {
        let parsed = parse("Example.COM=acme, rusticstack.com\nbücher.example=books  ,");
        assert_eq!(parsed.ignored, vec![]);
        assert_eq!(
            pairs(&parsed),
            vec![
                ("example.com", "acme"),
                ("rusticstack.com", "rusticstack-com"),
                ("xn--bcher-kva.example", "books"),
            ]
        );
        assert_eq!(parsed.rules.slug_for("example.com"), Some("acme"));
        assert_eq!(parsed.rules.slug_for("mail.example.com"), None);
        assert!(parse("").rules.is_empty());
        assert!(parse(" , ,\n").ignored.is_empty());
    }

    #[test]
    fn a_bad_entry_is_dropped_by_position_and_never_echoed() {
        let parsed = parse(
            "ok.example=ok, =x, a.example=, localhost=l, bad.example=Not_A_Slug, \
             ok.example=again, *.wild.example, user@mail.example, fine.example",
        );
        let reasons: Vec<(usize, Reason)> =
            parsed.ignored.iter().map(|i| (i.index, i.reason)).collect();
        assert_eq!(
            reasons,
            vec![
                (2, Reason::Shape),
                (3, Reason::Shape),
                (4, Reason::Domain),
                (5, Reason::Slug),
                (6, Reason::Duplicate),
                (7, Reason::Domain),
                (8, Reason::Domain),
            ]
        );
        assert_eq!(
            pairs(&parsed),
            vec![("ok.example", "ok"), ("fine.example", "fine-example")]
        );
        for reason in [Reason::Shape, Reason::Domain, Reason::Slug] {
            assert!(!reason.as_str().contains("Not_A_Slug"));
        }
    }

    #[test]
    fn derived_names_never_merge_two_domains() {
        // `a.b.example` and `a-b.example` would both become `a-b-example`.
        let parsed = parse("a.b.example, a-b.example, one.example=shared, two.example=shared");
        assert_eq!(
            parsed.ignored,
            vec![Ignored {
                index: 2,
                reason: Reason::SlugCollision
            }]
        );
        // Two explicit entries may name one organization on purpose.
        assert_eq!(parsed.rules.len(), 3);
        // An explicit name equal to an earlier derived one is refused too.
        let parsed = parse("acme.example, other.example=acme-example");
        assert_eq!(parsed.ignored[0].reason, Reason::SlugCollision);
    }

    #[test]
    fn an_overlong_derived_name_and_an_overlong_list_are_bounded() {
        let long = format!("{}.{}.example", "a".repeat(40), "b".repeat(40));
        assert_eq!(parse(&long).ignored[0].reason, Reason::Slug);
        let many: String = (0..MAX_ENTRIES + 5)
            .map(|n| format!("d{n}.example,"))
            .collect();
        let parsed = parse(&many);
        assert_eq!(parsed.rules.len(), MAX_ENTRIES);
        assert_eq!(
            parsed.ignored,
            vec![Ignored {
                index: MAX_ENTRIES + 1,
                reason: Reason::TooMany
            }]
        );
    }
}
