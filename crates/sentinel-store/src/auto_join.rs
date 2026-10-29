//! Trusted because the operator set it (no DNS proof); joins run on the single writer, so an organization is created once.

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

pub const MAX_ENTRIES: usize = 1_024;

/// Never carries the entry's text: a configuration value may hold something secret-like.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    Shape,
    Domain,
    Slug,
    Duplicate,
    SlugCollision,
    TooMany,
    GithubBacked,
    PersonalNamespace,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ignored {
    pub index: usize,
    pub reason: Reason,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rule {
    pub index: usize,
    pub domain: String,
    pub slug: String,
}

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

    pub fn slug_for(&self, domain: &str) -> Option<&str> {
        self.rules
            .iter()
            .find(|rule| rule.domain == domain)
            .map(|rule| rule.slug.as_str())
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
pub struct Parsed {
    pub rules: Rules,
    pub ignored: Vec<Ignored>,
}

pub fn parse(text: &str) -> Parsed {
    let mut parsed = Parsed::default();
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
    // A derived name may not be shared with another domain, or a.b.com and a-b.com would merge.
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

enum Target {
    Absent,
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

/// Records the rules in force. The controller calls it at every start; the stored rules, and the
/// generation that decides who is checked again at sign-in, change only when the effective set does.
pub fn set_rules(store: &Store, rules: &Rules) -> Result<Vec<Ignored>> {
    let rules = rules.clone();
    store.writer().write(move |tx| {
        let mut refused = Vec::new();
        let mut accepted: Vec<(&str, &str)> = Vec::with_capacity(rules.len());
        for rule in rules.iter() {
            if let Target::Refused(reason) = target(tx, &rule.slug)? {
                refused.push(Ignored {
                    index: rule.index,
                    reason,
                });
                continue;
            }
            accepted.push((rule.domain.as_str(), rule.slug.as_str()));
        }
        accepted.sort_unstable();
        let stored: Vec<(String, String)> = tx
            .prepare_cached("SELECT domain, slug FROM auto_join_domains ORDER BY domain")?
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<std::result::Result<_, _>>()?;
        let unchanged = stored.len() == accepted.len()
            && stored
                .iter()
                .zip(&accepted)
                .all(|((d, s), (ad, asl))| d == ad && s == asl);
        if unchanged {
            return Ok(refused);
        }
        tx.execute("DELETE FROM auto_join_domains", [])?;
        for (domain, slug) in accepted {
            tx.execute(
                "INSERT INTO auto_join_domains(domain, slug) VALUES (?1, ?2)",
                params![domain, slug],
            )?;
        }
        tx.execute("UPDATE auto_join_state SET generation = generation + 1", [])?;
        Ok(refused)
    })
}

const JOINED_ROLE: Role = Role::Reader;

/// Remembers that an administrator removed `user` from `tenant`, so `apply` never re-adds them.
/// Idempotent; the newest removal time wins.
pub(crate) fn record_removal(
    tx: &Transaction<'_>,
    tenant: TenantId,
    user: UserId,
    now: UnixMillis,
) -> Result<()> {
    tx.prepare_cached(
        "INSERT INTO membership_removals(tenant_id, user_id, removed_ms) VALUES (?1, ?2, ?3)
         ON CONFLICT(tenant_id, user_id) DO UPDATE SET removed_ms = excluded.removed_ms",
    )?
    .execute(params![tenant.as_bytes(), user.as_bytes(), now.0])?;
    Ok(())
}

/// The sign-in entry point: runs [`apply`] only for a person who has not been checked under the rules in
/// force. One conditional UPDATE, no read of the rules, is all a sign-in pays once the person was checked;
/// it records the check only for a person `apply` can act on, so an account that is not yet eligible
/// (unverified, waiting for approval) is looked at again at its next sign-in.
pub(crate) fn apply_if_due(
    tx: &Transaction<'_>,
    user: UserId,
    now: UnixMillis,
) -> Result<Option<TenantId>> {
    let due = tx
        .prepare_cached(
            "UPDATE users SET auto_join_gen = (SELECT generation FROM auto_join_state)
             WHERE id = ?1 AND kind = 0 AND active = 1 AND status = 1 AND super_admin = 0
               AND email_verified_ms IS NOT NULL
               AND auto_join_gen != (SELECT generation FROM auto_join_state)",
        )?
        .execute([user.as_bytes()])?;
    if due == 0 {
        return Ok(None);
    }
    apply(tx, user, now)
}

/// A platform administrator is never auto-joined: joining a tenant takes step-up and an audited reason.
pub(crate) fn apply(
    tx: &Transaction<'_>,
    user: UserId,
    now: UnixMillis,
) -> Result<Option<TenantId>> {
    let slug: Option<String> = tx
        .prepare_cached(
            "SELECT j.slug FROM users u
             JOIN auto_join_domains j ON j.domain = substr(u.email, instr(u.email, '@') + 1)
             WHERE u.id = ?1 AND u.kind = 0 AND u.active = 1 AND u.status = 1 AND u.super_admin = 0
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
                    "INSERT INTO memberships(tenant_id, user_id, role) SELECT ?1, ?2, ?3
                     WHERE NOT EXISTS(SELECT 1 FROM membership_removals
                                      WHERE tenant_id = ?1 AND user_id = ?2)
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
        let parsed = parse("Example.COM=acme, example.org\nbücher.example=books  ,");
        assert_eq!(parsed.ignored, vec![]);
        assert_eq!(
            pairs(&parsed),
            vec![
                ("example.com", "acme"),
                ("example.org", "example-org"),
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
        let parsed = parse("a.b.example, a-b.example, one.example=shared, two.example=shared");
        assert_eq!(
            parsed.ignored,
            vec![Ignored {
                index: 2,
                reason: Reason::SlugCollision
            }]
        );
        assert_eq!(parsed.rules.len(), 3);
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
