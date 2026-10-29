//! The `docs/api.md` route tables against the routes the router matches.
//!
//! Both sides are read as text: the match arms of the router modules (`("GET" | "POST", ["api",
//! "v1", slug, ...])`) and the first cell of every table row under "Routes". Each is reduced to
//! `METHOD /segments` with every parameter written `{}`, so a route that is documented but not
//! served, served but not documented, or documented under another method fails here.

use std::{collections::BTreeSet, fs, path::PathBuf};

fn read(path: &str) -> String {
    let full = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(path);
    fs::read_to_string(&full).unwrap_or_else(|e| panic!("{}: {e}", full.display()))
}

/// Everything before the unit tests of a source file.
fn production(source: &str) -> &str {
    source
        .find("#[cfg(test)]")
        .map_or(source, |end| &source[..end])
}

/// Quoted literals in `text`, in order.
fn literals(text: &str) -> Vec<String> {
    text.split('"')
        .skip(1)
        .step_by(2)
        .map(str::to_owned)
        .collect()
}

/// Split at top-level commas (not inside parentheses).
fn top_level(inner: &str) -> Vec<&str> {
    let (mut depth, mut start, mut out) = (0usize, 0usize, Vec::new());
    for (at, c) in inner.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth = depth.saturating_sub(1),
            ',' if depth == 0 => {
                out.push(inner[start..at].trim());
                start = at + 1;
            }
            _ => {}
        }
    }
    out.push(inner[start..].trim());
    out.retain(|piece| !piece.is_empty());
    out
}

/// Every method and every spelling of the segments, as `METHOD /a/b`.
fn expand(methods: &[String], alternatives: &[Vec<String>], into: &mut BTreeSet<String>) {
    let mut paths = vec![String::new()];
    for options in alternatives {
        paths = paths
            .iter()
            .flat_map(|path| options.iter().map(move |o| format!("{path}/{o}")))
            .collect();
    }
    for method in methods {
        for path in &paths {
            into.insert(format!("{method} {path}"));
        }
    }
}

struct Cursor<'a> {
    source: &'a str,
    at: usize,
}

impl Cursor<'_> {
    fn skip(&mut self) {
        while self
            .source
            .as_bytes()
            .get(self.at)
            .is_some_and(u8::is_ascii_whitespace)
        {
            self.at += 1;
        }
    }

    fn eat(&mut self, byte: u8) -> bool {
        self.skip();
        let hit = self.source.as_bytes().get(self.at) == Some(&byte);
        self.at += usize::from(hit);
        hit
    }

    fn quoted(&mut self) -> Option<String> {
        self.skip();
        if self.source.as_bytes().get(self.at) != Some(&b'"') {
            return None;
        }
        let end = self.source[self.at + 1..].find('"')? + self.at + 1;
        let text = self.source[self.at + 1..end].to_owned();
        self.at = end + 1;
        Some(text)
    }
}

/// Parse `( ["kind",] METHODS, [segments] )` tuples; `prefix` precedes the kind and the segments.
/// A tuple whose segments end in `rest @ ..` is a dispatcher to another module and is skipped:
/// that module is read with its own prefix.
fn arms(source: &str, prefix: &[&str], into: &mut BTreeSet<String>) {
    for (open, _) in source.match_indices('(') {
        let mut cursor = Cursor {
            source,
            at: open + 1,
        };
        let mut kind = None;
        let mut methods = Vec::new();
        while let Some(text) = cursor.quoted() {
            if text.chars().all(|c| c.is_ascii_uppercase()) {
                methods.push(text);
                if cursor.eat(b'|') {
                    continue;
                }
                break;
            }
            let lower = text.chars().all(|c| c.is_ascii_lowercase() || c == '-');
            if methods.is_empty() && kind.is_none() && lower && cursor.eat(b',') {
                kind = Some(text);
                continue;
            }
            methods.clear();
            break;
        }
        if methods.is_empty() || !cursor.eat(b',') || !cursor.eat(b'[') {
            continue;
        }
        let Some(close) = source[cursor.at..].find(']') else {
            continue;
        };
        let inner = &source[cursor.at..cursor.at + close];
        cursor.at += close + 1;
        cursor.eat(b',');
        if !cursor.eat(b')') {
            continue;
        }
        let mut alternatives: Vec<Vec<String>> = prefix
            .iter()
            .map(|segment| vec![(*segment).to_owned()])
            .collect();
        alternatives.extend(kind.map(|k| vec![k]));
        let mut dispatcher = false;
        for piece in top_level(inner) {
            if piece.ends_with("@ ..") {
                dispatcher = true;
                break;
            }
            let options = literals(piece);
            alternatives.push(if options.is_empty() {
                vec!["{}".into()]
            } else {
                options
            });
        }
        if !dispatcher {
            expand(&methods, &alternatives, into);
        }
    }
}

fn served() -> BTreeSet<String> {
    let mut routes = BTreeSet::new();
    for file in [
        "src/routes.rs",
        "src/routes/account.rs",
        "src/routes/admin.rs",
        "src/routes/email.rs",
        "src/routes/setup.rs",
        "src/routes/worker_enrollment.rs",
        "src/github.rs",
        "src/oauth/mod.rs",
    ] {
        arms(production(&read(file)), &[], &mut routes);
    }
    // Relative dispatchers: the tenant secret routes are `(kind, method, rest)` under a tenant.
    arms(
        production(&read("src/secret_routes.rs")),
        &["api", "v1", "tenants", "{}"],
        &mut routes,
    );
    // `oauth/service.rs` holds two dispatchers: grants, then a tenant's service accounts.
    let service = read("src/oauth/service.rs");
    let service = production(&service);
    let split = service
        .find("pub(crate) fn accounts")
        .expect("service accounts dispatcher");
    arms(&service[..split], &["api", "v1", "grants"], &mut routes);
    arms(
        &service[split..],
        &["api", "v1", "tenants", "{}", "service-accounts"],
        &mut routes,
    );
    // The `.well-known` arms match `rest @ ..` behind a guard; the guards name the paths.
    let oauth = read("src/oauth/mod.rs");
    for guard in [
        "\"oauth-authorization-server\", rest @ ..",
        "rest == [\"api\", \"v1\"]",
        "rest == [\"mcp\"]",
    ] {
        assert!(oauth.contains(guard), "oauth/mod.rs no longer has {guard}");
    }
    routes.insert("GET /.well-known/oauth-authorization-server".into());
    for resource in ["api/v1", "mcp"] {
        routes.insert(format!(
            "GET /.well-known/oauth-protected-resource/{resource}"
        ));
    }
    routes
}

/// The methods in `text` (`GET`, `GET|PUT`, `POST, GET`), when it is nothing else.
fn methods_of(text: &str) -> Option<Vec<String>> {
    let methods: Vec<String> = text
        .split(['|', ','])
        .map(str::trim)
        .filter(|m| !m.is_empty())
        .map(str::to_owned)
        .collect();
    (!methods.is_empty()
        && methods
            .iter()
            .all(|m| m.chars().all(|c| c.is_ascii_uppercase())))
    .then_some(methods)
}

/// The `METHOD /path` set the "Routes" tables of `docs/api.md` document.
fn documented() -> BTreeSet<String> {
    let docs = read("../../docs/api.md");
    let start = docs.find("\n## Routes").expect("Routes section");
    let end = docs.find("\n## The CLI").expect("CLI section");
    let mut routes = BTreeSet::new();
    for line in docs[start..end].lines() {
        let Some(cell) = line
            .strip_prefix("| `")
            .and_then(|rest| rest.split('`').next())
        else {
            continue;
        };
        let cell = cell.replace("\\|", "|");
        // `GET /x`, `GET\|PUT /x` or `POST, GET, DELETE /mcp`: the path starts at the first `/`.
        let Some(slash) = cell.find(" /") else {
            continue;
        };
        let Some(methods) = methods_of(&cell[..slash]) else {
            continue;
        };
        let path = cell[slash + 1..].split('?').next().unwrap_or_default();
        let mut segments: Vec<&str> = path.trim_matches('/').split('/').collect();
        if !["oauth", ".well-known", "device", "mcp", "auth"].contains(&segments[0]) {
            segments.splice(0..0, ["api", "v1"]);
        }
        let alternatives: Vec<Vec<String>> = segments
            .iter()
            .map(|segment| {
                if segment.starts_with('{') {
                    vec!["{}".to_owned()]
                } else {
                    segment.split('|').map(str::to_owned).collect()
                }
            })
            .collect();
        expand(&methods, &alternatives, &mut routes);
        if line.contains("(also `/metrics` outside `/api/v1`)") {
            routes.insert("GET /metrics".into());
        }
    }
    routes
}

#[test]
fn the_api_doc_lists_exactly_the_routes_the_router_serves() {
    let (served, documented) = (served(), documented());
    assert!(
        served.len() > 100 && documented.len() > 100,
        "the extraction found {} served and {} documented routes",
        served.len(),
        documented.len()
    );
    let undocumented: Vec<_> = served.difference(&documented).collect();
    let unserved: Vec<_> = documented.difference(&served).collect();
    assert!(
        undocumented.is_empty() && unserved.is_empty(),
        "served but not in docs/api.md: {undocumented:#?}\ndocumented but not served: {unserved:#?}"
    );
}

#[test]
fn the_extraction_reads_the_arm_shapes_the_router_uses() {
    let mut found = BTreeSet::new();
    arms(
        r#"match (m, p) {
            ("GET" | "POST", ["api", "v1", slug, "x"]) => a,
            (
                "POST",
                [
                    "api",
                    user,
                    action @ ("approve" | "reject"),
                ],
            ) => b,
            (_, ["api", "v1", "grants", rest @ ..]) => c,
            ("secrets", "GET", [name, "allow"]) => d,
        }"#,
        &["t"],
        &mut found,
    );
    let expected: BTreeSet<String> = [
        "GET /t/api/v1/{}/x",
        "POST /t/api/v1/{}/x",
        "POST /t/api/{}/approve",
        "POST /t/api/{}/reject",
        "GET /t/secrets/{}/allow",
    ]
    .map(str::to_owned)
    .into();
    assert_eq!(found, expected);
}
