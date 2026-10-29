//! `docs/compatibility.md` and `docs/upgrades.md` against the constants they describe.
//!
//! Both pages state numbers the code owns: the contract table's versions, the worker protocol
//! range, what each migration declares `readable_by` and the rollback matrix. They are read as
//! text here, so a bump that forgets a page (or a page that was wrong from the start) fails this
//! test instead of misleading an operator who sizes an upgrade or a rollback from it.

use std::{fs, path::PathBuf};

use sentinel_pipeline::run::{SPEC_FORMAT, SPEC_FORMAT_READ_MIN};
use sentinel_protocol::{
    negotiate::{SUPPORTED_MAX, SUPPORTED_MIN},
    summary::SUMMARY_FORMAT,
};
use sentinel_store::schema;

fn doc(name: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../docs")
        .join(name);
    fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()))
        .replace("\r\n", "\n")
}

/// The decimal numbers in `text`, in order.
fn numbers(text: &str) -> Vec<u64> {
    text.split(|c: char| !c.is_ascii_digit())
        .filter(|run| !run.is_empty())
        .filter_map(|run| run.parse().ok())
        .collect()
}

/// The line of the table whose first cell is `name`.
fn row<'a>(markdown: &'a str, name: &str) -> &'a str {
    let prefix = format!("| {name} |");
    markdown
        .lines()
        .find(|line| line.starts_with(&prefix))
        .unwrap_or_else(|| panic!("no table row starting {prefix:?}"))
}

/// What follows the first `marker` in `text`.
fn after<'a>(text: &'a str, marker: &str) -> &'a str {
    text.split_once(marker)
        .unwrap_or_else(|| panic!("{text:?} has no {marker:?}"))
        .1
}

/// The numbers following `marker` up to the next `;`, `)` or `|`.
fn stated(text: &str, marker: &str) -> Vec<u64> {
    let tail = after(text, marker);
    let end = tail.find([';', ')', '|']).unwrap_or(tail.len());
    numbers(&tail[..end])
}

/// Whether `text` says `phrase` followed by exactly `value` (so `readable by 5` is not `56`).
fn says(text: &str, phrase: &str, value: u32) -> bool {
    text.match_indices(phrase).any(|(at, _)| {
        let tail = &text[at + phrase.len()..];
        let digits: String = tail.chars().take_while(char::is_ascii_digit).collect();
        digits.parse::<u32>().ok() == Some(value)
    })
}

#[test]
fn the_contract_table_states_the_versions_the_code_declares() {
    let compat = doc("compatibility.md");

    let pipeline = row(&compat, "Pipeline schema");
    assert_eq!(
        stated(pipeline, "currently"),
        [sentinel_pipeline::schema::SCHEMA_VERSION as u64],
        "pipeline schema row: {pipeline}"
    );

    let spec = row(&compat, "Run spec blob");
    assert_eq!(
        stated(spec, "currently").first().copied(),
        Some(u64::from(SPEC_FORMAT)),
        "run spec row names the format written: {spec}"
    );
    assert_eq!(
        stated(spec, "reads"),
        [u64::from(SPEC_FORMAT_READ_MIN), u64::from(SPEC_FORMAT)],
        "run spec row names the formats read: {spec}"
    );

    let summary = row(&compat, "Attempt summary blob");
    assert_eq!(
        stated(summary, "currently"),
        [u64::from(SUMMARY_FORMAT)],
        "summary row: {summary}"
    );
    assert_eq!(
        stated(summary, "reads").last().copied(),
        Some(u64::from(SUMMARY_FORMAT)),
        "summary row names the newest format read: {summary}"
    );

    let database = row(&compat, "Metadata database");
    assert_eq!(
        stated(database, "currently"),
        [u64::from(schema::LATEST)],
        "metadata database row: {database}"
    );

    let protocol = row(&compat, "Worker protocol");
    assert_eq!(
        stated(protocol, "currently"),
        [u64::from(SUPPORTED_MIN.0), u64::from(SUPPORTED_MAX.0)],
        "worker protocol row: {protocol}"
    );
}

#[test]
fn the_upgrade_page_states_the_protocol_range_the_controller_negotiates() {
    let upgrades = doc("upgrades.md");
    let line = row(&upgrades, "Worker protocol");
    let range = after(line, "The controller speaks protocols");
    let end = range
        .find('(')
        .expect("the range is followed by its constants");
    assert_eq!(
        numbers(&range[..end]),
        [u64::from(SUPPORTED_MIN.0), u64::from(SUPPORTED_MAX.0)],
        "upgrades.md: {line}"
    );
}

/// The entries of the page: runs of lines that start at a line opening with a bold heading, so
/// entries written without a blank line between them are still told apart.
fn entries(markdown: &str) -> Vec<String> {
    let mut out = Vec::new();
    for chunk in markdown.split("\n\n") {
        let mut current = String::new();
        for line in chunk.lines() {
            if line.starts_with("**") && !current.is_empty() {
                out.push(std::mem::take(&mut current));
            }
            current.push_str(line);
            current.push('\n');
        }
        out.push(current);
    }
    out
}

/// The migrations a "Rollback after migrations ..." entry names (`54, 55, 56 and 59 to 63`).
fn grouped_rollback(entries: &[String]) -> (Vec<u32>, &str) {
    let paragraph = entries
        .iter()
        .find(|p| p.starts_with("**Rollback after migrations"))
        .expect("the grouped rollback entry");
    let heading_end = paragraph[2..].find("**").expect("heading end") + 2;
    let heading = &paragraph[..heading_end];
    let mut versions = Vec::new();
    let mut ranged = false;
    for word in heading.split(|c: char| !c.is_ascii_alphanumeric()) {
        match word.parse::<u32>() {
            Ok(to) if ranged => {
                let from = *versions.last().expect("a range starts at a number");
                versions.extend(from + 1..=to);
                ranged = false;
            }
            Ok(version) => versions.push(version),
            Err(_) => ranged = word == "to",
        }
    }
    (versions, paragraph)
}

/// The migrations a paragraph's bold heading names with `migration N`.
fn heading_migrations(paragraph: &str) -> Vec<u32> {
    let Some(rest) = paragraph.strip_prefix("**") else {
        return Vec::new();
    };
    let heading = &rest[..rest.find("**").unwrap_or(rest.len())];
    heading
        .match_indices("migration ")
        .filter_map(|(at, marker)| {
            let digits: String = heading[at + marker.len()..]
                .chars()
                .take_while(char::is_ascii_digit)
                .collect();
            digits.parse().ok()
        })
        .collect()
}

#[test]
fn every_migration_entry_states_the_readable_by_the_code_declares() {
    let compat = doc("compatibility.md");
    let entries = entries(&compat);
    let (grouped, grouped_text) = grouped_rollback(&entries);
    assert!(
        says(grouped_text, "database at schema ", schema::LATEST),
        "the grouped rollback paragraph names the current schema {}",
        schema::LATEST
    );
    for version in &grouped {
        assert!(
            (schema::READABLE_BY_SINCE..=schema::LATEST).contains(version)
                && schema::readable_by(*version) == *version,
            "the grouped rollback paragraph lists migration {version}, which READABLE_BY declares \
             readable (or which does not exist)"
        );
    }

    for version in schema::READABLE_BY_SINCE..=schema::LATEST {
        let entry: String = entries
            .iter()
            .filter(|p| heading_migrations(p).contains(&version))
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join("\n\n")
            .to_lowercase();
        assert!(
            !entry.is_empty(),
            "docs/compatibility.md has no entry headed `migration {version}`"
        );
        let reader = schema::readable_by(version);
        if reader < version {
            assert!(
                says(&entry, "readable by ", reader),
                "migration {version} is declared readable by {reader} (READABLE_BY) but its entry \
                 does not say `readable by {reader}`"
            );
        } else {
            assert!(
                entry.contains("not declared readable") || grouped.contains(&version),
                "migration {version} is not in READABLE_BY, so its entry must say `not declared \
                 readable` or the grouped rollback paragraph must list it"
            );
        }
    }
}

#[test]
fn the_rollback_matrix_matches_the_readable_by_column() {
    let upgrades = doc("upgrades.md");
    let section = after(&upgrades, "### Rollback matrix");
    let section = &section[..section.find("\n## ").unwrap_or(section.len())];
    let mut rows = section
        .lines()
        .filter(|l| l.starts_with('|') && !l.starts_with("|---"))
        .map(|l| {
            l.trim_matches('|')
                .split('|')
                .map(str::trim)
                .collect::<Vec<_>>()
        });
    let header = rows.next().expect("the matrix header");
    let schemas: Vec<u32> = header[1..]
        .iter()
        .map(|cell| numbers(cell)[0] as u32)
        .collect();
    assert_eq!(
        (
            schemas.last().copied(),
            header.last().map(|c| c.contains("(current)"))
        ),
        (Some(schema::LATEST), Some(true)),
        "the last matrix column is the current schema: {header:?}"
    );

    // Releases that matter: every `READABLE_BY` target and the two schemas before the latest.
    let mut releases: Vec<u32> = schema::READABLE_BY.iter().map(|&(_, by)| by).collect();
    releases.extend([schema::LATEST - 2, schema::LATEST - 1]);
    releases.sort_unstable();
    releases.dedup();

    let mut listed = Vec::new();
    for cells in rows {
        let release = numbers(cells[0])[0] as u32;
        listed.push(release);
        assert_eq!(cells.len(), schemas.len() + 1, "row {cells:?}");
        for (cell, &newest) in cells[1..].iter().zip(&schemas) {
            // A database at schema N runs on release R only when no migration in (R, N] declares
            // a `readable_by` above R.
            let expected = if release >= newest {
                "n/a"
            } else if (release + 1..=newest).all(|m| schema::readable_by(m) <= release) {
                "runs as is"
            } else {
                "copy or backup"
            };
            assert_eq!(
                *cell, expected,
                "release {release} on a database at schema {newest}"
            );
        }
    }
    assert_eq!(
        listed, releases,
        "the matrix rows are the READABLE_BY targets and the two schemas before the latest"
    );
}
