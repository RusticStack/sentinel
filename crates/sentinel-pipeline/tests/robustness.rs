use std::{fs, path::Path, time::Instant};

use sentinel_pipeline::{compile_str, yaml};

fn fixtures() -> Vec<(String, String)> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/pipelines");
    let mut out = Vec::new();
    for sub in ["valid", "invalid"] {
        for e in fs::read_dir(root.join(sub)).unwrap() {
            let p = e.unwrap().path();
            if p.extension().is_some_and(|x| x == "yml") {
                out.push((
                    p.file_name().unwrap().to_string_lossy().into_owned(),
                    fs::read_to_string(&p).unwrap(),
                ));
            }
        }
    }
    out
}

/// Compile within 500 ms; an overrun is re-measured and the fastest run judged, so one preempted run cannot fail the sweep.
fn check(name: &str, text: &str) {
    let run = || {
        let t = Instant::now();
        let _ = compile_str(text);
        t.elapsed()
    };
    let mut elapsed = run();
    for _ in 0..2 {
        if elapsed.as_millis() < 500 {
            break;
        }
        elapsed = elapsed.min(run());
    }
    assert!(
        elapsed.as_millis() < 500,
        "{name}: {} bytes took {elapsed:?}",
        text.len()
    );
}

#[test]
fn every_truncation_of_every_fixture_is_handled() {
    let mut cases = 0;
    for (name, text) in fixtures() {
        for cut in 0..text.len() {
            if text.is_char_boundary(cut) {
                check(&name, &text[..cut]);
                cases += 1;
            }
        }
    }
    assert!(cases > 1000);
}

#[test]
fn single_byte_mutations_of_every_fixture_are_handled() {
    let mut state: u64 = 0x9E37_79B9_7F4A_7C15;
    let mut next = move || {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        state
    };
    let replacements: &[&str] = &[
        "\0", "\t", "\n", " ", "-", ":", "[", "]", "{", "}", "&", "*", "!", "|", ">", "'", "\"",
        "#", "%", "@", "`", "$", "0", "9", "é", "€", "\u{feff}",
    ];
    let mut cases = 0;
    for (name, text) in fixtures() {
        for _ in 0..200 {
            let pos = (next() as usize) % text.len().max(1);
            let pos = (0..=pos)
                .rev()
                .find(|&i| text.is_char_boundary(i))
                .unwrap_or(0);
            let end = (pos + 1..=text.len())
                .find(|&i| text.is_char_boundary(i))
                .unwrap_or(text.len());
            let repl = replacements[(next() as usize) % replacements.len()];
            let mut mutated = String::with_capacity(text.len() + 4);
            mutated.push_str(&text[..pos]);
            mutated.push_str(repl);
            mutated.push_str(&text[end..]);
            check(&name, &mutated);
            cases += 1;
        }
    }
    assert!(cases >= 6000);
}

#[test]
fn hostile_documents_fail_fast_with_structured_errors() {
    let laughs = "a: &a [x, x]\nb: &b [*a, *a]\nc: &c [*b, *b]\nd: [*c, *c]\n";
    assert!(matches!(
        yaml::load(laughs).unwrap_err().kind,
        yaml::YamlErrorKind::Anchor
    ));
    let deep = format!("a: {}{}", "[".repeat(10_000), "]".repeat(10_000));
    let e = yaml::load(&deep).unwrap_err();
    assert!(
        matches!(
            e.kind,
            yaml::YamlErrorKind::TooDeep { .. } | yaml::YamlErrorKind::Syntax(_)
        ),
        "{e}"
    );
    let moderately_deep = format!("a: {}1{}", "[".repeat(40), "]".repeat(40));
    assert!(matches!(
        yaml::load(&moderately_deep).unwrap_err().kind,
        yaml::YamlErrorKind::TooDeep { .. }
    ));
    let big = format!("schema: 1\nrun: {}\n", "x".repeat(200_000));
    assert!(matches!(
        yaml::load(&big).unwrap_err().kind,
        yaml::YamlErrorKind::ScalarTooLong { .. }
    ));
    for text in [
        "\u{feff}schema: 1\r\non: [push]\r\njobs: {}\r\n",
        "schema: 1\non: [push]\njobs: \0\n",
    ] {
        let e = compile_str(text).unwrap_err().to_string();
        assert!(!e.is_empty());
    }
    let wide = format!(
        "schema: 1\non: [push]\njobs: {{{}}}\n",
        (0..20_000)
            .map(|i| format!("j{i}: 1"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    assert!(compile_str(&wide).is_err());
    let e = yaml::load(&wide).unwrap_err();
    assert_eq!(
        e.kind,
        yaml::YamlErrorKind::TooManyNodes {
            limit: yaml::MAX_NODES
        }
    );
    let jobs_line = wide.lines().nth(2).unwrap();
    assert_eq!(e.line, 3, "{e}");
    assert!(e.col < jobs_line.len() / 2, "stopped at column {}", e.col);
}
