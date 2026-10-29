//! Guard: no PEM private key is committed (tracked by git; a source archive without git
//! is walked instead). Tests that need an App key generate
//! a throwaway one at run time.

use std::{fs, path::Path};

const SKIP_DIRS: [&str; 5] = [".git", "target", "node_modules", ".qoder", "dist"];

/// A PEM private key is a BEGIN marker whose next line is base64 body. A bare
/// marker inside a string literal (the key parser) is not a key.
fn has_pem_body(text: &str) -> bool {
    let mut lines = text.lines();
    while let Some(line) = lines.next() {
        let Some(at) = line.find("-----BEGIN ") else {
            continue;
        };
        if !line[at..].contains("PRIVATE KEY-----") {
            continue;
        }
        let tail = &line[at..];
        let marker_end = tail[11..].find("-----").map_or(tail.len(), |i| i + 16);
        if tail[marker_end..].trim().len() >= 40 {
            return true;
        }
        if let Some(next) = lines.clone().next() {
            let n = next.trim();
            if n.len() >= 40
                && n.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
            {
                return true;
            }
        }
    }
    false
}

fn walk(dir: &Path, hits: &mut Vec<String>) {
    for entry in fs::read_dir(dir).unwrap().flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        if path.is_dir() {
            if !SKIP_DIRS.contains(&name.as_str()) {
                walk(&path, hits);
            }
        } else if let Ok(text) = fs::read_to_string(&path)
            && has_pem_body(&text)
        {
            hits.push(path.display().to_string());
        }
    }
}

/// The files git tracks, so an ignored local credential folder cannot trip the guard.
/// `None` when this is not a git checkout (a source archive): the caller walks the tree.
fn tracked(root: &Path) -> Option<Vec<std::path::PathBuf>> {
    let out = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args(["ls-files", "-z"])
        .output()
        .ok()
        .filter(|out| out.status.success())?;
    Some(
        out.stdout
            .split(|b| *b == 0)
            .filter(|name| !name.is_empty())
            .map(|name| root.join(String::from_utf8_lossy(name).as_ref()))
            .collect(),
    )
}

#[test]
fn no_pem_private_key_is_committed() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut hits = Vec::new();
    match tracked(&root) {
        Some(files) => {
            for path in files {
                if let Ok(text) = fs::read_to_string(&path)
                    && has_pem_body(&text)
                {
                    hits.push(path.display().to_string());
                }
            }
        }
        None => walk(&root, &mut hits),
    }
    assert!(hits.is_empty(), "committed PEM private key in: {hits:?}");
}

#[test]
fn detector_recognises_a_pem_body() {
    let body = "A".repeat(64);
    assert!(has_pem_body(&format!(
        "-----BEGIN PRIVATE KEY-----\n{body}\n-----END PRIVATE KEY-----\n"
    )));
    assert!(!has_pem_body(
        "let m = \"-----BEGIN PRIVATE KEY-----\";\nlet x = 1;"
    ));
}
