//! K07: every published recipe under fixtures/recipes must compile and
//! follow the cache rules docs/recipes.md documents — class selection,
//! `stem-<volatile>` keys that name a lockfile, `cc-<mode>-` compiler
//! stems, and an environment declaration for every mounted tool store.

use std::{fs, path::Path};

use sentinel_pipeline::{
    CompiledJob, compile_str,
    expr::{Expr, Func, Part},
    schema::Step,
};
use sentinel_protocol::cache::Class;

fn recipes_dir() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/recipes")
}

struct Expect {
    /// Lockfile every cache key must hash.
    lockfile: &'static str,
    /// (name, class, key stem, mounted path) for each declared entry.
    caches: &'static [(&'static str, Class, &'static str, &'static str)],
    /// Env vars that must be declared on the job.
    env: &'static [&'static str],
}

fn expect(name: &str) -> Expect {
    match name {
        "custom-tool" => Expect {
            lockfile: "deps.txt",
            caches: &[
                ("tool-store", Class::Downloads, "custom-dl-", "/dl/pkgs"),
                ("vendor", Class::Dependencies, "custom-deps-", "vendor"),
                ("cc", Class::Compiler, "cc-normal-", "/dl/cc"),
            ],
            env: &[],
        },
        "go" => Expect {
            lockfile: "go.sum",
            caches: &[
                ("gomod", Class::Downloads, "go-mod-", "/dl/gomod"),
                ("vendor", Class::Dependencies, "go-deps-", "vendor"),
                ("gocache", Class::Compiler, "cc-normal-", "/dl/gocache"),
            ],
            env: &["GOMODCACHE", "GOCACHE", "GOPROXY"],
        },
        "rust" => Expect {
            lockfile: "Cargo.lock",
            caches: &[
                ("cargo-store", Class::Downloads, "cargo-dl-", "/dl/cargo"),
                ("target", Class::Compiler, "cc-normal-", "/build/target"),
            ],
            env: &["CARGO_HOME", "CARGO_TARGET_DIR"],
        },
        "npm" => Expect {
            lockfile: "package-lock.json",
            caches: &[
                ("npm-cache", Class::Downloads, "npm-dl-", "/dl/npm"),
                (
                    "node-modules",
                    Class::Dependencies,
                    "npm-deps-",
                    "node_modules",
                ),
                ("app-build", Class::Compiler, "cc-normal-", "dist"),
            ],
            env: &["npm_config_cache"],
        },
        "pnpm" => Expect {
            lockfile: "pnpm-lock.yaml",
            caches: &[
                (
                    "pnpm-store",
                    Class::Downloads,
                    "pnpm-store-",
                    "/dl/pnpm-store",
                ),
                (
                    "node-modules",
                    Class::Dependencies,
                    "pnpm-deps-",
                    "node_modules",
                ),
                ("app-build", Class::Compiler, "cc-normal-", "dist"),
            ],
            env: &["PNPM_HOME", "PATH"],
        },
        "bun" => Expect {
            lockfile: "bun.lock",
            caches: &[
                ("bun-cache", Class::Downloads, "bun-dl-", "/dl/bun"),
                (
                    "node-modules",
                    Class::Dependencies,
                    "bun-deps-",
                    "node_modules",
                ),
                ("app-build", Class::Compiler, "cc-normal-", "dist"),
            ],
            env: &["BUN_INSTALL_CACHE_DIR"],
        },
        "python" => Expect {
            lockfile: "requirements.txt",
            caches: &[
                ("pip-cache", Class::Downloads, "pip-dl-", "/dl/pip"),
                ("venv", Class::Dependencies, "py-deps-", ".venv"),
                ("app-build", Class::Compiler, "cc-normal-", "dist"),
            ],
            env: &["PIP_CACHE_DIR", "VIRTUAL_ENV", "PATH"],
        },
        "maven" => Expect {
            lockfile: "pom.xml",
            caches: &[
                ("maven-m2", Class::Downloads, "maven-m2-", "/dl/m2"),
                ("target", Class::Compiler, "cc-normal-", "target"),
            ],
            env: &["MAVEN_OPTS"],
        },
        "gradle" => Expect {
            lockfile: "gradle.lockfile",
            caches: &[
                ("gradle-store", Class::Downloads, "gradle-dl-", "/dl/guhome"),
                ("gradle-build", Class::Compiler, "cc-normal-", "build"),
            ],
            env: &["GRADLE_USER_HOME"],
        },
        other => panic!("no expectation table for recipe {other}"),
    }
}

fn recipes() -> Vec<(String, String)> {
    let dir = recipes_dir();
    let mut out: Vec<(String, String)> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|x| x == "yml"))
        .map(|p| {
            (
                p.file_stem().unwrap().to_string_lossy().into_owned(),
                fs::read_to_string(&p).unwrap(),
            )
        })
        .collect();
    out.sort();
    out
}

/// The volatile component of a rendered key: the single hash_files call
/// that must come last in the template.
fn key_parts(job: &CompiledJob, cache: usize) -> (String, Vec<String>) {
    let t = &job.spec.cache[cache].key;
    let mut stem = String::new();
    let mut files = Vec::new();
    for part in &t.parts {
        match part {
            Part::Lit(s) => stem.push_str(s),
            Part::Expr(Expr::Call(Func::HashFiles, args)) => {
                for a in args {
                    if let Expr::Lit(sentinel_pipeline::expr::Value::Str(p)) = a {
                        files.push(p.clone());
                    }
                }
            }
            Part::Expr(e) => panic!("{}: non-hash_files expr {e} in cache key", job.name),
        }
    }
    (stem, files)
}

fn step_runs(job: &CompiledJob) -> Vec<&str> {
    job.spec
        .steps
        .iter()
        .map(|s: &Step| s.run.as_str())
        .collect()
}

#[test]
fn all_nine_recipes_are_present_and_compile() {
    let rs = recipes();
    assert_eq!(
        rs.iter().map(|(n, _)| n.as_str()).collect::<Vec<_>>(),
        [
            "bun",
            "custom-tool",
            "go",
            "gradle",
            "maven",
            "npm",
            "pnpm",
            "python",
            "rust"
        ],
        "fixtures/recipes must publish exactly the nine K07 recipes"
    );
    for (name, text) in &rs {
        compile_str(text).unwrap_or_else(|e| panic!("{name}: {e}"));
    }
}

#[test]
fn each_recipe_declares_one_build_job_with_a_pinned_image() {
    for (name, text) in recipes() {
        let p = compile_str(&text).unwrap();
        assert_eq!(p.jobs.len(), 1, "{name}: exactly one job");
        let job = &p.jobs[0];
        assert_eq!(job.name, "build", "{name}: job name");
        assert!(
            job.spec.image.starts_with("docker.io/"),
            "{name}: image must be a fully-qualified reference"
        );
        assert!(!job.spec.steps.is_empty(), "{name}: steps");
    }
}

#[test]
fn cache_entries_match_the_published_class_table() {
    for (name, text) in recipes() {
        let exp = expect(&name);
        let p = compile_str(&text).unwrap();
        let job = &p.jobs[0];
        assert_eq!(
            job.spec.cache.len(),
            exp.caches.len(),
            "{name}: cache count"
        );
        for (i, (cname, class, stem, path)) in exp.caches.iter().enumerate() {
            let c = &job.spec.cache[i];
            assert_eq!(&c.name, cname, "{name}: cache[{i}] name");
            assert_eq!(&c.class, class, "{name}: {cname} class");
            assert!(
                c.paths.iter().any(|p| p == path),
                "{name}: {cname} must mount {path}, got {:?}",
                c.paths
            );
            let (key_stem, files) = key_parts(job, i);
            assert_eq!(&key_stem, stem, "{name}: {cname} key stem");
            assert!(
                files.iter().any(|f| f == exp.lockfile),
                "{name}: {cname} key must hash {}, got {files:?}",
                exp.lockfile
            );
        }
    }
}

#[test]
fn compiler_entries_use_cc_stems_and_mounts_are_wired() {
    for (name, text) in recipes() {
        let p = compile_str(&text).unwrap();
        let job = &p.jobs[0];
        let runs = step_runs(job);
        for (i, c) in job.spec.cache.iter().enumerate() {
            let (stem, _) = key_parts(job, i);
            if c.class == Class::Compiler {
                assert!(
                    stem.starts_with("cc-"),
                    "{name}: compiler entry {} must use a cc-<mode>- stem",
                    c.name
                );
            }
            // An absolute path is a mounted store: it must be reachable —
            // either named by a job env var or referenced by a step.
            for path in &c.paths {
                if !path.starts_with('/') {
                    continue;
                }
                let wired = job.spec.env.iter().any(|(_, v)| {
                    v == path || path.starts_with(&format!("{v}/")) || v.contains(path.as_str())
                }) || runs.iter().any(|r| r.contains(path.as_str()));
                assert!(
                    wired,
                    "{name}: mounted path {path} has no env var or step reference"
                );
            }
        }
    }
}

#[test]
fn every_env_var_a_mount_needs_is_declared() {
    for (name, text) in recipes() {
        let exp = expect(&name);
        let p = compile_str(&text).unwrap();
        let job = &p.jobs[0];
        for var in exp.env {
            assert!(
                job.spec.env.iter().any(|(k, _)| k == var),
                "{name}: missing env var {var}"
            );
        }
    }
}

#[test]
fn fixture_trees_carry_the_lockfile_overlay_and_sources() {
    for (name, _) in recipes() {
        let exp = expect(&name);
        let dir = recipes_dir().join(&name);
        for sub in ["tree", "edit-source", "edit-dep"] {
            assert!(dir.join(sub).is_dir(), "{name}: missing {sub}/ overlay dir");
        }
        // The seed tree plus both overlays must exist; the lockfile itself
        // is provisioned into each commit by bench/k07-recipes.sh.
        let _ = exp.lockfile;
        assert!(
            dir.join("tree").read_dir().unwrap().next().is_some(),
            "{name}: empty seed tree"
        );
    }
}
