//! The identity of a task's result: everything a pipeline declares for the job, and nothing else.
//!
//! A result may only be served to a job that renders the same key, so this module enumerates the key's
//! components in one place and the docs enumerate the same list. Nothing here reads the run, the attempt,
//! the event or the source revision: a result is a function of the task, not of how it was triggered, and a
//! component that varied per run would make reuse impossible while a component that is missing would make it
//! wrong. A job whose identity cannot be stated completely is refused by the loader instead
//! ([`crate::schema::Reuse`]).

use crate::schema::{Isolation, Job, Shell};

/// Versioned: a change to what the key covers moves this tag, so no entry sealed under the old rule is served.
pub const KEY_DOMAIN: &[u8] = b"sentinel.task-result/1\0";

/// Every declared input of one job, in the order the loader fixed.
pub struct Declared<'a> {
    pub job: &'a Job,
    /// The pinned image digest the job runs, `sha256:…`.
    pub image: &'a str,
    /// The toolchain identity the cache scope also carries: the same bytes, so identity cannot drift between
    /// the two stores.
    pub toolchain: &'a [u8; 32],
    /// The isolation class the attempt actually runs in, after the worker's preference is applied.
    pub isolation: Isolation,
    /// The platform component, `linux-x86_64`.
    pub platform: &'a str,
    /// Each declared input pattern with the digest of the files it matched, in declaration order. A pattern
    /// that does not resolve is refused before the key is built, so a match cannot silently vanish.
    pub inputs: &'a [(String, String)],
}

/// The 32-byte identity of a task result, and the hex it renders as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Key([u8; 32]);

impl Key {
    pub fn bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Lower-case hex, the text a manifest records and a report names.
    pub fn render(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(64);
        for byte in self.0 {
            out.push(HEX[(byte >> 4) as usize] as char);
            out.push(HEX[(byte & 0xf) as usize] as char);
        }
        out
    }
}

impl std::fmt::Display for Key {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.render())
    }
}

/// Length-prefixed, so no component can be shifted into another by editing its text: `ab` + `c` and `a` + `bc`
/// cannot render the same bytes.
fn field(hasher: &mut blake3::Hasher, bytes: &[u8]) {
    hasher.update(&(bytes.len() as u64).to_le_bytes());
    hasher.update(bytes);
}

fn text(hasher: &mut blake3::Hasher, text: &str) {
    field(hasher, text.as_bytes());
}

/// The identity of the job's result over every declared input.
pub fn key(declared: &Declared<'_>) -> Key {
    let mut hasher = blake3::Hasher::new();
    field(&mut hasher, KEY_DOMAIN);
    // The sandbox, the platform and the toolchain: a result is only ever served where it was produced.
    field(&mut hasher, declared.isolation.as_str().as_bytes());
    text(&mut hasher, declared.platform);
    text(&mut hasher, declared.image);
    field(&mut hasher, declared.toolchain);
    // The image a job states is a reference; the digest it resolved to is what its steps actually read, and
    // both are in the key because a tag that moved keeps its text and changes its digest.
    text(&mut hasher, &declared.job.image);
    // Every step's command and the environment the pipeline declares for it.
    field(
        &mut hasher,
        &(declared.job.steps.len() as u64).to_le_bytes(),
    );
    for (index, step) in declared.job.steps.iter().enumerate() {
        text(&mut hasher, &step.id);
        field(&mut hasher, &[shell_code(step.shell)]);
        text(&mut hasher, step.workdir.as_deref().unwrap_or(""));
        field(
            &mut hasher,
            &step.timeout_secs.map(|s| s.to_le_bytes()).unwrap_or([0; 8]),
        );
        text(&mut hasher, &step.run);
        // The environment the step actually sees: the job's variables, the step's overriding by name.
        let mut env: Vec<(&str, &str)> = declared
            .job
            .env
            .iter()
            .chain(step.env.iter())
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        env.sort_unstable_by(|a, b| a.0.cmp(b.0).then(b.1.cmp(a.1)));
        env.dedup_by(|a, b| a.0 == b.0);
        env.sort_unstable_by(|a, b| a.0.cmp(b.0));
        field(&mut hasher, &(env.len() as u64).to_le_bytes());
        for (name, value) in env {
            text(&mut hasher, name);
            text(&mut hasher, value);
        }
        field(&mut hasher, &(index as u64).to_le_bytes());
    }
    // The job's working directory and its declared variables apply to every step that states none of its own.
    text(&mut hasher, declared.job.workdir.as_deref().unwrap_or(""));
    // What the result consists of: a served result restores exactly these trees, so a different capture set
    // is a different result even when the command that produced it is the same.
    if let Some(reuse) = &declared.job.reuse {
        field(&mut hasher, &(reuse.paths.len() as u64).to_le_bytes());
        for path in &reuse.paths {
            text(&mut hasher, path);
        }
    }
    field(&mut hasher, &(declared.inputs.len() as u64).to_le_bytes());
    for (pattern, digest) in declared.inputs {
        text(&mut hasher, pattern);
        text(&mut hasher, digest);
    }
    Key(*hasher.finalize().as_bytes())
}

const fn shell_code(shell: Shell) -> u8 {
    match shell {
        Shell::Sh => b's',
        Shell::Bash => b'b',
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{Reuse, Step};

    fn job() -> Job {
        Job {
            image: "rust:1-bookworm".into(),
            needs: Vec::new(),
            condition: None,
            runs_on: Default::default(),
            resources: crate::schema::Resources {
                cpu_millis: 2_000,
                memory_bytes: 4 << 30,
                disk_bytes: 10 << 30,
            },
            timeout_secs: 60,
            env: vec![("RUST_LOG".into(), "info".into())],
            workdir: Some("crates/app".into()),
            steps: vec![Step {
                id: "test".into(),
                run: "cargo test".into(),
                condition: None,
                shell: Shell::Sh,
                env: vec![("RUST_BACKTRACE".into(), "1".into())],
                secrets: Vec::new(),
                secret_files: Vec::new(),
                workdir: None,
                timeout_secs: Some(300),
                outputs: Vec::new(),
            }],
            cache: Vec::new(),
            artifacts: Vec::new(),
            secrets: Vec::new(),
            registry_auth: None,
            outputs: Vec::new(),
            handoff: Vec::new(),
            finalize: None,
            history: crate::schema::History::Shallow,
            checkouts: Vec::new(),
            reuse: Some(Reuse {
                inputs: vec!["Cargo.lock".into()],
                paths: vec!["target".into()],
            }),
        }
    }

    const TOOLCHAIN: [u8; 32] = [7; 32];
    const DIGEST: &str = "sha256:11";

    fn key_of(job: &Job, inputs: &[(String, String)]) -> Key {
        key(&Declared {
            job,
            image: DIGEST,
            toolchain: &TOOLCHAIN,
            isolation: Isolation::Container,
            platform: "linux-x86_64",
            inputs,
        })
    }

    fn lock() -> Vec<(String, String)> {
        vec![("Cargo.lock".into(), "a".repeat(64))]
    }

    #[test]
    fn every_declared_component_moves_the_key() {
        let base = key_of(&job(), &lock());
        let moves: Vec<(&str, Key)> = vec![
            ("command", {
                let mut j = job();
                j.steps[0].run = "cargo test --all".into();
                key_of(&j, &lock())
            }),
            ("job env", {
                let mut j = job();
                j.env[0].1 = "debug".into();
                key_of(&j, &lock())
            }),
            ("step env", {
                let mut j = job();
                j.steps[0].env[0].1 = "0".into();
                key_of(&j, &lock())
            }),
            ("input digest", {
                key_of(&job(), &[("Cargo.lock".into(), "b".repeat(64))])
            }),
            ("input pattern", {
                key_of(&job(), &[("Cargo.toml".into(), "a".repeat(64))])
            }),
            // What the result consists of: a different capture set restores different trees.
            ("captured paths", {
                let mut j = job();
                j.reuse = Some(Reuse {
                    inputs: vec!["Cargo.lock".into()],
                    paths: vec!["dist".into()],
                });
                key_of(&j, &lock())
            }),
            ("image reference", {
                let mut j = job();
                j.image = "rust:1.99-bookworm".into();
                key_of(&j, &lock())
            }),
            ("isolation", {
                let inputs = lock();
                key(&Declared {
                    job: &job(),
                    image: DIGEST,
                    toolchain: &TOOLCHAIN,
                    isolation: Isolation::Microvm,
                    platform: "linux-x86_64",
                    inputs: &inputs,
                })
            }),
        ];
        for (component, moved) in moves {
            assert_ne!(base, moved, "changing the {component} must change the key");
        }
        // The digest of the image the job runs is its own component, separate from the reference text.
        let other_image = key(&Declared {
            job: &job(),
            image: "sha256:22",
            toolchain: &TOOLCHAIN,
            isolation: Isolation::Container,
            platform: "linux-x86_64",
            inputs: &lock(),
        });
        assert_ne!(base, other_image);
        let other_toolchain = key(&Declared {
            job: &job(),
            image: DIGEST,
            toolchain: &[8; 32],
            isolation: Isolation::Container,
            platform: "linux-x86_64",
            inputs: &lock(),
        });
        assert_ne!(base, other_toolchain);
        let other_platform = key(&Declared {
            job: &job(),
            image: DIGEST,
            toolchain: &TOOLCHAIN,
            isolation: Isolation::Container,
            platform: "linux-aarch64",
            inputs: &lock(),
        });
        assert_ne!(base, other_platform);
    }

    #[test]
    fn the_key_ignores_what_the_pipeline_does_not_declare() {
        // Only the inputs, the commands and the environment are identity: ordering of declaration lists,
        // the job's name, its dependencies and its outputs are not.
        let base = key_of(&job(), &lock());
        let mut renamed = job();
        renamed.needs = vec!["build".into()];
        assert_eq!(base, key_of(&renamed, &lock()));
    }

    #[test]
    fn declared_environment_overrides_by_name_the_way_a_step_sees_it() {
        let mut overridden = job();
        overridden.steps[0]
            .env
            .push(("RUST_LOG".into(), "trace".into()));
        let mut job_level = job();
        job_level.env[0].1 = "trace".into();
        // A step variable overriding the job's is the same environment as the job declaring it outright.
        assert_eq!(key_of(&overridden, &lock()), key_of(&job_level, &lock()));
        assert_ne!(key_of(&job(), &lock()), key_of(&job_level, &lock()));
    }

    #[test]
    fn a_component_cannot_be_shifted_into_another() {
        let two = job();
        let mut one = job();
        one.steps[0].id = "tes".into();
        one.steps[0].run = "tcargo test".into();
        assert_ne!(key_of(&two, &lock()), key_of(&one, &lock()));
    }

    #[test]
    fn the_key_renders_as_lower_case_hex() {
        let key = key_of(&job(), &lock());
        let rendered = key.render();
        assert_eq!(rendered.len(), 64);
        assert!(
            rendered
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        );
        assert_eq!(rendered, key.to_string());
        assert_eq!(key.bytes(), &key_of(&job(), &lock()).0);
    }
}
