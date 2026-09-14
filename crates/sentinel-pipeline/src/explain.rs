//! Offline explanation of a compiled pipeline: what will run, in what
//! order, with which budgets, and what the run will need from outside the
//! file. Everything here is derived from the compiled form alone. Runtime
//! inputs (event context, dependency outcomes, `hash_files`) are reported
//! as *unresolved* with the phase that resolves them; they are never given
//! placeholder values, and secrets are listed by name only.
use serde::Serialize;

use crate::{
    compile::CompiledPipeline,
    expr::{Expr, Phase, Template},
    policy::Triggers,
    run::ImageRef,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Explanation {
    pub schema: &'static str,
    pub digest: String,
    pub triggers: Vec<&'static str>,
    /// Ref filters of the declared triggers, in kind order; a kind with no
    /// filter appears as the empty pattern lists.
    pub trigger_filters: Vec<TriggerFilterExplanation>,
    pub concurrency: Option<ConcurrencyExplanation>,
    /// Execution order: every job's dependencies appear before it.
    pub jobs: Vec<JobExplanation>,
    /// What the run needs granted before it can execute.
    pub requires: Requirements,
    /// Every input that cannot be known offline, with the phase that resolves it.
    pub unresolved: Vec<Unresolved>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct TriggerFilterExplanation {
    pub kind: &'static str,
    pub branches: Vec<String>,
    pub tags: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ConcurrencyExplanation {
    pub group: String,
    pub cancel_in_progress: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct JobExplanation {
    pub name: String,
    pub needs: Vec<String>,
    pub image: String,
    /// `true` only when the reference carries a digest.
    pub image_pinned: bool,
    pub condition: Option<String>,
    pub cpu_millis: u32,
    pub memory_bytes: u64,
    pub disk_bytes: u64,
    pub timeout_secs: u64,
    pub steps: Vec<StepExplanation>,
    pub caches: Vec<CacheExplanation>,
    pub artifacts: Vec<String>,
    pub secrets: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct StepExplanation {
    pub id: String,
    pub condition: Option<String>,
    pub timeout_secs: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CacheExplanation {
    pub name: String,
    /// The key template as written; interpolations are not evaluated.
    pub key: String,
    /// `true` when the key is a literal and therefore known offline.
    pub key_known: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Requirements {
    /// Read access to the pinned source is always required.
    pub repository_read: bool,
    /// Secret names that must be granted to the repository; values are never shown.
    pub secrets: Vec<String>,
    /// Cache names the worker will materialise (needs a cache scope grant).
    pub caches: Vec<String>,
    /// Artifact names that will be published (needs artifact storage).
    pub artifacts: Vec<String>,
    /// Images that will be pulled by tag and pinned at first pull.
    pub unpinned_images: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Unresolved {
    /// Dotted location, e.g. `jobs.report.if` or `jobs.test.cache.deps.key`.
    pub path: String,
    /// The expression text.
    pub expression: String,
    pub resolves_at: &'static str,
}

const fn phase_name(p: Phase) -> &'static str {
    match p {
        Phase::Compile => "compile",
        Phase::Dispatch => "dispatch",
        Phase::Schedule => "schedule",
        Phase::Worker => "worker",
    }
}

fn trigger_kinds(on: &Triggers) -> Vec<&'static str> {
    let mut kinds = Vec::with_capacity(4);
    if on.push.is_some() {
        kinds.push("push");
    }
    if on.pull_request.is_some() {
        kinds.push("pull_request");
    }
    if on.tag.is_some() {
        kinds.push("tag");
    }
    if on.manual {
        kinds.push("manual");
    }
    kinds
}

fn trigger_filters(on: &Triggers) -> Vec<TriggerFilterExplanation> {
    let mut out = Vec::with_capacity(3);
    for (kind, filter) in [
        ("push", &on.push),
        ("pull_request", &on.pull_request),
        ("tag", &on.tag),
    ] {
        if let Some(filter) = filter {
            out.push(TriggerFilterExplanation {
                kind,
                branches: filter.branches.clone(),
                tags: filter.tags.clone(),
            });
        }
    }
    out
}

fn note_expr(out: &mut Vec<Unresolved>, path: String, e: &Expr) {
    let phase = e.min_phase();
    if phase > Phase::Compile {
        out.push(Unresolved {
            path,
            expression: e.to_string(),
            resolves_at: phase_name(phase),
        });
    }
}

fn note_template(out: &mut Vec<Unresolved>, path: String, t: &Template) {
    let phase = t.min_phase();
    if phase > Phase::Compile {
        out.push(Unresolved {
            path,
            expression: t.to_string(),
            resolves_at: phase_name(phase),
        });
    }
}

fn push_unique(v: &mut Vec<String>, s: &str) {
    if !v.iter().any(|x| x == s) {
        v.push(s.to_owned());
    }
}

impl Explanation {
    pub fn of(p: &CompiledPipeline) -> Explanation {
        let mut unresolved = Vec::new();
        let mut requires = Requirements {
            repository_read: true,
            ..Requirements::default()
        };
        let concurrency = p.concurrency.as_ref().map(|c| {
            note_template(&mut unresolved, "concurrency.group".into(), &c.group);
            ConcurrencyExplanation {
                group: c.group.to_string(),
                cancel_in_progress: c.cancel_in_progress,
            }
        });
        let mut jobs = Vec::with_capacity(p.jobs.len());
        for j in &p.jobs {
            let s = &j.spec;
            let pinned = ImageRef::parse(&s.image).is_ok_and(|r| r.is_pinned());
            if !pinned {
                push_unique(&mut requires.unpinned_images, &s.image);
            }
            if let Some(c) = &s.condition {
                note_expr(&mut unresolved, format!("jobs.{}.if", j.name), c);
            }
            let steps = s
                .steps
                .iter()
                .map(|st| {
                    if let Some(c) = &st.condition {
                        note_expr(
                            &mut unresolved,
                            format!("jobs.{}.steps.{}.if", j.name, st.id),
                            c,
                        );
                    }
                    StepExplanation {
                        id: st.id.clone(),
                        condition: st.condition.as_ref().map(ToString::to_string),
                        timeout_secs: st.timeout_secs.unwrap_or(s.timeout_secs),
                    }
                })
                .collect();
            let caches = s
                .cache
                .iter()
                .map(|c| {
                    note_template(
                        &mut unresolved,
                        format!("jobs.{}.cache.{}.key", j.name, c.name),
                        &c.key,
                    );
                    push_unique(&mut requires.caches, &c.name);
                    CacheExplanation {
                        name: c.name.clone(),
                        key: c.key.to_string(),
                        key_known: c.key.is_literal(),
                    }
                })
                .collect();
            for a in &s.artifacts {
                push_unique(&mut requires.artifacts, &a.name);
            }
            for name in &s.secrets {
                push_unique(&mut requires.secrets, name);
            }
            jobs.push(JobExplanation {
                name: j.name.clone(),
                needs: j
                    .needs
                    .iter()
                    .map(|&i| p.jobs[i as usize].name.clone())
                    .collect(),
                image: s.image.clone(),
                image_pinned: pinned,
                condition: s.condition.as_ref().map(ToString::to_string),
                cpu_millis: s.resources.cpu_millis,
                memory_bytes: s.resources.memory_bytes,
                disk_bytes: s.resources.disk_bytes,
                timeout_secs: s.timeout_secs,
                steps,
                caches,
                artifacts: s.artifacts.iter().map(|a| a.name.clone()).collect(),
                secrets: s.secrets.clone(),
            });
        }
        requires.secrets.sort();
        Explanation {
            schema: "sentinel.explain/1",
            digest: format!("{:032x}", p.digest),
            triggers: trigger_kinds(&p.on),
            trigger_filters: trigger_filters(&p.on),
            concurrency,
            jobs,
            requires,
            unresolved,
        }
    }

    /// Human-readable rendering for the CLI.
    pub fn render_text(&self) -> String {
        use std::fmt::Write;
        let mut s = String::new();
        let _ = writeln!(s, "pipeline digest {}", self.digest);
        let _ = writeln!(s, "triggers: {}", self.triggers.join(", "));
        for filter in &self.trigger_filters {
            if filter.branches.is_empty() && filter.tags.is_empty() {
                continue;
            }
            let patterns: Vec<&str> = filter
                .branches
                .iter()
                .chain(filter.tags.iter())
                .map(String::as_str)
                .collect();
            let _ = writeln!(s, "  {} on {}", filter.kind, patterns.join(", "));
        }
        if let Some(c) = &self.concurrency {
            let _ = writeln!(
                s,
                "concurrency: {} (cancel in progress: {})",
                c.group, c.cancel_in_progress
            );
        }
        for j in &self.jobs {
            let _ = writeln!(s, "\njob {}", j.name);
            if !j.needs.is_empty() {
                let _ = writeln!(s, "  needs: {}", j.needs.join(", "));
            }
            let _ = writeln!(
                s,
                "  image: {}{}",
                j.image,
                if j.image_pinned {
                    ""
                } else {
                    " (unpinned: resolved at first pull)"
                }
            );
            if let Some(c) = &j.condition {
                let _ = writeln!(s, "  if: {c}");
            }
            let _ = writeln!(
                s,
                "  resources: {} cores, {} MiB memory, {} GiB disk; timeout {}s",
                j.cpu_millis as f64 / 1000.0,
                j.memory_bytes >> 20,
                j.disk_bytes >> 30,
                j.timeout_secs
            );
            for st in &j.steps {
                let _ = write!(s, "  step {} (timeout {}s)", st.id, st.timeout_secs);
                if let Some(c) = &st.condition {
                    let _ = write!(s, " if {c}");
                }
                s.push('\n');
            }
            for c in &j.caches {
                let _ = writeln!(
                    s,
                    "  cache {}: key {}{}",
                    c.name,
                    c.key,
                    if c.key_known {
                        ""
                    } else {
                        " (resolved by worker)"
                    }
                );
            }
            if !j.artifacts.is_empty() {
                let _ = writeln!(s, "  artifacts: {}", j.artifacts.join(", "));
            }
            if !j.secrets.is_empty() {
                let _ = writeln!(s, "  secrets: {}", j.secrets.join(", "));
            }
        }
        let _ = writeln!(s, "\nrequires:");
        let _ = writeln!(s, "  repository read access");
        for name in &self.requires.secrets {
            let _ = writeln!(
                s,
                "  secret {name} granted to this repository (value not checked offline)"
            );
        }
        for name in &self.requires.caches {
            let _ = writeln!(s, "  cache scope {name}");
        }
        for name in &self.requires.artifacts {
            let _ = writeln!(s, "  artifact storage for {name}");
        }
        for img in &self.requires.unpinned_images {
            let _ = writeln!(s, "  registry access to resolve {img}");
        }
        if !self.unresolved.is_empty() {
            let _ = writeln!(s, "\nunresolved until runtime:");
            for u in &self.unresolved {
                let _ = writeln!(s, "  {} = {} (at {})", u.path, u.expression, u.resolves_at);
            }
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compile_str;

    #[test]
    fn explanation_lists_requirements_and_unresolved_inputs_without_values() {
        let text = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../fixtures/pipelines/valid/conditions.yml"
        ))
        .unwrap()
        .replace(
            "    image: busybox\n    cache:",
            "    image: busybox\n    secrets: [DEPLOY_TOKEN]\n    cache:",
        );
        let p = compile_str(&text).unwrap();
        let e = Explanation::of(&p);
        assert_eq!(
            e.jobs.iter().map(|j| j.name.as_str()).collect::<Vec<_>>(),
            ["test", "report"]
        );
        assert_eq!(e.jobs[1].needs, ["test"]);
        assert!(!e.jobs[1].image_pinned);
        assert_eq!(e.requires.secrets, ["DEPLOY_TOKEN"]);
        assert_eq!(e.requires.caches, ["deps"]);
        assert_eq!(e.requires.unpinned_images, ["busybox"]);
        assert!(e.requires.repository_read);
        let cache = &e.jobs[1].caches[0];
        assert!(!cache.key_known);
        assert!(
            cache
                .key
                .contains("hash_files('Cargo.lock', 'crates/*/Cargo.toml')")
        );
        let paths: Vec<&str> = e.unresolved.iter().map(|u| u.path.as_str()).collect();
        assert_eq!(
            paths,
            [
                "concurrency.group",
                "jobs.test.steps.main-only.if",
                "jobs.report.if",
                "jobs.report.steps.on-failure.if",
                "jobs.report.cache.deps.key"
            ]
        );
        assert_eq!(e.unresolved[4].resolves_at, "worker");
        assert_eq!(e.unresolved[2].resolves_at, "schedule");
        let text = e.render_text();
        assert!(text.contains("secret DEPLOY_TOKEN granted"));
        assert!(text.contains("resolved by worker"));
        assert!(!text.contains("sha256"), "no invented hash values");
        let json = serde_json::to_string(&e).unwrap();
        assert!(json.contains("\"schema\":\"sentinel.explain/1\""));
    }
}
