//! Rule table version 1: how each construct the inventory records translates into a
//! native `.sentinel.yml`. Nothing is left undecided: every construct is translatable,
//! translatable with a stated change, or unsupported with its reason.
//!
//! A table version is a promise: the same constructs classify the same way, with the same
//! text, until the version moves, which is a compatibility entry.

pub const RULE_TABLE_VERSION: u16 = 1;

/// A construct a workflow uses, as the inventory records it. Job and step keys outside
/// this vocabulary are refused by the decoder, so the table is total by construction.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum Construct {
    Trigger {
        event: String,
    },
    Permissions,
    Concurrency,
    Env,
    Defaults,
    Needs,
    Condition,
    Timeout,
    Matrix,
    Container,
    Services,
    Environment,
    Outputs,
    ReusableWorkflow,
    ContinueOnError,
    Shell {
        shell: String,
    },
    Workdir,
    RunStep,
    /// One `uses:` step, as written (`actions/checkout@v4`, `docker://alpine:3`,
    /// `./.github/actions/build`).
    Action {
        uses: String,
    },
}

impl Construct {
    /// The name the preview shows for the construct.
    pub fn name(&self) -> &str {
        match self {
            Self::Trigger { .. } => "on",
            Self::Permissions => "permissions",
            Self::Concurrency => "concurrency",
            Self::Env => "env",
            Self::Defaults => "defaults",
            Self::Needs => "needs",
            Self::Condition => "if",
            Self::Timeout => "timeout-minutes",
            Self::Matrix => "strategy.matrix",
            Self::Container => "container",
            Self::Services => "services",
            Self::Environment => "environment",
            Self::Outputs => "outputs",
            Self::ReusableWorkflow => "jobs.<id>.uses",
            Self::ContinueOnError => "continue-on-error",
            Self::Shell { .. } => "shell",
            Self::Workdir => "working-directory",
            Self::RunStep => "run",
            Self::Action { .. } => "uses",
        }
    }
}

/// What the native path does with one construct.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Rule {
    Translatable,
    WithChange { change: &'static str },
    Unsupported { reason: &'static str },
}

impl Rule {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Translatable => "translatable",
            Self::WithChange { .. } => "with_change",
            Self::Unsupported { .. } => "unsupported",
        }
    }

    /// The stated change or the reason a construct is unsupported; `None` when it
    /// translates as it is.
    pub const fn note(self) -> Option<&'static str> {
        match self {
            Self::Translatable => None,
            Self::WithChange { change } => Some(change),
            Self::Unsupported { reason } => Some(reason),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RuleTable {
    version: u16,
}

impl RuleTable {
    pub const V1: Self = Self {
        version: RULE_TABLE_VERSION,
    };

    pub const fn version(self) -> u16 {
        self.version
    }

    pub fn classify(self, construct: &Construct) -> Rule {
        match construct {
            Construct::Trigger { event } => match event.as_str() {
                "push" | "pull_request" | "merge_group" | "workflow_dispatch" => Rule::Translatable,
                "schedule" => Rule::WithChange {
                    change: "the crons become a stored per-repository schedule; the translated \
                             pipeline accepts a scheduled run",
                },
                "workflow_call" | "workflow_run" => Rule::Unsupported {
                    reason: "reusable pipelines and workflow chaining do not exist yet (I10)",
                },
                "pull_request_target" => Rule::Unsupported {
                    reason: "the privileged pull_request_target context has no native equivalent",
                },
                _ => Rule::Unsupported {
                    reason: "no native trigger exists for this event",
                },
            },
            Construct::Permissions => Rule::WithChange {
                change: "the source credential's scopes replace GITHUB_TOKEN; a job holds no \
                         ambient token",
            },
            Construct::Concurrency => Rule::Translatable,
            Construct::Env => Rule::Translatable,
            Construct::Defaults => Rule::WithChange {
                change: "steps run under sh or bash, and `defaults.run` becomes the step's \
                         `shell` and `workdir`",
            },
            Construct::Needs => Rule::Translatable,
            Construct::Condition => Rule::WithChange {
                change: "`if` becomes a pipeline condition, written in the pipeline expression \
                         language and type-checked at compile time",
            },
            Construct::Timeout => Rule::Translatable,
            Construct::Matrix => Rule::WithChange {
                change: "one declared job per matrix cell; bounded matrices do not exist yet \
                         (I10)",
            },
            Construct::Container => Rule::Unsupported {
                reason: "a container needs a Docker daemon, which only a microVM sandbox can \
                         offer (I08)",
            },
            Construct::Services => Rule::Unsupported {
                reason: "a service container needs a Docker daemon (I08) and is not in the \
                         schema (I10)",
            },
            Construct::Environment => Rule::Unsupported {
                reason: "deployment environments with their secrets and approvals are not \
                         modelled",
            },
            Construct::Outputs => Rule::WithChange {
                change: "a job's outputs become the step `outputs` that write them and the job's own \
                         `outputs`, plain text in the run's record",
            },
            Construct::ReusableWorkflow => Rule::Unsupported {
                reason: "reusable pipelines do not exist yet (I10)",
            },
            Construct::ContinueOnError => Rule::Unsupported {
                reason: "a failing step fails its job; the pipeline has no continue-on-error",
            },
            Construct::Shell { shell } => match shell.as_str() {
                "sh" | "bash" => Rule::Translatable,
                _ => Rule::Unsupported {
                    reason: "steps run under sh or bash; no other shell is available",
                },
            },
            Construct::Workdir => Rule::Translatable,
            Construct::RunStep => Rule::Translatable,
            Construct::Action { uses } => classify_action(uses),
        }
    }
}

fn classify_action(uses: &str) -> Rule {
    if uses.starts_with("docker://") {
        return Rule::Unsupported {
            reason: "a Docker step needs a daemon, which only a microVM sandbox can offer \
                     (I08)",
        };
    }
    if uses.starts_with("./") {
        return Rule::Unsupported {
            reason: "a local action's own definition is not part of the workflow; the step is \
                     rewritten as commands or the job stays on GitHub",
        };
    }
    let Some((repository, _)) = uses.split_once('@') else {
        return Rule::Unsupported {
            reason: "an action reference without a version cannot be pinned",
        };
    };
    let repository = repository.to_ascii_lowercase();
    match repository.as_str() {
        "actions/checkout" => Rule::Translatable,
        "actions/cache"
        | "actions/cache/restore"
        | "actions/cache/save"
        | "swatinem/rust-cache" => Rule::WithChange {
            change: "the action becomes a declared cache: one of Sentinel's three classes, \
                         a key template and the paths to keep",
        },
        "actions/upload-artifact" => Rule::WithChange {
            change: "the upload becomes an artifact declared on the job, published at the end \
                     of the job",
        },
        "actions/download-artifact" => Rule::Unsupported {
            reason: "artifact handoff between jobs does not exist yet (I04)",
        },
        "actions/setup-node"
        | "actions/setup-python"
        | "actions/setup-go"
        | "actions/setup-java"
        | "actions/setup-dotnet"
        | "actions/setup-ruby"
        | "dtolnay/rust-toolchain"
        | "actions-rs/toolchain" => Rule::WithChange {
            change: "a digest-pinned toolchain image replaces the setup step; the selected \
                     version is recorded, never substituted silently",
        },
        "docker/build-push-action"
        | "docker/login-action"
        | "docker/setup-buildx-action"
        | "docker/setup-qemu-action" => Rule::Unsupported {
            reason: "Docker builds need a daemon, which only a microVM sandbox can offer (I08)",
        },
        _ => Rule::Unsupported {
            reason: "an action runs only in runner mode; the step is rewritten as commands or \
                     the job stays on GitHub",
        },
    }
}
