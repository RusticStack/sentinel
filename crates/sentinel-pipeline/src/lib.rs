//! Unsupported syntax is an error, never a silent no-op.

pub mod compile;
pub mod cron;
pub mod explain;
pub mod expr;
pub(crate) mod glob;
pub mod hash_files;
pub mod input;
pub mod policy;
pub mod reuse;
pub mod run;
pub mod schema;
pub mod workflow;
pub mod yaml;

use std::fmt;

pub use compile::{CompileError, CompiledJob, CompiledPipeline, job_check_name};
pub use cron::Cron;
pub use explain::Explanation;
pub use expr::{Context, Expr, Phase, Template, Value};
pub use hash_files::hash_files;
pub use input::{InputError, InputKind, InputSpec, InputValue, Inputs};
pub use policy::{Event, EventKind, RefFilter, Triggers};
pub use run::{ImageRef, PinnedSource, RunSpec, StepCommand};
pub use schema::{Document, Pipeline, ResourcePolicy, SCHEMA_VERSION, SchemaError};
pub use yaml::YamlError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Yaml(YamlError),
    Schema(SchemaError),
    Compile(CompileError),
    /// A document declaring several pipelines: naming one is the caller's choice, never a default.
    Ambiguous {
        pipelines: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Yaml(e) => write!(f, "yaml: {e}"),
            Self::Schema(e) => write!(f, "schema: {e}"),
            Self::Compile(e) => write!(f, "compile: {e}"),
            Self::Ambiguous { pipelines } => write!(
                f,
                "pipelines: the document declares {pipelines} pipelines; name one"
            ),
        }
    }
}
impl std::error::Error for Error {}

/// Every pipeline a document declares: its unnamed one, then its named ones ascending by name.
pub fn compile_document(text: &str) -> Result<Vec<CompiledPipeline>, Error> {
    compile_document_with(text, &ResourcePolicy::DEFAULT)
}

pub fn compile_document_with(
    text: &str,
    policy: &ResourcePolicy,
) -> Result<Vec<CompiledPipeline>, Error> {
    let root = yaml::load(text).map_err(Error::Yaml)?;
    let document = schema::decode(&root, policy).map_err(Error::Schema)?;
    compile::compile_document(document).map_err(Error::Compile)
}

/// The one pipeline a document declares, refusing a document that declares several.
pub fn compile_str(text: &str) -> Result<CompiledPipeline, Error> {
    compile_with(text, &ResourcePolicy::DEFAULT)
}

pub fn compile_with(text: &str, policy: &ResourcePolicy) -> Result<CompiledPipeline, Error> {
    let mut pipelines = compile_document_with(text, policy)?;
    match pipelines.len() {
        1 => Ok(pipelines.pop().expect("one pipeline")),
        n => Err(Error::Ambiguous { pipelines: n }),
    }
}
