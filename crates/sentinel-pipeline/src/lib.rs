//! `.sentinel.yml` schema 1: bounded strict loading, typed decoding and
//! deterministic compilation. Unsupported syntax is an error, never a
//! silent no-op, so a repository cannot depend on behaviour Sentinel does
//! not implement.

pub mod compile;
pub mod expr;
pub mod hash_files;
pub mod run;
pub mod schema;
pub mod yaml;

use std::fmt;

pub use compile::{CompileError, CompiledJob, CompiledPipeline};
pub use expr::{Context, Expr, Phase, Template, Value};
pub use hash_files::hash_files;
pub use run::{ImageRef, PinnedSource, RunSpec, StepCommand};
pub use schema::{Pipeline, ResourcePolicy, SCHEMA_VERSION, SchemaError};
pub use yaml::YamlError;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Yaml(YamlError),
    Schema(SchemaError),
    Compile(CompileError),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Yaml(e) => write!(f, "yaml: {e}"),
            Self::Schema(e) => write!(f, "schema: {e}"),
            Self::Compile(e) => write!(f, "compile: {e}"),
        }
    }
}
impl std::error::Error for Error {}

/// Load, decode and compile one pipeline file under the default policy.
pub fn compile_str(text: &str) -> Result<CompiledPipeline, Error> {
    compile_with(text, &ResourcePolicy::DEFAULT)
}

pub fn compile_with(text: &str, policy: &ResourcePolicy) -> Result<CompiledPipeline, Error> {
    let root = yaml::load(text).map_err(Error::Yaml)?;
    let pipeline = schema::decode(&root, policy).map_err(Error::Schema)?;
    compile::compile(pipeline).map_err(Error::Compile)
}
