//! A job that states a matrix is one job per combination, resolved when the pipeline compiles.
//!
//! Every cell is an ordinary job with its own name, so nothing after compilation — the store, the
//! scheduler, the worker, the checks — knows a matrix exists: a cell's check identity is its name, its
//! sandbox, cache scopes and secrets are the declared job's, and its place in the DAG is an ordinary
//! dependency. The bound is refused rather than truncated, because a silently dropped cell is a check
//! that never reports.

use std::collections::HashSet;

use crate::{
    compile::CompileError,
    expr::{Expr, Template, Value, value_text},
    schema::{DeclaredJob, Job, MAX_CELLS_PER_JOB, MAX_JOBS},
};

/// One cell's values: the axis names in declaration order, paired with the value this cell takes.
type Cell = [(String, Value)];

/// What one declared job became: its cell names, empty when the job states no matrix.
struct Declared {
    name: String,
    cells: Vec<String>,
}

/// Every job a pipeline declares, in declaration order, with each matrix job replaced by its cells.
pub fn expand(jobs: Vec<(String, DeclaredJob)>) -> Result<Vec<(String, Job)>, CompileError> {
    let mut declared: Vec<Declared> = Vec::with_capacity(jobs.len());
    let mut combinations: Vec<Vec<Vec<(String, Value)>>> = Vec::with_capacity(jobs.len());
    let mut total = 0usize;
    for (name, job) in &jobs {
        let cells = if job.matrix.is_empty() {
            vec![Vec::new()]
        } else {
            combinations_of(name, &job.matrix)?
        };
        total += cells.len();
        declared.push(Declared {
            name: name.clone(),
            cells: if job.matrix.is_empty() {
                Vec::new()
            } else {
                cells.iter().map(|cell| cell_name(name, cell)).collect()
            },
        });
        combinations.push(cells);
    }
    if total > MAX_JOBS {
        return Err(CompileError::Matrix {
            path: "jobs".to_owned(),
            message: format!(
                "{total} jobs after expanding matrices exceeds the bound of {MAX_JOBS}"
            ),
        });
    }

    let mut out: Vec<(String, Job)> = Vec::with_capacity(total);
    for ((name, declared_job), cells) in jobs.into_iter().zip(combinations) {
        check_refs(&name, &declared_job.job, &declared)?;
        // A dependency on a matrix is a dependency on every cell of it, whatever the dependent is.
        let mut job = declared_job.job;
        job.needs = needs_of(&job.needs, &declared);
        // A job that states no matrix keeps its name, its identity and its bytes; it is still checked,
        // so text that names a matrix value is refused rather than handed to a shell as a literal.
        if declared_job.matrix.is_empty() {
            out.push((name.clone(), substitute(&name, job, &[])?));
            continue;
        }
        let mut seen: HashSet<String> = HashSet::with_capacity(cells.len());
        for cell in &cells {
            let named = cell_name(&name, cell);
            if !seen.insert(named.clone()) {
                return Err(CompileError::Matrix {
                    path: format!("jobs.{name}.matrix"),
                    message: format!(
                        "two combinations both render the cell name `{named}`; one value states a `, ` the other splits on"
                    ),
                });
            }
            out.push((named, substitute(&name, job.clone(), cell)?));
        }
    }
    Ok(out)
}

/// `name (value, value)`: the job name and the cell's values in the order the document declared the
/// axes. A declared job name cannot contain a space or a bracket, so no document can write a cell's
/// name itself and two jobs can never share one.
fn cell_name(name: &str, cell: &Cell) -> String {
    let mut out = String::with_capacity(name.len() + 2 + cell.len() * 8);
    out.push_str(name);
    out.push_str(" (");
    for (i, (_, value)) in cell.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        out.push_str(&value_text(value));
    }
    out.push(')');
    out
}

/// The combinations of one job's axes, last axis varying fastest. Past the bound nothing is kept: the
/// declaration is refused, so a repository never gets a silently narrower matrix.
fn combinations_of(
    name: &str,
    matrix: &[crate::schema::MatrixAxis],
) -> Result<Vec<Vec<(String, Value)>>, CompileError> {
    let mut out: Vec<Vec<(String, Value)>> = vec![Vec::with_capacity(matrix.len())];
    for axis in matrix {
        let cells = out.len();
        let width = axis.values.len();
        let total = cells.saturating_mul(width);
        if total > MAX_CELLS_PER_JOB {
            return Err(CompileError::Matrix {
                path: format!("jobs.{name}.matrix"),
                message: format!(
                    "{total} combinations exceeds the bound of {MAX_CELLS_PER_JOB}; declare fewer axes or values"
                ),
            });
        }
        let mut next: Vec<Vec<(String, Value)>> = Vec::with_capacity(total);
        for cell in &out {
            for value in &axis.values {
                let mut cell = cell.clone();
                cell.push((axis.name.clone(), value.clone()));
                next.push(cell);
            }
        }
        out = next;
    }
    Ok(out)
}

fn undeclared(path: &str, axis: &str) -> CompileError {
    CompileError::Matrix {
        path: path.to_owned(),
        message: format!("`matrix.{axis}` names no matrix axis this job declares"),
    }
}

/// A dependency, a handoff or an expression cannot address a job that is several jobs: each cell is its
/// own job, so the document names one, and the refusal lists the cells it could have named.
fn check_refs(name: &str, job: &Job, declared: &[Declared]) -> Result<(), CompileError> {
    let matrix = |job: &str| {
        declared
            .iter()
            .find(|d| d.name == job && !d.cells.is_empty())
            .map(|d| d.cells.clone())
    };
    if let Some((from, cells)) = job
        .handoff
        .iter()
        .find_map(|h| matrix(&h.from).map(|c| (h.from.clone(), c)))
    {
        return Err(CompileError::Matrix {
            path: format!("jobs.{name}.handoff"),
            message: format!(
                "`{from}` is {} jobs: {}; a handoff takes one job's artifact, and a cell cannot be named here",
                cells.len(),
                cells.join(", ")
            ),
        });
    }
    let mut refs = Vec::new();
    if let Some(condition) = &job.condition {
        condition.referenced_needs(&mut refs);
    }
    for step in &job.steps {
        if let Some(condition) = &step.condition {
            condition.referenced_needs(&mut refs);
        }
    }
    for cache in &job.cache {
        cache.key.referenced_needs(&mut refs);
    }
    if let Some((from, cells)) = refs
        .iter()
        .find_map(|need| matrix(need).map(|c| (need.clone(), c)))
    {
        return Err(CompileError::Matrix {
            path: format!("jobs.{name}"),
            message: format!(
                "`needs.{from}.result` names {} jobs: {}; name one of them",
                cells.len(),
                cells.join(", ")
            ),
        });
    }
    Ok(())
}

/// One cell's job: the declared job with its matrix values rendered, its `needs` read as every cell of a
/// matrix it depends on, and every field a matrix value cannot reach refused.
fn substitute(name: &str, mut job: Job, cell: &Cell) -> Result<Job, CompileError> {
    let at = |field: &str| format!("jobs.{name}.{field}");
    job.image = render_text(&at("image"), &job.image, cell)?;
    for (key, value) in &mut job.env {
        *value = render_text(&at(&format!("env.{key}")), value, cell)?;
    }
    let lookup = |axis: &str| cell.iter().find(|(n, _)| n == axis).map(|(_, v)| v.clone());
    if job.condition.is_some() {
        let path = at("if");
        replace(&mut job.condition, &path, &lookup)?;
    }
    for step in &mut job.steps {
        step.run = render_text(&at(&format!("steps.{}.run", step.id)), &step.run, cell)?;
        for (key, value) in &mut step.env {
            *value = render_text(&at(&format!("steps.{}.env.{key}", step.id)), value, cell)?;
        }
        if step.condition.is_some() {
            let path = at(&format!("steps.{}.if", step.id));
            replace(&mut step.condition, &path, &lookup)?;
        }
    }
    for cache in &mut job.cache {
        let path = at(&format!("cache.{}.key", cache.name));
        cache.key = cache
            .key
            .substitute_matrix(&lookup)
            .map_err(|axis| undeclared(&path, &axis))?;
    }
    refuse_elsewhere(name, &job)?;
    Ok(job)
}

/// A job's dependencies with every matrix name read as the cells it declares.
fn needs_of(needs: &[String], declared: &[Declared]) -> Vec<String> {
    let mut out = Vec::with_capacity(needs.len());
    for need in needs {
        match declared.iter().find(|d| d.name == *need) {
            Some(d) if !d.cells.is_empty() => out.extend(d.cells.iter().cloned()),
            _ => out.push(need.clone()),
        }
    }
    out
}

fn replace(
    condition: &mut Option<Expr>,
    path: &str,
    lookup: &dyn Fn(&str) -> Option<Value>,
) -> Result<(), CompileError> {
    let Some(current) = condition else {
        return Ok(());
    };
    *condition = Some(
        current
            .substitute_matrix(lookup)
            .map_err(|axis| undeclared(path, &axis))?,
    );
    Ok(())
}

/// A matrix value renders in `image`, `env`, `run`, `if` and cache keys and nowhere else: a field that
/// would take one silently as text is refused instead.
fn refuse_elsewhere(name: &str, job: &Job) -> Result<(), CompileError> {
    let at = |field: &str| format!("jobs.{name}.{field}");
    let refuse = |path: String, text: &str| -> Result<(), CompileError> {
        match matrix_in(text) {
            None => Ok(()),
            Some(axis) => Err(CompileError::Matrix {
                path,
                message: format!(
                    "`matrix.{axis}` reaches a job's image, env, run, if and cache keys; it cannot be used here"
                ),
            }),
        }
    };
    if let Some(workdir) = &job.workdir {
        refuse(at("workdir"), workdir)?;
    }
    for label in &job.runs_on.labels {
        refuse(at("runs_on.labels"), label)?;
    }
    for secret in &job.secrets {
        refuse(at("secrets"), secret)?;
    }
    if let Some(auth) = &job.registry_auth {
        refuse(at("registry_auth"), auth)?;
    }
    for output in &job.outputs {
        refuse(at("outputs"), output)?;
    }
    for lock in &job.locks {
        refuse(at("locks"), &lock.name)?;
    }
    for checkout in &job.checkouts {
        refuse(at("checkout.repositories"), &checkout.repo)?;
        refuse(at("checkout.repositories"), &checkout.path)?;
        refuse(at("checkout.repositories"), &checkout.ref_name)?;
    }
    for cache in &job.cache {
        let path = at(&format!("cache.{}", cache.name));
        refuse(path.clone(), &cache.name)?;
        for entry in &cache.paths {
            refuse(path.clone(), entry)?;
        }
    }
    for artifact in &job.artifacts {
        let path = at(&format!("artifacts.{}", artifact.name));
        refuse(path.clone(), &artifact.name)?;
        for entry in &artifact.paths {
            refuse(path.clone(), entry)?;
        }
        if let Some(class) = &artifact.class {
            refuse(path.clone(), class)?;
        }
    }
    for handoff in &job.handoff {
        refuse(at("handoff"), &handoff.artifact)?;
        refuse(at("handoff"), &handoff.into)?;
    }
    if let Some(finalize) = &job.finalize {
        refuse(at("finalize.run"), &finalize.run)?;
        for (key, value) in &finalize.env {
            refuse(at(&format!("finalize.env.{key}")), value)?;
        }
        if let Some(workdir) = &finalize.workdir {
            refuse(at("finalize.workdir"), workdir)?;
        }
    }
    if let Some(reuse) = &job.reuse {
        for pattern in &reuse.inputs {
            refuse(at("reuse.inputs"), pattern)?;
        }
        for path in &reuse.paths {
            refuse(at("reuse.paths"), path)?;
        }
    }
    for step in &job.steps {
        let field = |f: &str| at(&format!("steps.{}.{f}", step.id));
        refuse(field("id"), &step.id)?;
        for secret in &step.secrets {
            refuse(field("secrets"), secret)?;
        }
        for file in &step.secret_files {
            refuse(field("secret_files"), &file.name)?;
            refuse(field("secret_files"), &file.path)?;
        }
        if let Some(workdir) = &step.workdir {
            refuse(field("workdir"), workdir)?;
        }
        for output in &step.outputs {
            refuse(field("outputs"), output)?;
        }
    }
    Ok(())
}

/// The first matrix axis a piece of text names, if it names one at all.
fn matrix_in(text: &str) -> Option<String> {
    if !text.contains("${{") {
        return None;
    }
    let template = Template::parse(text).ok()?;
    let mut used = Vec::new();
    template.referenced_matrix(&mut used);
    used.first().cloned()
}

/// Text that names a matrix value renders the cell's value; every other `${{ … }}` is the text it was,
/// exactly as it was before matrices existed, so a shell script that holds one keeps running.
fn render_text(path: &str, text: &str, cell: &Cell) -> Result<String, CompileError> {
    if !text.contains("${{") {
        return Ok(text.to_owned());
    }
    let mut out = String::with_capacity(text.len() + 8);
    let mut rest = text;
    while let Some(start) = rest.find("${{") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 3..];
        // An interpolation that never closes is text, and always was.
        let Some(end) = after.find("}}") else {
            out.push_str(&rest[start..]);
            return Ok(out);
        };
        let inner = &after[..end];
        match bare_axis(inner) {
            Some(axis) => match cell.iter().find(|(name, _)| *name == axis) {
                Some((_, value)) => out.push_str(&value_text(value)),
                None => return Err(undeclared(path, &axis)),
            },
            None => {
                if let Ok(expr) = Expr::parse(inner.trim()) {
                    let mut used = Vec::new();
                    expr.referenced_matrix(&mut used);
                    if let Some(axis) = used.first() {
                        return Err(CompileError::Matrix {
                            path: path.to_owned(),
                            message: format!(
                                "`matrix.{axis}` renders here only as `${{{{ matrix.{axis} }}}}`"
                            ),
                        });
                    }
                }
                out.push_str(&rest[start..start + 3 + end + 2]);
            }
        }
        rest = &after[end + 2..];
    }
    out.push_str(rest);
    Ok(out)
}

/// `matrix.<axis>` and nothing else: a comparison of a matrix value is an `if`, not a `run`.
fn bare_axis(inner: &str) -> Option<String> {
    match Expr::parse(inner.trim()) {
        Ok(Expr::Path(p)) if p.len() == 2 && p[0] == "matrix" => Some(p[1].clone()),
        _ => None,
    }
}
