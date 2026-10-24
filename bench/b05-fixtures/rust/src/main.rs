use clap::Parser;
use rayon::prelude::*;

#[derive(Parser)]
struct Args {
    #[arg(default_value_t = 1000)]
    n: u64,
}

#[derive(serde::Serialize)]
struct Out {
    sum: u64,
    matched: bool,
}

pub fn compute(n: u64) -> Out {
    let sum: u64 = (0..n).into_par_iter().sum();
    let matched = regex::Regex::new("^[0-9]+$").is_ok_and(|r| r.is_match(&sum.to_string()));
    Out { sum, matched }
}

#[tokio::main]
async fn main() {
    let args = Args::parse();
    let _app: axum::Router = axum::Router::new();
    println!(
        "{}",
        serde_json::to_string(&compute(args.n)).unwrap_or_default()
    );
}

#[cfg(test)]
mod tests {
    #[test]
    fn sums() {
        assert_eq!(super::compute(10).sum, 45);
    }
}
