//! Two mistakes in `.github/workflows/ci.yml` that no other check here would notice, because
//! nothing in the build parses the workflow: a file that GitHub refuses to load runs no job at
//! all, and a job that `ci-success` does not list is not enforced (docs/decisions/0007).
//!
//! These are text checks for those two mistakes, not a YAML parser.

use std::fs;
use std::path::Path;

fn workflow(name: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(".github/workflows")
        .join(name);
    fs::read_to_string(path).expect("the workflow can be read")
}

fn workflow_names() -> Vec<String> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join(".github/workflows");
    let mut names: Vec<String> = fs::read_dir(dir)
        .expect(".github/workflows can be read")
        .filter_map(|entry| entry.ok()?.file_name().into_string().ok())
        .filter(|name| {
            Path::new(name)
                .extension()
                .is_some_and(|extension| extension.eq_ignore_ascii_case("yml"))
        })
        .collect();
    names.sort();
    names
}

/// `- run: cargo test --lib store::` is a plain YAML scalar that ends in a colon, which YAML
/// reads as a mapping indicator: the whole file is invalid and no job starts.
#[test]
fn no_run_line_is_a_plain_scalar_that_ends_in_a_colon() {
    for name in workflow_names() {
        for (number, line) in workflow(&name).lines().enumerate() {
            let Some((_, value)) = line.split_once("run:") else {
                continue;
            };
            let value = value.trim();
            let quoted = value.starts_with(['"', '\'', '|', '>']);
            assert!(
                value.is_empty() || quoted || !value.ends_with(':'),
                "{name}:{}: an unquoted `run:` value that ends in a colon is invalid YAML; quote it: {line}",
                number + 1
            );
        }
    }
}

/// The names of the jobs: the keys at two spaces of indent under the top-level `jobs:`.
fn jobs(text: &str) -> Vec<String> {
    let mut in_jobs = false;
    let mut names = Vec::new();
    for line in text.lines() {
        if line.starts_with("jobs:") {
            in_jobs = true;
        } else if in_jobs && !line.is_empty() && !line.starts_with(' ') && !line.starts_with('#') {
            in_jobs = false;
        } else if in_jobs
            && line.starts_with("  ")
            && !line.starts_with("   ")
            && line.trim_end().ends_with(':')
            && !line.trim_start().starts_with('#')
        {
            names.push(line.trim().trim_end_matches(':').to_owned());
        }
    }
    names
}

#[test]
fn every_job_is_listed_in_the_aggregate_check() {
    let text = workflow("ci.yml");
    let jobs = jobs(&text);
    assert!(jobs.len() >= 10, "found only {jobs:?}");
    let needs_line = text
        .lines()
        .find(|line| line.trim_start().starts_with("needs: ["))
        .and_then(|_| text.lines().find(|l| l.contains("needs: [fmt")))
        .expect("ci-success lists its needs on one line");
    for job in jobs.iter().filter(|job| job.as_str() != "ci-success") {
        assert!(
            needs_line.contains(&format!("{job},")) || needs_line.contains(&format!("{job}]")),
            "job `{job}` is not in the needs list of ci-success: {needs_line}"
        );
    }
}
