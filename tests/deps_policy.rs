//! The direct dependency list, as a reviewable allowlist.
//!
//! Every direct dependency is compiled into the process that holds the OAuth credentials and
//! reads the mail, so the list is part of the security design. This test fails when a direct
//! dependency is added, removed or given another feature set without the allowlist below
//! changing in the same pull request, which puts the change in front of the reviewer. It also
//! fails on a dependency that is not pinned to an exact version or comes from anywhere but
//! crates.io.
//!
//! It does not judge whether a crate is "official or very widely used"; that is the author's
//! statement in the pull request and the reviewer's call (CONTRIBUTING.md). Version numbers are
//! deliberately not compared, so Dependabot's version bumps stay mergeable.
//! Why: docs/decisions/0004-dependency-policy-and-libraries.md.

/// A direct dependency the project has agreed to depend on.
struct Allowed {
    /// The manifest table: `dependencies`, `dev-dependencies` or `build-dependencies`.
    table: &'static str,
    name: &'static str,
    default_features: bool,
    /// The enabled features, sorted.
    features: &'static [&'static str],
}

/// To add a dependency or enable a feature: add or change a line here, and justify it in the
/// pull request (what it replaces, how many crates it adds, why a little code would not do).
const ALLOWED: &[Allowed] = &[
    Allowed {
        table: "dependencies",
        name: "html2text",
        default_features: true,
        features: &[],
    },
    Allowed {
        table: "dependencies",
        name: "lettre",
        default_features: false,
        features: &["builder"],
    },
    Allowed {
        table: "dependencies",
        name: "oauth2",
        default_features: false,
        features: &[],
    },
    Allowed {
        table: "dependencies",
        name: "ureq",
        default_features: false,
        features: &["rustls"],
    },
    Allowed {
        table: "dev-dependencies",
        name: "proptest",
        default_features: false,
        features: &["std"],
    },
];

#[cfg(test)]
mod manifest {
    use std::collections::BTreeSet;
    use std::fs;
    use std::path::Path;

    /// A dependency as written in `Cargo.toml`.
    #[derive(Debug, PartialEq, Eq)]
    pub struct Declared {
        pub table: String,
        pub name: String,
        pub requirement: String,
        pub default_features: bool,
        pub features: Vec<String>,
    }

    /// Reads the dependency tables of `Cargo.toml`. It understands exactly the two forms this
    /// project uses, `name = "=x.y.z"` and a one-line inline table with `version`,
    /// `default-features` and `features`, and refuses everything else (sub-tables, `git`,
    /// `path`, `registry`, `package`, `optional`, `workspace`, target-specific tables), so
    /// that a new form cannot slip past the allowlist unnoticed. Extend it deliberately.
    pub fn declared() -> Vec<Declared> {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
        let text = fs::read_to_string(path).expect("Cargo.toml can be read");
        let mut table = String::new();
        let mut out = Vec::new();
        for (number, raw) in text.lines().enumerate() {
            let line = raw.split('#').next().unwrap_or_default().trim();
            if line.is_empty() {
                continue;
            }
            if let Some(header) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
                assert!(
                    !header.contains("dependencies")
                        || matches!(
                            header,
                            "dependencies" | "dev-dependencies" | "build-dependencies"
                        ),
                    "Cargo.toml line {}: the dependency table [{header}] is a form tests/deps_policy.rs does not read; \
                     extend the parser deliberately before using it",
                    number + 1
                );
                table = header.to_owned();
                continue;
            }
            if matches!(
                table.as_str(),
                "dependencies" | "dev-dependencies" | "build-dependencies"
            ) {
                out.push(parse(&table, line, number + 1));
            }
        }
        out
    }

    fn parse(table: &str, line: &str, number: usize) -> Declared {
        let (name, value) = line.split_once('=').expect("a `name = value` line");
        let (name, value) = (name.trim(), value.trim());
        let mut declared = Declared {
            table: table.to_owned(),
            name: name.to_owned(),
            requirement: String::new(),
            default_features: true,
            features: Vec::new(),
        };
        if let Some(requirement) = string(value) {
            declared.requirement = requirement;
            return declared;
        }
        let inner = value
            .strip_prefix('{')
            .and_then(|v| v.strip_suffix('}'))
            .unwrap_or_else(|| panic!("Cargo.toml line {number}: `{name}` uses a form the dependency test does not read"));
        for item in split_top_level(inner) {
            let (key, value) = item
                .split_once('=')
                .expect("`key = value` inside an inline table");
            let (key, value) = (key.trim(), value.trim());
            match key {
                "version" => declared.requirement = string(value).expect("version is a string"),
                "default-features" => declared.default_features = value.parse().expect("a boolean"),
                "features" => {
                    let list = value
                        .strip_prefix('[')
                        .and_then(|v| v.strip_suffix(']'))
                        .expect("a list");
                    declared.features = split_top_level(list)
                        .iter()
                        .filter_map(|f| string(f.trim()))
                        .collect();
                    declared.features.sort();
                }
                other => panic!(
                    "Cargo.toml line {number}: `{name}` sets `{other}`, which the dependency policy does not allow \
                     (git, path, registry, package, optional and workspace dependencies need a deliberate change here)"
                ),
            }
        }
        declared
    }

    fn string(value: &str) -> Option<String> {
        value
            .strip_prefix('"')
            .and_then(|v| v.strip_suffix('"'))
            .map(str::to_owned)
    }

    /// Splits on commas that are not inside quotes or brackets.
    fn split_top_level(text: &str) -> Vec<&str> {
        let (mut parts, mut depth, mut quoted, mut start) = (Vec::new(), 0_i32, false, 0);
        for (i, c) in text.char_indices() {
            match c {
                '"' => quoted = !quoted,
                '[' if !quoted => depth += 1,
                ']' if !quoted => depth -= 1,
                ',' if !quoted && depth == 0 => {
                    parts.push(&text[start..i]);
                    start = i + 1;
                }
                _ => {}
            }
        }
        if !text[start..].trim().is_empty() {
            parts.push(&text[start..]);
        }
        parts
    }

    pub fn names(entries: impl Iterator<Item = (String, String)>) -> BTreeSet<(String, String)> {
        entries.collect()
    }
}

#[test]
fn the_direct_dependencies_are_exactly_the_allowlist() {
    let declared = manifest::declared();
    let found = manifest::names(declared.iter().map(|d| (d.table.clone(), d.name.clone())));
    let allowed = manifest::names(
        ALLOWED
            .iter()
            .map(|a| (a.table.to_owned(), a.name.to_owned())),
    );
    assert_eq!(
        found, allowed,
        "the direct dependencies in Cargo.toml (left) differ from the allowlist in \
         tests/deps_policy.rs (right). A dependency change must update the allowlist in the same \
         pull request and be justified there (CONTRIBUTING.md, docs/decisions/0004)."
    );
}

#[test]
fn every_dependency_has_the_allowed_features() {
    for dependency in manifest::declared() {
        let allowed = ALLOWED
            .iter()
            .find(|a| a.table == dependency.table && a.name == dependency.name)
            .unwrap_or_else(|| panic!("{} is not allowlisted", dependency.name));
        assert_eq!(
            dependency.default_features, allowed.default_features,
            "{}: default-features differs from the allowlist",
            dependency.name
        );
        assert_eq!(
            dependency.features, allowed.features,
            "{}: the enabled features differ from the allowlist (enabling a feature is a dependency change)",
            dependency.name
        );
    }
}

#[test]
fn every_dependency_is_pinned_to_an_exact_version() {
    for dependency in manifest::declared() {
        let version = dependency.requirement.strip_prefix('=').unwrap_or_else(|| {
            panic!(
                "{}: `{}` is not an exact `=x.y.z` pin",
                dependency.name, dependency.requirement
            )
        });
        let core = version.split(['-', '+']).next().unwrap_or_default();
        let parts: Vec<&str> = core.split('.').collect();
        assert!(
            parts.len() == 3
                && parts
                    .iter()
                    .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit())),
            "{}: `{}` is not an exact `=x.y.z` pin",
            dependency.name,
            dependency.requirement
        );
    }
}

#[test]
fn the_lockfile_is_committed() {
    let lock = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.lock");
    assert!(
        lock.is_file(),
        "Cargo.lock must be committed: CI and releases build with --locked"
    );
}
