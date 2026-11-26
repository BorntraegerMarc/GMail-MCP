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

/// The one platform-specific dependency table the project uses, for the macOS Keychain crate.
/// Other platforms compile a stub store, so that crate is not built there.
const MACOS_TABLE: &str = "target.'cfg(target_os = \"macos\")'.dependencies";

/// A direct dependency the project has agreed to depend on.
struct Allowed {
    /// The manifest table: `dependencies`, `dev-dependencies`, `build-dependencies` or
    /// [`MACOS_TABLE`].
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
        name: "base64",
        default_features: false,
        features: &["std"],
    },
    Allowed {
        table: "dependencies",
        name: "oauth2",
        default_features: false,
        features: &[],
    },
    Allowed {
        table: "dependencies",
        name: "serde_json",
        default_features: false,
        features: &["std"],
    },
    Allowed {
        table: "dependencies",
        name: "ureq",
        default_features: false,
        features: &["rustls"],
    },
    Allowed {
        table: MACOS_TABLE,
        name: "security-framework",
        default_features: false,
        features: &[],
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
    /// `default-features` and `features`, and refuses the forms it recognises as something
    /// else (sub-tables, `git`, `path`, `registry`, `package`, `optional`, `workspace`, and a
    /// target-specific table other than the macOS one). It is a hand-written reader, so it only
    /// sees what it was written to see; `cargo_itself_sees_exactly_the_allowlisted_direct_dependencies`
    /// below asks Cargo, which reads every form, and is the complete check.
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
                    !header.starts_with("patch") && !header.starts_with("replace"),
                    "Cargo.toml line {}: [{header}] swaps a dependency's source behind the allowlist's back",
                    number + 1
                );
                assert!(
                    !header.contains("dependencies")
                        || matches!(
                            header,
                            "dependencies" | "dev-dependencies" | "build-dependencies"
                        )
                        || header == super::MACOS_TABLE,
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
            ) || table == super::MACOS_TABLE
            {
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

/// A Cargo configuration file can replace the crate registry or patch a crate without
/// touching `Cargo.toml`, so the project has none.
#[test]
fn no_cargo_configuration_overrides_the_sources() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
    for name in [".cargo/config.toml", ".cargo/config", "vendor"] {
        assert!(!root.join(name).exists(), "{name} is not allowed");
    }
}

/// What Cargo itself says the direct dependencies are. The reader above only sees the forms it
/// knows, so a dependency declared another way (a dotted key, a quoted table name, a `dependencies`
/// key inside a `[target.x]` table) would go unseen by it. Cargo reads every form.
#[test]
fn cargo_itself_sees_exactly_the_allowlisted_direct_dependencies() {
    use std::collections::BTreeSet;

    let output = std::process::Command::new(env!("CARGO"))
        .args([
            "metadata",
            "--no-deps",
            "--format-version",
            "1",
            "--offline",
        ])
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("cargo can be run");
    assert!(
        output.status.success(),
        "cargo metadata failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    let metadata: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("cargo metadata prints JSON");
    let package = &metadata["packages"][0];

    let mut seen = BTreeSet::new();
    for dependency in package["dependencies"].as_array().expect("a list") {
        let name = dependency["name"].as_str().expect("a name");
        let table = match (dependency["kind"].as_str(), dependency["target"].as_str()) {
            (None, None) => "dependencies",
            (Some("dev"), None) => "dev-dependencies",
            (Some("build"), None) => "build-dependencies",
            (None, Some("cfg(target_os = \"macos\")")) => MACOS_TABLE,
            other => {
                panic!("{name}: a dependency kind or target the allowlist does not know: {other:?}")
            }
        };
        let allowed = ALLOWED
            .iter()
            .find(|a| a.table == table && a.name == name)
            .unwrap_or_else(|| {
                panic!("{name} ({table}) is a direct dependency but is not allowlisted")
            });
        assert_eq!(
            dependency["uses_default_features"].as_bool(),
            Some(allowed.default_features),
            "{name}: default-features differs from the allowlist"
        );
        let mut features: Vec<&str> = dependency["features"]
            .as_array()
            .expect("a list")
            .iter()
            .filter_map(serde_json::Value::as_str)
            .collect();
        features.sort_unstable();
        assert_eq!(
            features, allowed.features,
            "{name}: the enabled features differ"
        );
        assert_eq!(dependency["optional"], false, "{name} is optional");
        assert!(dependency["rename"].is_null(), "{name} is renamed");
        assert!(dependency["path"].is_null(), "{name} comes from a path");
        assert_eq!(
            dependency["source"].as_str(),
            Some("registry+https://github.com/rust-lang/crates.io-index"),
            "{name} does not come from crates.io"
        );
        seen.insert((table.to_owned(), name.to_owned()));
    }
    let allowed: BTreeSet<(String, String)> = ALLOWED
        .iter()
        .map(|a| (a.table.to_owned(), a.name.to_owned()))
        .collect();
    assert_eq!(
        seen, allowed,
        "Cargo's direct dependencies (left) differ from the allowlist (right)"
    );
}
