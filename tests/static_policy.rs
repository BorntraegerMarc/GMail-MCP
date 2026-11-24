//! Source-level tripwires for the guarantees the README makes.
//!
//! These tests read the Rust source under `src/` (comments removed, so prose may mention what
//! the code must never do) and fail on any forbidden Gmail endpoint, HTTP method, OAuth scope,
//! host, network or process API, or print to stdout or stderr outside the one logging module.
//!
//! They are tripwires, not proofs. They read this project's source text, so they cannot see a
//! compromised dependency, and a determined author can build a forbidden string at run time.
//! What they do is make every drift towards a new capability a red build instead of a quiet
//! change in review. Why: docs/decisions/0003-single-egress-allowlist.md.
//!
//! The hostile examples live in `egress_policy.rs`, outside `src/`, so they do not trip these
//! scans. Unit tests inside `src/` are scanned like production code, so they avoid URLs with
//! other hosts and the forbidden tokens below.

#[cfg(test)]
mod scan {
    use std::fs;
    use std::path::{Path, PathBuf};

    /// A Rust source file under `src/`: its path relative to `src/` and its text with
    /// comments removed.
    pub struct Source {
        pub name: String,
        pub code: String,
    }

    fn collect(dir: &Path, out: &mut Vec<PathBuf>) {
        let entries = fs::read_dir(dir).expect("src/ can be read");
        for entry in entries {
            let path = entry.expect("a directory entry").path();
            if path.is_dir() {
                collect(&path, out);
            } else if path.extension().is_some_and(|ext| ext == "rs") {
                out.push(path);
            }
        }
    }

    pub fn sources() -> Vec<Source> {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut paths = Vec::new();
        collect(&root, &mut paths);
        paths.sort();
        paths
            .iter()
            .map(|path| {
                let text = fs::read_to_string(path).expect("source files are UTF-8");
                Source {
                    name: path
                        .strip_prefix(&root)
                        .expect("under src/")
                        .to_string_lossy()
                        .replace('\\', "/"),
                    code: code_only(&text),
                }
            })
            .collect()
    }

    /// Source text with comments removed. String and character literals are kept whole,
    /// because a forbidden URL or path inside a literal is exactly what the scans look for.
    pub fn code_only(source: &str) -> String {
        let chars: Vec<char> = source.chars().collect();
        let at = |i: usize| chars.get(i).copied();
        let mut out = String::with_capacity(source.len());
        let mut i = 0;
        while let Some(c) = at(i) {
            match c {
                '/' if at(i + 1) == Some('/') => {
                    while at(i).is_some_and(|c| c != '\n') {
                        i += 1;
                    }
                }
                '/' if at(i + 1) == Some('*') => {
                    let mut depth = 0;
                    loop {
                        match (at(i), at(i + 1)) {
                            (Some('/'), Some('*')) => {
                                depth += 1;
                                i += 2;
                            }
                            (Some('*'), Some('/')) => {
                                depth -= 1;
                                i += 2;
                                if depth == 0 {
                                    break;
                                }
                            }
                            (Some(_), _) => i += 1,
                            (None, _) => break,
                        }
                    }
                }
                '"' => i = copy_string(&chars, i, &mut out),
                'r' if !at(i.wrapping_sub(1)).is_some_and(|p| p.is_alphanumeric() || p == '_')
                    && raw_string_start(&chars, i).is_some() =>
                {
                    i = copy_raw_string(&chars, i, &mut out);
                }
                '\'' => {
                    // A character literal is `'x'` or `'\...'`; anything else is a lifetime.
                    let end = if at(i + 1) == Some('\\') {
                        (i + 2..chars.len().min(i + 12)).find(|&j| chars[j] == '\'')
                    } else if at(i + 2) == Some('\'') {
                        Some(i + 2)
                    } else {
                        None
                    };
                    let stop = end.unwrap_or(i);
                    out.extend(&chars[i..=stop]);
                    i = stop + 1;
                }
                _ => {
                    out.push(c);
                    i += 1;
                }
            }
        }
        out
    }

    fn copy_string(chars: &[char], start: usize, out: &mut String) -> usize {
        out.push('"');
        let mut i = start + 1;
        while let Some(&c) = chars.get(i) {
            out.push(c);
            i += 1;
            if c == '\\' {
                if let Some(&escaped) = chars.get(i) {
                    out.push(escaped);
                    i += 1;
                }
            } else if c == '"' {
                break;
            }
        }
        i
    }

    /// For `r"`, `r#"`, `r##"`...: the number of `#`.
    fn raw_string_start(chars: &[char], at: usize) -> Option<usize> {
        let hashes = chars[at + 1..].iter().take_while(|&&c| c == '#').count();
        (chars.get(at + 1 + hashes) == Some(&'"')).then_some(hashes)
    }

    fn copy_raw_string(chars: &[char], start: usize, out: &mut String) -> usize {
        let hashes = raw_string_start(chars, start).expect("checked by the caller");
        let closing: Vec<char> = std::iter::once('"')
            .chain(std::iter::repeat_n('#', hashes))
            .collect();
        let body_start = start + 2 + hashes;
        let end = (body_start..chars.len())
            .find(|&j| chars[j..].starts_with(&closing))
            .map_or(chars.len(), |j| j + closing.len());
        out.extend(&chars[start..end]);
        end
    }

    /// Every `(file, token)` pair where `token` occurs in the file's code.
    pub fn find<'a>(files: &'a [Source], tokens: &[&'a str]) -> Vec<(&'a str, &'a str)> {
        let mut hits = Vec::new();
        for file in files {
            for token in tokens {
                if file.code.contains(token) {
                    hits.push((file.name.as_str(), *token));
                }
            }
        }
        hits
    }
}

use scan::{Source, code_only, find, sources};

/// The scans are only worth something if they read the real code.
#[test]
fn the_scan_reads_the_real_source_files() {
    let files = sources();
    let names: Vec<&str> = files.iter().map(|f| f.name.as_str()).collect();
    for expected in [
        "lib.rs",
        "main.rs",
        "http.rs",
        "policy.rs",
        "log.rs",
        "text.rs",
        "draft.rs",
    ] {
        assert!(
            names.contains(&expected),
            "{expected} not scanned: {names:?}"
        );
    }
    let policy = files
        .iter()
        .find(|f| f.name == "policy.rs")
        .expect("policy.rs");
    assert!(
        policy.code.contains("gmail.googleapis.com"),
        "the scan saw no code in policy.rs"
    );
}

#[test]
fn the_comment_stripper_removes_prose_and_keeps_literals() {
    let source = r##"
        // POST /messages/send in a line comment
        /// stdout in a doc comment
        /* block /* nested */ comment about /send */
        fn f<'a>(x: &'a str) -> &'a str {
            let url = "https://example.test/a//b"; // trailing comment
            let quote = '"'; let slash = '/';
            let raw = r#"raw "quoted" // not a comment"#;
            x
        }
    "##;
    let code = code_only(source);
    for gone in [
        "messages/send",
        "stdout",
        "nested",
        "line comment",
        "trailing comment",
        "block",
    ] {
        assert!(!code.contains(gone), "{gone} survived: {code}");
    }
    for kept in [
        "https://example.test/a//b",
        "'\"'",
        "'/'",
        "raw \"quoted\" // not a comment",
        "fn f<'a>",
    ] {
        assert!(code.contains(kept), "{kept} was lost: {code}");
    }
}

/// Paths of the Gmail API that send, delete, relabel, reconfigure or download. The route
/// table has no entry for any of them; this makes sure none sneaks into any other file.
#[test]
fn no_forbidden_gmail_endpoint_appears_in_the_source() {
    const FORBIDDEN: &[&str] = &[
        "/send",
        "/trash",
        "/untrash",
        "/modify",
        "/batchmodify",
        "/batchdelete",
        "/import",
        "/insert",
        "/settings",
        "/filters",
        "/forwardingaddresses",
        "/sendas",
        "/delegates",
        "/watch",
        "/stop",
        "/attachments",
        "/profile",
        "/history",
    ];
    let files: Vec<Source> = sources()
        .into_iter()
        .map(|file| Source {
            code: file.code.to_lowercase(),
            ..file
        })
        .collect();
    let hits = find(&files, FORBIDDEN);
    assert!(
        hits.is_empty(),
        "forbidden Gmail endpoint fragments in the source: {hits:?}"
    );
}

#[test]
fn no_method_other_than_get_and_post_appears_in_the_source() {
    const FORBIDDEN: &[&str] = &[
        "Method::PUT",
        "Method::DELETE",
        "Method::PATCH",
        "Method::HEAD",
        "Method::OPTIONS",
        "Method::TRACE",
        "Method::CONNECT",
        "\"PUT\"",
        "\"DELETE\"",
        "\"PATCH\"",
        "\"HEAD\"",
        "\"OPTIONS\"",
        "\"TRACE\"",
        "\"CONNECT\"",
        ".put(",
        ".delete(",
        ".patch(",
        "ureq::put",
        "ureq::delete",
        "ureq::patch",
    ];
    let files = sources();
    let hits = find(&files, FORBIDDEN);
    assert!(
        hits.is_empty(),
        "forbidden HTTP methods in the source: {hits:?}"
    );
}

/// The only OAuth scopes are `gmail.readonly` and `gmail.compose`, and no other Google
/// scope or the full-mailbox host is named anywhere.
#[test]
fn the_only_oauth_scopes_are_readonly_and_compose() {
    const FORBIDDEN: &[&str] = &[
        "gmail.modify",
        "gmail.send",
        "gmail.settings",
        "gmail.labels",
        "gmail.insert",
        "gmail.metadata",
        "gmail.addons",
        "mail.google.com",
        "auth/mail",
        "auth/userinfo",
        "auth/drive",
        "auth/calendar",
        "auth/contacts",
        "auth/cloud-platform",
    ];
    let files = sources();
    let hits = find(&files, FORBIDDEN);
    assert!(
        hits.is_empty(),
        "forbidden OAuth scopes in the source: {hits:?}"
    );

    for file in &files {
        for (index, _) in file.code.match_indices("googleapis.com/auth/") {
            let rest = &file.code[index + "googleapis.com/auth/".len()..];
            assert!(
                rest.starts_with("gmail.readonly\"") || rest.starts_with("gmail.compose\""),
                "{}: unexpected scope: {}",
                file.name,
                &rest[..rest.len().min(40)]
            );
        }
    }
}

/// Every URL written out in the source names an allowlisted host, over https. The two scope
/// URLs name `www.googleapis.com`, but only as an identifier, never as a place to connect to.
#[test]
fn every_url_literal_in_the_source_is_allowlisted() {
    const HOSTS: &[&str] = &["oauth2.googleapis.com", "gmail.googleapis.com"];
    let files = sources();
    let mut seen = 0;
    for file in &files {
        for (index, _) in file.code.match_indices("://") {
            let scheme: String = file.code[..index]
                .chars()
                .rev()
                .take_while(char::is_ascii_alphabetic)
                .collect::<Vec<_>>()
                .into_iter()
                .rev()
                .collect();
            let rest = &file.code[index + 3..];
            // `{scheme}://{addr}` and similar are templates, not literal URLs.
            if scheme.is_empty() || !rest.starts_with(|c: char| c.is_ascii_alphanumeric()) {
                continue;
            }
            seen += 1;
            let host: String = rest
                .chars()
                .take_while(|c| c.is_ascii_alphanumeric() || *c == '.' || *c == '-')
                .collect();
            let after_host = &rest[host.len()..];
            assert_eq!(
                scheme, "https",
                "{}: non-https URL: {scheme}://{host}",
                file.name
            );
            let scope_identifier = host == "www.googleapis.com"
                && (after_host.starts_with("/auth/gmail.readonly\"")
                    || after_host.starts_with("/auth/gmail.compose\""));
            assert!(
                HOSTS.contains(&host.as_str()) || scope_identifier,
                "{}: URL with a host that is not allowlisted: {scheme}://{host}",
                file.name
            );
        }
    }
    assert!(seen >= 4, "expected to see the policy's URLs, saw {seen}");
}

/// Sockets, HTTP and TLS clients, and child processes. Only the egress module may touch the
/// network; nothing may start a process, which could run a network tool and bypass the guard.
/// (The OAuth loopback listener joins the egress module in the list when `auth` lands.)
#[test]
fn network_and_process_apis_are_confined_to_the_egress_module() {
    const NETWORK: &[&str] = &[
        "ureq::",
        "std::net",
        "tokio::net",
        "TcpStream",
        "TcpListener",
        "UdpSocket",
        "ToSocketAddrs",
        "UnixStream",
        "UnixListener",
        "os::unix::net",
        "reqwest",
        "hyper::",
        "curl::",
        "curl_sys",
        "native_tls",
        "rustls::",
        "socket2",
        "oauth2::reqwest",
        "oauth2::ureq",
        "oauth2::curl",
    ];
    const PROCESS: &[&str] = &["std::process::Command", "process::Command", "Command::new"];
    const MAIL_TRANSPORT: &[&str] = &[
        "lettre::transport",
        "lettre::Transport",
        "lettre::AsyncTransport",
        "SmtpTransport",
        "SendmailTransport",
        "FileTransport",
        "StubTransport",
    ];

    let files = sources();
    let outside_egress: Vec<Source> = files
        .iter()
        .filter(|file| file.name != "http.rs")
        .map(|file| Source {
            name: file.name.clone(),
            code: file.code.clone(),
        })
        .collect();
    let hits = find(&outside_egress, NETWORK);
    assert!(
        hits.is_empty(),
        "network APIs outside src/http.rs: {hits:?}"
    );

    let hits = find(&files, PROCESS);
    assert!(hits.is_empty(), "process APIs in the source: {hits:?}");

    let hits = find(&files, MAIL_TRANSPORT);
    assert!(hits.is_empty(), "mail transports in the source: {hits:?}");
}

/// stdout belongs to the MCP protocol, and logs never carry data. Nothing prints, and the
/// one module that writes to stderr takes static messages only.
#[test]
fn nothing_prints_and_only_the_log_module_writes_to_stderr() {
    const PRINTING: &[&str] = &[
        "println!",
        "print!",
        "eprintln!",
        "eprint!",
        "dbg!",
        "stdout",
    ];
    let files = sources();
    let hits = find(&files, PRINTING);
    assert!(hits.is_empty(), "printing in the source: {hits:?}");

    let outside_log: Vec<Source> = files
        .iter()
        .filter(|file| file.name != "log.rs")
        .map(|file| Source {
            name: file.name.clone(),
            code: file.code.clone(),
        })
        .collect();
    let hits = find(&outside_log, &["stderr"]);
    assert!(hits.is_empty(), "stderr used outside src/log.rs: {hits:?}");
}
