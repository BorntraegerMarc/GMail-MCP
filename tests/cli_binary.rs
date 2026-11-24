//! The binary as a user runs it: exit codes, and where its words go. stdout carries the MCP
//! protocol, so nothing may ever be written to it; every message is on stderr.
//!
//! `auth` is not run on macOS: it reads the real Keychain, which tests must not touch.
//! Everything else it does is covered through `auth::authenticate` with a fake store and a fake
//! Google (`tests/auth_flow.rs`).

use std::process::{Command, Output};

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_gmail-mcp"))
        .args(args)
        .output()
        .expect("the binary can be started")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

#[test]
fn help_succeeds_and_goes_to_stderr() {
    for flag in ["--help", "-h", "help"] {
        let output = run(&[flag]);
        assert_eq!(output.status.code(), Some(0), "{flag}");
        assert!(output.stdout.is_empty(), "{flag} wrote to stdout");
        assert!(stderr(&output).contains("usage: gmail-mcp"), "{flag}");
    }
}

/// `serve` lands in the next phase. Until then it must refuse to run, not look like a working
/// server that answers nothing.
#[test]
fn serve_refuses_to_run_yet() {
    for args in [&[][..], &["serve"]] {
        let output = run(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?} wrote to stdout");
        assert!(
            stderr(&output).contains("serve is not implemented yet"),
            "{args:?}: {}",
            stderr(&output)
        );
    }
}

#[test]
fn a_mistake_is_a_usage_error_with_the_usage_text() {
    for args in [
        &["login"][..],
        &["serve", "extra"],
        &["--help", "extra"],
        &["auth", "--credentials"],
        &["auth", "--unknown"],
        &["auth", "--credentials", "a", "--credentials", "b"],
    ] {
        let output = run(args);
        assert_eq!(output.status.code(), Some(2), "{args:?}");
        assert!(output.stdout.is_empty(), "{args:?} wrote to stdout");
        assert!(stderr(&output).contains("usage: gmail-mcp"), "{args:?}");
    }
}

/// Where there is no secure credential store, `auth` fails at once, before anything else, and
/// says why. (On macOS this would read the real Keychain, so it is not run there.)
#[cfg(not(target_os = "macos"))]
#[test]
fn auth_fails_at_once_where_there_is_no_store() {
    let output = run(&["auth", "--credentials", "client_secret.json"]);
    assert_eq!(output.status.code(), Some(1));
    assert!(output.stdout.is_empty());
    assert!(stderr(&output).contains("no secure credential store exists"));
}
