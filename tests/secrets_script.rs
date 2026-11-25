//! `scripts/verify-no-plaintext-secrets.sh` finds what it is meant to find and never prints it.
//! The secrets below are made up and assembled at run time, so that this file does not match
//! the script's own patterns when the script scans the project.
//! Why: docs/decisions/0006-credentials-in-os-credential-store.md.

#![cfg(unix)]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const SCRIPT: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/scripts/verify-no-plaintext-secrets.sh"
);

fn tail(len: usize) -> String {
    "abcdefghij0123456789-_".chars().cycle().take(len).collect()
}

/// Text of the four kinds that Google issues. Each is shaped like the real thing and is not.
fn client_secret() -> String {
    format!("{}-{}", "GOCSPX", tail(28))
}
fn refresh_token() -> String {
    format!("{}//{}", "1", tail(60))
}
fn access_token() -> String {
    format!("{}.{}", "ya29", tail(60))
}
fn client_id() -> String {
    format!(
        "{}-{}.apps.{}.com",
        "123456789012",
        tail(20).to_lowercase().replace(['-', '_'], "a"),
        "googleusercontent"
    )
}

struct Scratch(PathBuf);

impl Scratch {
    fn new(label: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!(
            "gmail-mcp-test-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn dir(&self, name: &str) -> PathBuf {
        let path = self.0.join(name);
        fs::create_dir_all(&path).unwrap();
        path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(script: &Path, folders: &[&Path], env: &[(&str, &Path)]) -> Output {
    let mut command = Command::new("bash");
    command.arg(script).args(folders);
    for (name, value) in env {
        command.env(name, value);
    }
    command.output().unwrap()
}

fn text(output: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

#[test]
fn a_folder_without_secrets_passes() {
    let scratch = Scratch::new("secrets-clean");
    let folder = scratch.dir("clean");
    fs::write(
        folder.join("notes.txt"),
        "GOCSPX- is the prefix of a client secret; 1// starts a refresh token",
    )
    .unwrap();
    fs::write(folder.join("data.json"), "{\"installed\": {}}").unwrap();

    let output = run(Path::new(SCRIPT), &[&folder], &[]);

    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
    assert!(text(&output).contains("Nothing found"));
}

#[test]
fn each_kind_of_secret_is_reported_by_path_and_never_printed() {
    let secrets = [
        ("client secret", client_secret()),
        ("refresh token", refresh_token()),
        ("access token", access_token()),
        ("client id", client_id()),
    ];
    for (kind, secret) in secrets {
        let scratch = Scratch::new("secrets-content");
        let folder = scratch.dir("found");
        let file = folder.join("innocent-name.txt");
        fs::write(
            &file,
            format!("some text\nvalue = \"{secret}\"\nmore text\n"),
        )
        .unwrap();

        let output = run(Path::new(SCRIPT), &[&folder], &[]);

        let shown = text(&output);
        assert_eq!(output.status.code(), Some(1), "{kind}: {shown}");
        assert!(shown.contains(file.to_str().unwrap()), "{shown}");
        assert!(
            !shown.contains(&secret),
            "the script printed a secret: {shown}"
        );
        assert!(
            !shown.contains(&secret[..12]),
            "the script printed part of a secret: {shown}"
        );
    }
}

#[test]
fn the_files_that_google_and_older_tools_leave_are_reported_by_name() {
    let scratch = Scratch::new("secrets-names");
    let folder = scratch.dir("downloads");
    let names = [
        "client_secret_123456789-abc.apps.example.json",
        "client_secret.json",
        "credentials.json",
        "token.json",
        "tokens.json",
    ];
    for name in names {
        fs::write(folder.join(name), "{}").unwrap();
    }
    fs::write(folder.join("harmless.json"), "{}").unwrap();

    let output = run(Path::new(SCRIPT), &[&folder], &[]);

    let shown = text(&output);
    assert_eq!(output.status.code(), Some(1), "{shown}");
    for name in names {
        assert!(shown.contains(name), "{name} not reported: {shown}");
    }
    assert!(!shown.contains("harmless.json"), "{shown}");
}

#[test]
fn version_control_data_build_output_and_big_files_are_skipped() {
    let scratch = Scratch::new("secrets-skip");
    let folder = scratch.dir("project");
    let secret = client_secret();
    for skipped in [".git", "target"] {
        fs::create_dir_all(folder.join(skipped)).unwrap();
        fs::write(folder.join(skipped).join("file.txt"), &secret).unwrap();
    }
    let mut big = secret.clone();
    big.push_str(&" ".repeat(2 * 1024 * 1024));
    fs::write(folder.join("big.txt"), big).unwrap();

    let output = run(Path::new(SCRIPT), &[&folder], &[]);

    assert_eq!(output.status.code(), Some(0), "{}", text(&output));
}

/// Without arguments the script looks in this project, `~/.config`, the temporary folder and
/// `~/Downloads`. The script is copied into a made-up project so the real one is not scanned.
#[test]
fn by_default_it_looks_in_the_four_places_where_a_copy_could_be_left() {
    let scratch = Scratch::new("secrets-default");
    let project = scratch.dir("project");
    fs::create_dir_all(project.join("scripts")).unwrap();
    let script = project.join("scripts/verify-no-plaintext-secrets.sh");
    fs::copy(SCRIPT, &script).unwrap();
    let home = scratch.dir("home");
    let temp = scratch.dir("temp");
    let places = [
        project.join("note.txt"),
        home.join(".config/tool/settings.txt"),
        temp.join("scratch.txt"),
        home.join("Downloads/export.txt"),
    ];
    let env: &[(&str, &Path)] = &[("HOME", &home), ("TMPDIR", &temp)];

    let clean = run(&script, &[], env);
    assert_eq!(clean.status.code(), Some(0), "{}", text(&clean));

    for place in &places {
        fs::create_dir_all(place.parent().unwrap()).unwrap();
        fs::write(place, refresh_token()).unwrap();
        let output = run(&script, &[], env);
        let shown = text(&output);
        assert_eq!(
            output.status.code(),
            Some(1),
            "{place:?} not scanned: {shown}"
        );
        assert!(shown.contains(place.to_str().unwrap()), "{shown}");
        fs::remove_file(place).unwrap();
    }
}

#[test]
fn the_script_has_a_help_text() {
    let help = Command::new("bash")
        .arg(SCRIPT)
        .arg("--help")
        .output()
        .unwrap();
    assert_eq!(help.status.code(), Some(0));
    assert!(text(&help).contains("Usage:"));
}

/// Only `target` and `.git` folders inside the scanned folder are skipped. A scanned folder
/// that is itself called `target`, or sits below one, is read like any other.
#[test]
fn a_scan_root_called_target_or_below_one_is_still_read() {
    let scratch = Scratch::new("secrets-target-root");
    for root in ["target", "target/project"] {
        let folder = scratch.dir(root);
        fs::write(folder.join("note.txt"), client_secret()).unwrap();
        let output = run(Path::new(SCRIPT), &[&folder], &[]);
        assert_eq!(output.status.code(), Some(1), "{root}: {}", text(&output));
    }
}

/// A text file with one stray byte (a Latin-1 letter, say) is still text. In a UTF-8 locale
/// grep would take it for binary and skip it.
#[test]
fn a_text_file_with_a_stray_byte_is_still_read() {
    let scratch = Scratch::new("secrets-latin1");
    let folder = scratch.dir("found");
    let mut bytes = b"caf\xe9 ".to_vec();
    bytes.extend_from_slice(client_secret().as_bytes());
    fs::write(folder.join("note.txt"), bytes).unwrap();
    let output = run(
        Path::new(SCRIPT),
        &[&folder],
        &[("LANG", Path::new("en_US.UTF-8"))],
    );
    assert_eq!(output.status.code(), Some(1), "{}", text(&output));
}

/// A dotfiles setup often links `~/.config` to another folder; a scan root that is a link is
/// followed, so it cannot hide what is behind it.
#[test]
fn a_scan_root_that_is_a_symbolic_link_is_followed() {
    let scratch = Scratch::new("secrets-link");
    let real = scratch.dir("real");
    fs::write(real.join("note.txt"), refresh_token()).unwrap();
    let link = scratch.0.join("linked");
    std::os::unix::fs::symlink(&real, &link).unwrap();
    let output = run(Path::new(SCRIPT), &[&link], &[]);
    assert_eq!(output.status.code(), Some(1), "{}", text(&output));
}

// A verification script that says "nothing found" for a place it could not read gives a false
// assurance, so every way of not reading something is an error (exit status 2).

/// A name that is not a folder, such as a typo, is not a clean result.
#[test]
fn a_folder_that_was_asked_for_but_is_not_there_is_an_error() {
    let scratch = Scratch::new("secrets-typo");
    let real = scratch.dir("real");
    let output = run(
        Path::new(SCRIPT),
        &[&real, &scratch.0.join("Downlods")],
        &[],
    );
    let shown = text(&output);
    assert_eq!(output.status.code(), Some(2), "{shown}");
    assert!(shown.contains("CANNOT SCAN"), "{shown}");
    assert!(
        !shown.contains("Nothing found in:") || shown.contains("not everything"),
        "{shown}"
    );
}

/// The default places may be missing (not everyone has a `~/.config`): that is said, not hidden.
#[test]
fn a_default_place_that_is_not_there_is_skipped_and_said_so() {
    let scratch = Scratch::new("secrets-default-missing");
    let project = scratch.dir("project");
    fs::create_dir_all(project.join("scripts")).unwrap();
    let script = project.join("scripts/verify-no-plaintext-secrets.sh");
    fs::copy(SCRIPT, &script).unwrap();
    let (home, temp) = (scratch.dir("home"), scratch.dir("temp"));
    let output = run(&script, &[], &[("HOME", &home), ("TMPDIR", &temp)]);
    let shown = text(&output);
    assert_eq!(output.status.code(), Some(0), "{shown}");
    assert!(shown.contains("Skipped (not there)"), "{shown}");
}

/// A folder that cannot be read is not clean, and what was found elsewhere is still reported.
#[test]
fn a_folder_that_cannot_be_read_is_not_reported_as_clean() {
    use std::os::unix::fs::PermissionsExt;

    let scratch = Scratch::new("secrets-unreadable");
    let folder = scratch.dir("folder");
    let locked = folder.join("locked");
    fs::create_dir_all(&locked).unwrap();
    fs::write(locked.join("note.txt"), refresh_token()).unwrap();
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    // Whoever may read it anyway (root) cannot show this case.
    let readable_anyway = fs::read_dir(&locked).is_ok();

    let output = run(Path::new(SCRIPT), &[&folder], &[]);
    let found_elsewhere = {
        fs::write(folder.join("other.txt"), client_secret()).unwrap();
        run(Path::new(SCRIPT), &[&folder], &[])
    };

    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
    if readable_anyway {
        return;
    }
    let shown = text(&output);
    assert_eq!(output.status.code(), Some(2), "{shown}");
    assert!(shown.contains("COULD NOT READ PART OF"), "{shown}");
    assert!(!shown.contains("Nothing found in:"), "{shown}");
    let shown = text(&found_elsewhere);
    assert_eq!(found_elsewhere.status.code(), Some(1), "{shown}");
    assert!(
        shown.contains("other.txt") && shown.contains("may be incomplete"),
        "{shown}"
    );
}

/// Without `find` or `grep` there is nothing to scan with, which is not a clean result either.
#[test]
fn a_missing_tool_is_an_error_not_a_clean_result() {
    let scratch = Scratch::new("secrets-no-tools");
    let folder = scratch.dir("folder");
    let empty_path = scratch.dir("empty-path");
    let output = Command::new("/bin/bash")
        .arg(SCRIPT)
        .arg(&folder)
        .env("PATH", &empty_path)
        .output()
        .unwrap();
    let shown = text(&output);
    assert_eq!(output.status.code(), Some(2), "{shown}");
    assert!(shown.contains("Cannot run"), "{shown}");
}
