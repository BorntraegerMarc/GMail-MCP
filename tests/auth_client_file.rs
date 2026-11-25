//! Reading the client secret file that Google Cloud offers for download. The values here are
//! synthetic: no real client id or secret appears in this repository.
//! Why: docs/decisions/0015-sign-in-flow.md.

use std::fs;
use std::path::PathBuf;

use gmail_mcp::auth::{self, Error};
use gmail_mcp::policy::MAX_CLIENT_FILE_BYTES;
use serde_json::json;

fn desktop_file() -> serde_json::Value {
    json!({
        "installed": {
            "client_id": "000000000000-example.apps.example.invalid",
            "project_id": "example-project",
            "auth_uri": "https://accounts.example.invalid/o/oauth2/auth",
            "token_uri": "https://oauth2.example.invalid/token",
            "auth_provider_x509_cert_url": "https://www.example.invalid/oauth2/v1/certs",
            "client_secret": "EXAMPLE-SECRET-VALUE",
            "redirect_uris": ["http://localhost"]
        }
    })
}

fn parse(value: &serde_json::Value) -> Result<auth::Client, Error> {
    auth::parse_client_file(value.to_string().as_bytes())
}

#[test]
fn a_desktop_app_file_gives_the_client() {
    let client = parse(&desktop_file()).unwrap();
    assert_eq!(client.id(), "000000000000-example.apps.example.invalid");
}

/// The file names its own endpoints. They are never read, so a doctored file cannot point the
/// sign-in at another site: the sign-in uses the addresses in `policy`.
#[test]
fn the_endpoints_in_the_file_are_ignored() {
    let mut file = desktop_file();
    file["installed"]["auth_uri"] = json!("https://phishing.example.invalid/");
    file["installed"]["token_uri"] = json!("https://collect.example.invalid/token");
    file["installed"]["redirect_uris"] = json!(["https://collect.example.invalid/"]);
    assert!(parse(&file).is_ok());
}

#[test]
fn only_a_desktop_app_file_is_accepted() {
    // A "web" client needs redirect addresses registered in advance, which a loopback port
    // chosen at run time cannot satisfy.
    let web = json!({ "web": desktop_file()["installed"].clone() });
    assert_eq!(parse(&web).unwrap_err(), Error::ClientFileInvalid);
    assert_eq!(parse(&json!({})).unwrap_err(), Error::ClientFileInvalid);
}

#[test]
fn a_file_without_a_usable_id_and_secret_is_refused() {
    for key in ["client_id", "client_secret"] {
        let mut file = desktop_file();
        file["installed"].as_object_mut().unwrap().remove(key);
        assert_eq!(parse(&file).unwrap_err(), Error::ClientFileInvalid, "{key}");
        for wrong in [
            json!(""),
            json!(null),
            json!(1),
            json!(["x"]),
            json!("with space"),
            json!("new\nline"),
        ] {
            let mut file = desktop_file();
            file["installed"][key] = wrong;
            assert_eq!(parse(&file).unwrap_err(), Error::ClientFileInvalid, "{key}");
        }
    }
}

#[test]
fn text_that_is_not_the_file_is_refused() {
    for bytes in [
        &b""[..],
        b"null",
        b"[]",
        b"{",
        b"not json",
        b"{\"installed\": 1}",
        b"{\"installed\": []}",
        &[0xff, 0xfe, 0x00],
    ] {
        assert_eq!(
            auth::parse_client_file(bytes).unwrap_err(),
            Error::ClientFileInvalid
        );
    }
    // Deeply nested input is refused by the JSON reader's depth limit, not by a stack overflow.
    assert_eq!(
        auth::parse_client_file(&vec![b'['; 100_000]).unwrap_err(),
        Error::ClientFileInvalid
    );
}

/// A scratch directory under the system temporary folder, removed afterwards.
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
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn a_file_on_disk_is_read_and_a_missing_one_is_reported() {
    let scratch = Scratch::new("client-file");
    let path = scratch.0.join("client_secret.json");
    fs::write(&path, desktop_file().to_string()).unwrap();
    assert!(auth::read_client_file(&path).is_ok());

    assert_eq!(
        auth::read_client_file(&scratch.0.join("missing.json")).unwrap_err(),
        Error::ClientFileUnreadable
    );
    // A directory opens on some platforms and fails on the first read; either way it is
    // reported as unreadable, not as a panic.
    assert_eq!(
        auth::read_client_file(&scratch.0).unwrap_err(),
        Error::ClientFileUnreadable
    );
}

#[test]
fn an_oversized_file_is_refused_without_being_read_whole() {
    let scratch = Scratch::new("client-file-large");
    let path = scratch.0.join("client_secret.json");
    // Valid JSON followed by padding: only the size makes it wrong.
    let mut text = desktop_file().to_string();
    text.push_str(&" ".repeat(MAX_CLIENT_FILE_BYTES));
    fs::write(&path, text).unwrap();
    assert_eq!(
        auth::read_client_file(&path).unwrap_err(),
        Error::ClientFileInvalid
    );
}

#[test]
fn no_error_message_repeats_what_was_in_the_file() {
    let secret_file =
        json!({ "installed": { "client_id": "SENTINEL-ID", "client_secret": "SENTINEL SECRET" } });
    let error = parse(&secret_file).unwrap_err();
    let shown = format!("{error} {error:?}");
    assert!(!shown.contains("SENTINEL"), "{shown}");
}
