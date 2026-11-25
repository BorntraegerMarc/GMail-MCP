//! The macOS Keychain store against the real Keychain.
//!
//! These tests write to the Keychain of whoever runs them, so they are `#[ignore]`d: a plain
//! `cargo test` skips them. The narrow macOS CI job runs them on a throwaway keychain with
//! `cargo test --locked --test keychain_macos -- --ignored` (docs/decisions/0012-ci-on-linux.md).
//! Every item is stored under a service name that is made up for the test, never the real one,
//! and is removed again when the test ends.

#![cfg(target_os = "macos")]

use gmail_mcp::policy::SCOPE_READONLY;
use gmail_mcp::store::keychain::{ACCOUNT, Keychain, SERVICE};
use gmail_mcp::store::{CredentialStore, Credentials, Error, Secret};
use security_framework::passwords::set_generic_password;
use serde_json::json;

const WHY: &str = "writes to the real macOS Keychain; run in CI, or on purpose";

/// A store under a made-up service name, emptied again when it goes out of scope.
struct Throwaway(Keychain, String);

impl Throwaway {
    fn new(label: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let service = format!("gmail-mcp-test-{label}-{}-{nanos}", std::process::id());
        assert_ne!(service, SERVICE, "a test must never use the real item");
        Self(Keychain::with_service(service.clone()), service)
    }
}

impl Drop for Throwaway {
    fn drop(&mut self) {
        let _ = self.0.remove();
    }
}

fn credentials(refresh: &str) -> Credentials {
    Credentials::new(
        "client-id".to_owned(),
        Secret::new("client-secret".to_owned()),
        Secret::new(refresh.to_owned()),
        &[SCOPE_READONLY],
    )
    .unwrap()
}

#[test]
#[ignore = "writes to the real macOS Keychain; run in CI, or on purpose"]
fn an_empty_keychain_holds_no_credentials_and_removing_nothing_is_fine() {
    let _ = WHY;
    let item = Throwaway::new("empty");
    assert!(item.0.load().unwrap().is_none());
    item.0.remove().unwrap();
    item.0.remove().unwrap();
}

#[test]
#[ignore = "writes to the real macOS Keychain; run in CI, or on purpose"]
fn credentials_survive_a_round_trip_and_an_update_replaces_them() {
    let item = Throwaway::new("round-trip");
    item.0.save(&credentials("first-refresh-token")).unwrap();

    let loaded = item.0.load().unwrap().unwrap();
    assert_eq!(loaded.client_id(), "client-id");
    assert_eq!(loaded.client_secret().expose(), "client-secret");
    assert_eq!(loaded.refresh_token().expose(), "first-refresh-token");
    assert_eq!(loaded.scopes(), [SCOPE_READONLY]);

    // Saving again takes the update path of the Keychain, not the add path.
    item.0.save(&credentials("second-refresh-token")).unwrap();
    let loaded = item.0.load().unwrap().unwrap();
    assert_eq!(loaded.refresh_token().expose(), "second-refresh-token");

    item.0.remove().unwrap();
    assert!(item.0.load().unwrap().is_none());
}

/// Another program, or a person with Keychain Access, can edit the item. What it holds is
/// checked on every read, so a damaged or doctored item does not become credentials.
#[test]
#[ignore = "writes to the real macOS Keychain; run in CI, or on purpose"]
fn a_damaged_or_doctored_item_is_reported_as_corrupt() {
    let item = Throwaway::new("corrupt");
    set_generic_password(&item.1, ACCOUNT, b"not a record").unwrap();
    assert_eq!(item.0.load().unwrap_err(), Error::Corrupt);

    let broader = json!({
        "v": 1,
        "client_id": "client-id",
        "client_secret": "client-secret",
        "refresh_token": "refresh-token",
        "scopes": ["https://mail.google.com/"],
    });
    set_generic_password(&item.1, ACCOUNT, broader.to_string().as_bytes()).unwrap();
    assert_eq!(item.0.load().unwrap_err(), Error::Corrupt);

    // A fresh sign-in replaces a damaged item.
    item.0.save(&credentials("fresh-refresh-token")).unwrap();
    assert_eq!(
        item.0.load().unwrap().unwrap().refresh_token().expose(),
        "fresh-refresh-token"
    );
}
