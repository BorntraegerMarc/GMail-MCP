//! The credential record and the rule that it can only ever stand for a read-only grant.
//!
//! These are the hostile samples: scopes broader than `gmail.readonly`, look-alikes of the
//! read-only scope, and damaged or doctored store records. They live here and not in `src/`,
//! whose source scans refuse such strings. Why: docs/decisions/0014-read-only-no-composing.md,
//! docs/decisions/0006-credentials-in-os-credential-store.md.

use gmail_mcp::policy::{GrantError, SCOPE_READONLY};
use gmail_mcp::store::{self, CredentialStore, Credentials, Error, Secret};
use serde_json::{Value, json};

fn secret(text: &str) -> Secret {
    Secret::new(text.to_owned())
}

fn build(granted: &[&str]) -> Result<Credentials, Error> {
    Credentials::new(
        "client-id".to_owned(),
        secret("client-secret"),
        secret("refresh-token"),
        granted,
    )
}

/// Everything that is not exactly the read-only scope: broader scopes, other Google scopes, and
/// strings that look like the right scope but are not byte for byte equal to it.
const NOT_THE_READ_ONLY_SCOPE: &[&str] = &[
    "https://www.googleapis.com/auth/gmail.modify",
    "https://www.googleapis.com/auth/gmail.compose",
    "https://www.googleapis.com/auth/gmail.send",
    "https://www.googleapis.com/auth/gmail.settings.basic",
    "https://www.googleapis.com/auth/gmail.labels",
    "https://www.googleapis.com/auth/gmail.metadata",
    "https://mail.google.com/",
    "https://www.googleapis.com/auth/drive",
    "https://www.googleapis.com/auth/userinfo.email",
    "openid",
    "email",
    "profile",
    "gmail.readonly",
    "",
    " ",
    "https://www.googleapis.com/auth/gmail.readonly ",
    " https://www.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com/auth/gmail.readonly/",
    "https://www.googleapis.com/auth/gmail.readonly\n",
    "https://www.googleapis.com/auth/gmail.readonly\0",
    "https://www.googleapis.com/auth/gmail.readonly#x",
    "https://www.googleapis.com/auth/gmail.readonly?x=1",
    "https://www.googleapis.com/auth/gmail.readonly.extra",
    "https://www.googleapis.com/auth/gmail.readonly,https://mail.google.com/",
    "https://www.googleapis.com/auth/Gmail.readonly",
    "HTTPS://www.googleapis.com/auth/gmail.readonly",
    "http://www.googleapis.com/auth/gmail.readonly",
    "https://WWW.googleapis.com/auth/gmail.readonly",
    "https://www.googleapis.com./auth/gmail.readonly",
    "https://www.googleapis.com.evil.test/auth/gmail.readonly",
];

#[test]
fn only_exactly_the_read_only_scope_becomes_credentials() {
    assert!(build(&[SCOPE_READONLY]).is_ok());
    assert!(build(&[SCOPE_READONLY, SCOPE_READONLY]).is_ok());
}

/// An earlier consent for the same OAuth client can hand back more than a request names. The
/// server must not keep a token that can do more than read, whatever else comes with it.
#[test]
fn a_grant_with_any_other_scope_is_never_turned_into_credentials() {
    for other in NOT_THE_READ_ONLY_SCOPE {
        for granted in [
            vec![*other],
            vec![SCOPE_READONLY, *other],
            vec![*other, SCOPE_READONLY],
        ] {
            assert_eq!(
                build(&granted).unwrap_err(),
                Error::Grant(GrantError::Broader),
                "{granted:?} was accepted"
            );
        }
    }
}

#[test]
fn a_grant_that_google_did_not_report_is_never_turned_into_credentials() {
    let none: [&str; 0] = [];
    assert_eq!(
        build(&none).unwrap_err(),
        Error::Grant(GrantError::Unreported)
    );
}

#[test]
fn a_credential_value_that_cannot_be_one_is_refused() {
    let too_long = "x".repeat(gmail_mcp::policy::MAX_CREDENTIAL_CHARS + 1);
    for bad in [
        "",
        " ",
        "has space",
        "new\nline",
        "tab\t",
        "nul\0",
        "caf\u{e9}",
        "\u{202e}x",
        &too_long,
    ] {
        for (id, client_secret, refresh) in
            [(bad, "ok", "ok"), ("ok", bad, "ok"), ("ok", "ok", bad)]
        {
            let result = Credentials::new(
                id.to_owned(),
                secret(client_secret),
                secret(refresh),
                &[SCOPE_READONLY],
            );
            assert_eq!(result.unwrap_err(), Error::Invalid, "{bad:?}");
        }
    }
}

fn record(scopes: &Value) -> Vec<u8> {
    json!({
        "v": 1,
        "client_id": "client-id",
        "client_secret": "client-secret",
        "refresh_token": "refresh-token",
        "scopes": scopes,
    })
    .to_string()
    .into_bytes()
}

#[test]
fn the_record_in_the_store_says_read_only_and_nothing_else() {
    let credentials = build(&[SCOPE_READONLY]).unwrap();
    let Value::Object(map) = serde_json::from_slice(&credentials.encode()).unwrap() else {
        panic!("the record is not a JSON object");
    };
    let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["client_id", "client_secret", "refresh_token", "scopes", "v"]
    );
    assert_eq!(map["scopes"], json!([SCOPE_READONLY]));
    assert_eq!(map["v"], json!(1));
}

#[test]
fn a_record_that_holds_a_broader_grant_is_not_credentials() {
    assert!(Credentials::decode(&record(&json!([SCOPE_READONLY]))).is_ok());
    for other in NOT_THE_READ_ONLY_SCOPE {
        for scopes in [json!([other]), json!([SCOPE_READONLY, other])] {
            assert_eq!(
                Credentials::decode(&record(&scopes)).unwrap_err(),
                Error::Corrupt,
                "{scopes} was accepted"
            );
        }
    }
    for scopes in [
        json!([]),
        json!(null),
        json!("x"),
        json!({}),
        json!([1]),
        json!([null]),
    ] {
        assert_eq!(
            Credentials::decode(&record(&scopes)).unwrap_err(),
            Error::Corrupt,
            "{scopes} was accepted"
        );
    }
}

#[test]
fn a_damaged_or_doctored_record_is_not_credentials() {
    let good = || {
        json!({
            "v": 1,
            "client_id": "client-id",
            "client_secret": "client-secret",
            "refresh_token": "refresh-token",
            "scopes": [SCOPE_READONLY],
        })
    };
    let mut samples: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"null".to_vec(),
        b"[]".to_vec(),
        b"\"text\"".to_vec(),
        b"{".to_vec(),
        b"not json".to_vec(),
        vec![0xff, 0xfe, 0x00],
        b"{}".to_vec(),
        vec![b'['; 100_000],
    ];
    // Another version, an unknown key, a missing key, a value of the wrong type or shape.
    let mut other_version = good();
    other_version["v"] = json!(2);
    let mut text_version = good();
    text_version["v"] = json!("1");
    let mut extra = good();
    extra["extra"] = json!("x");
    samples
        .extend([other_version, text_version, extra].map(|value| value.to_string().into_bytes()));
    for key in ["v", "client_id", "client_secret", "refresh_token", "scopes"] {
        let mut missing = good();
        missing.as_object_mut().unwrap().remove(key);
        samples.push(missing.to_string().into_bytes());
    }
    for key in ["client_id", "client_secret", "refresh_token"] {
        for wrong in [
            json!(1),
            json!(null),
            json!(["x"]),
            json!(""),
            json!("with space"),
            json!("new\nline"),
        ] {
            let mut value = good();
            value[key] = wrong;
            samples.push(value.to_string().into_bytes());
        }
    }
    // Larger than any record the store writes.
    let mut huge = good();
    huge["padding"] = json!("x".repeat(gmail_mcp::policy::MAX_RECORD_BYTES));
    samples.push(huge.to_string().into_bytes());

    for sample in samples {
        let shown = String::from_utf8_lossy(&sample[..sample.len().min(60)]).into_owned();
        assert_eq!(
            Credentials::decode(&sample).unwrap_err(),
            Error::Corrupt,
            "accepted: {shown}"
        );
    }
}

/// A platform without a secure store fails every operation, and never falls back to a file.
#[test]
fn the_stub_store_fails_every_operation() {
    let stub = store::Unavailable;
    let credentials = build(&[SCOPE_READONLY]).unwrap();
    assert_eq!(stub.load().unwrap_err(), Error::Unsupported);
    assert_eq!(stub.save(&credentials).unwrap_err(), Error::Unsupported);
    assert_eq!(stub.remove().unwrap_err(), Error::Unsupported);
}

#[cfg(not(target_os = "macos"))]
#[test]
fn this_platform_has_no_secure_store_and_fails_closed() {
    let platform = store::platform();
    assert_eq!(platform.load().unwrap_err(), Error::Unsupported);
    let credentials = build(&[SCOPE_READONLY]).unwrap();
    assert_eq!(platform.save(&credentials).unwrap_err(), Error::Unsupported);
}

#[test]
fn error_messages_carry_no_values() {
    for error in [
        Error::Unsupported,
        Error::Denied,
        Error::Corrupt,
        Error::Failed,
        Error::Invalid,
        Error::Grant(GrantError::Broader),
        Error::Grant(GrantError::Unreported),
    ] {
        let text = error.to_string();
        assert_eq!(text, error.reason());
        assert!(!text.contains("client-secret") && !text.contains("refresh-token"));
    }
}

/// A refused grant is still live at Google, and the program cannot revoke it (there is no route
/// for that), so the message must tell the user what to do (docs/decisions/0015-sign-in-flow.md).
#[test]
fn a_refused_grant_tells_the_user_to_remove_the_apps_access() {
    for grant in [GrantError::Broader, GrantError::Unreported] {
        let reason = Error::Grant(grant).reason();
        assert!(reason.contains("nothing was stored"), "{reason}");
        assert!(
            reason.contains("remove this app's access in your Google account"),
            "{reason}"
        );
    }
}
