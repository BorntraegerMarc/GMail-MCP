//! The credential store: where the OAuth client, the refresh token and the granted scopes are
//! kept between runs.
//!
//! Credentials live only in the operating system's credential store, in one item, and are
//! never written to a file. The macOS Keychain is the only store so far; every other platform
//! compiles [`Unavailable`], which fails every operation instead of falling back to a file,
//! because a file would put a plaintext copy of the secrets back on disk. Access tokens are
//! never stored: they stay in memory.
//!
//! A [`Credentials`] value is built only from a grant whose scope is exactly read-only, and a
//! stored record must say so as well. What is checked on load is that label, which `auth`
//! wrote: a record that another program of the same user wrote with a valid label is accepted
//! (duplicate keys resolve to the last one). What bounds the server then is Google's scope on
//! the token and the egress allowlist, not the record; an attacker who controls the user's
//! account or the store is out of scope (SECURITY.md).
// why: docs/decisions/0006-credentials-in-os-credential-store.md,
// docs/decisions/0014-read-only-no-composing.md

use std::fmt;

use serde_json::{Value, json};

use crate::policy::{self, GrantError};

#[cfg(target_os = "macos")]
pub mod keychain;

/// Version of the stored record. A record with another number is refused rather than guessed
/// at, so a future format change cannot be mistaken for the current one.
const RECORD_VERSION: u64 = 1;

/// The keys of the stored record, which holds exactly these and nothing else.
const RECORD_KEYS: usize = 5;

/// Why the credential store could not do what was asked, or why credentials were refused.
/// Every message is static: errors reach the logs and the client, so none may carry a value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// This platform has no secure credential store yet. There is no file fallback.
    Unsupported,
    /// The store refused access: it is locked, or the user declined the prompt.
    Denied,
    /// The stored record is damaged, or was written by another version.
    Corrupt,
    /// The store failed for another reason.
    Failed,
    /// A credential value is empty, too long, or holds characters that cannot belong to it.
    Invalid,
    /// The grant holds more than the one read-only scope, or Google did not report it.
    Grant(GrantError),
}

impl Error {
    /// A fixed, human-readable reason that is safe to log and to return to a client.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Error::Unsupported => {
                "no secure credential store exists for this platform yet, and credentials are never written to a file instead"
            }
            Error::Denied => {
                "the credential store refused access (it is locked, or the prompt was declined)"
            }
            Error::Corrupt => {
                "the stored credentials are damaged or were written by another version; run auth with --credentials <client_secret.json> to replace them"
            }
            Error::Failed => "the credential store failed",
            Error::Invalid => "a credential value is empty, too long or has unexpected characters",
            Error::Grant(grant) => grant.reason(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for Error {}

impl From<GrantError> for Error {
    fn from(grant: GrantError) -> Self {
        Error::Grant(grant)
    }
}

/// A secret string, such as a client secret or a refresh token.
///
/// `Debug` is redacted and there is no `Display`, so a secret that ends up in a debug print,
/// a panic message or an error chain shows as `Secret(<redacted>)`. This is a guard against
/// accidents and not a proof, and the memory is not wiped on drop.
#[derive(Clone)]
pub struct Secret(String);

impl Secret {
    /// Wraps `value`.
    #[must_use]
    pub const fn new(value: String) -> Self {
        Self(value)
    }

    /// The secret itself. Call this only where the value must leave the wrapper, such as a
    /// request body to Google or the record written to the credential store.
    #[must_use]
    pub fn expose(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

/// Everything `serve` needs to sign in to Gmail again: the OAuth client and its refresh token.
/// The only scope it can stand for is [`policy::SCOPE_READONLY`].
pub struct Credentials {
    client_id: String,
    client_secret: Secret,
    refresh_token: Secret,
}

impl Credentials {
    /// Builds credentials from a finished sign-in. `granted` is the list of scopes Google
    /// reports for the grant; it must be exactly the read-only scope.
    ///
    /// # Errors
    ///
    /// [`Error::Grant`] if `granted` is empty or holds any scope other than the read-only
    /// one; [`Error::Invalid`] if the client id, client secret or refresh token is empty,
    /// longer than [`policy::MAX_CREDENTIAL_CHARS`] or has a character other than printable
    /// ASCII.
    // why: docs/decisions/0014-read-only-no-composing.md
    pub fn new<S: AsRef<str>>(
        client_id: String,
        client_secret: Secret,
        refresh_token: Secret,
        granted: &[S],
    ) -> Result<Self, Error> {
        policy::check_grant(granted)?;
        if ![
            client_id.as_str(),
            client_secret.expose(),
            refresh_token.expose(),
        ]
        .into_iter()
        .all(is_credential_text)
        {
            return Err(Error::Invalid);
        }
        Ok(Self {
            client_id,
            client_secret,
            refresh_token,
        })
    }

    /// The OAuth client id. It identifies the client and is not secret.
    #[must_use]
    pub fn client_id(&self) -> &str {
        &self.client_id
    }

    /// The OAuth client secret.
    #[must_use]
    pub const fn client_secret(&self) -> &Secret {
        &self.client_secret
    }

    /// The refresh token, which Google exchanges for short-lived access tokens.
    #[must_use]
    pub const fn refresh_token(&self) -> &Secret {
        &self.refresh_token
    }

    /// The scopes the credentials stand for: always the read-only scope.
    #[must_use]
    pub const fn scopes(&self) -> &'static [&'static str] {
        policy::SCOPES
    }

    /// The record that goes into the credential store: one JSON object with the version, the
    /// client, the refresh token and the scopes. The store encrypts it at rest.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        json!({
            "v": RECORD_VERSION,
            "client_id": self.client_id,
            "client_secret": self.client_secret.expose(),
            "refresh_token": self.refresh_token.expose(),
            "scopes": self.scopes(),
        })
        .to_string()
        .into_bytes()
    }

    /// Reads a record written by [`Credentials::encode`].
    ///
    /// The record is strict: the right version, exactly the five keys, and the scope check
    /// of [`Credentials::new`] on the record's own scope list. A store item that was damaged,
    /// edited into something else or written by another version does not become credentials;
    /// a well-formed record with a valid label does, whoever wrote it.
    ///
    /// # Errors
    ///
    /// [`Error::Corrupt`] for anything that is not a valid record.
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > policy::MAX_RECORD_BYTES {
            return Err(Error::Corrupt);
        }
        let Ok(Value::Object(record)) = serde_json::from_slice(bytes) else {
            return Err(Error::Corrupt);
        };
        if record.len() != RECORD_KEYS
            || record.get("v").and_then(Value::as_u64) != Some(RECORD_VERSION)
        {
            return Err(Error::Corrupt);
        }
        let text = |key: &str| record.get(key).and_then(Value::as_str);
        let scopes: Option<Vec<&str>> = record
            .get("scopes")
            .and_then(Value::as_array)
            .and_then(|list| list.iter().map(Value::as_str).collect());
        let (Some(client_id), Some(client_secret), Some(refresh_token), Some(scopes)) = (
            text("client_id"),
            text("client_secret"),
            text("refresh_token"),
            scopes,
        ) else {
            return Err(Error::Corrupt);
        };
        Self::new(
            client_id.to_owned(),
            Secret::new(client_secret.to_owned()),
            Secret::new(refresh_token.to_owned()),
            &scopes,
        )
        .map_err(|_| Error::Corrupt)
    }
}

impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Credentials(<redacted>)")
    }
}

/// Whether `text` can be a client id, a client secret or a refresh token: not empty, not
/// longer than [`policy::MAX_CREDENTIAL_CHARS`], and printable ASCII without spaces, which is
/// everything Google issues.
#[must_use]
pub fn is_credential_text(text: &str) -> bool {
    (1..=policy::MAX_CREDENTIAL_CHARS).contains(&text.len())
        && text.bytes().all(|byte| byte.is_ascii_graphic())
}

/// A place that keeps one set of [`Credentials`].
pub trait CredentialStore {
    /// Reads the credentials; `Ok(None)` if nothing is stored yet.
    ///
    /// # Errors
    ///
    /// [`Error::Unsupported`] where the platform has no store, [`Error::Denied`] if the store
    /// refuses access, [`Error::Corrupt`] if the item is not a valid record, otherwise
    /// [`Error::Failed`].
    fn load(&self) -> Result<Option<Credentials>, Error>;

    /// Stores `credentials`, replacing any that are stored.
    ///
    /// # Errors
    ///
    /// The same as [`CredentialStore::load`], except [`Error::Corrupt`].
    fn save(&self, credentials: &Credentials) -> Result<(), Error>;

    /// Removes the stored credentials. Removing nothing is not an error.
    ///
    /// # Errors
    ///
    /// The same as [`CredentialStore::save`].
    fn remove(&self) -> Result<(), Error>;
}

/// The store of a platform that has no secure credential store yet. Every operation fails
/// with [`Error::Unsupported`]: the server never falls back to a file, because that would put
/// a plaintext copy of the credentials on disk.
// why: docs/decisions/0006-credentials-in-os-credential-store.md
#[derive(Clone, Copy, Debug, Default)]
pub struct Unavailable;

impl CredentialStore for Unavailable {
    fn load(&self) -> Result<Option<Credentials>, Error> {
        Err(Error::Unsupported)
    }

    fn save(&self, _: &Credentials) -> Result<(), Error> {
        Err(Error::Unsupported)
    }

    fn remove(&self) -> Result<(), Error> {
        Err(Error::Unsupported)
    }
}

/// The credential store of the platform this binary was built for.
#[cfg(target_os = "macos")]
pub type Platform = keychain::Keychain;

/// The credential store of the platform this binary was built for.
#[cfg(not(target_os = "macos"))]
pub type Platform = Unavailable;

/// The credential store of this platform.
#[must_use]
pub fn platform() -> Platform {
    Platform::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Credentials {
        Credentials::new(
            "client-id".to_owned(),
            Secret::new("client-secret".to_owned()),
            Secret::new("refresh-token".to_owned()),
            &[policy::SCOPE_READONLY],
        )
        .unwrap()
    }

    #[test]
    fn a_record_survives_a_round_trip() {
        let decoded = Credentials::decode(&sample().encode()).unwrap();
        assert_eq!(decoded.client_id(), "client-id");
        assert_eq!(decoded.client_secret().expose(), "client-secret");
        assert_eq!(decoded.refresh_token().expose(), "refresh-token");
        assert_eq!(decoded.scopes(), policy::SCOPES);
    }

    #[test]
    fn a_secret_never_shows_in_a_debug_print() {
        let credentials = sample();
        for shown in [
            format!("{credentials:?}"),
            format!("{:?}", credentials.client_secret()),
            format!("{:?}", credentials.refresh_token()),
            format!("{:#?}", Some(&credentials)),
        ] {
            // Static messages: a failing assert must not print the text that leaked.
            assert!(
                !shown.contains("client-secret"),
                "a debug print shows the client secret"
            );
            assert!(
                !shown.contains("refresh-token"),
                "a debug print shows the refresh token"
            );
            assert!(
                shown.contains("redacted"),
                "a debug print has no redaction marker"
            );
        }
    }

    #[test]
    fn the_stub_fails_closed() {
        let stub = Unavailable;
        assert_eq!(stub.load().unwrap_err(), Error::Unsupported);
        assert_eq!(stub.save(&sample()).unwrap_err(), Error::Unsupported);
        assert_eq!(stub.remove().unwrap_err(), Error::Unsupported);
    }

    #[test]
    fn credential_text_is_printable_ascii_without_spaces() {
        assert!(is_credential_text("1//0abc-DEF_ghi"));
        assert!(!is_credential_text(""));
        assert!(!is_credential_text("has space"));
        assert!(!is_credential_text("new\nline"));
        assert!(!is_credential_text("tab\t"));
        assert!(!is_credential_text("caf\u{e9}"));
        assert!(!is_credential_text(
            &"x".repeat(policy::MAX_CREDENTIAL_CHARS + 1)
        ));
        assert!(is_credential_text(
            &"x".repeat(policy::MAX_CREDENTIAL_CHARS)
        ));
    }
}
