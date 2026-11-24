//! The macOS Keychain credential store.
//!
//! One generic-password item holds the whole record (OAuth client, refresh token, scopes), so
//! a read is one Keychain access and a write cannot leave half of the credentials behind. The
//! item lives in the user's login keychain, where macOS encrypts it at rest and asks before a
//! program other than its creator reads it. A binary that is rebuilt is a different program
//! to the Keychain, so macOS can ask again after a rebuild.
//!
//! This is the only module that talks to the Keychain, and it is compiled on macOS only.
//! Its tests write to the real Keychain, so they are `#[ignore]`d and run in the narrow macOS
//! CI job (`tests/keychain_macos.rs`).
// why: docs/decisions/0006-credentials-in-os-credential-store.md,
// docs/decisions/0012-ci-on-linux.md

use security_framework::base::Error as KeychainError;
use security_framework::passwords::{
    PasswordOptions, delete_generic_password, generic_password, set_generic_password,
};

use super::{CredentialStore, Credentials, Error};

/// The Keychain service of the real item, shown as its name in Keychain Access.
pub const SERVICE: &str = "gmail-mcp";

/// The Keychain account of the item.
pub const ACCOUNT: &str = "oauth-credentials";

// Keychain status codes (`OSStatus`) this store tells apart. Anything else is a plain failure.
// The numbers are part of Apple's stable `Security.framework` interface (`SecBase.h`).
/// `errSecUserCanceled`: the user declined the access prompt.
const ERR_USER_CANCELED: i32 = -128;
/// `errSecItemNotFound`: no item matches.
const ERR_ITEM_NOT_FOUND: i32 = -25300;
/// `errSecAuthFailed`: authorization or authentication failed.
const ERR_AUTH_FAILED: i32 = -25293;
/// `errSecInteractionNotAllowed`: the keychain is locked and may not ask the user to unlock it.
const ERR_INTERACTION_NOT_ALLOWED: i32 = -25308;

/// The credential store backed by the macOS Keychain.
#[derive(Clone, Debug)]
pub struct Keychain {
    service: String,
}

impl Default for Keychain {
    /// The store of the real item ([`SERVICE`], [`ACCOUNT`]).
    fn default() -> Self {
        Self::with_service(SERVICE)
    }
}

impl Keychain {
    /// A store under another service name. The tests use this so that they never touch the
    /// real item.
    #[must_use]
    pub fn with_service(service: impl Into<String>) -> Self {
        Self {
            service: service.into(),
        }
    }
}

/// Maps a Keychain failure to an error with a static message. The status code is dropped on
/// purpose: it is of no use to the model, and the messages carry no values.
fn failure(error: KeychainError) -> Error {
    match error.code() {
        ERR_USER_CANCELED | ERR_AUTH_FAILED | ERR_INTERACTION_NOT_ALLOWED => Error::Denied,
        _ => Error::Failed,
    }
}

impl CredentialStore for Keychain {
    fn load(&self) -> Result<Option<Credentials>, Error> {
        match generic_password(PasswordOptions::new_generic_password(
            &self.service,
            ACCOUNT,
        )) {
            Ok(record) => Credentials::decode(&record).map(Some),
            Err(error) if error.code() == ERR_ITEM_NOT_FOUND => Ok(None),
            Err(error) => Err(failure(error)),
        }
    }

    fn save(&self, credentials: &Credentials) -> Result<(), Error> {
        set_generic_password(&self.service, ACCOUNT, &credentials.encode()).map_err(failure)
    }

    fn remove(&self) -> Result<(), Error> {
        match delete_generic_password(&self.service, ACCOUNT) {
            Err(error) if error.code() != ERR_ITEM_NOT_FOUND => Err(failure(error)),
            _ => Ok(()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The error mapping looks at the status code only, so it needs no Keychain access.
    #[test]
    fn a_declined_or_locked_keychain_is_a_denial_and_anything_else_a_failure() {
        for code in [
            ERR_USER_CANCELED,
            ERR_AUTH_FAILED,
            ERR_INTERACTION_NOT_ALLOWED,
        ] {
            assert_eq!(
                failure(KeychainError::from_code(code)),
                Error::Denied,
                "{code}"
            );
        }
        for code in [-25291, -25294, -34018, -50, 1] {
            assert_eq!(
                failure(KeychainError::from_code(code)),
                Error::Failed,
                "{code}"
            );
        }
    }

    /// The real item has one fixed name, and only a store made on purpose under another name
    /// (the tests do) can be pointed elsewhere.
    #[test]
    fn the_default_store_is_the_real_item() {
        assert_eq!((SERVICE, ACCOUNT), ("gmail-mcp", "oauth-credentials"));
        assert_eq!(Keychain::default().service, SERVICE);
        assert_eq!(Keychain::with_service("other").service, "other");
    }
}
