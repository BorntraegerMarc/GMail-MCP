//! The signed-in session: loads the stored credentials on first use and turns the refresh token
//! into short-lived access tokens.
//!
//! Nothing here runs until a tool needs a token: starting the server does not touch the
//! credential store (ADR 0006). The refresh-token grant goes through the `oauth2` crate over
//! [`crate::auth::Guarded`], so it is held to the same egress allowlist as everything else, and
//! every token response passes [`policy::check_grant`]: a grant that is broader than read-only,
//! or that Google does not describe, is refused and its token is dropped. Access tokens stay in
//! memory and are never written anywhere.
// why: docs/decisions/0006-credentials-in-os-credential-store.md, docs/decisions/0014-read-only-no-composing.md

use std::fmt;
use std::time::{Duration, Instant};

use oauth2::basic::{BasicClient, BasicErrorResponse, BasicErrorResponseType};
use oauth2::{
    AuthType, ClientId, ClientSecret, RefreshToken, RequestTokenError, SyncHttpClient,
    TokenResponse, TokenUrl,
};

use crate::auth::Guarded;
use crate::http;
use crate::policy::{self, GrantError};
use crate::store::{self, CredentialStore, Credentials, Secret};

/// How much earlier than its stated expiry a token counts as expired, so a request that starts
/// just before the end does not fail on the way.
const EXPIRY_MARGIN: Duration = Duration::from_secs(60);

/// How long a token is trusted when Google states no lifetime.
const DEFAULT_LIFETIME: Duration = Duration::from_secs(5 * 60);

/// Why no access token could be had. Every message is static: errors reach the model and the
/// logs, so none carries a value, and in particular never a token or a client secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// Nothing is stored: the user has not signed in.
    NoCredentials,
    /// The credential store failed or refused access.
    Store(store::Error),
    /// The request to Google did not produce a response.
    Network(http::Error),
    /// Google no longer accepts the stored sign-in (`invalid_grant`).
    Expired,
    /// Google refused the refresh for another reason, such as an OAuth client that is gone.
    Refused,
    /// Google's answer was not the token response that was expected.
    BadResponse,
    /// Google granted a scope other than read-only, or did not report the grant.
    Grant(GrantError),
    /// The refresh request could not be set up (an address that must always parse did not).
    Setup,
}

impl Error {
    /// A fixed, human-readable reason that is safe to log and to return to the model.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Error::NoCredentials => "not signed in: run `gmail-mcp auth` first",
            Error::Store(error) => error.reason(),
            Error::Network(error) => error.reason(),
            Error::Expired => {
                "Google no longer accepts the stored sign-in; run `gmail-mcp auth` again (a consent screen in Testing status expires after 7 days)"
            }
            Error::Refused => {
                "Google refused to refresh the sign-in: the OAuth client may have been deleted; run `gmail-mcp auth` again"
            }
            Error::BadResponse => "Google's answer was not the token response that was expected",
            Error::Grant(error) => error.reason(),
            Error::Setup => "the token refresh could not be set up",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for Error {}

/// Where the Gmail client gets its access tokens.
pub trait TokenSource {
    /// A valid access token: the one in memory, or a fresh one.
    ///
    /// # Errors
    ///
    /// Any [`Error`].
    fn access_token(&mut self) -> Result<Secret, Error>;

    /// Forgets the token in memory, because Gmail refused it. The next call gets a fresh one.
    fn invalidate(&mut self);
}

/// An access token and the moment it stops being trusted.
struct Cached {
    token: Secret,
    until: Instant,
}

/// The credentials of the signed-in user and the access token made from them.
pub struct Session<H, S> {
    http: H,
    store: S,
    credentials: Option<Credentials>,
    cached: Option<Cached>,
}

impl Session<Guarded, store::Platform> {
    /// The session of this platform: the platform's credential store, and the OAuth library's
    /// HTTP client behind the egress guard.
    #[must_use]
    pub fn platform() -> Self {
        Self::new(Guarded::new(), store::platform())
    }
}

impl<H, S> Session<H, S> {
    /// A session over `http` and `store`. Nothing is read from the store yet.
    #[must_use]
    pub fn new(http: H, store: S) -> Self {
        Self {
            http,
            store,
            credentials: None,
            cached: None,
        }
    }
}

impl<H: SyncHttpClient<Error = http::Error>, S: CredentialStore> TokenSource for Session<H, S> {
    fn access_token(&mut self) -> Result<Secret, Error> {
        if let Some(cached) = &self.cached
            && Instant::now() < cached.until
        {
            return Ok(cached.token.clone());
        }
        self.cached = None;
        if self.credentials.is_none() {
            let stored = self.store.load().map_err(Error::Store)?;
            self.credentials = Some(stored.ok_or(Error::NoCredentials)?);
        }
        let Some(credentials) = &self.credentials else {
            return Err(Error::NoCredentials);
        };
        match refresh(&self.http, credentials) {
            Ok((token, lifetime)) => {
                self.cached = Instant::now()
                    .checked_add(lifetime.saturating_sub(EXPIRY_MARGIN))
                    .map(|until| Cached {
                        token: token.clone(),
                        until,
                    });
                Ok(token)
            }
            Err(error) => {
                // A sign-in that Google refuses may have been replaced by a new `auth` run since
                // it was loaded, so the next call reads the store again.
                if error == Error::Expired {
                    self.credentials = None;
                }
                Err(error)
            }
        }
    }

    fn invalidate(&mut self) {
        self.cached = None;
    }
}

/// One refresh-token grant. The scope of the answer is checked before the token is used.
// why: docs/decisions/0014-read-only-no-composing.md
fn refresh<H: SyncHttpClient<Error = http::Error>>(
    http: &H,
    credentials: &Credentials,
) -> Result<(Secret, Duration), Error> {
    let oauth = BasicClient::new(ClientId::new(credentials.client_id().to_owned()))
        .set_client_secret(ClientSecret::new(
            credentials.client_secret().expose().to_owned(),
        ))
        .set_token_uri(TokenUrl::new(policy::TOKEN_URL.to_owned()).map_err(|_| Error::Setup)?)
        // Google documents the client credentials as form fields of the token request.
        .set_auth_type(AuthType::RequestBody);
    let refresh_token = RefreshToken::new(credentials.refresh_token().expose().to_owned());
    let tokens = oauth
        .exchange_refresh_token(&refresh_token)
        .request(http)
        .map_err(|error| failure(&error))?;

    let granted: Vec<String> = tokens
        .scopes()
        .map(|scopes| scopes.iter().map(|scope| scope.to_string()).collect())
        .unwrap_or_default();
    policy::check_grant(&granted).map_err(Error::Grant)?;
    Ok((
        Secret::new(tokens.access_token().secret().clone()),
        tokens.expires_in().unwrap_or(DEFAULT_LIFETIME),
    ))
}

/// Turns a failed token request into an error with a static message. The details are dropped on
/// purpose: they can hold the response body, and a response can hold tokens.
fn failure(error: &RequestTokenError<http::Error, BasicErrorResponse>) -> Error {
    match error {
        RequestTokenError::Request(error) => Error::Network(*error),
        RequestTokenError::ServerResponse(response)
            if *response.error() == BasicErrorResponseType::InvalidGrant =>
        {
            Error::Expired
        }
        RequestTokenError::ServerResponse(_) => Error::Refused,
        _ => Error::BadResponse,
    }
}
