//! The sign-in flow behind `gmail-mcp auth`.
//!
//! The OAuth authorization-code flow with PKCE, for a Google "Desktop app" client the user
//! created. The consent page opens in the user's own browser and Google redirects it back to a
//! listener on `127.0.0.1`; the code is then exchanged for tokens through the egress guard.
//! The one scope is `gmail.readonly`, and a grant that holds any other scope is refused before
//! anything is stored.
//!
//! This module may accept connections on `127.0.0.1`, as the one other place besides the
//! egress guard that touches sockets. It never dials out: the listener only answers the
//! browser, and everything sent to Google goes through [`crate::http::Egress`].
//! Why each step is the way it is: `docs/decisions/0015-sign-in-flow.md`.
// why: docs/decisions/0003-single-egress-allowlist.md, docs/decisions/0015-sign-in-flow.md

use std::fmt;
use std::fs::File;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::Path;
use std::thread;
use std::time::{Duration, Instant};

use oauth2::basic::{BasicClient, BasicErrorResponse};
use oauth2::url::{Url, form_urlencoded};
use oauth2::{
    AuthType, AuthUrl, AuthorizationCode, ClientId, ClientSecret, CsrfToken, HttpRequest,
    HttpResponse, PkceCodeChallenge, RedirectUrl, RequestTokenError, Scope, SyncHttpClient,
    TokenResponse, TokenUrl,
};
use serde_json::Value;

use crate::http::{self, Egress};
use crate::log;
use crate::policy::{self, GrantError};
use crate::store::{self, CredentialStore, Credentials, Secret};

/// How often the listener looks for a new connection while it waits.
const POLL: Duration = Duration::from_millis(50);

/// What the browser is shown once the redirect arrived. It does not say that the sign-in worked:
/// the code has still to be exchanged and the grant checked, and the terminal reports that.
const PAGE_DONE: &str = "<!doctype html><meta charset=\"utf-8\"><title>gmail-mcp</title>\
<p>Google's answer reached gmail-mcp. You can close this tab and return to the terminal, \
which says whether the sign-in worked.";

/// What the browser is shown if the user said no on the consent page.
const PAGE_DECLINED: &str = "<!doctype html><meta charset=\"utf-8\"><title>gmail-mcp</title>\
<p>Access was not granted. You can close this tab and return to the terminal.";

/// What anything that is not this sign-in's redirect is shown.
const PAGE_REFUSED: &str = "<!doctype html><meta charset=\"utf-8\"><title>gmail-mcp</title>\
<p>This request is not the sign-in redirect that gmail-mcp is waiting for, so it was ignored.";

/// Why signing in failed. Every message is static: errors reach the logs, so none carries a
/// value, and in particular never a token, a code or a client secret.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// No client is stored and no client secret file was given.
    NoClient,
    /// The client secret file could not be opened or read.
    ClientFileUnreadable,
    /// The file is too large, is not JSON, or is not the file of a Desktop app client.
    ClientFileInvalid,
    /// The local listener could not be opened or failed.
    Listener,
    /// The sign-in could not be set up (an address that must always parse did not).
    Setup,
    /// The user did not finish on the consent page in time.
    TimedOut,
    /// The user declined on the consent page.
    Declined,
    /// The request to Google did not produce a response.
    Network(http::Error),
    /// Google refused the request: the client or the code is not valid.
    Refused,
    /// Google's answer is not the token response that was expected.
    BadResponse,
    /// Google issued no refresh token, so the server could not sign in again later.
    NoRefreshToken,
    /// The credential store failed or refused the credentials, a grant of more than the
    /// read-only scope included.
    Store(store::Error),
}

impl Error {
    /// A fixed, human-readable reason that is safe to log and to return to a client.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Error::NoClient => {
                "no OAuth client is stored yet: run auth with --credentials <client_secret.json>"
            }
            Error::ClientFileUnreadable => "the client secret file could not be read",
            Error::ClientFileInvalid => {
                "the client secret file is too large or is not the JSON of a Desktop app OAuth client (it needs an \"installed\" section)"
            }
            Error::Listener => "the local sign-in listener on 127.0.0.1 could not be used",
            Error::Setup => "the sign-in could not be set up",
            Error::TimedOut => "no sign-in arrived in time; run auth again",
            Error::Declined => "access was declined on the Google consent page",
            Error::Network(error) => error.reason(),
            Error::Refused => {
                "Google refused the sign-in: the OAuth client or the code is not valid"
            }
            Error::BadResponse => "Google's answer was not the token response that was expected",
            Error::NoRefreshToken => "Google issued no refresh token, so nothing is stored",
            Error::Store(error) => error.reason(),
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for Error {}

impl From<store::Error> for Error {
    fn from(error: store::Error) -> Self {
        Error::Store(error)
    }
}

impl From<GrantError> for Error {
    fn from(error: GrantError) -> Self {
        Error::Store(store::Error::Grant(error))
    }
}

/// The OAuth client the user created in Google Cloud: an id and a secret.
pub struct Client {
    id: String,
    secret: Secret,
}

impl Client {
    /// Wraps a client id and secret.
    ///
    /// # Errors
    ///
    /// [`Error::ClientFileInvalid`] if either is empty, too long or not printable ASCII.
    pub fn new(id: String, secret: Secret) -> Result<Self, Error> {
        if store::is_credential_text(&id) && store::is_credential_text(secret.expose()) {
            Ok(Self { id, secret })
        } else {
            Err(Error::ClientFileInvalid)
        }
    }

    /// The client id.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
}

impl From<&Credentials> for Client {
    /// The client of stored credentials, for signing in again without the file.
    fn from(credentials: &Credentials) -> Self {
        Self {
            id: credentials.client_id().to_owned(),
            secret: credentials.client_secret().clone(),
        }
    }
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Client(<redacted>)")
    }
}

/// Reads the OAuth client out of the JSON file that Google Cloud offers for download.
///
/// Only a "Desktop app" client works: its file has an `installed` section. The file also
/// names Google's endpoints and redirect addresses, and all of that is ignored: the sign-in
/// uses the addresses in [`policy`], so a doctored file cannot point it at another site.
///
/// # Errors
///
/// [`Error::ClientFileInvalid`] if the text is not that JSON or lacks the client id or
/// secret.
// why: docs/decisions/0015-sign-in-flow.md
pub fn parse_client_file(bytes: &[u8]) -> Result<Client, Error> {
    let Ok(Value::Object(file)) = serde_json::from_slice(bytes) else {
        return Err(Error::ClientFileInvalid);
    };
    let Some(Value::Object(installed)) = file.get("installed") else {
        return Err(Error::ClientFileInvalid);
    };
    match (
        installed.get("client_id").and_then(Value::as_str),
        installed.get("client_secret").and_then(Value::as_str),
    ) {
        (Some(id), Some(secret)) => Client::new(id.to_owned(), Secret::new(secret.to_owned())),
        _ => Err(Error::ClientFileInvalid),
    }
}

/// Reads and parses a client secret file, reading at most
/// [`policy::MAX_CLIENT_FILE_BYTES`] of it.
///
/// # Errors
///
/// [`Error::ClientFileUnreadable`] if the file cannot be read, otherwise as for
/// [`parse_client_file`].
pub fn read_client_file(path: &Path) -> Result<Client, Error> {
    let file = File::open(path).map_err(|_| Error::ClientFileUnreadable)?;
    let mut bytes = Vec::new();
    file.take(policy::MAX_CLIENT_FILE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Error::ClientFileUnreadable)?;
    if bytes.len() > policy::MAX_CLIENT_FILE_BYTES {
        return Err(Error::ClientFileInvalid);
    }
    parse_client_file(&bytes)
}

/// The OAuth library's HTTP client. It sends through the egress guard, so the library's
/// traffic is held to the same allowlist as everything else.
// why: docs/decisions/0003-single-egress-allowlist.md
#[derive(Default)]
pub struct Guarded {
    egress: Egress,
}

impl Guarded {
    /// Creates the client, with its own egress guard.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl SyncHttpClient for Guarded {
    type Error = http::Error;

    fn call(&self, request: HttpRequest) -> Result<HttpResponse, http::Error> {
        self.egress.send(request)
    }
}

/// Opens the sign-in listener: `127.0.0.1` only, on a port the system picks. Other machines
/// cannot connect to it. Other programs on this machine still can, which is why the redirect
/// must carry the `state` that was issued ([`await_redirect`]).
///
/// # Errors
///
/// [`Error::Listener`] if the address cannot be bound.
// why: docs/decisions/0009-stdio-only-transport.md
pub fn bind_loopback() -> Result<TcpListener, Error> {
    TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|_| Error::Listener)
}

/// The redirect address that Google is told about for `listener`.
///
/// # Errors
///
/// [`Error::Listener`] if the listener has no address.
pub fn redirect_uri(listener: &TcpListener) -> Result<String, Error> {
    let address = listener.local_addr().map_err(|_| Error::Listener)?;
    Ok(format!("http://{address}"))
}

/// What one connection to the listener amounted to.
enum Visit {
    /// The redirect of this sign-in, with the authorization code.
    Code(AuthorizationCode),
    /// The redirect of this sign-in, saying that the user declined.
    Declined,
    /// Anything else: a stray request, a probe, a redirect for another sign-in.
    Ignored,
}

/// A connection to the listener whose request has not arrived in full yet.
struct Visitor {
    stream: TcpStream,
    /// What has arrived so far.
    head: Vec<u8>,
    /// When the connection was accepted.
    since: Instant,
}

/// How far a [`Visitor`] has got.
enum Progress {
    /// The request is not complete, and the visitor may still send the rest.
    Waiting,
    /// The visitor hung up or failed, so there is nobody to answer.
    Gone,
    /// The head is complete, or has grown to the size limit: its first line can be read.
    Arrived,
}

impl Visitor {
    /// Wraps an accepted connection. It is read without blocking: the listener serves many
    /// visitors at once, so that one that says nothing cannot keep the others waiting.
    fn new(stream: TcpStream) -> Option<Self> {
        stream.set_nonblocking(true).ok()?;
        Some(Self {
            stream,
            head: Vec::new(),
            since: Instant::now(),
        })
    }

    /// Takes in whatever has arrived, up to the end of the head or
    /// [`policy::MAX_REDIRECT_HEAD_BYTES`].
    fn advance(&mut self) -> Progress {
        let mut chunk = [0_u8; 1024];
        loop {
            if self.head.windows(4).any(|window| window == b"\r\n\r\n")
                || self.head.len() >= policy::MAX_REDIRECT_HEAD_BYTES
            {
                return Progress::Arrived;
            }
            match self.stream.read(&mut chunk) {
                Ok(0) => return Progress::Gone,
                Ok(read) => match chunk.get(..read) {
                    Some(bytes) => self.head.extend_from_slice(bytes),
                    None => return Progress::Gone,
                },
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    return Progress::Waiting;
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(_) => return Progress::Gone,
            }
        }
    }
}

/// Waits for Google to redirect the user's browser back, and returns the authorization code.
///
/// Other software on the machine can connect to the listener too, so a request is acted on
/// only if it is a `GET` of `/` whose `state` equals the one issued for this sign-in. Any
/// other request is answered with a 400 and the wait goes on: a stray connection must not be
/// able to complete or end the sign-in.
///
/// Connections are served side by side, not one after the other. A connection that says
/// nothing is dropped after [`policy::REDIRECT_CONNECTION_TIMEOUT`], and at most
/// [`policy::MAX_REDIRECT_CONNECTIONS`] are kept: a new one pushes the oldest out. So a
/// program that opens silent connections cannot keep the browser's real redirect waiting. Only
/// the first line of a request counts, so a head that is longer than
/// [`policy::MAX_REDIRECT_HEAD_BYTES`] (cookies for `127.0.0.1` go to every port) does not stop
/// a genuine redirect. A program that floods the port faster than it is served can still make the
/// sign-in time out; it cannot complete it.
///
/// The listener is expected to be dropped by the caller once this returns, so that it accepts
/// nothing else.
///
/// # Errors
///
/// [`Error::TimedOut`] if no valid redirect arrives within `timeout`, [`Error::Declined`] if
/// the redirect says the user declined, [`Error::Listener`] if the listener fails.
// why: docs/decisions/0003-single-egress-allowlist.md, docs/decisions/0015-sign-in-flow.md
pub fn await_redirect(
    listener: &TcpListener,
    state: &CsrfToken,
    timeout: Duration,
) -> Result<AuthorizationCode, Error> {
    let deadline = Instant::now().checked_add(timeout).ok_or(Error::Listener)?;
    listener
        .set_nonblocking(true)
        .map_err(|_| Error::Listener)?;
    let mut visitors: Vec<Visitor> = Vec::new();
    loop {
        accept_waiting(listener, &mut visitors)?;
        let mut index = 0;
        while let Some(visitor) = visitors.get_mut(index) {
            let progress = visitor.advance();
            let expired = visitor.since.elapsed() >= policy::REDIRECT_CONNECTION_TIMEOUT;
            match progress {
                Progress::Waiting if !expired => index += 1,
                Progress::Waiting | Progress::Gone => {
                    visitors.remove(index);
                }
                Progress::Arrived => {
                    let mut visitor = visitors.remove(index);
                    match answer(&mut visitor, state) {
                        Visit::Code(code) => return Ok(code),
                        Visit::Declined => return Err(Error::Declined),
                        Visit::Ignored => {}
                    }
                }
            }
        }
        if Instant::now() >= deadline {
            return Err(Error::TimedOut);
        }
        thread::sleep(POLL);
    }
}

/// Takes the connections that are waiting, as many as the listener keeps at once. When it is
/// full, the oldest is pushed out: the browser's redirect is the newest connection that matters.
fn accept_waiting(listener: &TcpListener, visitors: &mut Vec<Visitor>) -> Result<(), Error> {
    for _ in 0..policy::MAX_REDIRECT_CONNECTIONS {
        match listener.accept() {
            Ok((stream, _)) => {
                if let Some(visitor) = Visitor::new(stream) {
                    if visitors.len() >= policy::MAX_REDIRECT_CONNECTIONS {
                        visitors.remove(0);
                    }
                    visitors.push(visitor);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
            // A client that gave up before it was accepted, or a signal: nothing to act on.
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionAborted | io::ErrorKind::Interrupted
                ) => {}
            Err(_) => return Err(Error::Listener),
        }
    }
    Ok(())
}

/// Reads the request line of a visitor whose head has arrived, answers it, and says what it was.
fn answer(visitor: &mut Visitor, state: &CsrfToken) -> Visit {
    let visit = interpret(&visitor.head, state);
    let (status, body) = match visit {
        Visit::Code(_) => ("200 OK", PAGE_DONE),
        Visit::Declined => ("200 OK", PAGE_DECLINED),
        Visit::Ignored => ("400 Bad Request", PAGE_REFUSED),
    };
    reply(&mut visitor.stream, status, body);
    visit
}

/// What a request head is worth: a `GET` of `/` with this sign-in's `state`, and either a
/// code or an error. Only the first line is read. Anything else, a repeated parameter
/// included, is ignored.
fn interpret(head: &[u8], state: &CsrfToken) -> Visit {
    let Some(end) = head.iter().position(|&byte| byte == b'\n') else {
        return Visit::Ignored;
    };
    let Some(line) = head
        .get(..end)
        .and_then(|line| std::str::from_utf8(line).ok())
    else {
        return Visit::Ignored;
    };
    let mut parts = line.trim_end_matches('\r').split(' ');
    let (Some("GET"), Some(target), Some(version), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Visit::Ignored;
    };
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if path != "/" || !version.starts_with("HTTP/1.") {
        return Visit::Ignored;
    }

    let (mut code, mut got_state, mut error) = (None, None, None);
    for (name, value) in form_urlencoded::parse(query.as_bytes()) {
        let slot = match &*name {
            "code" => &mut code,
            "state" => &mut got_state,
            "error" => &mut error,
            _ => continue,
        };
        if slot.replace(value.into_owned()).is_some() {
            return Visit::Ignored;
        }
    }
    if !got_state.is_some_and(|got| same(&got, state.secret())) {
        return Visit::Ignored;
    }
    match (code, error) {
        (Some(code), None) if store::is_credential_text(&code) => {
            Visit::Code(AuthorizationCode::new(code))
        }
        (None, Some(_)) => Visit::Declined,
        _ => Visit::Ignored,
    }
}

/// Equality of two strings that does not stop at the first difference. The `state` is not a
/// long-lived secret, but a check against one costs nothing to make exact.
fn same(a: &str, b: &str) -> bool {
    a.len() == b.len()
        && a.bytes()
            .zip(b.bytes())
            .fold(0_u8, |difference, (x, y)| difference | (x ^ y))
            == 0
}

/// Writes a complete answer and lets the connection close. The page loads nothing, tells the
/// browser to send no referrer and not to cache it: the address bar holds the code.
fn reply(stream: &mut TcpStream, status: &str, body: &str) {
    let response = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\n\
         Cache-Control: no-store\r\nReferrer-Policy: no-referrer\r\nX-Content-Type-Options: nosniff\r\n\
         Content-Security-Policy: default-src 'none'\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    // The visitor was read without blocking. The answer is short and goes out in one write; the
    // limit keeps a visitor that never reads from holding the listener. The browser may also
    // have gone already, and there is nobody to tell.
    let _ = stream.set_nonblocking(false);
    let _ = stream.set_write_timeout(Some(policy::REDIRECT_REPLY_TIMEOUT));
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

/// Signs in: opens the listener, has the user approve on the consent page, exchanges the code
/// and stores the result.
///
/// `announce` is called once with the consent address, which the user must open. Nothing is
/// stored unless Google granted exactly the read-only scope and issued a refresh token, so a
/// refused grant leaves any credentials already in `store` as they were.
///
/// # Errors
///
/// Any [`Error`]. [`Error::Store`] with [`store::Error::Grant`] is the refusal of a grant
/// that holds a scope other than the read-only one.
// why: docs/decisions/0014-read-only-no-composing.md, docs/decisions/0015-sign-in-flow.md
pub fn login<H: SyncHttpClient<Error = http::Error>>(
    http: &H,
    store: &dyn CredentialStore,
    client: &Client,
    announce: &dyn Fn(&Url),
    timeout: Duration,
) -> Result<(), Error> {
    let listener = bind_loopback()?;
    let redirect = RedirectUrl::new(redirect_uri(&listener)?).map_err(|_| Error::Setup)?;
    let oauth = BasicClient::new(ClientId::new(client.id.clone()))
        .set_client_secret(ClientSecret::new(client.secret.expose().to_owned()))
        .set_auth_uri(AuthUrl::new(policy::CONSENT_URL.to_owned()).map_err(|_| Error::Setup)?)
        .set_token_uri(TokenUrl::new(policy::TOKEN_URL.to_owned()).map_err(|_| Error::Setup)?)
        .set_redirect_uri(redirect)
        // Google documents the client credentials as form fields of the token request.
        .set_auth_type(AuthType::RequestBody);

    let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
    let (consent, state) = oauth
        .authorize_url(CsrfToken::new_random)
        .add_scopes(
            policy::SCOPES
                .iter()
                .map(|scope| Scope::new((*scope).to_owned())),
        )
        .set_pkce_challenge(challenge)
        // Without these Google may omit the refresh token on a repeated consent.
        .add_extra_param("access_type", "offline")
        .add_extra_param("prompt", "consent")
        .url();

    announce(&consent);
    let code = await_redirect(&listener, &state, timeout)?;
    // The redirect has arrived: nothing else may connect to the port.
    drop(listener);

    let tokens = oauth
        .exchange_code(code)
        .set_pkce_verifier(verifier)
        .request(http)
        .map_err(|error| exchange_failure(&error))?;

    // The check comes before anything else is looked at: a grant that is broader than
    // read-only is refused whatever else the response holds.
    let granted: Vec<String> = tokens
        .scopes()
        .map(|scopes| scopes.iter().map(|scope| scope.to_string()).collect())
        .unwrap_or_default();
    policy::check_grant(&granted)?;
    let refresh = tokens.refresh_token().ok_or(Error::NoRefreshToken)?;
    let credentials = Credentials::new(
        client.id.clone(),
        client.secret.clone(),
        Secret::new(refresh.secret().clone()),
        &granted,
    )?;
    store.save(&credentials)?;
    Ok(())
}

/// Turns a failed token request into an error with a static message. The details are dropped
/// on purpose: they can hold the response body, and a response can hold tokens.
fn exchange_failure(error: &RequestTokenError<http::Error, BasicErrorResponse>) -> Error {
    match error {
        RequestTokenError::Request(error) => Error::Network(*error),
        RequestTokenError::ServerResponse(_) => Error::Refused,
        _ => Error::BadResponse,
    }
}

/// Picks the OAuth client and signs in with it, against any store, HTTP client and consent
/// announcer.
///
/// The store is read first, so a platform without one fails before the user is asked to do
/// anything. The client comes from `credentials_file` (Google's downloaded JSON) if one is given,
/// otherwise from the credentials already stored, which is how a later run signs in again. A
/// stored item that is damaged is replaced, but only by a sign-in that brings its own client.
///
/// # Errors
///
/// Any [`Error`]: [`Error::NoClient`] if there is neither a file nor a stored client, the store's
/// own error if it cannot be read, otherwise as for [`login`].
// why: docs/decisions/0006-credentials-in-os-credential-store.md, docs/decisions/0015-sign-in-flow.md
pub fn authenticate<H: SyncHttpClient<Error = http::Error>>(
    http: &H,
    store: &dyn CredentialStore,
    credentials_file: Option<&Path>,
    announce: &dyn Fn(&Url),
    timeout: Duration,
) -> Result<(), Error> {
    let stored = match store.load() {
        Ok(stored) => stored,
        Err(store::Error::Corrupt) if credentials_file.is_some() => None,
        Err(error) => return Err(error.into()),
    };
    let client = match (credentials_file, stored) {
        (Some(path), _) => read_client_file(path)?,
        (None, Some(stored)) => Client::from(&stored),
        (None, None) => return Err(Error::NoClient),
    };
    login(http, store, &client, announce, timeout)
}

/// `gmail-mcp auth`: signs in and stores the credentials in this platform's credential store.
///
/// With `credentials_file`, the OAuth client comes from Google's downloaded JSON; without it,
/// from the credentials already stored (see [`authenticate`]).
///
/// # Errors
///
/// As for [`authenticate`].
pub fn run(credentials_file: Option<&Path>) -> Result<(), Error> {
    authenticate(
        &Guarded::new(),
        &store::platform(),
        credentials_file,
        &log::consent_url,
        policy::LOGIN_TIMEOUT,
    )?;
    log::info("signed in: the read-only credentials are in the credential store");
    if credentials_file.is_some() {
        log::info(
            "delete the client secret file now: auth has stored what it needs and never deletes your files",
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_compares_whole_strings() {
        assert!(same("abc", "abc"));
        assert!(!same("abc", "abd"));
        assert!(!same("abc", "abcd"));
        assert!(!same("", "a"));
        assert!(same("", ""));
    }

    #[test]
    fn the_redirect_address_names_the_loopback_listener() {
        let listener = bind_loopback().unwrap();
        let port = listener.local_addr().unwrap().port();
        let address = Url::parse(&redirect_uri(&listener).unwrap()).unwrap();
        assert_eq!(address.scheme(), "http");
        assert_eq!(address.host_str(), Some("127.0.0.1"));
        assert_eq!(address.port(), Some(port));
        assert!(address.query().is_none() && address.fragment().is_none());
    }

    #[test]
    fn an_error_has_a_static_message_without_values() {
        for error in [
            Error::NoClient,
            Error::ClientFileUnreadable,
            Error::ClientFileInvalid,
            Error::Listener,
            Error::Setup,
            Error::TimedOut,
            Error::Declined,
            Error::Network(http::Error::Timeout),
            Error::Refused,
            Error::BadResponse,
            Error::NoRefreshToken,
            Error::Store(store::Error::Unsupported),
        ] {
            assert_ne!(error.reason(), "");
            assert_eq!(error.to_string(), error.reason());
        }
    }
}
