//! The whole sign-in against a fake Google and a fake credential store: the consent address, the
//! redirect on a real loopback socket, the code exchange and the scope check. Nothing here
//! touches a real Google account, the network or a real credential store.
//! Why: docs/decisions/0014-read-only-no-composing.md, docs/decisions/0015-sign-in-flow.md.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use gmail_mcp::auth::{self, Client, Error};
use gmail_mcp::http::{self, Request, Response, header};
use gmail_mcp::policy::{self, GrantError, SCOPE_READONLY};
use gmail_mcp::store::{self, CredentialStore, Credentials, Secret};
use oauth2::url::{Url, form_urlencoded};
use oauth2::{HttpRequest, HttpResponse, PkceCodeChallenge, PkceCodeVerifier, SyncHttpClient};
use serde_json::{Map, Value, json};

const CLIENT_ID: &str = "000000000000-example.apps.example.invalid";
const CLIENT_SECRET: &str = "CLIENT-SECRET-SENTINEL";
const REFRESH: &str = "REFRESH-TOKEN-SENTINEL";
const ACCESS: &str = "ACCESS-TOKEN-SENTINEL";
const CODE: &str = "AUTHORIZATION-CODE-SENTINEL";
const TIMEOUT: Duration = Duration::from_secs(10);

/// A credential store in memory, which can be told to fail.
#[derive(Default)]
struct MemoryStore {
    slot: RefCell<Option<Credentials>>,
    saves: Cell<usize>,
    fail_with: Cell<Option<store::Error>>,
    load_fails: Cell<Option<store::Error>>,
}

/// `Credentials` has no `Clone`, so a copy is built from its parts.
fn copy(credentials: &Credentials) -> Credentials {
    Credentials::new(
        credentials.client_id().to_owned(),
        credentials.client_secret().clone(),
        credentials.refresh_token().clone(),
        credentials.scopes(),
    )
    .unwrap()
}

impl CredentialStore for MemoryStore {
    fn load(&self) -> Result<Option<Credentials>, store::Error> {
        if let Some(error) = self.load_fails.get() {
            return Err(error);
        }
        Ok(self.slot.borrow().as_ref().map(copy))
    }

    fn save(&self, credentials: &Credentials) -> Result<(), store::Error> {
        if let Some(error) = self.fail_with.get() {
            return Err(error);
        }
        self.saves.set(self.saves.get() + 1);
        *self.slot.borrow_mut() = Some(copy(credentials));
        Ok(())
    }

    fn remove(&self) -> Result<(), store::Error> {
        *self.slot.borrow_mut() = None;
        Ok(())
    }
}

impl MemoryStore {
    /// The refresh token held, if anything is.
    fn refresh_token(&self) -> Option<String> {
        self.slot
            .borrow()
            .as_ref()
            .map(|credentials| credentials.refresh_token().expose().to_owned())
    }
}

/// A fake Google: records every request and answers with whatever `reply` says.
struct FakeGoogle {
    seen: RefCell<Vec<HttpRequest>>,
    reply: Box<dyn Fn() -> Result<HttpResponse, http::Error>>,
}

impl SyncHttpClient for FakeGoogle {
    type Error = http::Error;

    fn call(&self, request: HttpRequest) -> Result<HttpResponse, http::Error> {
        self.seen.borrow_mut().push(request);
        (self.reply)()
    }
}

fn google(reply: impl Fn() -> Result<HttpResponse, http::Error> + 'static) -> FakeGoogle {
    FakeGoogle {
        seen: RefCell::default(),
        reply: Box::new(reply),
    }
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "the fake's reply closures return a Result, as a real request does"
)]
fn json_response(status: u16, body: &Value) -> Result<HttpResponse, http::Error> {
    Ok(Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
        .body(body.to_string().into_bytes())
        .unwrap())
}

/// What Google answers to a good code exchange; `scope` and `refresh_token` can be left out.
fn tokens(scope: Option<&str>, refresh: Option<&str>) -> Value {
    let mut body = Map::new();
    body.insert("access_token".into(), json!(ACCESS));
    body.insert("token_type".into(), json!("Bearer"));
    body.insert("expires_in".into(), json!(3599));
    if let Some(scope) = scope {
        body.insert("scope".into(), json!(scope));
    }
    if let Some(refresh) = refresh {
        body.insert("refresh_token".into(), json!(refresh));
    }
    Value::Object(body)
}

fn good_tokens() -> Value {
    tokens(Some(SCOPE_READONLY), Some(REFRESH))
}

fn client() -> Client {
    Client::new(CLIENT_ID.to_owned(), Secret::new(CLIENT_SECRET.to_owned())).unwrap()
}

/// What the user's browser does: reads the consent address, then follows Google's redirect.
struct Browser {
    consent: RefCell<Option<Url>>,
    page: RefCell<Option<JoinHandle<String>>>,
}

impl Browser {
    fn new() -> Self {
        Self {
            consent: RefCell::default(),
            page: RefCell::default(),
        }
    }

    /// Records the consent address and, in the background, sends the redirect that
    /// `redirect_query` builds from the `state` of that address.
    fn visit(
        &self,
        url: &Url,
        redirect_query: impl FnOnce(&str) -> Option<String> + Send + 'static,
    ) {
        *self.consent.borrow_mut() = Some(url.clone());
        let pairs: HashMap<String, String> = url
            .query_pairs()
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect();
        let redirect = Url::parse(&pairs["redirect_uri"]).unwrap();
        let address = format!(
            "{}:{}",
            redirect.host_str().unwrap(),
            redirect.port().unwrap()
        );
        let query = redirect_query(&pairs["state"]);
        let handle = thread::spawn(move || {
            let Some(query) = query else {
                return String::new();
            };
            let mut stream = TcpStream::connect(&address).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(15)))
                .unwrap();
            let request = format!("GET /?{query} HTTP/1.1\r\nHost: {address}\r\n\r\n");
            stream.write_all(request.as_bytes()).unwrap();
            let mut page = Vec::new();
            let _ = stream.read_to_end(&mut page);
            String::from_utf8_lossy(&page).into_owned()
        });
        *self.page.borrow_mut() = Some(handle);
    }

    fn consent(&self) -> Url {
        self.consent
            .borrow()
            .clone()
            .expect("the consent address was shown")
    }

    fn pairs(&self) -> HashMap<String, String> {
        self.consent()
            .query_pairs()
            .map(|(name, value)| (name.into_owned(), value.into_owned()))
            .collect()
    }

    fn page(&self) -> String {
        self.page.borrow_mut().take().unwrap().join().unwrap()
    }
}

/// A sign-in in which the user approves: the redirect carries the code and the right `state`.
fn approving(browser: &Browser) -> impl Fn(&Url) + '_ {
    |url| {
        browser.visit(url, |state| {
            Some(format!("state={state}&code={CODE}&scope=x"))
        });
    }
}

fn sign_in(http: &FakeGoogle, store: &MemoryStore, announce: &dyn Fn(&Url)) -> Result<(), Error> {
    auth::login(http, store, &client(), announce, TIMEOUT)
}

fn form(request: &HttpRequest) -> HashMap<String, String> {
    form_urlencoded::parse(request.body())
        .map(|(name, value)| (name.into_owned(), value.into_owned()))
        .collect()
}

#[test]
fn a_good_sign_in_stores_the_read_only_credentials() {
    let (browser, store) = (Browser::new(), MemoryStore::default());
    let fake = google(|| json_response(200, &good_tokens()));

    sign_in(&fake, &store, &approving(&browser)).unwrap();

    assert_eq!(store.refresh_token().as_deref(), Some(REFRESH));
    assert_eq!(store.saves.get(), 1);
    let stored = store.load().unwrap().unwrap();
    assert_eq!(stored.client_id(), CLIENT_ID);
    assert_eq!(stored.client_secret().expose(), CLIENT_SECRET);
    assert_eq!(stored.scopes(), policy::SCOPES);
    assert!(browser.page().contains("reached gmail-mcp"));
}

#[test]
fn the_consent_address_asks_for_the_read_only_scope_with_pkce_and_a_state() {
    let (browser, store) = (Browser::new(), MemoryStore::default());
    let fake = google(|| json_response(200, &good_tokens()));
    sign_in(&fake, &store, &approving(&browser)).unwrap();

    let consent = browser.consent();
    assert_eq!(
        format!(
            "{}://{}{}",
            consent.scheme(),
            consent.host_str().unwrap(),
            consent.path()
        ),
        policy::CONSENT_URL
    );
    assert!(consent.port().is_none() && consent.username().is_empty());
    let pairs = browser.pairs();
    assert_eq!(pairs["response_type"], "code");
    assert_eq!(pairs["client_id"], CLIENT_ID);
    // Exactly one scope, the read-only one.
    assert_eq!(pairs["scope"], SCOPE_READONLY);
    assert_eq!(pairs["code_challenge_method"], "S256");
    assert!(pairs["code_challenge"].len() >= 43);
    assert!(pairs["state"].len() >= 16);
    // So that Google issues a refresh token even if this client was approved before.
    assert_eq!(pairs["access_type"], "offline");
    assert_eq!(pairs["prompt"], "consent");
    // The redirect address is the loopback listener, with a port, and nothing else.
    let redirect = Url::parse(&pairs["redirect_uri"]).unwrap();
    assert_eq!(redirect.scheme(), "http");
    assert_eq!(redirect.host_str(), Some("127.0.0.1"));
    assert!(redirect.port().is_some());
    assert!(redirect.path() == "/" && redirect.query().is_none());
    // Nothing secret is in the address the user is asked to open.
    let shown = consent.to_string();
    assert!(!shown.contains(CLIENT_SECRET) && !shown.contains("code_verifier"));
}

#[test]
fn the_code_exchange_is_one_guarded_request_that_proves_the_pkce_verifier() {
    let (browser, store) = (Browser::new(), MemoryStore::default());
    let fake = google(|| json_response(200, &good_tokens()));
    sign_in(&fake, &store, &approving(&browser)).unwrap();

    let seen = fake.seen.borrow();
    assert_eq!(seen.len(), 1, "exactly one request to Google");
    let request = &seen[0];
    assert_eq!(request.method().as_str(), "POST");
    assert_eq!(request.uri().to_string(), policy::TOKEN_URL);
    // The request passes every rule of the egress guard: route, headers, size.
    assert_eq!(
        policy::authorize("POST", &request.uri().to_string()),
        Ok(())
    );
    for name in request.headers().keys() {
        assert!(
            policy::header_allowed(name.as_str()),
            "{name} is not allowed"
        );
    }
    assert!(request.body().len() <= policy::MAX_REQUEST_BYTES);

    let fields = form(request);
    assert_eq!(fields["grant_type"], "authorization_code");
    assert_eq!(fields["code"], CODE);
    assert_eq!(fields["client_id"], CLIENT_ID);
    assert_eq!(fields["client_secret"], CLIENT_SECRET);
    assert_eq!(fields["redirect_uri"], browser.pairs()["redirect_uri"]);
    // The verifier is the one whose SHA-256 the consent address announced.
    let challenge = PkceCodeChallenge::from_code_verifier_sha256(&PkceCodeVerifier::new(
        fields["code_verifier"].clone(),
    ));
    assert_eq!(challenge.as_str(), browser.pairs()["code_challenge"]);
}

/// An earlier consent for the same client can hand back more than the request names. Nothing is
/// stored then, and what was stored before stays as it was.
#[test]
fn a_grant_with_any_other_scope_is_refused_and_nothing_is_stored() {
    for extra in [
        "https://www.googleapis.com/auth/gmail.modify",
        "https://mail.google.com/",
        "https://www.googleapis.com/auth/gmail.compose",
        "openid",
    ] {
        let (browser, store) = (Browser::new(), MemoryStore::default());
        store
            .save(
                &Credentials::new(
                    "older-client".to_owned(),
                    Secret::new("older-secret".to_owned()),
                    Secret::new("older-refresh".to_owned()),
                    &[SCOPE_READONLY],
                )
                .unwrap(),
            )
            .unwrap();
        let saves_before = store.saves.get();
        let scope = format!("{SCOPE_READONLY} {extra}");
        let fake = google(move || json_response(200, &tokens(Some(&scope), Some(REFRESH))));

        let result = sign_in(&fake, &store, &approving(&browser));

        assert_eq!(
            result.unwrap_err(),
            Error::Store(store::Error::Grant(GrantError::Broader)),
            "{extra}"
        );
        assert_eq!(
            store.saves.get(),
            saves_before,
            "something was stored for {extra}"
        );
        assert_eq!(store.refresh_token().as_deref(), Some("older-refresh"));
    }
}

#[test]
fn a_grant_that_is_not_the_read_only_scope_alone_is_refused() {
    for scope in [
        "https://www.googleapis.com/auth/gmail.modify",
        "openid email",
        " ",
    ] {
        let (browser, store) = (Browser::new(), MemoryStore::default());
        let scope = scope.to_owned();
        let fake = google(move || json_response(200, &tokens(Some(&scope), Some(REFRESH))));
        let result = sign_in(&fake, &store, &approving(&browser));
        assert_eq!(
            result.unwrap_err(),
            Error::Store(store::Error::Grant(GrantError::Broader))
        );
        assert_eq!(store.saves.get(), 0);
    }
}

#[test]
fn a_grant_that_google_does_not_describe_is_refused() {
    let (browser, store) = (Browser::new(), MemoryStore::default());
    let fake = google(|| json_response(200, &tokens(None, Some(REFRESH))));
    let result = sign_in(&fake, &store, &approving(&browser));
    assert_eq!(
        result.unwrap_err(),
        Error::Store(store::Error::Grant(GrantError::Unreported))
    );
    assert_eq!(store.saves.get(), 0);
}

#[test]
fn without_a_refresh_token_nothing_is_stored() {
    let (browser, store) = (Browser::new(), MemoryStore::default());
    let fake = google(|| json_response(200, &tokens(Some(SCOPE_READONLY), None)));
    let result = sign_in(&fake, &store, &approving(&browser));
    assert_eq!(result.unwrap_err(), Error::NoRefreshToken);
    assert_eq!(store.saves.get(), 0);
}

#[test]
fn a_refusal_by_google_is_reported_without_its_text() {
    let (browser, store) = (Browser::new(), MemoryStore::default());
    let fake = google(|| {
        json_response(
            400,
            &json!({ "error": "invalid_grant", "error_description": "Bad Request ACCESS-TOKEN-SENTINEL" }),
        )
    });
    let error = sign_in(&fake, &store, &approving(&browser)).unwrap_err();
    assert_eq!(error, Error::Refused);
    assert!(!format!("{error} {error:?}").contains("SENTINEL"));
    assert_eq!(store.saves.get(), 0);
}

#[test]
fn an_answer_that_is_not_a_token_response_is_reported_without_its_text() {
    let answers: Vec<Box<dyn Fn() -> Result<HttpResponse, http::Error>>> = vec![
        Box::new(|| json_response(200, &json!({ "unexpected": ACCESS }))),
        Box::new(|| json_response(200, &json!([ACCESS]))),
        Box::new(|| {
            Ok(Response::builder()
                .status(200)
                .header(header::CONTENT_TYPE, "text/html")
                .body(format!("<html>{ACCESS}").into_bytes())
                .unwrap())
        }),
        Box::new(|| {
            Ok(Response::builder()
                .status(200)
                .header(header::CONTENT_TYPE, "application/json")
                .body(format!("{{\"access_token\": \"{ACCESS}").into_bytes())
                .unwrap())
        }),
        Box::new(|| {
            Ok(Response::builder()
                .status(502)
                .body(format!("gateway {ACCESS}").into_bytes())
                .unwrap())
        }),
        Box::new(|| {
            Ok(Response::builder()
                .status(200)
                .header(header::CONTENT_TYPE, "application/json")
                .body(Vec::new())
                .unwrap())
        }),
    ];
    for answer in answers {
        let (browser, store) = (Browser::new(), MemoryStore::default());
        let fake = FakeGoogle {
            seen: RefCell::default(),
            reply: answer,
        };
        let error = sign_in(&fake, &store, &approving(&browser)).unwrap_err();
        assert_eq!(error, Error::BadResponse);
        assert!(!format!("{error} {error:?}").contains("SENTINEL"));
        assert_eq!(store.saves.get(), 0);
    }
}

#[test]
fn a_failed_request_is_reported_with_the_guards_own_message() {
    for failure in [
        http::Error::Timeout,
        http::Error::Network,
        http::Error::Redirect,
        http::Error::TooLarge,
    ] {
        let (browser, store) = (Browser::new(), MemoryStore::default());
        let fake = google(move || Err(failure));
        let error = sign_in(&fake, &store, &approving(&browser)).unwrap_err();
        assert_eq!(error, Error::Network(failure));
        assert_eq!(error.reason(), failure.reason());
        assert_eq!(store.saves.get(), 0);
    }
}

#[test]
fn a_user_who_declines_never_reaches_google() {
    let (browser, store) = (Browser::new(), MemoryStore::default());
    let fake = google(|| json_response(200, &good_tokens()));
    let declining = |url: &Url| {
        browser.visit(url, |state| {
            Some(format!("error=access_denied&state={state}"))
        });
    };

    let error = sign_in(&fake, &store, &declining).unwrap_err();

    assert_eq!(error, Error::Declined);
    assert!(fake.seen.borrow().is_empty(), "Google was contacted");
    assert_eq!(store.saves.get(), 0);
    assert!(browser.page().contains("Access was not granted"));
}

/// A redirect that carries another sign-in's state is not this sign-in: it is ignored, and
/// without the real redirect the sign-in times out and contacts nobody.
#[test]
fn a_redirect_with_a_foreign_state_is_not_used() {
    let (browser, store) = (Browser::new(), MemoryStore::default());
    let fake = google(|| json_response(200, &good_tokens()));
    let foreign = |url: &Url| {
        browser.visit(url, |_| Some(format!("state=someone-elses&code={CODE}")));
    };

    let result = auth::login(
        &fake,
        &store,
        &client(),
        &foreign,
        Duration::from_millis(800),
    );

    assert_eq!(result.unwrap_err(), Error::TimedOut);
    assert!(fake.seen.borrow().is_empty(), "Google was contacted");
    assert_eq!(store.saves.get(), 0);
    assert!(browser.page().starts_with("HTTP/1.1 400"));
}

#[test]
fn a_sign_in_nobody_finishes_times_out() {
    let (browser, store) = (Browser::new(), MemoryStore::default());
    let fake = google(|| json_response(200, &good_tokens()));
    let idle = |url: &Url| browser.visit(url, |_| None);
    let result = auth::login(&fake, &store, &client(), &idle, Duration::from_millis(300));
    assert_eq!(result.unwrap_err(), Error::TimedOut);
    assert!(fake.seen.borrow().is_empty());
}

#[test]
fn a_store_that_refuses_the_credentials_fails_the_sign_in() {
    let (browser, store) = (Browser::new(), MemoryStore::default());
    store.fail_with.set(Some(store::Error::Denied));
    let fake = google(|| json_response(200, &good_tokens()));
    let error = sign_in(&fake, &store, &approving(&browser)).unwrap_err();
    assert_eq!(error, Error::Store(store::Error::Denied));
}

/// No message, `Debug` output or error text of the flow repeats a secret it handled.
#[test]
fn no_secret_shows_up_in_any_text_the_flow_produces() {
    let (browser, store) = (Browser::new(), MemoryStore::default());
    let fake = google(|| json_response(200, &good_tokens()));
    sign_in(&fake, &store, &approving(&browser)).unwrap();

    let stored = store.load().unwrap().unwrap();
    let texts = [
        format!("{stored:?}"),
        format!("{:?}", client()),
        format!("{:?}", stored.client_secret()),
        format!("{:?}", stored.refresh_token()),
    ];
    for text in texts {
        for sentinel in [CLIENT_SECRET, REFRESH, ACCESS, CODE] {
            // A static message: a failing assert must not print the text that leaked.
            assert!(!text.contains(sentinel), "a secret shows in a debug print");
        }
    }
}

/// The OAuth library's traffic goes through the egress guard: a request the allowlist does not
/// list is refused before anything is sent, so these calls need no network.
#[test]
fn the_oauth_clients_traffic_is_held_to_the_allowlist() {
    let guarded = auth::Guarded::new();
    let refused = |method: &str, url: &str| -> Result<HttpResponse, http::Error> {
        let request: Request<Vec<u8>> = Request::builder()
            .method(method)
            .uri(url)
            .body(Vec::new())
            .unwrap();
        guarded.call(request)
    };
    for (method, url) in [
        ("GET", policy::CONSENT_URL),
        ("POST", policy::CONSENT_URL),
        ("GET", "https://example.test/token"),
        ("GET", policy::TOKEN_URL),
        ("POST", "https://oauth2.googleapis.com/revoke"),
        (
            "POST",
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/send",
        ),
        (
            "DELETE",
            "https://gmail.googleapis.com/gmail/v1/users/me/messages/abc",
        ),
    ] {
        assert!(
            matches!(refused(method, url), Err(http::Error::Denied(_))),
            "{method} {url} was not refused"
        );
    }
}

// The choice of client and the order of the steps, as `gmail-mcp auth` runs them.

fn credentials(id: &str, secret: &str, refresh: &str) -> Credentials {
    Credentials::new(
        id.to_owned(),
        Secret::new(secret.to_owned()),
        Secret::new(refresh.to_owned()),
        &[SCOPE_READONLY],
    )
    .unwrap()
}

/// A client secret file in the shape Google offers, in a scratch folder removed afterwards.
struct ClientFile(PathBuf);

impl ClientFile {
    fn new(label: &str, id: &str, secret: &str) -> Self {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "gmail-mcp-test-{label}-{}-{nanos}",
            std::process::id()
        ));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("client_secret.json");
        let file = json!({ "installed": { "client_id": id, "client_secret": secret } });
        fs::write(&path, file.to_string()).unwrap();
        Self(path)
    }

    fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for ClientFile {
    fn drop(&mut self) {
        if let Some(dir) = self.0.parent() {
            let _ = fs::remove_dir_all(dir);
        }
    }
}

/// An announcer that records whether the user was ever asked to open the consent page.
fn asked(flag: &Cell<bool>) -> impl Fn(&Url) + '_ {
    |_| flag.set(true)
}

/// Whatever goes wrong before the consent page must be reported before the user is asked to do
/// anything, and without contacting Google.
fn assert_stopped_early(fake: &FakeGoogle, asked: &Cell<bool>) {
    assert!(!asked.get(), "the user was asked to open the consent page");
    assert!(fake.seen.borrow().is_empty(), "Google was contacted");
}

#[test]
fn a_platform_without_a_store_fails_before_the_user_is_asked_to_do_anything() {
    let file = ClientFile::new("no-store", CLIENT_ID, CLIENT_SECRET);
    for credentials_file in [None, Some(file.path())] {
        let (flag, fake) = (
            Cell::new(false),
            google(|| json_response(200, &good_tokens())),
        );
        let result = auth::authenticate(
            &fake,
            &store::Unavailable,
            credentials_file,
            &asked(&flag),
            TIMEOUT,
        );
        assert_eq!(result.unwrap_err(), Error::Store(store::Error::Unsupported));
        assert_stopped_early(&fake, &flag);
    }
}

#[test]
fn a_store_that_refuses_to_be_read_stops_the_sign_in_even_with_a_file() {
    let file = ClientFile::new("denied", CLIENT_ID, CLIENT_SECRET);
    let store = MemoryStore::default();
    store.load_fails.set(Some(store::Error::Denied));
    for credentials_file in [None, Some(file.path())] {
        let (flag, fake) = (
            Cell::new(false),
            google(|| json_response(200, &good_tokens())),
        );
        let result = auth::authenticate(&fake, &store, credentials_file, &asked(&flag), TIMEOUT);
        assert_eq!(result.unwrap_err(), Error::Store(store::Error::Denied));
        assert_stopped_early(&fake, &flag);
    }
}

#[test]
fn without_a_file_or_a_stored_client_there_is_nothing_to_sign_in_with() {
    let (flag, store) = (Cell::new(false), MemoryStore::default());
    let fake = google(|| json_response(200, &good_tokens()));
    let result = auth::authenticate(&fake, &store, None, &asked(&flag), TIMEOUT);
    assert_eq!(result.unwrap_err(), Error::NoClient);
    assert_stopped_early(&fake, &flag);
}

/// Signing in again after the refresh token expired needs no file: the client is in the store.
#[test]
fn without_a_file_the_stored_client_signs_in_again() {
    let (browser, store) = (Browser::new(), MemoryStore::default());
    store
        .save(&credentials(
            "stored-client",
            "stored-secret",
            "old-refresh",
        ))
        .unwrap();
    let fake = google(|| json_response(200, &good_tokens()));

    auth::authenticate(&fake, &store, None, &approving(&browser), TIMEOUT).unwrap();

    let fields = form(&fake.seen.borrow()[0]);
    assert_eq!(fields["client_id"], "stored-client");
    assert_eq!(fields["client_secret"], "stored-secret");
    assert_eq!(browser.pairs()["client_id"], "stored-client");
    let now = store.load().unwrap().unwrap();
    assert_eq!(now.client_id(), "stored-client");
    assert_eq!(now.refresh_token().expose(), REFRESH);
}

#[test]
fn a_client_file_replaces_the_stored_client() {
    let (browser, store) = (Browser::new(), MemoryStore::default());
    store
        .save(&credentials(
            "stored-client",
            "stored-secret",
            "old-refresh",
        ))
        .unwrap();
    let file = ClientFile::new("replace", "file-client", "file-secret");
    let fake = google(|| json_response(200, &good_tokens()));

    auth::authenticate(
        &fake,
        &store,
        Some(file.path()),
        &approving(&browser),
        TIMEOUT,
    )
    .unwrap();

    assert_eq!(form(&fake.seen.borrow()[0])["client_id"], "file-client");
    let now = store.load().unwrap().unwrap();
    assert_eq!(now.client_id(), "file-client");
    assert_eq!(now.client_secret().expose(), "file-secret");
    // Telling the user to delete the file is the program's part; deleting it is not.
    assert!(file.path().is_file(), "auth deleted the client secret file");
}

/// A damaged item is replaced, but only by a sign-in that brings its own client: without a
/// file there is no client to sign in with, and the damage is reported.
#[test]
fn a_damaged_item_is_replaced_only_by_a_sign_in_that_brings_its_own_client() {
    let (flag, store) = (Cell::new(false), MemoryStore::default());
    store.load_fails.set(Some(store::Error::Corrupt));
    let fake = google(|| json_response(200, &good_tokens()));
    let result = auth::authenticate(&fake, &store, None, &asked(&flag), TIMEOUT);
    assert_eq!(result.unwrap_err(), Error::Store(store::Error::Corrupt));
    assert_stopped_early(&fake, &flag);

    let (browser, file) = (
        Browser::new(),
        ClientFile::new("damaged", "file-client", "file-secret"),
    );
    auth::authenticate(
        &fake,
        &store,
        Some(file.path()),
        &approving(&browser),
        TIMEOUT,
    )
    .unwrap();
    assert_eq!(store.refresh_token().as_deref(), Some(REFRESH));
}

#[test]
fn a_client_file_that_is_missing_or_wrong_stops_the_sign_in_before_the_consent_page() {
    let store = MemoryStore::default();
    let wrong = ClientFile::new("wrong", "id", "secret");
    fs::write(
        wrong.path(),
        json!({ "web": { "client_id": "id" } }).to_string(),
    )
    .unwrap();
    let missing = wrong.path().with_file_name("missing.json");
    for (file, expected) in [
        (missing.as_path(), Error::ClientFileUnreadable),
        (wrong.path(), Error::ClientFileInvalid),
    ] {
        let (flag, fake) = (
            Cell::new(false),
            google(|| json_response(200, &good_tokens())),
        );
        let result = auth::authenticate(&fake, &store, Some(file), &asked(&flag), TIMEOUT);
        assert_eq!(result.unwrap_err(), expected);
        assert_stopped_early(&fake, &flag);
    }
}

/// The grant check comes before anything else in the response is looked at: a grant that is
/// broader than read-only is reported as that, even if the response also lacks a refresh token.
#[test]
fn a_broader_grant_is_reported_before_a_missing_refresh_token() {
    let (browser, store) = (Browser::new(), MemoryStore::default());
    let scope = format!("{SCOPE_READONLY} https://mail.google.com/");
    let fake = google(move || json_response(200, &tokens(Some(&scope), None)));
    let result = sign_in(&fake, &store, &approving(&browser));
    assert_eq!(
        result.unwrap_err(),
        Error::Store(store::Error::Grant(GrantError::Broader))
    );
    assert_eq!(store.saves.get(), 0);
}
