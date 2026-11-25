//! The token refresh against a fake Google token endpoint and an in-memory credential store.
//!
//! No test touches the network or a real credential store. Assert messages are static where they
//! could repeat text that came from a token: `CodeQL` flags interpolating such text, tests
//! included. Why: docs/decisions/0006-credentials-in-os-credential-store.md,
//! docs/decisions/0014-read-only-no-composing.md.

use std::cell::{Cell, RefCell};
use std::collections::HashMap;
use std::rc::Rc;

use gmail_mcp::http::{self, Response, header};
use gmail_mcp::policy::{self, GrantError, SCOPE_READONLY};
use gmail_mcp::session::{Error, Session, TokenSource};
use gmail_mcp::store::{self, CredentialStore, Credentials, Secret};
use oauth2::url::form_urlencoded;
use oauth2::{HttpRequest, HttpResponse, SyncHttpClient};
use serde_json::{Map, Value, json};

const CLIENT_ID: &str = "000000000000-example.apps.example.invalid";
const CLIENT_SECRET: &str = "CLIENT-SECRET-SENTINEL";
const REFRESH: &str = "REFRESH-TOKEN-SENTINEL";
const ACCESS: &str = "ACCESS-TOKEN-SENTINEL";

/// A store that holds the sample credentials, or nothing, and counts its reads.
struct Store {
    have: bool,
    loads: Rc<Cell<usize>>,
}

impl CredentialStore for Store {
    fn load(&self) -> Result<Option<Credentials>, store::Error> {
        self.loads.set(self.loads.get() + 1);
        if !self.have {
            return Ok(None);
        }
        Credentials::new(
            CLIENT_ID.to_owned(),
            Secret::new(CLIENT_SECRET.to_owned()),
            Secret::new(REFRESH.to_owned()),
            &[SCOPE_READONLY],
        )
        .map(Some)
    }

    fn save(&self, _: &Credentials) -> Result<(), store::Error> {
        Err(store::Error::Failed)
    }

    fn remove(&self) -> Result<(), store::Error> {
        Err(store::Error::Failed)
    }
}

type Reply = Box<dyn Fn(usize) -> Result<HttpResponse, http::Error>>;

/// A fake Google: records every request and answers as `reply` says for the request's number.
struct Google {
    seen: Rc<RefCell<Vec<HttpRequest>>>,
    reply: Reply,
}

impl SyncHttpClient for Google {
    type Error = http::Error;

    fn call(&self, request: HttpRequest) -> Result<HttpResponse, http::Error> {
        let index = self.seen.borrow().len();
        self.seen.borrow_mut().push(request);
        (self.reply)(index)
    }
}

struct Rig {
    session: Session<Google, Store>,
    seen: Rc<RefCell<Vec<HttpRequest>>>,
    loads: Rc<Cell<usize>>,
}

fn rig(have: bool, reply: impl Fn(usize) -> Result<HttpResponse, http::Error> + 'static) -> Rig {
    let seen = Rc::new(RefCell::new(Vec::new()));
    let loads = Rc::new(Cell::new(0));
    let google = Google {
        seen: Rc::clone(&seen),
        reply: Box::new(reply),
    };
    let store = Store {
        have,
        loads: Rc::clone(&loads),
    };
    Rig {
        session: Session::new(google, store),
        seen,
        loads,
    }
}

fn answer(status: u16, body: &Value) -> HttpResponse {
    Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, "application/json; charset=utf-8")
        .body(body.to_string().into_bytes())
        .expect("a response")
}

/// What Google answers to a refresh; `scope` can be left out.
fn tokens(scope: Option<&str>, expires_in: u64) -> Value {
    let mut body = Map::new();
    body.insert("access_token".into(), json!(ACCESS));
    body.insert("token_type".into(), json!("Bearer"));
    body.insert("expires_in".into(), json!(expires_in));
    if let Some(scope) = scope {
        body.insert("scope".into(), json!(scope));
    }
    Value::Object(body)
}

fn good() -> HttpResponse {
    answer(200, &tokens(Some(SCOPE_READONLY), 3599))
}

fn is_access_token(token: &Secret) -> bool {
    token.expose() == ACCESS
}

#[test]
fn nothing_is_read_from_the_store_until_a_token_is_needed() {
    let mut rig = rig(true, |_| Ok(good()));
    assert_eq!(rig.loads.get(), 0, "the store was read at start");
    assert!(is_access_token(
        &rig.session.access_token().expect("a token")
    ));
    assert_eq!(rig.loads.get(), 1);
}

#[test]
fn no_stored_sign_in_asks_the_user_to_run_auth_and_sends_nothing() {
    let mut rig = rig(false, |_| Ok(good()));
    let error = rig.session.access_token().expect_err("no sign-in");
    assert_eq!(error, Error::NoCredentials);
    assert!(error.reason().contains("gmail-mcp auth"));
    assert!(rig.seen.borrow().is_empty(), "a request was sent");
}

#[test]
fn a_refresh_is_one_guarded_post_and_the_token_is_kept_until_it_expires() {
    let mut rig = rig(true, |_| Ok(good()));
    assert!(is_access_token(&rig.session.access_token().expect("first")));
    assert!(is_access_token(
        &rig.session.access_token().expect("second")
    ));
    assert_eq!(rig.seen.borrow().len(), 1, "the second call made a request");
    {
        let seen = rig.seen.borrow();
        let request = &seen[0];
        assert_eq!(request.method().as_str(), "POST");
        let url = request.uri().to_string();
        assert_eq!(url, policy::TOKEN_URL);
        policy::authorize("POST", &url).expect("the guard accepts the request");
        let form: HashMap<String, String> = form_urlencoded::parse(request.body())
            .into_owned()
            .collect();
        assert_eq!(
            form.get("grant_type").map(String::as_str),
            Some("refresh_token")
        );
        assert!(
            form.get("refresh_token")
                .is_some_and(|value| value == REFRESH)
        );
        assert!(
            form.get("client_id")
                .is_some_and(|value| value == CLIENT_ID)
        );
        assert!(
            form.get("client_secret")
                .is_some_and(|value| value == CLIENT_SECRET)
        );
    }
    rig.session.invalidate();
    rig.session.access_token().expect("after invalidate");
    assert_eq!(
        rig.seen.borrow().len(),
        2,
        "an invalidated token was reused"
    );
}

#[test]
fn a_token_that_is_about_to_expire_is_not_reused() {
    let mut rig = rig(true, |_| Ok(answer(200, &tokens(Some(SCOPE_READONLY), 30))));
    rig.session.access_token().expect("first");
    rig.session.access_token().expect("second");
    assert_eq!(rig.seen.borrow().len(), 2);
}

#[test]
fn invalid_grant_says_to_sign_in_again_and_the_store_is_read_again_next_time() {
    let mut rig = rig(true, |_| {
        Ok(answer(400, &json!({ "error": "invalid_grant" })))
    });
    let error = rig.session.access_token().expect_err("expired");
    assert_eq!(error, Error::Expired);
    assert!(error.reason().contains("gmail-mcp auth"));
    assert_eq!(rig.loads.get(), 1);
    rig.session.access_token().expect_err("still expired");
    assert_eq!(rig.loads.get(), 2, "a new sign-in would have been missed");
}

#[test]
fn another_refusal_never_repeats_what_google_said() {
    let mut rig = rig(true, |_| {
        Ok(answer(
            401,
            &json!({ "error": "invalid_client", "error_description": "GOOGLE-TEXT-SENTINEL" }),
        ))
    });
    let error = rig.session.access_token().expect_err("refused");
    assert_eq!(error, Error::Refused);
    assert!(!error.reason().contains("GOOGLE-TEXT-SENTINEL"));
}

#[test]
fn a_refresh_that_grants_more_than_read_only_is_refused_and_not_kept() {
    let broader = format!("{SCOPE_READONLY} https://www.googleapis.com/auth/gmail.modify");
    let mut rig = rig(true, move |_| {
        Ok(answer(200, &tokens(Some(&broader), 3599)))
    });
    let error = rig.session.access_token().expect_err("broader grant");
    assert_eq!(error, Error::Grant(GrantError::Broader));
    rig.session.access_token().expect_err("still refused");
    assert_eq!(rig.seen.borrow().len(), 2, "a refused token was kept");
}

#[test]
fn a_refresh_that_does_not_say_what_it_granted_is_refused() {
    let mut rig = rig(true, |_| Ok(answer(200, &tokens(None, 3599))));
    assert_eq!(
        rig.session.access_token().expect_err("unreported grant"),
        Error::Grant(GrantError::Unreported)
    );
}

#[test]
fn a_network_failure_is_a_static_error() {
    let mut rig = rig(true, |_| Err(http::Error::Network));
    let error = rig.session.access_token().expect_err("no network");
    assert_eq!(error, Error::Network(http::Error::Network));
    assert_eq!(error.reason(), http::Error::Network.reason());
}
