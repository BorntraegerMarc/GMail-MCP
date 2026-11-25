//! The Gmail client: the four read calls behind the tools.
//!
//! [`Gmail`] builds each request from the fixed route shapes that the route table in
//! [`crate::policy`] lists, sends it through a [`Transport`] with a bearer token from a
//! [`TokenSource`], and turns Google's JSON answer into plain structures. Nothing here decides
//! what the model sees: every string in these structures comes from a mail and stays untrusted
//! until [`crate::tools`] has wrapped it (ADR 0005).
//!
//! The answer is parsed as `serde_json::Value` and read with `get`, never by indexing, so a
//! missing or mistyped field leaves a default and cannot panic. What a hostile answer can cost is
//! bounded by the response limit of the egress guard, the nesting limit of the JSON parser and
//! the MIME limits below.
// why: docs/decisions/0003-single-egress-allowlist.md, docs/decisions/0005-untrusted-email-content.md

use std::fmt;

use base64::Engine as _;
use base64::alphabet::URL_SAFE;
use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
use oauth2::url::form_urlencoded;
use serde_json::Value;

use crate::http::{self, Egress, Method, Request, header};
use crate::policy::ResourceId;
use crate::session::{self, TokenSource};
use crate::text;

/// The Gmail API root for the signed-in user. Every request starts with it, and the egress guard
/// refuses any path that is not in the route table.
const BASE: &str = "https://gmail.googleapis.com/gmail/v1/users/me";

/// Deepest nesting of MIME parts that is read; deeper parts are skipped and the message is
/// marked incomplete. A hostile mail can nest parts without limit, and the walk must not.
// why: docs/decisions/0005-untrusted-email-content.md
pub const MAX_MIME_DEPTH: usize = 8;

/// Most MIME parts read from one message; the rest are skipped and the message is marked
/// incomplete.
// why: docs/decisions/0005-untrusted-email-content.md
pub const MAX_MIME_PARTS: usize = 200;

/// Most decoded text kept from one message, plain text and HTML together. The converter and the
/// output budget cut it further; this bounds what a hostile body can make the process hold.
// why: docs/decisions/0005-untrusted-email-content.md
pub const MAX_TEXT_BYTES: usize = 1024 * 1024;

/// Gmail's body encoding: base64url, usually without padding. Padding is optional on input, so
/// both spellings decode.
const BASE64URL: GeneralPurpose = GeneralPurpose::new(
    &URL_SAFE,
    GeneralPurposeConfig::new()
        .with_encode_padding(false)
        .with_decode_padding_mode(DecodePaddingMode::Indifferent),
);

/// What a JSON field that is absent reads as.
static NULL: Value = Value::Null;

/// Why a Gmail call failed. Every message is static: errors reach the model and the logs, and
/// Google's answer, which can echo mail or tokens, is never part of one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The request did not produce a response.
    Network(http::Error),
    /// The response was larger than the size limit.
    TooLarge,
    /// No access token could be obtained.
    Token(session::Error),
    /// Gmail refused the access token, again after a refresh.
    Unauthorized,
    /// Gmail refused the request (HTTP 403).
    Forbidden,
    /// No such thread or message (HTTP 404).
    NotFound,
    /// Gmail asked for fewer requests (HTTP 429).
    RateLimited,
    /// Any other status than 200.
    Status,
    /// The answer was not JSON of the expected kind.
    BadResponse,
}

impl Error {
    /// A fixed, human-readable reason that is safe to log and to return to the model.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Error::Network(error) => error.reason(),
            Error::TooLarge => "the response is larger than the size limit",
            Error::Token(error) => error.reason(),
            Error::Unauthorized => {
                "Gmail refused the access token even after a refresh; run `gmail-mcp auth` again"
            }
            Error::Forbidden => {
                "Gmail refused the request: is the Gmail API enabled for the OAuth client's project, and is gmail.readonly granted?"
            }
            Error::NotFound => "there is no such thread or message",
            Error::RateLimited => "Gmail is limiting requests; wait a little and try again",
            Error::Status => "Gmail answered with an unexpected status",
            Error::BadResponse => "Gmail's answer was not the JSON that was expected",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for Error {}

impl From<http::Error> for Error {
    fn from(error: http::Error) -> Self {
        match error {
            http::Error::TooLarge => Error::TooLarge,
            other => Error::Network(other),
        }
    }
}

/// What one request got back: the status and the body, whatever the status.
#[derive(Debug)]
pub struct Reply {
    /// The HTTP status code.
    pub status: u16,
    /// The response body.
    pub body: Vec<u8>,
}

/// Sends one authenticated `GET`. The production implementation is [`EgressTransport`]; tests
/// use a fake, so no test reaches the network.
pub trait Transport {
    /// Sends `GET url` with `bearer` as the access token and returns the status and body. A 4xx
    /// or 5xx answer is a [`Reply`], not an error.
    ///
    /// # Errors
    ///
    /// The failure of the exchange itself, as the egress guard reports it.
    fn get(&self, url: &str, bearer: &str) -> Result<Reply, http::Error>;
}

/// The production [`Transport`]: every request goes through the egress guard, which holds it to
/// the route table.
// why: docs/decisions/0003-single-egress-allowlist.md
#[derive(Default)]
pub struct EgressTransport {
    egress: Egress,
}

impl EgressTransport {
    /// Creates the transport, with its own egress guard.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Transport for EgressTransport {
    fn get(&self, url: &str, bearer: &str) -> Result<Reply, http::Error> {
        let request = Request::builder()
            .method(Method::GET)
            .uri(url)
            .header(header::AUTHORIZATION, format!("Bearer {bearer}"))
            .header(header::ACCEPT, "application/json")
            .body(Vec::new())
            // A token with a character a header cannot hold fails here, before anything is sent.
            .map_err(|_| http::Error::Network)?;
        let response = self.egress.send(request)?;
        Ok(Reply {
            status: response.status().as_u16(),
            body: response.into_body(),
        })
    }
}

/// How Gmail classes a label.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LabelKind {
    /// Built in, such as `INBOX`.
    System,
    /// Created by the user.
    User,
    /// Anything else Gmail may report.
    Other,
}

impl LabelKind {
    /// A fixed word for the kind, safe to print outside the delimiters.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            LabelKind::System => "system",
            LabelKind::User => "user",
            LabelKind::Other => "other",
        }
    }
}

/// One label of the mailbox. The name is user-chosen text and untrusted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Label {
    /// The label's display name.
    pub name: String,
    /// The label's kind.
    pub kind: LabelKind,
}

/// One search hit with the headers of its thread's first and last message. Every string is
/// untrusted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ThreadSummary {
    /// The thread's identifier, checked against the strict pattern.
    pub id: ResourceId,
    /// Gmail's snippet of the thread.
    pub snippet: String,
    /// How many messages the thread holds.
    pub messages: usize,
    /// The subject of the first message.
    pub subject: String,
    /// The sender of the first message.
    pub from: String,
    /// The date of the last message.
    pub date: String,
}

/// An attachment, described and never downloaded. Name and type come from the mail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attachment {
    /// The file name, possibly empty.
    pub filename: String,
    /// The declared media type.
    pub mime_type: String,
    /// The size in bytes that Gmail reports.
    pub size: u64,
}

/// One message, read in full. Every string is untrusted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Message {
    /// The message's identifier, checked against the strict pattern.
    pub id: ResourceId,
    /// The `Subject` header.
    pub subject: String,
    /// The `From` header.
    pub from: String,
    /// The `To` header.
    pub to: String,
    /// The `Cc` header.
    pub cc: String,
    /// The `Date` header.
    pub date: String,
    /// The text of the message: its plain-text part, or its HTML part converted to text.
    pub body: String,
    /// The attachments, as metadata only.
    pub attachments: Vec<Attachment>,
    /// Whether some parts were skipped (nesting, part count, size or encoding limits), so the
    /// body may be incomplete.
    pub incomplete: bool,
}

/// A thread, read in full.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Thread {
    /// The thread's identifier.
    pub id: ResourceId,
    /// Its messages, oldest first. Messages whose identifier is not valid are left out.
    pub messages: Vec<Message>,
}

/// The Gmail client.
pub struct Gmail<T, K> {
    transport: T,
    tokens: K,
}

impl<T: Transport, K: TokenSource> Gmail<T, K> {
    /// A client that sends through `transport` with tokens from `tokens`.
    #[must_use]
    pub fn new(transport: T, tokens: K) -> Self {
        Self { transport, tokens }
    }

    /// The mailbox's labels.
    ///
    /// # Errors
    ///
    /// Any [`Error`].
    pub fn labels(&mut self) -> Result<Vec<Label>, Error> {
        let answer = self.get(&format!("{BASE}/labels"))?;
        Ok(array(&answer, "labels")
            .iter()
            .filter_map(|label| {
                let name = text_of(label, "name");
                if name.is_empty() {
                    return None;
                }
                let kind = match text_of(label, "type") {
                    "system" => LabelKind::System,
                    "user" => LabelKind::User,
                    _ => LabelKind::Other,
                };
                Some(Label {
                    name: name.to_owned(),
                    kind,
                })
            })
            .collect())
    }

    /// Threads matching `query` (Gmail's search syntax; empty means the newest threads), at most
    /// `max_results`, each with the headers of its first and last message: one list call, then
    /// one metadata read per hit. A hit that vanishes between the two calls is left out.
    ///
    /// # Errors
    ///
    /// Any [`Error`].
    pub fn search(&mut self, query: &str, max_results: u16) -> Result<Vec<ThreadSummary>, Error> {
        let answer = self.get(&search_url(query, max_results))?;
        let mut found = Vec::new();
        for hit in array(&answer, "threads")
            .iter()
            .take(usize::from(max_results))
        {
            // An identifier from the answer is checked like one from a tool argument before it
            // goes into a URL.
            let Ok(id) = ResourceId::parse(text_of(hit, "id")) else {
                continue;
            };
            let snippet = text_of(hit, "snippet").to_owned();
            match self.get(&metadata_url(&id)) {
                Ok(thread) => found.push(summarise(id, snippet, &thread)),
                Err(Error::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
        Ok(found)
    }

    /// A thread with all its messages in full.
    ///
    /// # Errors
    ///
    /// Any [`Error`]; [`Error::TooLarge`] for a thread beyond the response limit.
    pub fn thread(&mut self, id: &ResourceId) -> Result<Thread, Error> {
        let answer = self.get(&format!("{BASE}/threads/{id}?format=full"))?;
        Ok(Thread {
            id: id.clone(),
            messages: array(&answer, "messages")
                .iter()
                .filter_map(parse_message)
                .collect(),
        })
    }

    /// One message in full.
    ///
    /// # Errors
    ///
    /// Any [`Error`]; [`Error::BadResponse`] if the answer holds no message with a valid
    /// identifier.
    pub fn message(&mut self, id: &ResourceId) -> Result<Message, Error> {
        let answer = self.get(&format!("{BASE}/messages/{id}?format=full"))?;
        parse_message(&answer).ok_or(Error::BadResponse)
    }

    /// One `GET` with the status mapped to a static error. A 401 gets exactly one refresh and
    /// one retry: a token can be revoked or expire early, and one retry is all it takes to
    /// tell that from a sign-in that Google no longer accepts.
    // why: docs/decisions/0006-credentials-in-os-credential-store.md
    fn get(&mut self, url: &str) -> Result<Value, Error> {
        let mut reply = self.send(url)?;
        if reply.status == 401 {
            self.tokens.invalidate();
            reply = self.send(url)?;
        }
        match reply.status {
            200 => serde_json::from_slice(&reply.body).map_err(|_| Error::BadResponse),
            401 => Err(Error::Unauthorized),
            403 => Err(Error::Forbidden),
            404 => Err(Error::NotFound),
            429 => Err(Error::RateLimited),
            _ => Err(Error::Status),
        }
    }

    fn send(&mut self, url: &str) -> Result<Reply, Error> {
        let token = self.tokens.access_token().map_err(Error::Token)?;
        Ok(self.transport.get(url, token.expose())?)
    }
}

/// The list call of a search. The query is percent-encoded, so nothing in it can end its value
/// or add a parameter; the route table checks the shape again.
// why: docs/decisions/0003-single-egress-allowlist.md
fn search_url(query: &str, max_results: u16) -> String {
    let mut url = format!("{BASE}/threads?maxResults={max_results}");
    if !query.is_empty() {
        url.push_str("&q=");
        url.extend(form_urlencoded::byte_serialize(query.as_bytes()));
    }
    url
}

/// The metadata read of one search hit: three headers, no bodies.
fn metadata_url(id: &ResourceId) -> String {
    format!(
        "{BASE}/threads/{id}?format=metadata&metadataHeaders=Subject&metadataHeaders=From&metadataHeaders=Date"
    )
}

/// A string field, or the empty string if it is absent or not a string.
fn text_of<'a>(value: &'a Value, key: &str) -> &'a str {
    value.get(key).and_then(Value::as_str).unwrap_or_default()
}

/// An array field, or an empty slice if it is absent or not an array.
fn array<'a>(value: &'a Value, key: &str) -> &'a [Value] {
    value
        .get(key)
        .and_then(Value::as_array)
        .map_or(&[], Vec::as_slice)
}

/// The first header called `name` (any letter case) of a message payload.
fn header_value(payload: &Value, name: &str) -> String {
    array(payload, "headers")
        .iter()
        .find(|header| text_of(header, "name").eq_ignore_ascii_case(name))
        .map(|header| text_of(header, "value").to_owned())
        .unwrap_or_default()
}

fn payload_of(message: &Value) -> &Value {
    message.get("payload").unwrap_or(&NULL)
}

/// The summary of one hit from its metadata answer.
fn summarise(id: ResourceId, snippet: String, thread: &Value) -> ThreadSummary {
    let messages = array(thread, "messages");
    let first = messages.first().map_or(&NULL, payload_of);
    let last = messages.last().map_or(&NULL, payload_of);
    ThreadSummary {
        id,
        snippet,
        messages: messages.len(),
        subject: header_value(first, "Subject"),
        from: header_value(first, "From"),
        date: header_value(last, "Date"),
    }
}

/// What the walk over a message's MIME parts collects.
#[derive(Default)]
struct Parts {
    plain: String,
    html: String,
    attachments: Vec<Attachment>,
    visited: usize,
    text_bytes: usize,
    incomplete: bool,
}

impl Parts {
    /// Visits `part` and, up to [`MAX_MIME_DEPTH`], its children. Bounded in depth and in the
    /// number of parts, so a hostile nesting costs neither stack nor time.
    // why: docs/decisions/0005-untrusted-email-content.md
    fn walk(&mut self, part: &Value, depth: usize) {
        if self.visited >= MAX_MIME_PARTS {
            self.incomplete = true;
            return;
        }
        self.visited += 1;
        let body = part.get("body").unwrap_or(&NULL);
        let named = !text_of(part, "filename").is_empty();
        if named || body.get("attachmentId").is_some() {
            self.attachments.push(Attachment {
                filename: text_of(part, "filename").to_owned(),
                mime_type: text_of(part, "mimeType").to_owned(),
                size: body.get("size").and_then(Value::as_u64).unwrap_or(0),
            });
        } else if let Some(data) = body.get("data").and_then(Value::as_str) {
            let kind = text_of(part, "mimeType");
            if kind.eq_ignore_ascii_case("text/plain") {
                self.add_text(false, data);
            } else if kind.eq_ignore_ascii_case("text/html") {
                self.add_text(true, data);
            }
        }
        let children = array(part, "parts");
        if depth >= MAX_MIME_DEPTH {
            self.incomplete |= !children.is_empty();
            return;
        }
        for child in children {
            self.walk(child, depth + 1);
        }
    }

    /// Decodes one text part and appends it, within [`MAX_TEXT_BYTES`] for the whole message.
    fn add_text(&mut self, html: bool, data: &str) {
        let room = MAX_TEXT_BYTES.saturating_sub(self.text_bytes);
        let Ok(mut bytes) = BASE64URL.decode(data) else {
            self.incomplete = true;
            return;
        };
        if bytes.len() > room {
            bytes.truncate(room);
            self.incomplete = true;
        }
        self.text_bytes += bytes.len();
        let target = if html {
            &mut self.html
        } else {
            &mut self.plain
        };
        if !target.is_empty() {
            target.push('\n');
        }
        target.push_str(&String::from_utf8_lossy(&bytes));
    }
}

/// One message from its `format=full` answer, or `None` if its identifier is not valid.
fn parse_message(message: &Value) -> Option<Message> {
    let id = ResourceId::parse(text_of(message, "id")).ok()?;
    let payload = payload_of(message);
    let mut parts = Parts::default();
    parts.walk(payload, 0);
    // Plain text first; an HTML-only mail goes through the converter.
    let body = if parts.plain.trim().is_empty() {
        text::html_to_text(&parts.html)
    } else {
        parts.plain
    };
    Some(Message {
        id,
        subject: header_value(payload, "Subject"),
        from: header_value(payload, "From"),
        to: header_value(payload, "To"),
        cc: header_value(payload, "Cc"),
        date: header_value(payload, "Date"),
        body,
        attachments: parts.attachments,
        incomplete: parts.incomplete,
    })
}
