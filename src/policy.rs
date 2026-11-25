//! The server's permission policy in one reviewable place: the egress allowlist, the OAuth
//! scope, identifier validation and every size and time limit.
//!
//! The server reads mail and does nothing else (`docs/decisions/0014-read-only-no-composing.md`):
//! there is one OAuth scope, `gmail.readonly`, and the Gmail host has no route but `GET`. The
//! scope is enforced by Google. The route table is the same promise made a second time inside
//! the process, and it is what keeps the server from talking to any other host.
//!
//! The module is data and pure functions with no I/O, so the whole policy can be read and
//! tested without a network. The egress guard in [`crate::http`] enforces it. Why the egress
//! rules are what they are: `docs/decisions/0003-single-egress-allowlist.md`.

use std::fmt;
use std::time::Duration;

/// Host of Google's OAuth token endpoint.
pub const HOST_OAUTH: &str = "oauth2.googleapis.com";

/// Host of the Gmail API.
pub const HOST_GMAIL: &str = "gmail.googleapis.com";

/// The scope that allows reading mail and nothing else: Google refuses every write, send and
/// settings change for a token that only holds it.
// why: docs/decisions/0014-read-only-no-composing.md
pub const SCOPE_READONLY: &str = "https://www.googleapis.com/auth/gmail.readonly";

/// The OAuth scopes the server requests. Only the read-only scope: no scope that can create
/// drafts, send or modify is ever requested.
// why: docs/decisions/0014-read-only-no-composing.md
pub const SCOPES: &[&str] = &[SCOPE_READONLY];

/// Host of Google's consent page, which the user's browser opens. The server never connects to
/// it, so it has no route in the table below: it is named only so that the one URL that
/// points to it can be checked before it is shown to the user.
// why: docs/decisions/0003-single-egress-allowlist.md (excluded hosts)
pub const HOST_CONSENT: &str = "accounts.google.com";

/// The consent page where the user approves the scope. The user opens it; the code never does.
// why: docs/decisions/0015-sign-in-flow.md
pub const CONSENT_URL: &str = "https://accounts.google.com/o/oauth2/v2/auth";

/// Google's token endpoint, the one `POST` the egress guard allows. The sign-in flow uses this
/// address and never one read from the client secret file, which names its own endpoints.
// why: docs/decisions/0015-sign-in-flow.md
pub const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";

/// The only two HTTP methods this server uses. There is deliberately no variant for the
/// methods that delete or replace data: adding one is a policy change, not a refactor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Method {
    Get,
    Post,
}

impl Method {
    /// Exact, case-sensitive match: `get` is not `GET`, so odd spellings are refused.
    fn parse(name: &str) -> Option<Self> {
        match name {
            "GET" => Some(Method::Get),
            "POST" => Some(Method::Post),
            _ => None,
        }
    }
}

/// How the value of a query parameter is checked.
enum Values {
    /// Whatever percent-encoding produces: letters, digits, `- . _ ~ * +`, and `%` followed
    /// by two hex digits. Nothing that could end the value (`&`, `=`, `#`, `?`) or start a
    /// path (`/`).
    Encoded,
    /// One to four digits.
    Digits,
    /// Exactly one of these.
    OneOf(&'static [&'static str]),
}

/// One query parameter a route accepts.
struct Param {
    name: &'static str,
    values: Values,
    /// May appear more than once (an array parameter).
    repeatable: bool,
}

/// One allowed request shape.
struct Route {
    method: Method,
    host: &'static str,
    /// Matched segment by segment, never as a prefix. `{id}` stands for exactly one
    /// segment that passes [`is_valid_id`]; every other segment must match literally.
    path: &'static str,
    /// The query parameters the route accepts. A request with any other parameter, a
    /// duplicate of a parameter that is not repeatable, or a value that does not pass is
    /// refused.
    query: &'static [Param],
}

const NO_QUERY: &[Param] = &[];

/// Parameters of the thread and message reads. `format=raw` is not allowed: it returns the
/// whole message including attachments, and attachments are metadata only.
const READ_QUERY: &[Param] = &[
    Param {
        name: "format",
        values: Values::OneOf(&["full", "metadata", "minimal"]),
        repeatable: false,
    },
    Param {
        name: "metadataHeaders",
        values: Values::Encoded,
        repeatable: true,
    },
];

/// Parameters of the thread search.
const SEARCH_QUERY: &[Param] = &[
    Param {
        name: "q",
        values: Values::Encoded,
        repeatable: false,
    },
    Param {
        name: "maxResults",
        values: Values::Digits,
        repeatable: false,
    },
    Param {
        name: "pageToken",
        values: Values::Encoded,
        repeatable: false,
    },
    Param {
        name: "labelIds",
        values: Values::Encoded,
        repeatable: true,
    },
];

/// Every request the server may send. Anything not listed is refused.
///
/// Reads match exact path shapes and not prefixes: a prefix such as `.../messages` would also
/// admit the attachment download below a message, which the design never calls ("attachments
/// are metadata only"). Query parameters are listed too, because Google's APIs accept
/// parameters that change what a request does (a method override, for one), and a value that
/// is not on the list is refused. The Gmail host has no route but `GET`: no send, draft,
/// delete, label, filter or settings request can be expressed. The one `POST` is the OAuth
/// token endpoint.
// why: docs/decisions/0003-single-egress-allowlist.md
const ROUTES: &[Route] = &[
    // OAuth token endpoint: code exchange and refresh.
    Route {
        method: Method::Post,
        host: HOST_OAUTH,
        path: "/token",
        query: NO_QUERY,
    },
    // `list_labels`.
    Route {
        method: Method::Get,
        host: HOST_GMAIL,
        path: "/gmail/v1/users/me/labels",
        query: NO_QUERY,
    },
    // `search_threads` (the list call; each hit is then read with the thread route).
    Route {
        method: Method::Get,
        host: HOST_GMAIL,
        path: "/gmail/v1/users/me/threads",
        query: SEARCH_QUERY,
    },
    // `get_thread` and the per-hit reads of a search.
    Route {
        method: Method::Get,
        host: HOST_GMAIL,
        path: "/gmail/v1/users/me/threads/{id}",
        query: READ_QUERY,
    },
    // `get_message`.
    Route {
        method: Method::Get,
        host: HOST_GMAIL,
        path: "/gmail/v1/users/me/messages/{id}",
        query: READ_QUERY,
    },
];

/// Request headers a caller may set. Everything else is refused, so a caller cannot
/// override `Host` (to reach another site through an allowed address) or add headers that
/// carry data to Google that the design never sends, such as a method override.
const ALLOWED_REQUEST_HEADERS: &[&str] = &["accept", "authorization", "content-type"];

/// Longest response body the guard reads. The biggest legitimate response is a full
/// `format=full` read of a long thread; this bounds what a broken or hostile response can
/// make the process hold in memory.
// why: docs/decisions/0003-single-egress-allowlist.md
pub const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

/// Longest request body the guard sends. The only request with a body is the OAuth token
/// call, a few hundred bytes of form data; this bounds the guard whatever the caller does.
pub const MAX_REQUEST_BYTES: usize = 16 * 1024;

/// Longest request URL the guard accepts. A search query is the only long part.
pub const MAX_URL_BYTES: usize = 2048;

/// Time limit for one whole request, from connecting to the last byte of the response.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Time limit for opening the connection.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Longest identifier accepted. Gmail's own identifiers are far shorter; the cap only
/// bounds what ends up in a URL.
pub const MAX_ID_BYTES: usize = 128;

/// Longest text returned to the model for one tool call, in characters, delimiters and
/// truncation markers included. A visible `[truncated]` marker ends anything cut.
// why: docs/decisions/0005-untrusted-email-content.md
pub const MAX_OUTPUT_CHARS: usize = 30_000;

/// Longest text returned for one short field (a subject, an address, a filename), so a
/// hostile field cannot use up the whole output budget.
pub const MAX_FIELD_CHARS: usize = 1_000;

/// Longest HTML the converter reads. The converter works in one pass, so this only bounds the
/// time spent on a hostile email; mail that needs more has its text cut with a visible marker.
// why: docs/decisions/0013-hand-written-html-converter.md
pub const MAX_HTML_BYTES: usize = 1024 * 1024;

/// How long `auth` waits for the user to finish on the consent page. The user may have to
/// find the right Google account and read the screen, so this is minutes, not seconds.
// why: docs/decisions/0015-sign-in-flow.md
pub const LOGIN_TIMEOUT: Duration = Duration::from_secs(5 * 60);

/// Time one connection to the sign-in listener may take, from accept to the end of the
/// request. Browsers sometimes open a connection ahead of time and say nothing on it; such a
/// connection, or a hostile one, is dropped after this long, and in the meantime the other
/// connections are served.
// why: docs/decisions/0015-sign-in-flow.md
pub const REDIRECT_CONNECTION_TIMEOUT: Duration = Duration::from_secs(5);

/// Longest request head the sign-in listener reads before it acts on the first line. The
/// redirect is a short `GET` line, but the browser adds its cookies for `127.0.0.1`, which go to
/// every port, so a longer head is not a reason to refuse the request.
pub const MAX_REDIRECT_HEAD_BYTES: usize = 8 * 1024;

/// How many connections the sign-in listener keeps at once. A new one pushes the oldest out, so a
/// program that opens silent connections cannot keep the browser's real redirect waiting.
// why: docs/decisions/0015-sign-in-flow.md
pub const MAX_REDIRECT_CONNECTIONS: usize = 16;

/// Time allowed to write the listener's short answer, so a visitor that never reads cannot hold
/// the listener.
pub const REDIRECT_REPLY_TIMEOUT: Duration = Duration::from_secs(1);

/// Longest client secret file `auth` reads. Google's file is well under 1 KiB; the cap only
/// stops `--credentials` from reading an endless file.
pub const MAX_CLIENT_FILE_BYTES: usize = 64 * 1024;

/// Longest credential-store record that is decoded.
pub const MAX_RECORD_BYTES: usize = 16 * 1024;

/// Longest client id, client secret, refresh token or authorization code accepted. Google's
/// are a few hundred characters at most; the cap bounds what goes into a request body.
pub const MAX_CREDENTIAL_CHARS: usize = 2048;

/// Why [`authorize`] refused a request. Every message is static: errors travel back to the
/// client and into logs, so they must never contain request data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Denied {
    /// The URL is too long, or has a character other than printable ASCII, a `#` or a `\`.
    Malformed,
    /// The URL does not use `https`.
    NotHttps,
    /// The host is not on the allowlist. This also covers user info, ports, upper case and
    /// trailing dots in the host, none of which the server ever writes.
    Host,
    /// The method is neither `GET` nor `POST`.
    Method,
    /// The host is allowed, but this method and path combination is not.
    Route,
    /// The path is allowed, but the query has a parameter or a value that is not.
    Query,
    /// A `GET` request has a body.
    Body,
    /// The request sets a header that is not on the allowlist.
    Header,
    /// The request body is larger than [`MAX_REQUEST_BYTES`].
    TooLarge,
}

impl Denied {
    /// A fixed, human-readable reason that is safe to log and to return to a client.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Denied::Malformed => "egress refused: the URL is malformed or too long",
            Denied::NotHttps => "egress refused: only https is allowed",
            Denied::Host => "egress refused: the host is not on the allowlist",
            Denied::Method => "egress refused: the method is not allowed",
            Denied::Route => "egress refused: the method and path are not on the allowlist",
            Denied::Query => "egress refused: a query parameter or value is not allowed",
            Denied::Body => "egress refused: a GET request must not have a body",
            Denied::Header => "egress refused: the request has a header that is not allowed",
            Denied::TooLarge => "egress refused: the request body is too large",
        }
    }
}

impl fmt::Display for Denied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for Denied {}

/// Decides whether the server may send a request with this method to this URL.
///
/// The grammar is deliberately narrower than a general URL parser, so there is no room for
/// a parsing difference between this check and the HTTP client: the URL must be exactly
/// `https://<allowed host>/<path>` with an optional `?<query>`, in printable ASCII with no
/// fragment, and the host must match a route's host byte for byte. The query may only hold
/// the parameters the matching route lists.
///
/// # Errors
///
/// Returns the first reason the request is refused. `Ok` means the request matches a route.
// why: docs/decisions/0003-single-egress-allowlist.md
pub fn authorize(method: &str, url: &str) -> Result<(), Denied> {
    if url.len() > MAX_URL_BYTES
        || !url
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'#' && b != b'\\')
    {
        return Err(Denied::Malformed);
    }
    let rest = url.strip_prefix("https://").ok_or(Denied::NotHttps)?;
    let (host, path_and_query) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let (path, query) = match path_and_query.split_once('?') {
        Some((path, query)) => (path, Some(query)),
        None => (path_and_query, None),
    };
    let method = Method::parse(method).ok_or(Denied::Method)?;

    if !ROUTES.iter().any(|route| route.host == host) {
        return Err(Denied::Host);
    }
    let route = ROUTES
        .iter()
        .find(|route| {
            route.host == host && route.method == method && path_matches(route.path, path)
        })
        .ok_or(Denied::Route)?;
    if query_allowed(route.query, query) {
        Ok(())
    } else {
        Err(Denied::Query)
    }
}

/// Why a grant of scopes was refused. Every message is static, like the other errors here.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantError {
    /// Google did not say which scopes it granted, so the grant cannot be checked.
    Unreported,
    /// A scope other than the read-only one was granted.
    Broader,
}

impl GrantError {
    /// A fixed, human-readable reason that is safe to log and to return to a client.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            GrantError::Unreported => {
                "Google did not report which scopes it granted, so nothing was stored; remove this app's access in your Google account and sign in again"
            }
            GrantError::Broader => {
                "Google granted a scope other than gmail.readonly, so nothing was stored; remove this app's access in your Google account and sign in again"
            }
        }
    }
}

impl fmt::Display for GrantError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for GrantError {}

/// Checks that `granted` holds the one scope the server requests and nothing else.
///
/// An earlier consent for the same OAuth client can hand back more scopes than a request
/// names, and the server must never keep a token that can do more than read. A list that is
/// empty counts as unreported: it cannot be checked, so it is not trusted. Repeating the
/// read-only scope is harmless.
///
/// # Errors
///
/// [`GrantError::Unreported`] for an empty list, [`GrantError::Broader`] if any entry is
/// not exactly [`SCOPE_READONLY`].
// why: docs/decisions/0014-read-only-no-composing.md
pub fn check_grant<S: AsRef<str>>(granted: &[S]) -> Result<(), GrantError> {
    if granted.is_empty() {
        return Err(GrantError::Unreported);
    }
    if granted.iter().any(|scope| scope.as_ref() != SCOPE_READONLY) {
        return Err(GrantError::Broader);
    }
    Ok(())
}

/// Whether `header` (any letter case) may be set on a request.
#[must_use]
pub fn header_allowed(header: &str) -> bool {
    ALLOWED_REQUEST_HEADERS
        .iter()
        .any(|allowed| allowed.eq_ignore_ascii_case(header))
}

/// Segment-by-segment match of a request path against a route pattern. Equal segment
/// counts are required, so a trailing slash or an extra segment never matches.
fn path_matches(pattern: &str, path: &str) -> bool {
    let mut pattern = pattern.split('/');
    let mut path = path.split('/');
    loop {
        match (pattern.next(), path.next()) {
            (None, None) => return true,
            (Some("{id}"), Some(segment)) if is_valid_id(segment) => {}
            (Some(expected), Some(segment)) if expected != "{id}" && expected == segment => {}
            _ => return false,
        }
    }
}

/// Whether every `name=value` pair of `query` is a parameter of the route, with a value that
/// passes. No query, or an empty one, is always fine.
fn query_allowed(params: &[Param], query: Option<&str>) -> bool {
    let Some(query) = query.filter(|query| !query.is_empty()) else {
        return true;
    };
    let mut seen: Vec<&str> = Vec::new();
    for pair in query.split('&') {
        let Some((name, value)) = pair.split_once('=') else {
            return false;
        };
        let Some(param) = params.iter().find(|param| param.name == name) else {
            return false;
        };
        if !param.repeatable && seen.contains(&name) {
            return false;
        }
        seen.push(name);
        let passes = match param.values {
            Values::Encoded => is_encoded(value),
            Values::Digits => {
                (1..=4).contains(&value.len()) && value.bytes().all(|b| b.is_ascii_digit())
            }
            Values::OneOf(allowed) => allowed.contains(&value),
        };
        if !passes {
            return false;
        }
    }
    true
}

/// A non-empty value made only of what percent-encoding leaves alone and valid `%XX` escapes.
fn is_encoded(value: &str) -> bool {
    let bytes = value.as_bytes();
    let mut at = 0;
    while let Some(&byte) = bytes.get(at) {
        if byte == b'%' {
            let hex = |offset: usize| bytes.get(at + offset).is_some_and(u8::is_ascii_hexdigit);
            if !(hex(1) && hex(2)) {
                return false;
            }
            at += 3;
        } else if byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'*' | b'+')
        {
            at += 1;
        } else {
            return false;
        }
    }
    !bytes.is_empty()
}

/// Gmail identifiers are 1 to [`MAX_ID_BYTES`] characters of `A-Z a-z 0-9 _ -`.
///
/// Nothing else may enter a URL path: not `.` and `/` (which would walk to
/// `../settings/filters`), not `%` (an encoded version of the same) and not `?` or `#`.
// why: docs/decisions/0003-single-egress-allowlist.md
fn is_valid_id(candidate: &str) -> bool {
    (1..=MAX_ID_BYTES).contains(&candidate.len())
        && candidate
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// A Gmail message, thread or label identifier that has been checked against the strict
/// identifier pattern, so it is safe to place in a URL path.
///
/// Identifiers come from tool arguments (chosen by a model that may have read a hostile
/// email) and from API responses; both become a `ResourceId` before they are used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResourceId(String);

/// The text was not a valid identifier. The text itself is left out on purpose.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidId;

impl fmt::Display for InvalidId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("not a valid Gmail identifier")
    }
}

impl std::error::Error for InvalidId {}

impl ResourceId {
    /// Checks `text` against the identifier pattern.
    ///
    /// # Errors
    ///
    /// Returns [`InvalidId`] if `text` is empty, longer than [`MAX_ID_BYTES`] or contains a
    /// character other than `A-Z a-z 0-9 _ -`.
    pub fn parse(text: &str) -> Result<Self, InvalidId> {
        if is_valid_id(text) {
            Ok(Self(text.to_owned()))
        } else {
            Err(InvalidId)
        }
    }

    /// The identifier, safe to place in a URL path.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for ResourceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_only_scope_is_the_read_only_one() {
        assert_eq!(SCOPES, [SCOPE_READONLY]);
        assert_eq!(
            SCOPE_READONLY,
            "https://www.googleapis.com/auth/gmail.readonly"
        );
    }

    /// The token address the sign-in flow uses must be exactly the one route the guard
    /// allows for `POST`, or the code exchange would be refused at run time.
    #[test]
    fn the_token_url_is_the_one_post_route() {
        assert_eq!(authorize("POST", TOKEN_URL), Ok(()));
        assert_eq!(
            authorize("GET", TOKEN_URL),
            Err(Denied::Route),
            "the token endpoint is POST only"
        );
    }

    /// The consent page is opened by the user's browser. The server never connects to it, so
    /// the guard must refuse it, and the constant must name exactly [`HOST_CONSENT`].
    #[test]
    fn the_consent_page_is_named_but_never_routable() {
        assert!(CONSENT_URL.starts_with(&format!("https://{HOST_CONSENT}/")));
        assert_eq!(authorize("GET", CONSENT_URL), Err(Denied::Host));
        assert_eq!(authorize("POST", CONSENT_URL), Err(Denied::Host));
        assert!(!ROUTES.iter().any(|route| route.host == HOST_CONSENT));
    }

    #[test]
    fn a_grant_of_exactly_the_read_only_scope_is_accepted() {
        assert_eq!(check_grant(&[SCOPE_READONLY]), Ok(()));
        assert_eq!(check_grant(&[SCOPE_READONLY, SCOPE_READONLY]), Ok(()));
        assert_eq!(check_grant(&[SCOPE_READONLY.to_owned()]), Ok(()));
    }

    #[test]
    fn a_grant_that_cannot_be_checked_is_refused() {
        let none: [&str; 0] = [];
        assert_eq!(check_grant(&none), Err(GrantError::Unreported));
    }

    /// The look-alikes of the scope URL itself are in `tests/store_policy.rs`: this file is
    /// scanned for scope URLs, so a hostile variant of one cannot be written here.
    #[test]
    fn a_grant_with_anything_else_is_refused() {
        for other in ["openid", "email", "", " ", "gmail.readonly"] {
            assert_eq!(
                check_grant(&[SCOPE_READONLY, other]),
                Err(GrantError::Broader),
                "{other:?} slipped through next to the read-only scope"
            );
            assert_eq!(
                check_grant(&[other]),
                Err(GrantError::Broader),
                "{other:?} slipped through alone"
            );
        }
    }

    /// The route table, pinned. A new route, method, path shape or query parameter changes
    /// this list, so it cannot slip in unnoticed, and a reviewer sees it in the diff.
    #[test]
    fn the_route_table_is_exactly_the_documented_one() {
        let described: Vec<String> = ROUTES
            .iter()
            .map(|route| {
                let params: Vec<&str> = route.query.iter().map(|param| param.name).collect();
                format!(
                    "{:?} {}{} ?{}",
                    route.method,
                    route.host,
                    route.path,
                    params.join(",")
                )
            })
            .collect();
        assert_eq!(
            described,
            [
                "Post oauth2.googleapis.com/token ?",
                "Get gmail.googleapis.com/gmail/v1/users/me/labels ?",
                "Get gmail.googleapis.com/gmail/v1/users/me/threads ?q,maxResults,pageToken,labelIds",
                "Get gmail.googleapis.com/gmail/v1/users/me/threads/{id} ?format,metadataHeaders",
                "Get gmail.googleapis.com/gmail/v1/users/me/messages/{id} ?format,metadataHeaders",
            ]
        );
    }

    /// The README promises that the server writes nothing to Gmail. The Gmail host has no
    /// route for any method but `GET`, whatever else the table says.
    #[test]
    fn the_gmail_host_has_no_route_but_get() {
        assert!(
            ROUTES
                .iter()
                .filter(|route| route.host == HOST_GMAIL)
                .all(|route| route.method == Method::Get)
        );
        let posts: Vec<_> = ROUTES
            .iter()
            .filter(|route| route.method == Method::Post)
            .map(|route| (route.host, route.path))
            .collect();
        assert_eq!(posts, [(HOST_OAUTH, "/token")]);
    }

    #[test]
    fn every_route_pattern_is_well_formed() {
        for route in ROUTES {
            assert!(route.path.starts_with('/'), "{}", route.path);
            assert!(!route.path.ends_with('/'), "{}", route.path);
            assert!(!route.path.contains("//"), "{}", route.path);
            assert!(!route.path.contains('?'), "{}", route.path);
            assert!(
                route.host == HOST_OAUTH || route.host == HOST_GMAIL,
                "{}",
                route.host
            );
            for param in route.query {
                assert!(
                    param.name.bytes().all(|b| b.is_ascii_alphanumeric()),
                    "{}",
                    param.name
                );
            }
        }
    }

    #[test]
    fn identifiers_accept_gmail_shapes_and_nothing_else() {
        for ok in [
            "18c3a5b2f1e4d7a0",
            "INBOX",
            "Label_12",
            "a-b_C9",
            &"a".repeat(MAX_ID_BYTES),
        ] {
            assert!(ResourceId::parse(ok).is_ok(), "{ok}");
        }
        for bad in [
            "",
            "a b",
            "a/b",
            "..",
            "a.b",
            "a%2Fb",
            "a?b",
            "a#b",
            "é",
            "a\n",
            &"a".repeat(MAX_ID_BYTES + 1),
        ] {
            assert!(ResourceId::parse(bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            ResourceId::parse("abc").map(|id| id.to_string()),
            Ok("abc".to_owned())
        );
    }

    #[test]
    fn encoded_values_are_what_percent_encoding_produces() {
        for ok in ["abc", "from%3Aalice", "a+b", "A-b_c.d~e*f", "%00%ff%FF"] {
            assert!(is_encoded(ok), "{ok}");
        }
        for bad in [
            "", "a b", "a&b", "a=b", "a#b", "a?b", "a/b", "$x", "%", "%4", "%zz", "é",
        ] {
            assert!(!is_encoded(bad), "{bad:?}");
        }
    }

    #[test]
    fn the_read_routes_are_allowed() {
        let base = "https://gmail.googleapis.com/gmail/v1/users/me";
        assert_eq!(authorize("GET", &format!("{base}/labels")), Ok(()));
        assert_eq!(
            authorize("GET", &format!("{base}/threads?q=x&maxResults=5")),
            Ok(())
        );
        assert_eq!(
            authorize("POST", &format!("{base}/labels")),
            Err(Denied::Route)
        );
    }
}
