//! The server's permission policy in one reviewable place: the egress allowlist, the OAuth
//! scopes, identifier validation and every size and time limit.
//!
//! The module is data and pure functions with no I/O, so the whole policy can be read and
//! tested without a network. The egress guard in [`crate::http`] enforces it. Why the rules
//! are what they are: `docs/decisions/0002-two-layer-permission-model.md` and
//! `docs/decisions/0003-single-egress-allowlist.md`.

use std::fmt;
use std::time::Duration;

/// Host of Google's OAuth token endpoint.
pub const HOST_OAUTH: &str = "oauth2.googleapis.com";

/// Host of the Gmail API.
pub const HOST_GMAIL: &str = "gmail.googleapis.com";

/// Scope that allows reading mail and nothing else.
pub const SCOPE_READONLY: &str = "https://www.googleapis.com/auth/gmail.readonly";

/// Scope that allows creating drafts. Google has no draft-only scope, so this one also
/// permits sending at the API level: in drafts mode the no-send guarantee rests on the
/// route table below and its tests, not on the scope.
// why: docs/decisions/0002-two-layer-permission-model.md
pub const SCOPE_COMPOSE: &str = "https://www.googleapis.com/auth/gmail.compose";

/// What the server may do. Read-only unless the user opts into drafts.
///
/// The mode is the server-side layer of the two-layer model. The Google-side layer is the
/// scope the user granted, see [`Mode::scopes`].
// why: docs/decisions/0002-two-layer-permission-model.md
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mode {
    /// Search and read mail. Nothing is written.
    ReadOnly,
    /// Everything in [`Mode::ReadOnly`], plus creating drafts. A draft is never sent.
    Drafts,
}

impl Mode {
    /// The OAuth scopes to request for this mode. Both modes include read access, because
    /// `auth` refuses a grant without it.
    #[must_use]
    pub const fn scopes(self) -> &'static [&'static str] {
        match self {
            Mode::ReadOnly => &[SCOPE_READONLY],
            Mode::Drafts => &[SCOPE_READONLY, SCOPE_COMPOSE],
        }
    }
}

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

/// One allowed request shape.
struct Route {
    method: Method,
    host: &'static str,
    /// Matched segment by segment, never as a prefix. `{id}` stands for exactly one
    /// segment that passes [`is_valid_id`]; every other segment must match literally.
    path: &'static str,
    /// Only allowed in [`Mode::Drafts`].
    needs_drafts: bool,
}

/// Every request the server may send. Anything not listed is refused.
///
/// Reads match exact path shapes and not prefixes: a prefix such as `.../messages` would
/// also admit the attachment download below a message, which the design never calls
/// ("attachments are metadata only"). The one Gmail write is creating a draft; there is no
/// route for send, delete, trash, labels, filters or settings.
// why: docs/decisions/0003-single-egress-allowlist.md
const ROUTES: &[Route] = &[
    // OAuth token endpoint: code exchange and refresh.
    Route {
        method: Method::Post,
        host: HOST_OAUTH,
        path: "/token",
        needs_drafts: false,
    },
    // `list_labels`.
    Route {
        method: Method::Get,
        host: HOST_GMAIL,
        path: "/gmail/v1/users/me/labels",
        needs_drafts: false,
    },
    // `search_threads` (the list call; each hit is then read with the thread route).
    Route {
        method: Method::Get,
        host: HOST_GMAIL,
        path: "/gmail/v1/users/me/threads",
        needs_drafts: false,
    },
    // `get_thread` and the per-hit reads of a search.
    Route {
        method: Method::Get,
        host: HOST_GMAIL,
        path: "/gmail/v1/users/me/threads/{id}",
        needs_drafts: false,
    },
    // `get_message`, and the header read that lets a draft reply thread correctly.
    Route {
        method: Method::Get,
        host: HOST_GMAIL,
        path: "/gmail/v1/users/me/messages/{id}",
        needs_drafts: false,
    },
    // `create_draft`: the only write.
    Route {
        method: Method::Post,
        host: HOST_GMAIL,
        path: "/gmail/v1/users/me/drafts",
        needs_drafts: true,
    },
];

/// Request headers a caller may set. Everything else is refused, so a caller cannot
/// override `Host` (to reach another site through an allowed address) or add headers that
/// carry data to Google that the design never sends.
const ALLOWED_REQUEST_HEADERS: &[&str] = &["accept", "authorization", "content-type"];

/// Longest response body the guard reads. The biggest legitimate response is a full
/// `format=full` read of a long thread; this bounds what a broken or hostile response can
/// make the process hold in memory.
// why: docs/decisions/0003-single-egress-allowlist.md
pub const MAX_RESPONSE_BYTES: u64 = 8 * 1024 * 1024;

/// Longest request body the guard sends. A draft is capped at [`MAX_BODY_BYTES`] before it
/// gets here; this is the guard's own bound, independent of the caller.
pub const MAX_REQUEST_BYTES: usize = 512 * 1024;

/// Longest request URL the guard accepts. A search query is the only long part.
pub const MAX_URL_BYTES: usize = 2048;

/// Time limit for one whole request, from connecting to the last byte of the response.
pub const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// Time limit for opening the connection.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Longest identifier accepted. Gmail's own identifiers are far shorter; the cap only
/// bounds what ends up in a URL.
pub const MAX_ID_BYTES: usize = 128;

/// Longest text returned to the model for one tool call, in characters. A visible
/// `[truncated]` marker ends anything cut.
// why: docs/decisions/0005-untrusted-email-content.md
pub const MAX_OUTPUT_CHARS: usize = 30_000;

/// Longest text returned for one short field (a subject, an address, a filename), so a
/// hostile field cannot use up the whole output budget.
pub const MAX_FIELD_CHARS: usize = 1_000;

/// Longest HTML the converter reads. Converting hostile HTML costs time that grows with its
/// size and, quadratically, with its nesting depth; this bounds the worst case to a few
/// seconds even if the depth check below is fooled. Mail that needs more than this has its
/// text cut with a visible marker.
// why: docs/decisions/0005-untrusted-email-content.md
pub const MAX_HTML_BYTES: usize = 256 * 1024;

/// Deepest HTML nesting the converter reads. The converter's run time grows with the square
/// of the nesting depth (measured: 50,000 nested `div` elements took about 3 seconds),
/// while browsers stop at 512 levels and so do we.
// why: docs/decisions/0005-untrusted-email-content.md
pub const MAX_HTML_DEPTH: usize = 512;

/// Most recipients (to, cc and bcc together) in one draft.
pub const MAX_RECIPIENTS: usize = 20;

/// Longest draft subject, in characters.
pub const MAX_SUBJECT_CHARS: usize = 300;

/// Longest draft body, in bytes.
pub const MAX_BODY_BYTES: usize = 100 * 1024;

/// Most message identifiers kept in a reply's `References` header, the parent's included.
/// RFC 5322 chains grow with every reply; Gmail threads on the last few.
pub const MAX_REFERENCES: usize = 20;

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
    /// The route creates a draft, and the server is in read-only mode.
    DraftsDisabled,
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
            Denied::DraftsDisabled => "egress refused: creating drafts needs --allow-drafts",
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
/// fragment, and the host must match a route's host byte for byte.
///
/// # Errors
///
/// Returns the first reason the request is refused. `Ok` means the request matches a route
/// that the given [`Mode`] permits.
// why: docs/decisions/0003-single-egress-allowlist.md
pub fn authorize(mode: Mode, method: &str, url: &str) -> Result<(), Denied> {
    if url.len() > MAX_URL_BYTES
        || !url
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'#' && b != b'\\')
    {
        return Err(Denied::Malformed);
    }
    let rest = url.strip_prefix("https://").ok_or(Denied::NotHttps)?;
    let (host, path_and_query) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let path = path_and_query
        .split_once('?')
        .map_or(path_and_query, |(path, _query)| path);
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
    if route.needs_drafts && mode != Mode::Drafts {
        return Err(Denied::DraftsDisabled);
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
    fn scopes_are_exactly_the_documented_pair() {
        assert_eq!(Mode::ReadOnly.scopes(), [SCOPE_READONLY]);
        assert_eq!(Mode::Drafts.scopes(), [SCOPE_READONLY, SCOPE_COMPOSE]);
        assert_eq!(
            SCOPE_READONLY,
            "https://www.googleapis.com/auth/gmail.readonly"
        );
        assert_eq!(
            SCOPE_COMPOSE,
            "https://www.googleapis.com/auth/gmail.compose"
        );
    }

    /// The README promises one Gmail write, and only behind `--allow-drafts`. This pins it
    /// in the table itself: a new POST route, or a write that is not gated, fails here.
    #[test]
    fn the_only_gmail_write_is_the_gated_draft_creation() {
        let writes: Vec<_> = ROUTES
            .iter()
            .filter(|route| route.host == HOST_GMAIL && route.method == Method::Post)
            .collect();
        assert_eq!(writes.len(), 1);
        assert_eq!(writes[0].path, "/gmail/v1/users/me/drafts");
        assert!(writes[0].needs_drafts);

        let gated: Vec<_> = ROUTES.iter().filter(|route| route.needs_drafts).collect();
        assert_eq!(gated.len(), 1);

        let posts: Vec<_> = ROUTES
            .iter()
            .filter(|route| route.method == Method::Post)
            .map(|route| (route.host, route.path))
            .collect();
        assert_eq!(
            posts,
            [
                (HOST_OAUTH, "/token"),
                (HOST_GMAIL, "/gmail/v1/users/me/drafts")
            ]
        );
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
    fn the_read_routes_allow_in_read_only_mode_and_drafts_need_the_mode() {
        let base = "https://gmail.googleapis.com/gmail/v1/users/me";
        assert_eq!(
            authorize(Mode::ReadOnly, "GET", &format!("{base}/labels")),
            Ok(())
        );
        assert_eq!(
            authorize(
                Mode::ReadOnly,
                "GET",
                &format!("{base}/threads?q=x&maxResults=5")
            ),
            Ok(())
        );
        assert_eq!(
            authorize(Mode::ReadOnly, "POST", &format!("{base}/drafts")),
            Err(Denied::DraftsDisabled)
        );
        assert_eq!(
            authorize(Mode::Drafts, "POST", &format!("{base}/drafts")),
            Ok(())
        );
    }
}
