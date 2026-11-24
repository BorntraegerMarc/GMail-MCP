//! The egress allowlist, attacked from outside the crate.
//!
//! These tests are the table behind the README's claim that the server can reach two Google
//! hosts, read mail, and create a draft only in drafts mode. They use hostile examples (the
//! forbidden endpoints, hosts and parsing tricks by name), which is why they live here: the
//! source scan in `static_policy.rs` reads `src/` and would flag the same strings there.
//! Why: docs/decisions/0003-single-egress-allowlist.md

use gmail_mcp::http::{Egress, Error, Method, Request, header};
use gmail_mcp::policy::{self, Denied, Mode, ResourceId, authorize};

const GMAIL: &str = "https://gmail.googleapis.com/gmail/v1/users/me";

#[cfg(test)]
mod support {
    use super::*;

    pub fn request(method: &str, url: &str) -> Request<Vec<u8>> {
        Request::builder()
            .method(method)
            .uri(url)
            .body(Vec::new())
            .expect("a well-formed test request")
    }
}

#[test]
fn every_allowed_request_passes() {
    let allowed: &[(Mode, &str, String)] = &[
        (Mode::ReadOnly, "GET", format!("{GMAIL}/labels")),
        (Mode::ReadOnly, "GET", format!("{GMAIL}/threads")),
        (
            Mode::ReadOnly,
            "GET",
            format!("{GMAIL}/threads?q=from%3Aalice&maxResults=25&pageToken=abc"),
        ),
        (
            Mode::ReadOnly,
            "GET",
            format!("{GMAIL}/threads/18c3a5b2f1e4d7a0?format=full"),
        ),
        (
            Mode::ReadOnly,
            "GET",
            format!("{GMAIL}/messages/18c3a5b2f1e4d7a0?format=metadata&metadataHeaders=Message-ID"),
        ),
        (
            Mode::ReadOnly,
            "POST",
            "https://oauth2.googleapis.com/token".to_owned(),
        ),
        (Mode::Drafts, "GET", format!("{GMAIL}/labels")),
        (
            Mode::Drafts,
            "POST",
            "https://oauth2.googleapis.com/token".to_owned(),
        ),
        (Mode::Drafts, "POST", format!("{GMAIL}/drafts")),
    ];
    for (mode, method, url) in allowed {
        assert_eq!(
            authorize(*mode, method, url),
            Ok(()),
            "{mode:?} {method} {url}"
        );
    }
}

/// A query string is data for Gmail, never a path: content in it cannot change which route
/// matched, so it is free.
#[test]
fn query_strings_cannot_change_the_route() {
    for url in [
        format!("{GMAIL}/labels?next=/gmail/v1/users/me/settings/filters"),
        format!("{GMAIL}/labels?"),
        format!("{GMAIL}/labels?a=b?c=d&e=%2e%2e"),
    ] {
        assert_eq!(authorize(Mode::ReadOnly, "GET", &url), Ok(()), "{url}");
    }
}

/// Drafts are refused in read-only mode by the guard itself, whatever scope was granted.
#[test]
fn creating_a_draft_needs_drafts_mode() {
    assert_eq!(
        authorize(Mode::ReadOnly, "POST", &format!("{GMAIL}/drafts")),
        Err(Denied::DraftsDisabled)
    );
}

/// Every request below would send, delete, relabel, reconfigure or download something, or
/// would reach a place the design never calls. None may pass in either mode.
#[test]
fn every_write_and_every_unlisted_read_is_refused() {
    let routes: Vec<(&str, String)> = vec![
        // Sending and forwarding.
        ("POST", format!("{GMAIL}/messages/send")),
        ("POST", format!("{GMAIL}/drafts/send")),
        ("POST", format!("{GMAIL}/drafts/18c3a5b2f1e4d7a0/send")),
        ("POST", format!("{GMAIL}/settings/forwardingAddresses")),
        // Deleting, trashing, restoring, marking spam, relabelling.
        ("DELETE", format!("{GMAIL}/messages/18c3a5b2f1e4d7a0")),
        ("DELETE", format!("{GMAIL}/threads/18c3a5b2f1e4d7a0")),
        ("DELETE", format!("{GMAIL}/drafts/18c3a5b2f1e4d7a0")),
        ("POST", format!("{GMAIL}/messages/18c3a5b2f1e4d7a0/trash")),
        ("POST", format!("{GMAIL}/messages/18c3a5b2f1e4d7a0/untrash")),
        ("POST", format!("{GMAIL}/threads/18c3a5b2f1e4d7a0/trash")),
        ("POST", format!("{GMAIL}/messages/18c3a5b2f1e4d7a0/modify")),
        ("POST", format!("{GMAIL}/threads/18c3a5b2f1e4d7a0/modify")),
        ("POST", format!("{GMAIL}/messages/batchModify")),
        ("POST", format!("{GMAIL}/messages/batchDelete")),
        ("POST", format!("{GMAIL}/messages/import")),
        ("POST", format!("{GMAIL}/messages/insert")),
        ("POST", format!("{GMAIL}/labels")),
        ("PATCH", format!("{GMAIL}/labels/Label_1")),
        ("PUT", format!("{GMAIL}/labels/Label_1")),
        ("PUT", format!("{GMAIL}/drafts/18c3a5b2f1e4d7a0")),
        // Settings, filters, delegates, notifications.
        ("GET", format!("{GMAIL}/settings")),
        ("GET", format!("{GMAIL}/settings/filters")),
        ("POST", format!("{GMAIL}/settings/filters")),
        ("GET", format!("{GMAIL}/settings/sendAs")),
        ("POST", format!("{GMAIL}/settings/delegates")),
        ("POST", format!("{GMAIL}/watch")),
        ("POST", format!("{GMAIL}/stop")),
        // Reads the design never makes: attachments are metadata only.
        (
            "GET",
            format!("{GMAIL}/messages/18c3a5b2f1e4d7a0/attachments/ANGjdJ8"),
        ),
        ("GET", format!("{GMAIL}/messages")),
        ("GET", format!("{GMAIL}/drafts")),
        ("GET", format!("{GMAIL}/drafts/18c3a5b2f1e4d7a0")),
        ("GET", format!("{GMAIL}/labels/Label_1")),
        ("GET", format!("{GMAIL}/profile")),
        ("GET", format!("{GMAIL}/history")),
        ("GET", format!("{GMAIL}/threads/18c3a5b2f1e4d7a0/messages")),
        // Wrong method on an allowed path.
        ("POST", format!("{GMAIL}/labels")),
        ("POST", format!("{GMAIL}/threads")),
        ("POST", format!("{GMAIL}/threads/18c3a5b2f1e4d7a0")),
        ("POST", format!("{GMAIL}/messages/18c3a5b2f1e4d7a0")),
        ("GET", "https://oauth2.googleapis.com/token".to_owned()),
        // Other OAuth endpoints.
        ("POST", "https://oauth2.googleapis.com/revoke".to_owned()),
        (
            "POST",
            "https://oauth2.googleapis.com/token/extra".to_owned(),
        ),
        ("POST", "https://oauth2.googleapis.com/token/".to_owned()),
        ("GET", "https://oauth2.googleapis.com/tokeninfo".to_owned()),
    ];
    for mode in [Mode::ReadOnly, Mode::Drafts] {
        for (method, url) in &routes {
            let verdict = authorize(mode, method, url);
            assert!(verdict.is_err(), "{mode:?} {method} {url} was allowed");
        }
    }
}

/// Attacks on the path, aimed at slipping a forbidden endpoint under an allowed prefix.
#[test]
fn path_tricks_cannot_reach_another_endpoint() {
    let long_id = "a".repeat(policy::MAX_ID_BYTES + 1);
    for url in [
        format!("{GMAIL}/messages/../settings/filters"),
        format!("{GMAIL}/messages/%2e%2e/settings/filters"),
        format!("{GMAIL}/messages/..%2fsettings"),
        format!("{GMAIL}/messages/abc/../../settings"),
        format!("{GMAIL}/messages/abc/"),
        format!("{GMAIL}/messages//abc"),
        format!("{GMAIL}/messages/abc;x=1"),
        format!("{GMAIL}/messages/abc%00"),
        format!("{GMAIL}/messages/abc%2Fattachments%2Fdef"),
        format!("{GMAIL}/messages/{long_id}"),
        format!("{GMAIL}/messages/"),
        format!("{GMAIL}/Labels"),
        format!("{GMAIL}/labels/"),
        "https://gmail.googleapis.com//gmail/v1/users/me/labels".to_owned(),
        "https://gmail.googleapis.com/gmail/v1/users/other@example.test/messages/abc".to_owned(),
        "https://gmail.googleapis.com/gmail/v1/users/me2/labels".to_owned(),
        "https://gmail.googleapis.com/gmail/v2/users/me/labels".to_owned(),
        "https://gmail.googleapis.com/GMAIL/v1/users/me/labels".to_owned(),
        "https://gmail.googleapis.com/upload/gmail/v1/users/me/drafts".to_owned(),
        "https://gmail.googleapis.com".to_owned(),
        "https://gmail.googleapis.com/".to_owned(),
    ] {
        assert_eq!(
            authorize(Mode::Drafts, "GET", &url),
            Err(Denied::Route),
            "{url}"
        );
    }
}

#[test]
fn only_the_two_allowlisted_hosts_are_reachable() {
    for url in [
        "https://evil.example/gmail/v1/users/me/labels",
        "https://gmail.googleapis.com.evil.example/gmail/v1/users/me/labels",
        "https://evilgmail.googleapis.com/gmail/v1/users/me/labels",
        "https://gmail.googleapis.com@evil.example/gmail/v1/users/me/labels",
        "https://user@gmail.googleapis.com/gmail/v1/users/me/labels",
        "https://user:pass@gmail.googleapis.com/gmail/v1/users/me/labels",
        "https://gmail.googleapis.com:443/gmail/v1/users/me/labels",
        "https://gmail.googleapis.com:8443/gmail/v1/users/me/labels",
        "https://GMAIL.googleapis.com/gmail/v1/users/me/labels",
        "https://gmail.googleapis.com./gmail/v1/users/me/labels",
        "https://gmail.googleapis.com?/gmail/v1/users/me/labels",
        "https://gmail.googleapis.com%2f@evil.example/gmail/v1/users/me/labels",
        "https://www.googleapis.com/gmail/v1/users/me/labels",
        "https://accounts.google.com/o/oauth2/v2/auth",
        "https://gmailmcp.googleapis.com/mcp",
        "https://mail.google.com/mail/feed/atom",
        "https://127.0.0.1/gmail/v1/users/me/labels",
        "https://localhost/gmail/v1/users/me/labels",
        "https://[::1]/gmail/v1/users/me/labels",
        "https://2130706433/gmail/v1/users/me/labels",
    ] {
        assert_eq!(
            authorize(Mode::Drafts, "GET", url),
            Err(Denied::Host),
            "{url}"
        );
    }
}

#[test]
fn only_https_is_accepted() {
    for url in [
        "http://gmail.googleapis.com/gmail/v1/users/me/labels",
        "HTTPS://gmail.googleapis.com/gmail/v1/users/me/labels",
        "ftp://gmail.googleapis.com/gmail/v1/users/me/labels",
        "//gmail.googleapis.com/gmail/v1/users/me/labels",
        "gmail.googleapis.com/gmail/v1/users/me/labels",
        "/gmail/v1/users/me/labels",
        "",
    ] {
        assert_eq!(
            authorize(Mode::Drafts, "GET", url),
            Err(Denied::NotHttps),
            "{url:?}"
        );
    }
}

#[test]
fn urls_with_unusual_characters_are_refused_outright() {
    let too_long = format!("{GMAIL}/threads?q={}", "a".repeat(policy::MAX_URL_BYTES));
    for url in [
        format!("{GMAIL}/labels "),
        format!("{GMAIL}/la bels"),
        format!("{GMAIL}/labels\n"),
        format!("{GMAIL}/labels\r\nHost: evil.example"),
        format!("{GMAIL}/labels\t"),
        format!("{GMAIL}/labels\0"),
        format!("{GMAIL}/labels#fragment"),
        format!("{GMAIL}/labels#@evil.example"),
        format!("{GMAIL}/labels\\..\\settings"),
        "https://evil.example\\@gmail.googleapis.com/gmail/v1/users/me/labels".to_owned(),
        format!("{GMAIL}/lábels"),
        too_long,
    ] {
        assert_eq!(
            authorize(Mode::Drafts, "GET", &url),
            Err(Denied::Malformed),
            "{url:?}"
        );
    }
}

#[test]
fn only_get_and_post_exist() {
    for method in [
        "PUT",
        "DELETE",
        "PATCH",
        "HEAD",
        "OPTIONS",
        "TRACE",
        "CONNECT",
        "get",
        "Get",
        "post",
        "GET ",
        " GET",
        "",
        "GET\r\nX: y",
    ] {
        assert_eq!(
            authorize(Mode::Drafts, method, &format!("{GMAIL}/labels")),
            Err(Denied::Method),
            "{method:?}"
        );
    }
}

#[test]
fn identifiers_cannot_carry_a_path_or_control_characters() {
    for id in [
        "",
        "..",
        "../settings",
        "a/b",
        "a\\b",
        "a b",
        "a\n",
        "a\0",
        "a.b",
        "a%2e",
        "a;b",
        "a?b",
        "a#b",
        "é",
        "😀",
    ] {
        assert!(ResourceId::parse(id).is_err(), "{id:?}");
    }
    assert!(ResourceId::parse(&"a".repeat(policy::MAX_ID_BYTES + 1)).is_err());
    assert!(ResourceId::parse("18c3a5b2f1e4d7a0").is_ok());
}

#[test]
fn request_headers_are_limited_to_three() {
    for ok in ["authorization", "Authorization", "CONTENT-TYPE", "accept"] {
        assert!(policy::header_allowed(ok), "{ok}");
    }
    for bad in [
        "host",
        "Host",
        "cookie",
        "x-forwarded-for",
        "user-agent",
        "proxy-authorization",
        "content-length",
        "transfer-encoding",
        "x-goog-api-key",
        "",
    ] {
        assert!(!policy::header_allowed(bad), "{bad}");
    }
}

// ---- the guard itself, without a network ----------------------------------------------
//
// Each request below is refused before any connection is opened. If the guard let one
// through, the client would try to resolve a name that does not exist and the test would
// fail with a network error instead of `Denied`.

#[test]
fn the_guard_refuses_another_host_without_connecting() {
    let guard = Egress::new(Mode::Drafts);
    let result = guard.send(support::request("GET", "https://evil.example/exfiltrate"));
    assert_eq!(result.unwrap_err(), Error::Denied(Denied::Host));
}

#[test]
fn the_guard_refuses_a_draft_in_read_only_mode_without_connecting() {
    let guard = Egress::new(Mode::ReadOnly);
    let result = guard.send(support::request("POST", &format!("{GMAIL}/drafts")));
    assert_eq!(result.unwrap_err(), Error::Denied(Denied::DraftsDisabled));
}

#[test]
fn the_guard_refuses_a_delete_on_an_allowed_url_without_connecting() {
    let guard = Egress::new(Mode::Drafts);
    let request = Request::builder()
        .method(Method::DELETE)
        .uri(format!("{GMAIL}/messages/18c3a5b2f1e4d7a0"))
        .body(Vec::new())
        .expect("a well-formed test request");
    assert_eq!(
        guard.send(request).unwrap_err(),
        Error::Denied(Denied::Method)
    );
}

#[test]
fn the_guard_refuses_a_host_header_override_without_connecting() {
    let guard = Egress::new(Mode::Drafts);
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("{GMAIL}/labels"))
        .header(header::HOST, "evil.example")
        .body(Vec::new())
        .expect("a well-formed test request");
    assert_eq!(
        guard.send(request).unwrap_err(),
        Error::Denied(Denied::Header)
    );
}
