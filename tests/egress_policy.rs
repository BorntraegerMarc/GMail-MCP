//! The egress allowlist, attacked from outside the crate.
//!
//! These tests are the table behind the README's claim that the server can reach two Google
//! hosts and read mail, and that nothing it can send writes to Gmail. They use hostile
//! examples (the forbidden endpoints, hosts, parameters and parsing tricks by name), which is
//! why they live here: the source scan in `static_policy.rs` reads `src/` and would flag the
//! same strings there.
//! Why: docs/decisions/0003-single-egress-allowlist.md

use gmail_mcp::http::{Egress, Error, Method, Request, header};
use gmail_mcp::policy::{self, Denied, ResourceId, authorize};

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
    let allowed: &[(&str, String)] = &[
        ("GET", format!("{GMAIL}/labels")),
        ("GET", format!("{GMAIL}/threads")),
        (
            "GET",
            format!(
                "{GMAIL}/threads?q=from%3Aalice&maxResults=25&pageToken=abc&labelIds=INBOX&labelIds=UNREAD"
            ),
        ),
        (
            "GET",
            format!("{GMAIL}/threads/18c3a5b2f1e4d7a0?format=full"),
        ),
        (
            "GET",
            format!(
                "{GMAIL}/threads/18c3a5b2f1e4d7a0?format=metadata&metadataHeaders=Message-ID&metadataHeaders=Subject"
            ),
        ),
        (
            "GET",
            format!("{GMAIL}/messages/18c3a5b2f1e4d7a0?format=minimal"),
        ),
        ("POST", "https://oauth2.googleapis.com/token".to_owned()),
    ];
    for (method, url) in allowed {
        assert_eq!(authorize(method, url), Ok(()), "{method} {url}");
    }
}

/// An encoded `&` or `=` stays inside its value: only a raw one ends a parameter.
#[test]
fn query_values_are_opaque_and_empty_queries_are_fine() {
    for url in [
        format!("{GMAIL}/labels?"),
        format!("{GMAIL}/threads?q=a%26httpMethod%3DDELETE"),
        format!("{GMAIL}/threads?q=a+b%20c*d"),
        format!("{GMAIL}/threads?q=%00%ff%FF"),
    ] {
        assert_eq!(authorize("GET", &url), Ok(()), "{url}");
    }
}

/// Google's APIs accept parameters that change what a request does: a method override turns
/// a read into a delete, `alt` and `format=raw` pull whole messages with attachments. A
/// query parameter that is not listed, a value that is not allowed, a duplicate and anything
/// that could end a value early are refused.
#[test]
fn query_parameters_cannot_change_what_a_request_does() {
    let id = "18c3a5b2f1e4d7a0";
    let denied = [
        // No route here takes any parameter.
        format!("{GMAIL}/labels?x=1"),
        // Method overrides and Google's standard parameters.
        format!("{GMAIL}/labels?$httpMethod=DELETE"),
        format!("{GMAIL}/labels?%24httpMethod=DELETE"),
        format!("{GMAIL}/threads/{id}?$httpMethod=DELETE"),
        format!("{GMAIL}/messages/{id}?$httpMethod=POST"),
        format!("{GMAIL}/messages/{id}?format=full&$httpMethod=DELETE"),
        format!("{GMAIL}/messages/{id}?alt=media"),
        format!("{GMAIL}/messages/{id}?key=x"),
        format!("{GMAIL}/messages/{id}?access_token=x"),
        format!("{GMAIL}/messages/{id}?callback=x"),
        format!("{GMAIL}/messages/{id}?fields=id"),
        format!("{GMAIL}/messages/{id}?prettyPrint=false"),
        format!("{GMAIL}/messages/{id}?quotaUser=x"),
        format!("{GMAIL}/messages/{id}?uploadType=media"),
        format!("{GMAIL}/threads?includeSpamTrash=true"),
        // Whole messages with attachments, and values that are not formats.
        format!("{GMAIL}/messages/{id}?format=raw"),
        format!("{GMAIL}/messages/{id}?format=RAW"),
        format!("{GMAIL}/messages/{id}?format="),
        format!("{GMAIL}/messages/{id}?format=full&format=metadata"),
        format!("{GMAIL}/threads/{id}?format=full%26x%3D1"),
        // Duplicates of parameters that are not arrays.
        format!("{GMAIL}/threads?q=a&q=b"),
        format!("{GMAIL}/threads?maxResults=1&maxResults=2"),
        // Values that are not numbers.
        format!("{GMAIL}/threads?maxResults=abc"),
        format!("{GMAIL}/threads?maxResults=12345"),
        format!("{GMAIL}/threads?maxResults=-1"),
        format!("{GMAIL}/threads?maxResults=1.5"),
        format!("{GMAIL}/threads?maxResults="),
        // Shapes that are not `name=value` pairs, and raw characters that end or start things.
        format!("{GMAIL}/threads?q"),
        format!("{GMAIL}/threads?&q=a"),
        format!("{GMAIL}/threads?q=a&&maxResults=1"),
        format!("{GMAIL}/threads?q=a&b"),
        format!("{GMAIL}/threads?q=a=b"),
        format!("{GMAIL}/threads?q=a?b"),
        format!("{GMAIL}/threads?q=a/b"),
        format!("{GMAIL}/threads?q=a;b"),
        format!("{GMAIL}/threads?q=a,b"),
        format!("{GMAIL}/threads?q=%"),
        format!("{GMAIL}/threads?q=%4"),
        format!("{GMAIL}/threads?q=%zz"),
        format!("{GMAIL}/threads?q="),
    ];
    for url in denied {
        assert_eq!(authorize("GET", &url), Err(Denied::Query), "{url}");
    }
    assert_eq!(
        authorize("POST", "https://oauth2.googleapis.com/token?x=1"),
        Err(Denied::Query)
    );
}

/// Every request below would send, draft, delete, relabel, reconfigure or download something,
/// or would reach a place the design never calls. None may pass: the Gmail host has no
/// route but a few `GET`s, so nothing that writes can even be expressed.
#[test]
fn every_write_and_every_unlisted_read_is_refused() {
    let routes: Vec<(&str, String)> = vec![
        // Sending and forwarding.
        ("POST", format!("{GMAIL}/messages/send")),
        ("POST", format!("{GMAIL}/drafts/send")),
        ("POST", format!("{GMAIL}/drafts/18c3a5b2f1e4d7a0/send")),
        ("POST", format!("{GMAIL}/settings/forwardingAddresses")),
        // Creating, changing, reading and sending drafts: the server composes no mail.
        ("POST", format!("{GMAIL}/drafts")),
        ("GET", format!("{GMAIL}/drafts")),
        ("GET", format!("{GMAIL}/drafts/18c3a5b2f1e4d7a0")),
        ("PUT", format!("{GMAIL}/drafts/18c3a5b2f1e4d7a0")),
        ("DELETE", format!("{GMAIL}/drafts/18c3a5b2f1e4d7a0")),
        (
            "POST",
            "https://gmail.googleapis.com/upload/gmail/v1/users/me/drafts".to_owned(),
        ),
        // Deleting, trashing, restoring, marking spam, relabelling.
        ("DELETE", format!("{GMAIL}/messages/18c3a5b2f1e4d7a0")),
        ("DELETE", format!("{GMAIL}/threads/18c3a5b2f1e4d7a0")),
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
        ("GET", format!("{GMAIL}/labels/Label_1")),
        ("GET", format!("{GMAIL}/profile")),
        ("GET", format!("{GMAIL}/history")),
        ("GET", format!("{GMAIL}/threads/18c3a5b2f1e4d7a0/messages")),
        // Wrong method on an allowed path: the Gmail host takes GET and nothing else.
        ("POST", format!("{GMAIL}/threads")),
        ("POST", format!("{GMAIL}/threads/18c3a5b2f1e4d7a0")),
        ("POST", format!("{GMAIL}/messages/18c3a5b2f1e4d7a0")),
        ("PUT", format!("{GMAIL}/labels")),
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
    for (method, url) in &routes {
        let verdict = authorize(method, url);
        assert!(verdict.is_err(), "{method} {url} was allowed");
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
        "https://gmail.googleapis.com".to_owned(),
        "https://gmail.googleapis.com/".to_owned(),
    ] {
        assert_eq!(authorize("GET", &url), Err(Denied::Route), "{url}");
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
        assert_eq!(authorize("GET", url), Err(Denied::Host), "{url}");
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
        assert_eq!(authorize("GET", url), Err(Denied::NotHttps), "{url:?}");
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
        format!("{GMAIL}/threads?q=a b"),
        too_long,
    ] {
        assert_eq!(authorize("GET", &url), Err(Denied::Malformed), "{url:?}");
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
            authorize(method, &format!("{GMAIL}/labels")),
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
        "x-http-method-override",
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
    let result = Egress::new().send(support::request("GET", "https://evil.example/exfiltrate"));
    assert_eq!(result.unwrap_err(), Error::Denied(Denied::Host));
}

#[test]
fn the_guard_refuses_to_create_a_draft_without_connecting() {
    let result = Egress::new().send(support::request("POST", &format!("{GMAIL}/drafts")));
    assert_eq!(result.unwrap_err(), Error::Denied(Denied::Route));
}

#[test]
fn the_guard_refuses_a_delete_on_an_allowed_url_without_connecting() {
    let request = Request::builder()
        .method(Method::DELETE)
        .uri(format!("{GMAIL}/messages/18c3a5b2f1e4d7a0"))
        .body(Vec::new())
        .expect("a well-formed test request");
    assert_eq!(
        Egress::new().send(request).unwrap_err(),
        Error::Denied(Denied::Method)
    );
}

#[test]
fn the_guard_refuses_a_method_override_without_connecting() {
    let result = Egress::new().send(support::request(
        "GET",
        &format!("{GMAIL}/messages/18c3a5b2f1e4d7a0?$httpMethod=DELETE"),
    ));
    assert_eq!(result.unwrap_err(), Error::Denied(Denied::Query));

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("{GMAIL}/labels"))
        .header("x-http-method-override", "DELETE")
        .body(Vec::new())
        .expect("a well-formed test request");
    assert_eq!(
        Egress::new().send(request).unwrap_err(),
        Error::Denied(Denied::Header)
    );
}

#[test]
fn the_guard_refuses_a_host_header_override_without_connecting() {
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("{GMAIL}/labels"))
        .header(header::HOST, "evil.example")
        .body(Vec::new())
        .expect("a well-formed test request");
    assert_eq!(
        Egress::new().send(request).unwrap_err(),
        Error::Denied(Denied::Header)
    );
}

#[test]
fn the_guard_refuses_a_get_with_a_body_without_connecting() {
    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("{GMAIL}/labels"))
        .body(b"payload".to_vec())
        .expect("a well-formed test request");
    assert_eq!(
        Egress::new().send(request).unwrap_err(),
        Error::Denied(Denied::Body)
    );
}

// ---- the proxy ----------------------------------------------------------------------------
//
// The HTTP client reads proxy settings from the environment unless it is told not to, and a
// proxy is a hop the guard does not control. A test cannot set environment variables without
// `unsafe`, which this crate forbids, so the test re-runs this test binary as a child process
// with the variables set and has the child report what the guard does.

#[test]
fn the_proxy_variables_of_the_environment_are_ignored() {
    let program = std::env::current_exe().expect("the path of this test binary");
    let mut child = std::process::Command::new(program);
    child.args([
        "--ignored",
        "--exact",
        "child_checks_that_the_environment_proxy_is_ignored",
    ]);
    for name in [
        "HTTPS_PROXY",
        "https_proxy",
        "ALL_PROXY",
        "all_proxy",
        "HTTP_PROXY",
        "http_proxy",
    ] {
        child.env(name, "http://127.0.0.1:1");
    }
    let output = child.output().expect("the test binary can be started");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        output.status.success(),
        "the guard picked up a proxy from the environment:\n{stdout}\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(
        stdout.contains("1 passed"),
        "the child test did not run:\n{stdout}"
    );
}

/// Run by the test above in a child process with proxy variables set; ignored on its own.
#[test]
#[ignore = "run in a child process by the_proxy_variables_of_the_environment_are_ignored"]
fn child_checks_that_the_environment_proxy_is_ignored() {
    assert!(
        std::env::var_os("HTTPS_PROXY").is_some(),
        "the parent test sets the proxy variables"
    );
    assert!(!Egress::new().uses_proxy());
}
