//! The one address that is not a static message in the logs: the Google consent page that the
//! user is asked to open. The logger shows nothing else, so it cannot be used to print a token.
//! Why: docs/decisions/0015-sign-in-flow.md.

use gmail_mcp::log::consent_text;
use gmail_mcp::policy::CONSENT_URL;
use oauth2::url::Url;

fn text(address: &str) -> Option<String> {
    consent_text(&Url::parse(address).expect("a valid URL"))
}

#[test]
fn the_consent_page_is_shown_in_full() {
    let address = format!("{CONSENT_URL}?client_id=abc&state=xyz&scope=s");
    let shown = text(&address).expect("the consent page is shown");
    assert!(shown.contains(&address), "{shown}");
    assert!(shown.starts_with("gmail-mcp info: "), "{shown}");
    assert!(shown.ends_with('\n'));
}

#[test]
fn nothing_but_the_consent_page_is_shown() {
    for address in [
        "https://example.test/o/oauth2/v2/auth?client_id=abc",
        "https://accounts.google.com.example.test/o/oauth2/v2/auth",
        "https://evilaccounts.google.com/o/oauth2/v2/auth",
        "https://accounts.google.com@example.test/o/oauth2/v2/auth",
        "https://user:pass@accounts.google.com/o/oauth2/v2/auth",
        "https://accounts.google.com:8443/o/oauth2/v2/auth",
        "http://accounts.google.com/o/oauth2/v2/auth",
        "https://accounts.google.com/",
        "https://accounts.google.com/o/oauth2/v2/authx",
        "https://accounts.google.com/o/oauth2/v2/auth/",
        "https://accounts.google.com/o/oauth2/token",
        "https://accounts.google.com/o/oauth2/v2/auth#access_token=x",
        "https://accounts.google.com/o/oauth2/v2/auth?refresh_token=x",
        "https://accounts.google.com/o/oauth2/v2/auth?client_id=abc&token=x",
        "https://accounts.google.com/o/oauth2/v2/auth?client_id=abc#x",
        "https://oauth2.googleapis.com/token",
        "https://gmail.googleapis.com/gmail/v1/users/me/labels",
        "ftp://accounts.google.com/o/oauth2/v2/auth",
        "file:///etc/passwd",
    ] {
        assert_eq!(text(address), None, "{address} would have been shown");
    }
}
