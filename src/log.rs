//! Logging to stderr, with static messages only.
//!
//! stdout carries the MCP protocol, so nothing in this crate prints to it, and clippy
//! denies the print macros. Everything that is logged goes through this module to stderr.
//!
//! A message must be a `&'static str`, which the compiler checks: a `format!` result is a
//! `String` and does not compile. That makes it impossible to log a token, a client secret,
//! a subject, an address or any other request, response or mail data by accident.
//!
//! The libraries this crate uses emit records through the `log` crate. No logger is
//! installed, on purpose, so those records go nowhere. Do not install one: `ureq`'s debug
//! records contain request URLs.
// why: docs/decisions/0006-credentials-in-os-credential-store.md (secrets out of logs)

use std::io::Write;

use oauth2::url::Url;

use crate::policy;

/// How serious a log line is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    /// Something failed and the server cannot do what was asked.
    Error,
    /// Something was refused or looks wrong, but the server carries on.
    Warn,
    /// Ordinary progress worth recording.
    Info,
}

impl Level {
    const fn label(self) -> &'static str {
        match self {
            Level::Error => "error",
            Level::Warn => "warn",
            Level::Info => "info",
        }
    }
}

/// Writes one line to stderr: `gmail-mcp <level>: <message>`.
///
/// A failure to write is ignored. A closed stderr must not stop the server, and there is
/// nowhere left to report it.
pub fn log(level: Level, message: &'static str) {
    let _ = write_line(&mut std::io::stderr().lock(), level, message);
}

/// Logs at [`Level::Error`].
pub fn error(message: &'static str) {
    log(Level::Error, message);
}

/// Logs at [`Level::Warn`].
pub fn warn(message: &'static str) {
    log(Level::Warn, message);
}

/// Logs at [`Level::Info`].
pub fn info(message: &'static str) {
    log(Level::Info, message);
}

/// The query parameters of the consent address: the ones the sign-in sets, and no others.
const CONSENT_PARAMETERS: &[&str] = &[
    "response_type",
    "client_id",
    "state",
    "code_challenge",
    "code_challenge_method",
    "redirect_uri",
    "scope",
    "access_type",
    "prompt",
];

/// The text that asks the user to open the Google consent page, or `None` if `url` is not that
/// page: `https`, the consent host with no user info and no port, the consent path, no fragment
/// and no query parameter the sign-in does not set.
///
/// This is the one message that is not a static string, because the user must receive the
/// address to open. The checks narrow what it can print to the consent page and its own
/// parameters, so it is no use for printing a token, a subject or a path. The values of those
/// parameters are not inspected: this is a guard against careless use, not a proof.
#[must_use]
pub fn consent_text(url: &Url) -> Option<String> {
    let is_consent_page = url.scheme() == "https"
        && url.host_str() == Some(policy::HOST_CONSENT)
        && url.port().is_none()
        && url.username().is_empty()
        && url.password().is_none()
        && url.path() == "/o/oauth2/v2/auth"
        && url.fragment().is_none()
        && url
            .query_pairs()
            .all(|(name, _)| CONSENT_PARAMETERS.contains(&name.as_ref()));
    is_consent_page.then(|| {
        format!(
            "gmail-mcp info: open this address in your browser and approve read-only access to Gmail:\n{url}\n"
        )
    })
}

/// Shows the user the Google consent address, so they can open it in a browser. Nothing here
/// starts a program or a browser.
///
/// Anything that is not the consent page is refused with an error line.
// why: docs/decisions/0015-sign-in-flow.md
pub fn consent_url(url: &Url) {
    match consent_text(url) {
        Some(text) => {
            let _ = std::io::stderr().lock().write_all(text.as_bytes());
        }
        None => error("refused to show an address that is not the Google consent page"),
    }
}

fn write_line(out: &mut impl Write, level: Level, message: &'static str) -> std::io::Result<()> {
    writeln!(out, "gmail-mcp {}: {message}", level.label())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(level: Level, message: &'static str) -> String {
        let mut out = Vec::new();
        write_line(&mut out, level, message).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn lines_have_a_fixed_shape() {
        assert_eq!(
            line(Level::Error, "token refresh failed"),
            "gmail-mcp error: token refresh failed\n"
        );
        assert_eq!(line(Level::Warn, "x"), "gmail-mcp warn: x\n");
        assert_eq!(line(Level::Info, "x"), "gmail-mcp info: x\n");
    }

    #[test]
    fn a_broken_stderr_does_not_panic() {
        struct Closed;
        impl Write for Closed {
            fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
                Err(std::io::ErrorKind::BrokenPipe.into())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        assert!(write_line(&mut Closed, Level::Info, "x").is_err());
    }
}
