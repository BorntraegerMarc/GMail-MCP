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
