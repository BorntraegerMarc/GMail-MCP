//! Secure, minimal, unofficial Gmail MCP server. It reads mail and does nothing else.
//!
//! The crate is built in phases, one reviewable pull request each (the phases are listed in
//! docs/decisions/README.md). So far: the policy core (what the server may do and how
//! untrusted data is handled) and the sign-in (`gmail-mcp auth`), with no server on top yet.
//!
//! - [`policy`]: the one OAuth scope, the egress allowlist, identifier validation, limits.
//! - [`http`]: the egress guard, the only code that dials out to the network.
//! - [`auth`]: the sign-in flow, with the local listener that receives Google's redirect.
//! - [`store`]: the credential store (the macOS Keychain; other platforms fail closed).
//! - [`text`]: wrapping and sanitising of email content on its way to the model, and the
//!   conversion of HTML-only mail to text.
//! - [`cli`]: the command line.
//! - [`log`]: stderr logging with static messages only.

pub mod auth;
pub mod cli;
pub mod http;
pub mod log;
pub mod policy;
pub mod store;
pub mod text;

/// Crate version, as declared in `Cargo.toml`.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

#[cfg(test)]
mod tests {
    use super::VERSION;

    #[test]
    fn version_is_semver_shaped() {
        let parts: Vec<&str> = VERSION.split('.').collect();
        assert_eq!(parts.len(), 3, "unexpected version: {VERSION}");
        assert!(parts.iter().all(|p| p.parse::<u64>().is_ok()));
    }
}
