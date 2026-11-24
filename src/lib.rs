//! Secure, minimal, unofficial Gmail MCP server.
//!
//! The crate is built in phases, one reviewable pull request each (the phases are listed in
//! docs/decisions/README.md). This is the policy core: the pieces that decide what the
//! server may do and how untrusted data is handled, with no server on top of them yet.
//!
//! - [`policy`]: the permission model, the egress allowlist, identifier validation, limits.
//! - [`http`]: the egress guard, the only code that talks to the network.
//! - [`text`]: wrapping and sanitising of email content on its way to the model.
//! - [`draft`]: building a draft from the model's fields, with header-injection checks.
//! - [`log`]: stderr logging with static messages only.

pub mod draft;
pub mod http;
pub mod log;
pub mod policy;
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
