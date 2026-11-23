//! Secure, minimal, unofficial Gmail MCP server.
//!
//! This is the Phase 0 scaffold: the implementation lands in later pull requests,
//! one reviewable phase at a time (the phases are listed in docs/decisions/README.md).

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
