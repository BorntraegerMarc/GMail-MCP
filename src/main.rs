//! Scaffold entry point.
//!
//! The real CLI (`serve`, `auth`) lands in later pull requests. Until then the binary
//! refuses to run instead of pretending to be a working server.

use std::process::ExitCode;

#[allow(
    clippy::print_stderr,
    reason = "scaffold notice; real logging lands in log.rs"
)]
fn main() -> ExitCode {
    eprintln!(
        "gmail-mcp {}: scaffold build, not implemented yet",
        gmail_mcp::VERSION
    );
    ExitCode::from(2)
}
