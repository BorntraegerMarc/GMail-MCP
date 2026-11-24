//! Scaffold entry point.
//!
//! The real CLI (`serve`, `auth`) lands in later pull requests. Until then the binary
//! refuses to run instead of pretending to be a working server.

use std::process::ExitCode;

use gmail_mcp::log;

fn main() -> ExitCode {
    log::error(concat!(
        "version ",
        env!("CARGO_PKG_VERSION"),
        ": scaffold build, not implemented yet"
    ));
    ExitCode::from(2)
}
