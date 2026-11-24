//! The `gmail-mcp` binary: `auth` signs in, and `serve` will run the MCP server.
//!
//! `serve` lands in the next phase. Until then it refuses to run instead of pretending to be
//! a working server.

use std::process::ExitCode;

use gmail_mcp::cli::{self, Task};
use gmail_mcp::{auth, log};

fn main() -> ExitCode {
    match cli::parse(std::env::args_os().skip(1)) {
        Ok(Task::Auth { credentials }) => match auth::run(credentials.as_deref()) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                log::error(error.reason());
                ExitCode::FAILURE
            }
        },
        Ok(Task::Serve) => {
            log::error(concat!(
                "version ",
                env!("CARGO_PKG_VERSION"),
                ": serve is not implemented yet"
            ));
            ExitCode::from(2)
        }
        Ok(Task::Help) => {
            log::info(cli::USAGE);
            ExitCode::SUCCESS
        }
        Err(error) => {
            log::error(error.reason());
            log::info(cli::USAGE);
            ExitCode::from(2)
        }
    }
}
