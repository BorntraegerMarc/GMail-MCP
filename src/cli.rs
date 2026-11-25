//! The command line: which job the binary was asked to do.
//!
//! Parsing is by hand: the interface is two words and one option, which does not justify a
//! dependency (docs/decisions/0004-dependency-policy-and-libraries.md).

use std::ffi::OsString;
use std::fmt;
use std::path::PathBuf;

/// The usage text, shown on a request for help and after a mistake.
pub const USAGE: &str = "usage: gmail-mcp [serve] | gmail-mcp auth [--credentials <client_secret.json>] | gmail-mcp --version | gmail-mcp --help";

/// What the binary was asked to do.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Task {
    /// Run the MCP server on stdin and stdout. The default when there are no arguments.
    Serve,
    /// Sign in to Google and store the credentials. `credentials` is the client secret file
    /// to import, or `None` to reuse the client that is already stored.
    Auth { credentials: Option<PathBuf> },
    /// Show the usage text.
    Help,
    /// Show the version, for bug reports.
    Version,
}

/// Why the arguments were not understood. Every message is static.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UsageError {
    /// The first argument is not a task.
    UnknownTask,
    /// An argument that the task does not take.
    UnexpectedArgument,
    /// `--credentials` without a file.
    MissingValue,
    /// `--credentials` more than once.
    Repeated,
}

impl UsageError {
    /// A fixed, human-readable reason that is safe to log.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            UsageError::UnknownTask => "unknown command",
            UsageError::UnexpectedArgument => "unexpected argument",
            UsageError::MissingValue => "--credentials needs the path of the client secret file",
            UsageError::Repeated => "--credentials was given more than once",
        }
    }
}

impl fmt::Display for UsageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for UsageError {}

/// Reads the arguments after the program name.
///
/// # Errors
///
/// [`UsageError`] for anything that is not `serve`, `auth [--credentials <file>]`, `--version`
/// or `--help`.
pub fn parse<I: IntoIterator<Item = OsString>>(args: I) -> Result<Task, UsageError> {
    let mut args = args.into_iter();
    let Some(first) = args.next() else {
        return Ok(Task::Serve);
    };
    match first.to_str() {
        Some("serve") => no_more(args, Task::Serve),
        Some("--help" | "-h" | "help") => no_more(args, Task::Help),
        Some("--version" | "-V") => no_more(args, Task::Version),
        Some("auth") => {
            let mut credentials = None;
            while let Some(argument) = args.next() {
                if argument.to_str() != Some("--credentials") {
                    return Err(UsageError::UnexpectedArgument);
                }
                let path = args.next().ok_or(UsageError::MissingValue)?;
                if credentials.replace(PathBuf::from(path)).is_some() {
                    return Err(UsageError::Repeated);
                }
            }
            Ok(Task::Auth { credentials })
        }
        _ => Err(UsageError::UnknownTask),
    }
}

fn no_more(mut rest: impl Iterator<Item = OsString>, task: Task) -> Result<Task, UsageError> {
    if rest.next().is_some() {
        Err(UsageError::UnexpectedArgument)
    } else {
        Ok(task)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_strs(args: &[&str]) -> Result<Task, UsageError> {
        parse(args.iter().map(OsString::from))
    }

    #[test]
    fn no_arguments_serve() {
        assert_eq!(parse_strs(&[]), Ok(Task::Serve));
        assert_eq!(parse_strs(&["serve"]), Ok(Task::Serve));
    }

    #[test]
    fn auth_takes_one_optional_file() {
        assert_eq!(parse_strs(&["auth"]), Ok(Task::Auth { credentials: None }));
        assert_eq!(
            parse_strs(&["auth", "--credentials", "file.json"]),
            Ok(Task::Auth {
                credentials: Some(PathBuf::from("file.json"))
            })
        );
    }

    #[test]
    fn help_is_recognised() {
        for word in ["--help", "-h", "help"] {
            assert_eq!(parse_strs(&[word]), Ok(Task::Help));
        }
    }

    #[test]
    fn the_version_is_recognised() {
        for word in ["--version", "-V"] {
            assert_eq!(parse_strs(&[word]), Ok(Task::Version));
        }
        assert_eq!(
            parse_strs(&["--version", "x"]),
            Err(UsageError::UnexpectedArgument)
        );
    }

    #[test]
    fn mistakes_are_refused() {
        assert_eq!(parse_strs(&["login"]), Err(UsageError::UnknownTask));
        assert_eq!(parse_strs(&["--credentials"]), Err(UsageError::UnknownTask));
        assert_eq!(
            parse_strs(&["serve", "x"]),
            Err(UsageError::UnexpectedArgument)
        );
        assert_eq!(
            parse_strs(&["--help", "x"]),
            Err(UsageError::UnexpectedArgument)
        );
        assert_eq!(
            parse_strs(&["auth", "x"]),
            Err(UsageError::UnexpectedArgument)
        );
        assert_eq!(
            parse_strs(&["auth", "--credentials"]),
            Err(UsageError::MissingValue)
        );
        assert_eq!(
            parse_strs(&["auth", "--credentials", "a", "--credentials", "b"]),
            Err(UsageError::Repeated)
        );
    }
}
