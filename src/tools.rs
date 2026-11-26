//! The four read tools, as plain functions: `list_labels`, `search_threads`, `get_thread` and
//! `get_message`.
//!
//! Each tool validates its arguments, calls Gmail through [`crate::gmail`] and returns one
//! `String`, or a static [`ToolError`]. The string is built only here and only through
//! [`Untrusted`]: the notice line comes first, and every field that comes from a mail (subjects,
//! addresses, dates, snippets, label names, attachment names, bodies) goes through `wrap` or
//! `wrap_body`, so it sits inside delimiters that carry a per-call nonce and share one output
//! budget. What is printed outside the delimiters is fixed text, numbers and identifiers that
//! passed [`ResourceId::parse`]. The wrapping reduces the risk of prompt injection; it does not
//! remove it.
// why: docs/decisions/0005-untrusted-email-content.md

use std::fmt;

use crate::auth::Guarded;
use crate::gmail::{self, EgressTransport, Gmail, Message, Transport};
use crate::policy::{self, ResourceId};
use crate::session::{Session, TokenSource};
use crate::store;
use crate::text::{self, Untrusted};

/// How many threads a search returns when the caller names no number.
pub const DEFAULT_MAX_RESULTS: u32 = 10;

/// The most threads a search may return: each hit costs one more request to Gmail.
// why: docs/decisions/0008-blocking-http-client.md
pub const MAX_RESULTS: u32 = 25;

/// The longest search query, in bytes. Percent-encoding can triple it, and the whole address must
/// stay within [`policy::MAX_URL_BYTES`].
// why: docs/decisions/0003-single-egress-allowlist.md
pub const MAX_QUERY_BYTES: usize = 400;

/// The least room one message of a thread gets for its body, in characters, so that a long
/// thread shows the start of many messages rather than all of the first.
const MIN_BODY_CHARS: usize = 2_000;

const CUT_NOTE: &str = "[output limit reached: the rest is not shown]";
const THREAD_CUT_NOTE: &str =
    "[output limit reached: later messages are not shown; read them one by one with get_message]";
const INCOMPLETE_NOTE: &str =
    "[some parts of this message were skipped: nesting, part count, size or encoding limits]";

/// Why a tool call failed. Every message is static and none repeats an argument or Google's
/// answer, because the text reaches the model and the logs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ToolError {
    /// An identifier argument is not 1 to 128 characters of letters, digits, `-` and `_`.
    InvalidId,
    /// `max_results` is not a whole number from 1 to 25.
    InvalidMaxResults,
    /// The search query is too long or holds control characters.
    InvalidQuery,
    /// The thread is larger than the response limit.
    ThreadTooLarge,
    /// The call to Gmail failed.
    Gmail(gmail::Error),
}

impl ToolError {
    /// A fixed, human-readable reason that is safe to log and to return to the model.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            ToolError::InvalidId => {
                "the id is not a valid Gmail identifier (letters, digits, - and _ only)"
            }
            ToolError::InvalidMaxResults => "max_results must be a whole number from 1 to 25",
            ToolError::InvalidQuery => {
                "the search query is longer than 400 bytes or has control characters"
            }
            ToolError::ThreadTooLarge => {
                "the thread is larger than the size limit; read single messages with get_message"
            }
            ToolError::Gmail(error) => error.reason(),
        }
    }
}

impl fmt::Display for ToolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
    }
}

impl std::error::Error for ToolError {}

impl From<gmail::Error> for ToolError {
    fn from(error: gmail::Error) -> Self {
        ToolError::Gmail(error)
    }
}

/// The tools, over one Gmail client.
pub struct Tools<T, K> {
    client: Gmail<T, K>,
}

impl Tools<EgressTransport, Session<Guarded, store::Platform>> {
    /// The tools of this platform: the real Gmail client behind the egress guard, with the
    /// credentials loaded from the platform's store on the first call.
    #[must_use]
    pub fn platform() -> Self {
        Self::new(Gmail::new(EgressTransport::new(), Session::platform()))
    }
}

impl<T: Transport, K: TokenSource> Tools<T, K> {
    /// Tools that read through `gmail`.
    #[must_use]
    pub fn new(gmail: Gmail<T, K>) -> Self {
        Self { client: gmail }
    }

    /// Lists the mailbox's labels.
    ///
    /// # Errors
    ///
    /// [`ToolError::Gmail`] if the call fails.
    pub fn list_labels(&mut self) -> Result<String, ToolError> {
        let labels = self.client.labels()?;
        let mut wrap = Untrusted::new();
        let mut out = opening(&wrap);
        if labels.is_empty() {
            line(&mut out, "No labels.");
            return Ok(out);
        }
        line(&mut out, &format!("Labels ({}):", labels.len()));
        for (shown, label) in labels.iter().enumerate() {
            if wrap.exhausted() {
                let hidden = labels.len().saturating_sub(shown);
                line(
                    &mut out,
                    &format!("[output limit reached: {hidden} more labels are not shown]"),
                );
                break;
            }
            let name = wrap.wrap("label", &label.name);
            line(&mut out, &format!("- {name} ({})", label.kind.name()));
        }
        Ok(out)
    }

    /// Searches for threads. `query` uses Gmail's search syntax and may be empty (the newest
    /// threads); `max_results` is 1 to 25 and defaults to 10.
    ///
    /// # Errors
    ///
    /// [`ToolError::InvalidMaxResults`] or [`ToolError::InvalidQuery`] for a bad argument,
    /// [`ToolError::Gmail`] if a call fails.
    pub fn search_threads(
        &mut self,
        query: &str,
        max_results: Option<u32>,
    ) -> Result<String, ToolError> {
        let limit = max_results.unwrap_or(DEFAULT_MAX_RESULTS);
        if !(1..=MAX_RESULTS).contains(&limit) {
            return Err(ToolError::InvalidMaxResults);
        }
        let limit = u16::try_from(limit).map_err(|_| ToolError::InvalidMaxResults)?;
        if query.len() > MAX_QUERY_BYTES || query.chars().any(char::is_control) {
            return Err(ToolError::InvalidQuery);
        }
        let hits = self.client.search(query, limit)?;
        let mut wrap = Untrusted::new();
        let mut out = opening(&wrap);
        if hits.is_empty() {
            line(&mut out, "No threads matched.");
            return Ok(out);
        }
        line(&mut out, &format!("Threads found ({}):", hits.len()));
        for (index, hit) in hits.iter().enumerate() {
            if wrap.exhausted() {
                line(&mut out, CUT_NOTE);
                break;
            }
            line(
                &mut out,
                &format!(
                    "{}. thread_id: {} messages: {}",
                    index.saturating_add(1),
                    hit.id,
                    hit.messages
                ),
            );
            for (name, value) in [
                ("subject", &hit.subject),
                ("from", &hit.from),
                ("date", &hit.date),
                ("snippet", &hit.snippet),
            ] {
                field(&mut out, &mut wrap, "   ", name, value);
            }
        }
        Ok(out)
    }

    /// Reads a whole thread, every message in full.
    ///
    /// # Errors
    ///
    /// [`ToolError::InvalidId`] for a bad id, [`ToolError::ThreadTooLarge`] if the thread is
    /// beyond the response limit, otherwise [`ToolError::Gmail`].
    pub fn get_thread(&mut self, id: &str) -> Result<String, ToolError> {
        let id = ResourceId::parse(id).map_err(|_| ToolError::InvalidId)?;
        let thread = self.client.thread(&id).map_err(|error| match error {
            gmail::Error::TooLarge => ToolError::ThreadTooLarge,
            other => ToolError::Gmail(other),
        })?;
        let mut wrap = Untrusted::new();
        let mut out = opening(&wrap);
        let count = thread.messages.len();
        line(&mut out, &format!("thread_id: {}", thread.id));
        line(&mut out, &format!("messages: {count}"));
        let share = (policy::MAX_OUTPUT_CHARS / count.max(1)).max(MIN_BODY_CHARS);
        for (index, message) in thread.messages.iter().enumerate() {
            if wrap.exhausted() {
                line(&mut out, THREAD_CUT_NOTE);
                break;
            }
            let number = index.saturating_add(1);
            line(&mut out, &format!("--- message {number} of {count} ---"));
            describe(&mut wrap, &mut out, message, share);
        }
        Ok(out)
    }

    /// Reads one message in full.
    ///
    /// # Errors
    ///
    /// [`ToolError::InvalidId`] for a bad id, otherwise [`ToolError::Gmail`].
    pub fn get_message(&mut self, id: &str) -> Result<String, ToolError> {
        let id = ResourceId::parse(id).map_err(|_| ToolError::InvalidId)?;
        let message = self.client.message(&id)?;
        let mut wrap = Untrusted::new();
        let mut out = opening(&wrap);
        describe(&mut wrap, &mut out, &message, policy::MAX_OUTPUT_CHARS);
        Ok(out)
    }
}

/// The start of every result: the notice that marked text is data.
fn opening(wrap: &Untrusted) -> String {
    let mut out = wrap.notice();
    out.push('\n');
    out
}

fn line(out: &mut String, text: &str) {
    out.push_str(text);
    out.push('\n');
}

/// One `name: <wrapped value>` line, left out when the value is empty.
fn field(out: &mut String, wrap: &mut Untrusted, indent: &str, name: &'static str, value: &str) {
    if !value.is_empty() {
        let block = wrap.wrap(name, value);
        line(out, &format!("{indent}{name}: {block}"));
    }
}

/// Writes one message: its identifier, headers, attachment metadata and body. The body is cut to
/// `body_chars` first, so one long message cannot use the budget that its neighbours need.
fn describe(wrap: &mut Untrusted, out: &mut String, message: &Message, body_chars: usize) {
    line(out, &format!("message_id: {}", message.id));
    for (name, value) in [
        ("subject", &message.subject),
        ("from", &message.from),
        ("to", &message.to),
        ("cc", &message.cc),
        ("date", &message.date),
    ] {
        field(out, wrap, "", name, value);
    }
    if !message.attachments.is_empty() {
        line(
            out,
            &format!(
                "attachments: {} (metadata only, never downloaded)",
                message.attachments.len()
            ),
        );
        for attachment in &message.attachments {
            if wrap.exhausted() {
                break;
            }
            let described = format!(
                "{} ({}, {} bytes)",
                attachment.filename, attachment.mime_type, attachment.size
            );
            line(out, &format!("- {}", wrap.wrap("attachment", &described)));
        }
    }
    if message.body.trim().is_empty() {
        line(out, "body: (no text)");
    } else if wrap.exhausted() {
        line(out, CUT_NOTE);
    } else {
        line(out, "body:");
        line(
            out,
            &wrap.wrap_body(&text::truncate(&message.body, body_chars)),
        );
    }
    if message.incomplete {
        line(out, INCOMPLETE_NOTE);
    }
}
