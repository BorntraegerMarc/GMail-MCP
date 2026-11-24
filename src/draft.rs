//! Building a draft from the model's fields.
//!
//! With `--allow-drafts`, `create_draft` takes its fields from a model that may have just read
//! a hostile email, and those fields end up in mail headers. Every header-bound value is
//! checked here before the MIME library sees it, even though the library encodes what it is
//! given: the check is deliberate defence in depth and must not be removed as a duplicate.
//!
//! The result is the raw RFC 5322 message. This module never sends anything; creating the
//! draft in Gmail is the job of the Gmail client, behind the egress guard.
// why: docs/decisions/0005-untrusted-email-content.md (writing side)

use std::fmt;
use std::str::FromStr;

use lettre::Address;
use lettre::message::{Mailbox, Message, SinglePart, header};

use crate::policy::{self, InvalidId, ResourceId};

/// A draft as the model asked for it. Every field is untrusted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct DraftRequest {
    /// Recipients. Plain addresses only, such as `person@example.com`.
    pub to: Vec<String>,
    /// Carbon-copy recipients.
    pub cc: Vec<String>,
    /// Blind-carbon-copy recipients. They stay in the draft so the user can see them.
    pub bcc: Vec<String>,
    /// The subject line.
    pub subject: String,
    /// The plain-text body.
    pub body: String,
}

/// The message a draft replies to, as read from Gmail. These values come from a received
/// email, so they are untrusted and get the same checks as the model's fields.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reply {
    /// The thread the draft joins.
    pub thread_id: String,
    /// The replied-to message's `Message-ID` header, including its angle brackets.
    pub message_id: String,
    /// The replied-to message's `References` header, if it has one.
    pub references: Option<String>,
}

/// A draft ready to be created in Gmail.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Draft {
    /// The complete message in RFC 5322 form. Gmail expects it base64url encoded.
    pub raw: Vec<u8>,
    /// The thread to attach the draft to, for a reply.
    pub thread_id: Option<ResourceId>,
}

/// Why a draft was refused. The messages name the field and the rule, never the value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DraftError {
    /// There is no recipient at all (to, cc and bcc are all empty).
    NoRecipient,
    /// More than [`policy::MAX_RECIPIENTS`] recipients.
    TooManyRecipients,
    /// An address is not a plain `local@domain.tld` address. Display names, quoting and
    /// non-ASCII addresses are not accepted.
    InvalidAddress(&'static str),
    /// A header-bound field contains a control character, which includes CR, LF and NUL.
    ControlCharacter(&'static str),
    /// The subject is longer than [`policy::MAX_SUBJECT_CHARS`].
    SubjectTooLong,
    /// The body is larger than [`policy::MAX_BODY_BYTES`].
    BodyTooLarge,
    /// The body contains a control character other than tab and line breaks, such as NUL.
    BodyControlCharacter,
    /// The reply's thread ID or `Message-ID` is not in the form the server will copy into a
    /// header.
    InvalidReply(&'static str),
    /// The mail library refused to build the message.
    Build,
}

impl fmt::Display for DraftError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DraftError::NoRecipient => {
                f.write_str("a draft needs at least one recipient (to, cc or bcc)")
            }
            DraftError::TooManyRecipients => write!(
                f,
                "a draft can have at most {} recipients in total",
                policy::MAX_RECIPIENTS
            ),
            DraftError::InvalidAddress(field) => write!(
                f,
                "{field}: each address must be a plain address like person@example.com (no display name, quotes or non-ASCII characters)"
            ),
            DraftError::ControlCharacter(field) => {
                write!(
                    f,
                    "{field}: control characters (including line breaks) are not allowed"
                )
            }
            DraftError::SubjectTooLong => write!(
                f,
                "the subject is longer than {} characters",
                policy::MAX_SUBJECT_CHARS
            ),
            DraftError::BodyTooLarge => {
                write!(
                    f,
                    "the body is larger than {} bytes",
                    policy::MAX_BODY_BYTES
                )
            }
            DraftError::BodyControlCharacter => {
                f.write_str("the body contains a control character other than tab and line breaks")
            }
            DraftError::InvalidReply(what) => write!(f, "cannot thread the reply: {what}"),
            DraftError::Build => f.write_str("the message could not be built"),
        }
    }
}

impl std::error::Error for DraftError {}

/// Rejects any control character: CR, LF and NUL, which is the injection set, and every
/// other control character too, since a legitimate subject or address has none.
fn reject_control(field: &'static str, value: &str) -> Result<(), DraftError> {
    if value.chars().any(char::is_control) {
        Err(DraftError::ControlCharacter(field))
    } else {
        Ok(())
    }
}

fn is_domain_label(label: &str) -> bool {
    (1..=63).contains(&label.len())
        && label
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        && !label.starts_with('-')
        && !label.ends_with('-')
}

/// The strict address shape: ASCII, a dot-atom local part, and a domain of at least two
/// letters-digits-hyphen labels. This is narrower than RFC 5322 on purpose: no quoted local
/// parts, no address literals, no internationalised addresses, no single-label hosts.
fn is_strict_address(address: &str) -> bool {
    let Some((local, domain)) = address.split_once('@') else {
        return false;
    };
    address.len() <= 254
        && (1..=64).contains(&local.len())
        && local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~.".contains(&b))
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && domain.contains('.')
        && domain.split('.').all(is_domain_label)
}

fn parse_address(field: &'static str, text: &str) -> Result<Mailbox, DraftError> {
    reject_control(field, text)?;
    if !is_strict_address(text) {
        return Err(DraftError::InvalidAddress(field));
    }
    let address = Address::from_str(text).map_err(|_| DraftError::InvalidAddress(field))?;
    Ok(Mailbox::new(None, address))
}

/// The `Message-ID` shape accepted for copying into a header: `<` and `>` around printable
/// ASCII characters from the RFC 5322 atom set plus `.`, `@`, `[` and `]`.
fn is_message_id(text: &str) -> bool {
    let Some(inner) = text
        .strip_prefix('<')
        .and_then(|rest| rest.strip_suffix('>'))
    else {
        return false;
    };
    text.len() <= 255
        && !inner.is_empty()
        && inner
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-/=?^_`{|}~.@[]".contains(&b))
}

/// The `References` value for a reply: the parent's own references (those that are valid
/// message IDs, the most recent ones if there are too many) followed by the parent's ID.
fn reply_references(reply: &Reply) -> String {
    let mut ids: Vec<&str> = reply
        .references
        .as_deref()
        .unwrap_or_default()
        .split_whitespace()
        .filter(|candidate| is_message_id(candidate))
        .collect();
    // The parent's own ID takes the last slot.
    let keep = policy::MAX_REFERENCES.saturating_sub(1);
    let excess = ids.len().saturating_sub(keep);
    ids.drain(..excess);
    ids.push(&reply.message_id);
    ids.join(" ")
}

fn check_reply(reply: &Reply) -> Result<ResourceId, DraftError> {
    let thread = ResourceId::parse(&reply.thread_id)
        .map_err(|InvalidId| DraftError::InvalidReply("the thread ID is not valid"))?;
    if !is_message_id(&reply.message_id) {
        return Err(DraftError::InvalidReply(
            "the Message-ID of the original is not in a form that can be copied into a header",
        ));
    }
    Ok(thread)
}

/// The mail library will not build a message without a `From`, but the real sender is the
/// signed-in account, which only Gmail knows. [`build`] removes this placeholder again before
/// it formats the message, so it never leaves this module (`.invalid` is reserved and never
/// resolves, in case it ever did).
fn placeholder_sender() -> Result<Mailbox, DraftError> {
    let address = Address::new("sender", "example.invalid").map_err(|_| DraftError::Build)?;
    Ok(Mailbox::new(None, address))
}

/// Builds a draft, or says why it cannot.
///
/// Every address, the subject and the reply's headers are checked for control characters
/// (CR, LF and NUL included) before the mail library sees them. Addresses must be plain
/// addresses. The recipient count, the subject length and the body size are capped. Bcc
/// recipients stay in the message, so the user sees them in the draft. The `From` header is
/// left out: Gmail fills in the signed-in account.
///
/// # Errors
///
/// Returns the first rule the request breaks, see [`DraftError`].
// why: docs/decisions/0005-untrusted-email-content.md
pub fn build(request: &DraftRequest, reply: Option<&Reply>) -> Result<Draft, DraftError> {
    let total = request.to.len() + request.cc.len() + request.bcc.len();
    if total == 0 {
        return Err(DraftError::NoRecipient);
    }
    if total > policy::MAX_RECIPIENTS {
        return Err(DraftError::TooManyRecipients);
    }
    reject_control("subject", &request.subject)?;
    if request.subject.chars().count() > policy::MAX_SUBJECT_CHARS {
        return Err(DraftError::SubjectTooLong);
    }
    if request.body.len() > policy::MAX_BODY_BYTES {
        return Err(DraftError::BodyTooLarge);
    }
    if request
        .body
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\t' | '\n' | '\r'))
    {
        return Err(DraftError::BodyControlCharacter);
    }

    let mut builder = Message::builder()
        .from(placeholder_sender()?)
        .subject(request.subject.as_str());
    for address in &request.to {
        builder = builder.to(parse_address("to", address)?);
    }
    for address in &request.cc {
        builder = builder.cc(parse_address("cc", address)?);
    }
    for address in &request.bcc {
        builder = builder.bcc(parse_address("bcc", address)?);
    }
    // The library drops Bcc by default; a draft must keep it, so the user can see it.
    builder = builder.keep_bcc();

    let thread_id = match reply {
        Some(reply) => {
            let thread = check_reply(reply)?;
            builder = builder
                .in_reply_to(reply.message_id.clone())
                .references(reply_references(reply));
            Some(thread)
        }
        None => None,
    };

    let mut message = builder
        .singlepart(SinglePart::plain(request.body.clone()))
        .map_err(|_| DraftError::Build)?;
    message.headers_mut().remove::<header::From>();
    Ok(Draft {
        raw: message.formatted(),
        thread_id,
    })
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    fn request() -> DraftRequest {
        DraftRequest {
            to: vec!["alice@example.test".to_owned()],
            subject: "Lunch on Friday".to_owned(),
            body: "Does noon work?\n".to_owned(),
            ..DraftRequest::default()
        }
    }

    fn text(draft: &Draft) -> String {
        String::from_utf8(draft.raw.clone()).unwrap()
    }

    /// The header block of a message, with folded lines joined, as (name, value) pairs.
    fn headers(raw: &str) -> Vec<(String, String)> {
        let head = raw.split("\r\n\r\n").next().unwrap_or_default();
        let mut out: Vec<(String, String)> = Vec::new();
        for line in head.split("\r\n") {
            if line.starts_with(' ') || line.starts_with('\t') {
                if let Some(last) = out.last_mut() {
                    last.1.push_str(line);
                }
            } else if let Some((name, value)) = line.split_once(':') {
                out.push((name.to_owned(), value.trim().to_owned()));
            } else {
                out.push((line.to_owned(), String::new()));
            }
        }
        out
    }

    const EXPECTED_HEADERS: &[&str] = &[
        "To",
        "Cc",
        "Bcc",
        "Subject",
        "In-Reply-To",
        "References",
        "MIME-Version",
        "Date",
        "Content-Type",
        "Content-Transfer-Encoding",
    ];

    fn assert_only_expected_headers(raw: &str) {
        for (name, _) in headers(raw) {
            assert!(
                EXPECTED_HEADERS.contains(&name.as_str()),
                "unexpected header {name:?} in:\n{raw}"
            );
        }
    }

    #[test]
    fn a_plain_draft_has_the_expected_headers_and_no_from() {
        let draft = build(&request(), None).unwrap();
        let raw = text(&draft);
        let names: Vec<String> = headers(&raw).into_iter().map(|(name, _)| name).collect();
        assert!(names.contains(&"To".to_owned()));
        assert!(names.contains(&"Subject".to_owned()));
        assert!(
            !names.contains(&"From".to_owned()),
            "the placeholder sender must not leak"
        );
        assert!(!raw.contains("example.invalid"));
        assert_only_expected_headers(&raw);
        assert!(raw.contains("Does noon work?"));
        assert_eq!(draft.thread_id, None);
    }

    #[test]
    fn bcc_recipients_are_kept_in_the_draft() {
        let mut req = request();
        req.bcc = vec!["hidden@example.test".to_owned()];
        let raw = text(&build(&req, None).unwrap());
        assert!(raw.contains("Bcc: hidden@example.test"), "{raw}");
    }

    #[test]
    fn non_ascii_text_is_encoded_for_transport() {
        let mut req = request();
        req.subject = "Grüße ✓".to_owned();
        req.body = "Schöne Grüße\n".to_owned();
        let raw = text(&build(&req, None).unwrap());
        assert!(raw.is_ascii(), "{raw}");
        assert!(raw.contains("charset=utf-8"));
    }

    // ---- header injection ----------------------------------------------------------

    /// A model steered by a hostile email tries to add a Bcc header through every field.
    #[test]
    fn crlf_in_any_header_field_is_rejected_before_the_mail_library() {
        let injection = "x\r\nBcc: attacker@example.test";
        for bad in [
            injection,
            "x\nBcc: attacker@example.test",
            "x\rBcc: a",
            "x\0y",
            "x\u{85}y",
        ] {
            let mut req = request();
            req.subject = bad.to_owned();
            assert_eq!(
                build(&req, None),
                Err(DraftError::ControlCharacter("subject")),
                "{bad:?}"
            );

            for (field, set) in [("to", 0), ("cc", 1), ("bcc", 2)] {
                let mut req = request();
                let value = format!("a@example.test{bad}");
                match set {
                    0 => req.to = vec![value],
                    1 => req.cc = vec![value],
                    _ => req.bcc = vec![value],
                }
                assert_eq!(
                    build(&req, None),
                    Err(DraftError::ControlCharacter(field)),
                    "{field} {bad:?}"
                );
            }
        }
    }

    #[test]
    fn crlf_in_the_reply_headers_is_rejected() {
        for message_id in ["<a@b>\r\nBcc: attacker@example.test", "<a@b\n>", "<a@b>\0"] {
            let reply = Reply {
                thread_id: "abc".to_owned(),
                message_id: message_id.to_owned(),
                references: None,
            };
            assert!(
                matches!(
                    build(&request(), Some(&reply)),
                    Err(DraftError::InvalidReply(_))
                ),
                "{message_id:?}"
            );
        }
        // Bad tokens in References are dropped, never copied.
        let reply = Reply {
            thread_id: "abc".to_owned(),
            message_id: "<c@d>".to_owned(),
            references: Some("<a@b> bad\r\nBcc:x <e@f>".to_owned()),
        };
        assert_eq!(reply_references(&reply), "<a@b> <e@f> <c@d>");
    }

    #[test]
    fn a_thread_id_cannot_carry_a_path() {
        for thread_id in ["../other", "a/b", "a b", "", "a\n"] {
            let reply = Reply {
                thread_id: thread_id.to_owned(),
                message_id: "<a@b>".to_owned(),
                references: None,
            };
            assert!(
                matches!(
                    build(&request(), Some(&reply)),
                    Err(DraftError::InvalidReply(_))
                ),
                "{thread_id:?}"
            );
        }
    }

    // ---- addresses -----------------------------------------------------------------

    #[test]
    fn only_plain_ascii_addresses_are_accepted() {
        for ok in [
            "alice@example.test",
            "a.b+tag@sub.example.test",
            "o'brien@example.test",
            "x_y-z@ex-ample.test",
        ] {
            assert!(is_strict_address(ok), "{ok}");
            assert!(parse_address("to", ok).is_ok(), "{ok}");
        }
        for bad in [
            "Alice <alice@example.test>",
            "<alice@example.test>",
            "\"a b\"@example.test",
            "alice@localhost",
            "alice@[127.0.0.1]",
            "alice@exämple.test",
            "ü@example.test",
            "a@b@example.test",
            "a b@example.test",
            ".a@example.test",
            "a.@example.test",
            "a..b@example.test",
            "a@-example.test",
            "a@example..test",
            "a@example.test,b@example.test",
            "a@example.test;b@example.test",
            "",
            "@example.test",
            "a@",
        ] {
            assert!(parse_address("to", bad).is_err(), "{bad:?}");
        }
    }

    // ---- limits --------------------------------------------------------------------

    #[test]
    fn caps_on_recipients_subject_and_body_hold() {
        let mut req = request();
        req.to = vec![];
        assert_eq!(build(&req, None), Err(DraftError::NoRecipient));

        let mut req = request();
        req.to = (0..=policy::MAX_RECIPIENTS)
            .map(|n| format!("user{n}@example.test"))
            .collect();
        assert_eq!(build(&req, None), Err(DraftError::TooManyRecipients));

        let mut req = request();
        req.subject = "s".repeat(policy::MAX_SUBJECT_CHARS + 1);
        assert_eq!(build(&req, None), Err(DraftError::SubjectTooLong));

        let mut req = request();
        req.body = "b".repeat(policy::MAX_BODY_BYTES + 1);
        assert_eq!(build(&req, None), Err(DraftError::BodyTooLarge));

        let mut req = request();
        req.body = "a\0b".to_owned();
        assert_eq!(build(&req, None), Err(DraftError::BodyControlCharacter));

        let mut req = request();
        req.body = "tab\there\r\nline\n".to_owned();
        assert!(build(&req, None).is_ok());
    }

    // ---- replies -------------------------------------------------------------------

    #[test]
    fn a_reply_threads_with_in_reply_to_and_references() {
        let reply = Reply {
            thread_id: "18c3a5b2f1e4d7a0".to_owned(),
            message_id: "<third@mail.example.test>".to_owned(),
            references: Some("<first@mail.example.test> <second@mail.example.test>".to_owned()),
        };
        let draft = build(&request(), Some(&reply)).unwrap();
        let raw = text(&draft);
        let headers = headers(&raw);
        let value = |name: &str| {
            headers
                .iter()
                .find(|(n, _)| n == name)
                .map(|(_, v)| v.clone())
        };
        assert_eq!(
            value("In-Reply-To").as_deref(),
            Some("<third@mail.example.test>")
        );
        assert_eq!(
            value("References").as_deref(),
            Some("<first@mail.example.test> <second@mail.example.test> <third@mail.example.test>")
        );
        assert_eq!(
            draft.thread_id.map(|id| id.to_string()).as_deref(),
            Some("18c3a5b2f1e4d7a0")
        );
        assert_only_expected_headers(&raw);
    }

    #[test]
    fn a_long_references_chain_keeps_the_most_recent_ids() {
        let references: Vec<String> = (0..50).map(|n| format!("<m{n}@x.test>")).collect();
        let reply = Reply {
            thread_id: "abc".to_owned(),
            message_id: "<parent@x.test>".to_owned(),
            references: Some(references.join(" ")),
        };
        let joined = reply_references(&reply);
        let ids: Vec<&str> = joined.split(' ').collect();
        assert_eq!(ids.len(), policy::MAX_REFERENCES);
        assert_eq!(ids.last(), Some(&"<parent@x.test>"));
        assert_eq!(ids.first(), Some(&"<m31@x.test>"));
    }

    // ---- no injection, whatever the input ------------------------------------------

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(128))]

        /// Whatever a model sends, either the draft is refused or its headers are exactly
        /// the expected set: no field can add a header, a recipient or a body.
        #[test]
        fn arbitrary_fields_never_inject_headers(
            to in any::<String>(),
            cc in any::<String>(),
            subject in any::<String>(),
            body in any::<String>(),
            message_id in any::<String>(),
            references in any::<String>(),
        ) {
            let req = DraftRequest {
                to: vec![to, "ok@example.test".to_owned()],
                cc: vec![cc],
                bcc: vec![],
                subject,
                body,
            };
            let reply = Reply {
                thread_id: "abc".to_owned(),
                message_id,
                references: Some(references),
            };
            for reply in [None, Some(&reply)] {
                if let Ok(draft) = build(&req, reply) {
                    let raw = String::from_utf8(draft.raw).unwrap();
                    for (name, _) in headers(&raw) {
                        prop_assert!(EXPECTED_HEADERS.contains(&name.as_str()), "header {name:?}");
                    }
                }
            }
        }

        #[test]
        fn arbitrary_addresses_never_panic(address in any::<String>()) {
            let _ = parse_address("to", &address);
            let _ = is_message_id(&address);
        }
    }
}
