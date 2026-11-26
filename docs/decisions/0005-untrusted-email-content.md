# 0005. Untrusted email content handling

- Status: Accepted (2026-11-23)
- Implementation: Partly in place (phase 1). `src/text.rs` has the sanitizer, the nonce wrapper with its shared character budget, truncation and the HTML-to-text converter (0013), with unit, structural-cost and property tests. In place (phase 3a): `src/tools.rs` applies them to every tool result, `src/gmail.rs` reads Gmail's answers within fixed limits (MIME depth 8, 200 parts, 1 MiB of text per message) and `tests/gmail_tools.rs` pins, with hostile fixtures, that no mail-derived text leaves a wrapper and that no look-alike delimiter survives inside one.

## Context

Anyone who can email the user controls much of what a read tool returns: the subject, sender and body, among other fields. That text lands in a model's context, where the model may follow it as if the user had written it. This is the "Prompt injection via email" row of the README's security table. The server has to return the text to be useful, so the levers here are what reaches the model and how that text is labeled.

## Decision

Email content is untrusted data on its way to the model.

- Wrap every email-derived field, whichever header or part it comes from (for example subject, sender, date, snippet, body, attachment filenames), not only bodies. The delimiter tags carry a per-call random nonce, so an attacker cannot write a matching closing tag in advance, and look-alike tags inside the content are neutralized by rewriting the tag name wherever it occurs, in any letter case, so brackets and spacing do not matter.
- Generate the per-call nonce with `oauth2::CsrfToken::new_random`, which avoids a separate randomness dependency. An OAuth type used for a non-OAuth purpose is deliberate, so replacing it with a randomness crate needs a superseding record (dependency policy: 0004-dependency-policy-and-libraries.md).
- Start each result with a one-line notice that the content is data and that instructions inside it must not be followed.
- Strip invisible Unicode (the tag block U+E0000 to U+E007F, zero-width characters, bidi overrides and isolates, variation selectors and the other default-ignorable code points) and control characters (C0, DEL and C1) other than tab and line breaks, so text a person cannot see is less likely to reach the model. Every kind of line break (CR LF, a lone CR, U+2028, U+2029) becomes one `\n`. Stripping comes first and neutralizing second, so a tag name split by an invisible character cannot be rejoined afterwards.
- Prefer text/plain, and convert HTML-only mail with the hand-written converter (0013). It reads the HTML in one pass, cannot panic, and its cost follows the length of the input and nothing else; the input is cut at 1 MiB.
- Cap output at about 30k characters for a whole tool call, delimiters and markers included, shared by all its fields, and end each cut with a visible `[truncated]` marker. Short fields have a smaller cap of their own, so one hostile subject cannot use up the budget. Once the budget is spent the wrapper returns nothing, and the tool says, outside the delimiters, that its output was cut.
- Return attachments as metadata only; never download them.

The server composes no mail (0014-read-only-no-composing.md), so no text chosen by a model reaches a mail header. This record once also covered drafts (checks for control characters before the mail library, strict addresses, caps, Bcc and threading headers); those rules went with the drafts.

## Consequences

- Wrapping reduces prompt-injection risk and does not eliminate it: the delimiters and the notice inform the model but cannot make it ignore injected text.
- A model that reads a hostile email while holding other tools (file writing, web fetch, other MCP servers) can still be steered into misusing them: writing a misleading suggested reply to a file, or leaking what it read through a URL. This server cannot prevent that; it can only limit its own reach (0014-read-only-no-composing.md, 0003-single-egress-allowlist.md). A suggested reply has to be read before it is pasted into a mail.
- Text a person cannot see can still reach the model: the stripping is a deny-list of known hiding places, and some survive (U+2800 BRAILLE PATTERN BLANK, U+FFFC, U+1D159, noncharacters and private-use characters, and format characters that render as a visible mark). The HTML conversion is not a sanitizer: text hidden with styling such as `display: none` stays, and the text/plain part is written by the sender and need not match the HTML part a mail client shows. Stripping also changes legitimate text, such as a zero-width non-joiner in Persian or the emoji presentation selector.
- The converter and a mail client can read a deliberately malformed page differently. That affects what the model sees, not what the server does.
- Costs: stripping and the cap change what the model sees, legitimate text included; the wrapper, the sanitizer and the converter are hand-written security code to maintain and test.

## What would change this decision

- New injection techniques observed in practice that get past the nonce delimiters, the tag neutralizing or the stripping.
- A different wrapping format recommended by the vendor of the model that reads the output.

## References

- Decision records: [0003-single-egress-allowlist.md](0003-single-egress-allowlist.md) (where the server can send data), [0004-dependency-policy-and-libraries.md](0004-dependency-policy-and-libraries.md) (dependency policy and the chosen libraries), [0013-hand-written-html-converter.md](0013-hand-written-html-converter.md), [0014-read-only-no-composing.md](0014-read-only-no-composing.md) (what the server can do at all)
- Repo files: [README.md](../../README.md) (security table, honest limits), [SECURITY.md](../../SECURITY.md) (what counts as a vulnerability)
