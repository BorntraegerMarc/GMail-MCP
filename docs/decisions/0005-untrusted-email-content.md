# 0005. Untrusted email content handling

- Status: Accepted (2026-11-23)
- Implementation: Partly in place (phase 1). `src/text.rs` has the sanitizer, the nonce wrapper with its shared character budget, truncation and the bounded HTML conversion; `src/draft.rs` has the header-bound checks, strict addresses, the caps, the threading headers and Bcc handling. Both have unit and property tests. Planned: `src/tools.rs`, which applies them and exposes `create_draft`, and the one extra Gmail read for a threaded draft, in phase 3 (Gmail client and MCP tools).

## Context

Anyone who can email the user controls much of what a read tool returns: the subject, sender and body, among other fields. That text lands in a model's context, where the model may follow it as if the user had written it. This is the "Prompt injection via email" row of the README's security table. The server has to return the text to be useful, so the levers here are what reaches the model and how that text is labeled.

The other direction matters too. With `--allow-drafts`, `create_draft` takes fields from a model that may have just read a hostile email, and those fields end up in mail headers. SECURITY.md lists header injection in drafts as in scope.

## Decision

**Reading side**: email content is untrusted data on its way to the model.

- Wrap every email-derived field, whichever header or part it comes from (for example subject, sender, date, snippet, body, attachment filenames), not only bodies. The delimiter tags carry a per-call random nonce, so an attacker cannot write a matching closing tag in advance, and look-alike tags inside the content are neutralized by rewriting the tag name wherever it occurs, in any letter case, so brackets and spacing do not matter.
- Generate the per-call nonce with `oauth2::CsrfToken::new_random`, which avoids a separate randomness dependency. An OAuth type used for a non-OAuth purpose is deliberate, so replacing it with a randomness crate needs a superseding record (dependency policy: 0004-dependency-policy-and-libraries.md).
- Start each result with a one-line notice that the content is data and that instructions inside it must not be followed.
- Strip invisible Unicode (the tag block U+E0000 to U+E007F, zero-width characters, bidi overrides and isolates, variation selectors and the other default-ignorable code points) and control characters (C0, DEL and C1) other than tab and line breaks, so text a person cannot see is less likely to reach the model. Stripping comes first and neutralizing second, so a tag name split by an invisible character cannot be rejoined afterwards.
- Prefer text/plain and convert HTML-only mail with the `html2text` crate. Bound the HTML first: at most 256 KiB and 512 levels of nesting, cut with the truncation marker, because the converter's run time grows with the square of the nesting depth.
- Cap output at about 30k characters for a whole tool call, shared by all its fields, and end each cut with a visible `[truncated]` marker. Short fields have a smaller cap of their own, so one hostile subject cannot use up the budget.
- Return attachments as metadata only; never download them.

**Writing side**: the model's draft fields are untrusted input on their way to mail headers.

- Reject CR, LF and NUL, and every other control character, in every header-bound field before `lettre` sees it. This is deliberate defense in depth, so it must not be removed as a duplicate: `lettre` would encode such a value rather than refuse it.
- Parse addresses strictly (plain ASCII `local@domain.tld` addresses only: no display names, quoting, address literals or internationalized addresses), cap the recipient count, the subject and the body size, and keep Bcc with `keep_bcc()`: `lettre` strips it by default and a draft must keep it.
- For a reply, read the last message's Message-ID, References and Subject once so Gmail threads the draft. These values come from a received email, so they get the same check as every other header-bound field. A References entry that is not a valid message ID is dropped, and at most 20 entries are kept.
- `lettre` will not build a message without a From, and the real sender is the signed-in account. The builder uses a placeholder sender and removes it again before formatting, so no sender is claimed; Gmail is expected to fill in the account's address on a draft that has none. That expectation is unverified until the first live draft.

## Consequences

- Wrapping reduces prompt-injection risk and does not eliminate it: the delimiters and the notice inform the model but cannot make it ignore injected text.
- A model that reads a hostile email while holding other tools (web fetch, other MCP servers) can still be steered into leaking data through those tools. This server cannot prevent that; it can only limit its own reach (0002-two-layer-permission-model.md, 0003-single-egress-allowlist.md).
- With `--allow-drafts`, a steered model can still write a misleading draft, for example one addressed to an attacker, so drafts must be read before they are sent. The server never sends a draft; 0002-two-layer-permission-model.md says what that rests on.
- Text a person cannot see can still reach the model: the stripping is a deny-list of known hiding places, the HTML conversion is not a sanitizer (text hidden with styling such as `display: none` can remain), and the text/plain part is written by the sender and need not match the HTML part a mail client shows. Stripping also changes legitimate text, such as a zero-width non-joiner in Persian or the emoji presentation selector.
- `html2text` parses attacker-controlled HTML (library choice: 0004-dependency-policy-and-libraries.md). It runs only on HTML-only mail and its output is treated as data. It is written in Rust, which lowers memory-safety risk but does not remove it.
- The converter's run time grows with the square of the nesting depth (measured on 2026-11-24 with `html2text` 0.17.4: 50,000 nested `div` elements took about 3 seconds and 500,000 took about 5.5 minutes; it did not overflow the stack). The size and depth bound avoids that for ordinary attacks. The depth check estimates the parser's nesting and does not reproduce it, so crafted markup that the real parser nests deeper than the estimate can still cost a few seconds of CPU, bounded by the size cap.
- Costs: one extra Gmail read for each threaded draft; stripping and the cap change what the model sees, legitimate text included; the wrapper and sanitizer are hand-written security code to maintain and test.

## What would change this decision

- New injection techniques observed in practice that get past the nonce delimiters, the tag neutralizing or the stripping.
- A different wrapping format recommended by the vendor of the model that reads the output.
- `html2text` proving too heavy a dependency. The fallback is a small hand-written stripper.

## References

- Decision records: [0002-two-layer-permission-model.md](0002-two-layer-permission-model.md) (what the server can do at all), [0003-single-egress-allowlist.md](0003-single-egress-allowlist.md) (where it can send data), [0004-dependency-policy-and-libraries.md](0004-dependency-policy-and-libraries.md) (dependency policy and the chosen libraries)
- Repo files: [README.md](../../README.md) (security table, honest limits), [SECURITY.md](../../SECURITY.md) (what counts as a vulnerability)

