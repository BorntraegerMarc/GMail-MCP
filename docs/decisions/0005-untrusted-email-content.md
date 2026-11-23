# 0005. Untrusted email content handling

- Status: Accepted (2026-11-23)
- Implementation: Scaffold only today: no wrapping, sanitizing or draft code exists. Planned: `src/text.rs` and `src/draft.rs` in phase 1 (policy core); `src/tools.rs`, which applies them and exposes `create_draft`, in phase 3 (Gmail client and MCP tools).

## Context

Anyone who can email the user controls much of what a read tool returns: the subject, sender and body, among other fields. That text lands in a model's context, where the model may follow it as if the user had written it. This is the "Prompt injection via email" row of the README's security table. The server has to return the text to be useful, so the levers here are what reaches the model and how that text is labeled.

The other direction matters too. With `--allow-drafts`, `create_draft` takes fields from a model that may have just read a hostile email, and those fields end up in mail headers. SECURITY.md lists header injection in drafts as in scope.

## Decision

**Reading side**: email content is untrusted data on its way to the model.

- Wrap every email-derived field, whichever header or part it comes from (for example subject, sender, date, snippet, body, attachment filenames), not only bodies. The delimiter tags carry a per-call random nonce, so an attacker cannot write a matching closing tag in advance, and look-alike tags inside the content are neutralized.
- Generate the per-call nonce with `oauth2::CsrfToken::new_random`, which avoids a separate randomness dependency. An OAuth type used for a non-OAuth purpose is deliberate, so replacing it with a randomness crate needs a superseding record (dependency policy: 0004-dependency-policy-and-libraries.md).
- Start each result with a one-line notice that the content is data and that instructions inside it must not be followed.
- Strip invisible Unicode (the tag block U+E0000 to U+E007F, zero-width characters, bidi overrides) and C0 control characters other than tab and line breaks, so text a person cannot see is less likely to reach the model.
- Prefer text/plain and convert HTML-only mail with the `html2text` crate.
- Cap output at about 30k characters and end it with a visible `[truncated]` marker.
- Return attachments as metadata only; never download them.

**Writing side**: the model's draft fields are untrusted input on their way to mail headers.

- Reject CR, LF and NUL in every header-bound field before `lettre` sees it. This is deliberate defense in depth, so it must not be removed as a duplicate.
- Parse addresses strictly, cap the recipient count and the body size, and keep Bcc with `keep_bcc()`: `lettre` strips it by default and a draft must keep it.
- For a reply, read the last message's Message-ID, References and Subject once so Gmail threads the draft. These values come from a received email, so they get the same check as every other header-bound field.

## Consequences

- Wrapping reduces prompt-injection risk and does not eliminate it: the delimiters and the notice inform the model but cannot make it ignore injected text.
- A model that reads a hostile email while holding other tools (web fetch, other MCP servers) can still be steered into leaking data through those tools. This server cannot prevent that; it can only limit its own reach (0002-two-layer-permission-model.md, 0003-single-egress-allowlist.md).
- With `--allow-drafts`, a steered model can still write a misleading draft, for example one addressed to an attacker, so drafts must be read before they are sent. The server never sends a draft; 0002-two-layer-permission-model.md says what that rests on.
- Text a person cannot see can still reach the model: the stripping is a deny-list of known hiding places, the HTML conversion is not a sanitizer (text hidden with styling such as `display: none` can remain), and the text/plain part is written by the sender and need not match the HTML part a mail client shows.
- `html2text` parses attacker-controlled HTML (library choice: 0004-dependency-policy-and-libraries.md). It runs only on HTML-only mail and its output is treated as data. It is written in Rust, which lowers memory-safety risk but does not remove it.
- Costs: one extra Gmail read for each threaded draft; stripping and the cap change what the model sees, legitimate text included; the wrapper and sanitizer are hand-written security code to maintain and test.

## What would change this decision

- New injection techniques observed in practice that get past the nonce delimiters, the tag neutralizing or the stripping.
- A different wrapping format recommended by the vendor of the model that reads the output.
- `html2text` proving too heavy a dependency. The fallback is a small hand-written stripper.

## References

- Decision records: [0002-two-layer-permission-model.md](0002-two-layer-permission-model.md) (what the server can do at all), [0003-single-egress-allowlist.md](0003-single-egress-allowlist.md) (where it can send data), [0004-dependency-policy-and-libraries.md](0004-dependency-policy-and-libraries.md) (dependency policy and the chosen libraries)
- Repo files: [README.md](../../README.md) (security table, honest limits), [SECURITY.md](../../SECURITY.md) (what counts as a vulnerability)

