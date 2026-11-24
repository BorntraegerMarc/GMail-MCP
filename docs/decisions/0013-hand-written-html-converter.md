# 0013. HTML-only mail is converted by a small hand-written converter, not `html2text`

- Status: Accepted (2026-11-24)
- Implementation: In place (phase 1): `html_to_text` in `src/text.rs`, tested by unit tests, tests of hostile structure (cost must follow the input, not its shape) and property tests. `html2text` is not a dependency.

## Context

0004 and 0005 chose the `html2text` crate to turn HTML-only mail into text, and named "a small hand-written stripper" as the fallback if it proved too heavy. An independent review and measurements on 2026-11-24, with `html2text` 0.17.4, found that it is not safe to point at hostile input:

- It panics on tiny inputs. About 40 bytes are enough: an `ol` with a huge `start`, a `td` with a huge `colspan` (arithmetic overflow), and a table with a `colspan` and `rowspan` together (an `unwrap` on `None`). Release builds set `panic = "abort"` and `overflow-checks`, so one hostile email would stop the server every time it was read. Fuzzing for 40 seconds hit those sites twice, so more are likely.
- Its run time grows with the square of the nesting depth: 50,000 nested `div` elements took about 3 seconds and 500,000 took about 5.5 minutes.
- Deeply nested quotes or lists multiply the output: 250 KB of input produced 120 MB of output and 600 MB of memory at a nesting depth of 500.

A size and depth check in front of it was tried and did not hold. It had to guess how the HTML parser nests the markup, and markup such as `<p a==">` or `<svg><title>` is read differently by the parser, which got 3 to 5 seconds of CPU per email past it.

## Decision

`html_to_text` in `src/text.rs` converts HTML-only mail. It makes one pass and builds no tree:

- It tokenizes tags, attributes, comments and raw-text elements as the HTML tokenizer does, and writes text, paragraph and list structure, link targets after the link text, image descriptions and preformatted text. Scripts, styles, comments, titles and templates are dropped, and a short list of character references is decoded.
- It stops at an output limit, so the output cannot grow beyond it however the input is built. Nesting depth costs nothing because there is nothing to nest. Its cost grows with the length of the input and nothing else.
- It cannot panic: no `unwrap` or `expect`, no recursion, and input-derived positions are only used through `get`.
- `html2text` and the crates only it needed leave the dependency list.
- Rejected: keeping `html2text` behind `catch_unwind`. That needs `panic = "unwind"`, which gives up abort on panic for the whole program (the `[profile.release]` comment in `Cargo.toml` says why), and it does not fix the time and memory problems.
- Rejected: using `html5ever` directly. It is a new direct dependency, and it still builds a tree whose depth and size would need bounding.

## Consequences

- Less fidelity than `html2text`: no table layout (cells are joined with spaces and rows get their own line), no list numbering (every item starts with `* `), no indentation for nesting, and only common character references are decoded (the others stay as written, for example `&eacute;`). The text of a typical marketing email reads well.
- The limits of 0005 stay: text hidden with styling such as `display: none` is kept, and the converter and a mail client can read a deliberately malformed page differently.
- This is hand-written code that parses attacker-controlled input. The dependency policy accepts that kind of code where a library has been shown unfit (0004), and it is covered by unit, structural-cost and property tests.
- The tree gets smaller: 18 crates, mostly the HTML parser and its tree, are out.

## What would change this decision

- A maintained HTML-to-text crate that survives fuzzing on hostile input and has a bounded cost, checked before adoption.
- Real mail that the converter renders badly enough to matter. The answer is to improve the converter first.

## References

- Decision records: [0004-dependency-policy-and-libraries.md](0004-dependency-policy-and-libraries.md), [0005-untrusted-email-content.md](0005-untrusted-email-content.md)
- Repo files: [src/text.rs](../../src/text.rs), [Cargo.toml](../../Cargo.toml) (the release profile)
