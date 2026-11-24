# 0015. Sign-in: authorization code with PKCE, a loopback listener, a printed consent address

- Status: Accepted (2026-11-24)
- Implementation: In place (phase 2): `src/auth.rs` (flow, listener, OAuth HTTP adapter), the scope rule in `policy::check_grant` and `store::Credentials::new`, and `log::consent_text`. Pinned by `tests/auth_flow.rs` (the whole flow against a fake Google and a fake store), `tests/auth_redirect.rs` (the listener on real loopback sockets), `tests/auth_client_file.rs`, `tests/store_policy.rs`, `tests/consent_url.rs` and the scans in `tests/static_policy.rs`. Not yet run against Google: the maintainer's first `gmail-mcp auth` is that check.

## Context

`gmail-mcp auth` must obtain a refresh token for the read-only scope without writing a secret to disk, without a second network path (0003), and without trusting what a browser or another program on the machine sends. The user brings their own Google "Desktop app" OAuth client (0006). Alternatives weighed:

- Google's device flow needs no listener, but its documented scope list (OpenID Connect, Google Sign-In, parts of the Drive and YouTube APIs) does not include Gmail (checked 2026-11-24).
- Copying a code from the consent page (out-of-band flow): Google deprecated it because of phishing and app impersonation risks.
- A library that runs the whole flow, such as `yup-oauth2`: it brings its own HTTP stack and an async runtime into the path that holds the credentials (0004, 0008).
- Starting the browser from the program: needs a process API, which the source scan forbids everywhere (0003), since a started process can run any network tool and bypass the guard.

What is left is what Google documents for desktop apps: the authorization-code flow with PKCE and a redirect to a loopback port.

## Decision

- **Flow.** Authorization code with PKCE (S256) and a random `state`, through the `oauth2` crate. One scope, `gmail.readonly`; `access_type=offline` and `prompt=consent`, so a refresh token is issued even if the client was approved before.
- **The user opens the consent address.** The program prints it through `log::consent_text`, the one log message that is not a static string. It shows an `https` address of the consent host with only the parameters the sign-in sets and no fragment. That narrows what it can print and makes it no use for a token, a subject or a path; the parameter values are not inspected, so it is a guard against careless use and not a proof.
- **Google's endpoints are constants** in `policy.rs`. The client secret file names its own endpoints and redirect addresses; they are ignored, and only a file with an `installed` section is read.
- **The listener** binds `127.0.0.1` on a port the system picks. Other programs on the machine can still connect, so a request counts only if it is a `GET` of `/` with this sign-in's `state` (constant-time compare), either a code or an error, and no repeated parameter. Anything else gets a 400 and the wait goes on; a redirect that says the user declined, with the right `state`, ends it. Connections are served side by side, 5 seconds each, 16 at most, a new one pushing the oldest out, so silent connections cannot keep the browser's redirect waiting. Only the first request line counts, so the cookies a browser sends to `127.0.0.1` cannot make a genuine redirect too long. The wait is 5 minutes, and the listener is dropped when the code arrives. The reply page loads nothing, sends no referrer, is not cached, and does not claim the sign-in worked, since the exchange and the scope check come after it.
- **The code exchange goes through the guard**: `auth::Guarded` implements the `oauth2` crate's HTTP trait by calling the egress function. Client credentials go in the request body, as Google documents.
- **The grant is checked before anything is stored.** `policy::check_grant` requires exactly the read-only scope; a response without a `scope` field is refused because it cannot be checked. Then a refresh token must be present, and only then do `Credentials::new` and the store run. A refused sign-in leaves stored credentials as they were. Nothing revokes a refused grant (a revoke call would need a route, which widens egress), so the error tells the user to remove the app's access in their Google account.
- **The store is read first**, so a platform without one fails before the user is asked to do anything. A damaged item is replaced only by a sign-in that brings its own client file.
- **Errors are static.** The `oauth2` crate's parse error holds the response body, which can hold tokens, so errors keep only a kind. `auth` never deletes the client secret file; it tells the user to (0006).

## Consequences

- The user copies a long address into a browser. In return, no code in the crate starts a process.
- Other programs on the machine cannot complete the sign-in or end it early, since they do not know the `state`. One that floods the port faster than it is served can still make it time out; the user runs it again. A program that can read the terminal sees the `state`; that is the same user's account and out of scope (SECURITY.md).
- The authorization code sits in the browser's address bar for a moment. It works once, and only with the PKCE verifier, which only this process and Google see.
- Secrets sit in ordinary heap memory while `auth` runs and are not wiped afterwards.
- If Google moves the consent or token address, a code edit follows; the guard fails closed meanwhile.

## What would change this decision

- Google allowing Gmail scopes in the device flow. The listener, the only socket besides the egress guard (0009), could then go.
- A wish to revoke grants from the program: it needs its own record and an allowlist route.

## References

- Decision records: [0003](0003-single-egress-allowlist.md), [0006](0006-credentials-in-os-credential-store.md), [0009](0009-stdio-only-transport.md), [0014](0014-read-only-no-composing.md)
- Google: [OAuth 2.0 for iOS and desktop apps](https://developers.google.com/identity/protocols/oauth2/native-app), [for TV and limited-input device apps](https://developers.google.com/identity/protocols/oauth2/limited-input-device) (allowed scopes), [OOB flow migration](https://developers.google.com/identity/protocols/oauth2/resources/oob-migration)
- Repo files: [src/auth.rs](../../src/auth.rs), [src/policy.rs](../../src/policy.rs), [src/store.rs](../../src/store.rs), [src/log.rs](../../src/log.rs)
