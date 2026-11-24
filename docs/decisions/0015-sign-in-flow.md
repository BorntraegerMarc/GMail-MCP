# 0015. Sign-in: authorization code with PKCE, a loopback listener, a printed consent address

- Status: Accepted (2026-11-24)
- Implementation: In place (phase 2). `src/auth.rs` holds the flow, the listener and the OAuth HTTP adapter; the scope rule is `policy::check_grant` and `store::Credentials::new`; `log::consent_text` is the one non-static log message. `tests/auth_redirect.rs` (the listener, with real loopback sockets), `tests/auth_flow.rs` (the whole flow against a fake Google and a fake store), `tests/auth_client_file.rs`, `tests/store_policy.rs` and `tests/consent_url.rs` pin it, and `tests/static_policy.rs` pins the listener's address and that it never dials out. Nobody has run it against Google yet: the maintainer's first `gmail-mcp auth` is the live check.

## Context

`gmail-mcp auth` has to obtain a refresh token for the read-only scope from Google and keep it in the credential store (0006), without writing a secret to disk, without a second network path (0003) and without trusting what a browser or another program on the machine sends to it. The user brings their own Google OAuth client (0006), a "Desktop app" client.

Alternatives weighed:

- Google's device flow (no listener at all). Google's documentation for it lists the scopes it allows: OpenID Connect and Google Sign-In, and parts of the Drive and YouTube APIs. Gmail is not among them (checked 2026-11-24), so it cannot ask for `gmail.readonly`.
- Copying a code from the consent page (the out-of-band flow). Google deprecated it because of phishing and app impersonation risks.
- A library that runs the whole flow, such as `yup-oauth2`. It brings its own HTTP stack and an async runtime into the path that holds the credentials (0004, 0008).
- Starting the browser from the program. That needs a process API, which the source scan forbids everywhere (0003): a started process can run any network tool and bypass the guard.

What is left is what Google documents for desktop apps: the authorization-code flow with PKCE and a redirect to a port on the loopback address.

## Decision

- **Flow.** Authorization code with PKCE (S256) and a random `state`, through the `oauth2` crate. The request has one scope, `gmail.readonly`, and `access_type=offline` with `prompt=consent`, so that Google issues a refresh token even if the client was approved before.
- **The user opens the consent address.** The program shows it and starts no browser. It goes through `log::consent_text`, the one log message that is not a static string. The function shows an `https` address of the consent host, with only the parameters the sign-in sets and no fragment, and nothing else. That narrows what it can print to the consent page and makes it no use for a token, a subject or a path, but the parameter values are not inspected, so it is a guard against careless use and not a proof.
- **Google's endpoints are constants.** The consent and token addresses are in `policy.rs`. The client secret file names its own `auth_uri`, `token_uri` and redirect addresses; they are ignored, and only a file with an `installed` section (a Desktop app client) is read. A doctored file cannot point the sign-in at another site, and the egress guard would refuse any host but Google's anyway.
- **The listener.** It binds `127.0.0.1` on a port the system picks, so other machines cannot connect. Other programs on the machine can, so it acts on a request only if it is a `GET` of `/` that carries this sign-in's `state`, compared in constant time, with a code or an error but not both, and without a repeated parameter. Any other request gets a 400 and the wait goes on, so a stray connection cannot end the sign-in. A redirect that says the user declined, with the right `state`, ends it. Connections are served side by side, not one after the other, because a program that opened a few silent connections would otherwise keep the browser's real redirect waiting behind them: each connection gets 5 seconds, at most 16 are kept, and a new one pushes the oldest out. Only the first line of the request counts, so the cookies that a browser sends to `127.0.0.1` (they go to every port) cannot make a genuine redirect too long. The whole wait is 5 minutes, and the listener is dropped the moment the code arrives. The reply page loads nothing, sends no referrer and is not cached, and it does not claim that the sign-in worked, since the exchange and the scope check come after it.
- **The code exchange goes through the guard.** The `oauth2` crate's HTTP trait is implemented by `auth::Guarded`, which calls the egress function, so the exchange meets the same allowlist as every other request. The client credentials go in the request body, as Google documents.
- **The grant is checked before anything is stored.** `policy::check_grant` requires exactly the read-only scope; a response without a `scope` field is refused, because it cannot be checked. Then a refresh token must be present. Only then does `Credentials::new` build the credentials, which cannot hold another scope, and the store saves them. A refused sign-in leaves credentials that are already stored as they were.
- **A refused grant is not revoked.** Revoking would need a route for Google's revoke endpoint, which widens egress. The error tells the user that nothing was stored, and they can remove the app's access in their Google account.
- **The store is probed first.** `auth` reads the store before it asks the user to do anything, so a platform without a store fails at once. A damaged item is replaced only by a sign-in that brings its own client file.
- **Errors say little.** Every message is static. The `oauth2` crate's parse error holds the response body, which can hold tokens, so errors are reduced to a kind and the details are dropped.
- **`auth` never deletes the client secret file.** It tells the user to (0006).

## Consequences

- The user copies a long address into a browser by hand. In return, no code in the crate starts a process.
- Other programs on the machine can connect to the listener. They cannot complete the sign-in or end it early, because they do not know the `state`, and silent connections do not hold up the redirect. A program that floods the port faster than the listener serves it can still make the sign-in time out; the user runs it again. A program that can read the terminal output sees the `state`; that is the same user's account and is out of scope (SECURITY.md).
- The authorization code is in the browser's address bar for a moment. It works once and only together with the PKCE verifier, which never leaves the process.
- Secrets sit in ordinary heap memory while `auth` runs and are not wiped afterwards.
- If Google changes the consent address or the token endpoint, the constants and the route change with a code edit. The egress guard fails closed until then.

## What would change this decision

- Google allowing Gmail scopes in the device flow. The listener, the only socket besides the egress guard (0009), could then go.
- A wish to revoke a grant from the program. It needs its own record and a route in the allowlist.

## References

- Decision records: [0003-single-egress-allowlist.md](0003-single-egress-allowlist.md), [0006-credentials-in-os-credential-store.md](0006-credentials-in-os-credential-store.md), [0009-stdio-only-transport.md](0009-stdio-only-transport.md), [0014-read-only-no-composing.md](0014-read-only-no-composing.md)
- Google: [OAuth 2.0 for iOS and desktop apps](https://developers.google.com/identity/protocols/oauth2/native-app), [OAuth 2.0 for TV and limited-input device apps](https://developers.google.com/identity/protocols/oauth2/limited-input-device) (the allowed scopes), [Out-of-band (OOB) flow migration](https://developers.google.com/identity/protocols/oauth2/resources/oob-migration)
- Repo files: [src/auth.rs](../../src/auth.rs), [src/policy.rs](../../src/policy.rs), [src/store.rs](../../src/store.rs), [src/log.rs](../../src/log.rs)
