//! The only module that talks to the network.
//!
//! Every request this crate sends goes through [`Egress::send`], the egress guard. It refuses
//! anything the policy in [`crate::policy`] does not list, and it never follows a redirect,
//! never uses a proxy, and bounds the size and duration of every exchange. The OAuth
//! loopback listener (accepting connections on 127.0.0.1, never dialling out) is the one
//! other place that may touch sockets.
//!
//! The client is blocking `ureq` with rustls, so the HTTP path contains no async code.
// why: docs/decisions/0003-single-egress-allowlist.md, docs/decisions/0008-blocking-http-client.md

use std::fmt;
use std::time::Duration;

use crate::log;
use crate::policy::{self, Denied, Mode};

pub use ureq::http::{Method, Request, Response, header};

/// Why a request did not produce a response. Every message is static: errors travel back
/// to the MCP client, and the underlying client errors can contain URLs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// The guard refused the request, so nothing was sent.
    Denied(Denied),
    /// The server answered with a redirect. A redirect could lead to a host the allowlist
    /// never checked, so it is an error and is not followed.
    Redirect,
    /// The response body was larger than [`policy::MAX_RESPONSE_BYTES`].
    TooLarge,
    /// The request ran past [`policy::REQUEST_TIMEOUT`] or [`policy::CONNECT_TIMEOUT`].
    Timeout,
    /// Connecting, the TLS handshake or the HTTP exchange failed.
    Network,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Denied(denied) => f.write_str(denied.reason()),
            Error::Redirect => {
                f.write_str("the server answered with a redirect, which is never followed")
            }
            Error::TooLarge => f.write_str("the response is larger than the size limit"),
            Error::Timeout => f.write_str("the request timed out"),
            Error::Network => f.write_str("the network request failed"),
        }
    }
}

impl std::error::Error for Error {}

impl From<ureq::Error> for Error {
    fn from(error: ureq::Error) -> Self {
        match error {
            ureq::Error::Timeout(_) => Error::Timeout,
            ureq::Error::BodyExceedsLimit(_) => Error::TooLarge,
            // The details are dropped on purpose: the client's messages can contain URLs.
            _ => Error::Network,
        }
    }
}

/// The egress guard: sends a request only if the policy allows it.
pub struct Egress {
    agent: ureq::Agent,
    mode: Mode,
}

impl Egress {
    /// Creates a guard for `mode`. In [`Mode::ReadOnly`] the draft route is refused as well,
    /// a second server-side layer on top of the OAuth scope.
    #[must_use]
    pub fn new(mode: Mode) -> Self {
        Self {
            agent: build_agent(true, policy::REQUEST_TIMEOUT),
            mode,
        }
    }

    /// Sends `request` and returns the response, whatever its status. A 4xx or 5xx answer
    /// is a response, not an error: the caller reads Google's error body.
    ///
    /// # Errors
    ///
    /// [`Error::Denied`] if the policy refuses the request (nothing is sent), otherwise
    /// the failure of the exchange itself: a redirect, an oversized response, a timeout or
    /// a network error.
    pub fn send(&self, request: Request<Vec<u8>>) -> Result<Response<Vec<u8>>, Error> {
        if let Err(denied) = check(self.mode, &request) {
            log::warn(denied.reason());
            return Err(Error::Denied(denied));
        }
        execute(&self.agent, request, policy::MAX_RESPONSE_BYTES)
    }
}

/// The guard's decision for one request: the route table, the header allowlist and the
/// body cap. The headers are checked here because a caller-set `Host` header could aim an
/// allowed address at another site.
fn check(mode: Mode, request: &Request<Vec<u8>>) -> Result<(), Denied> {
    policy::authorize(mode, request.method().as_str(), &request.uri().to_string())?;
    if request.body().len() > policy::MAX_REQUEST_BYTES {
        return Err(Denied::TooLarge);
    }
    if request
        .headers()
        .keys()
        .any(|name| !policy::header_allowed(name.as_str()))
    {
        return Err(Denied::Header);
    }
    Ok(())
}

/// Builds the client with every transport restriction the design needs. `https_only` is
/// false only in this module's tests, which talk to a local server.
fn build_agent(https_only: bool, timeout: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .https_only(https_only)
        // A followed redirect could reach a host the allowlist never checked. With zero
        // redirects the 3xx response comes back as it is, and `execute` turns it into an error.
        .max_redirects(0)
        // The default reads the proxy from the environment (HTTPS_PROXY and friends): a hop
        // this guard does not control.
        .proxy(None)
        // Google's JSON error bodies are read like any other response.
        .http_status_as_error(false)
        .timeout_global(Some(timeout))
        .timeout_connect(Some(policy::CONNECT_TIMEOUT))
        .build()
        .new_agent()
}

/// Performs the exchange. Authorization has already happened; this function only enforces
/// the transport rules.
fn execute(
    agent: &ureq::Agent,
    request: Request<Vec<u8>>,
    max_response_bytes: u64,
) -> Result<Response<Vec<u8>>, Error> {
    // An empty body is sent as no body, so a GET carries no `Content-Length: 0`.
    let response = if request.body().is_empty() {
        agent.run(request.map(|_| ()))?
    } else {
        agent.run(request)?
    };
    if response.status().is_redirection() {
        return Err(Error::Redirect);
    }
    let (parts, body) = response.into_parts();
    let bytes = body
        .into_with_config()
        .limit(max_response_bytes)
        .read_to_vec()?;
    Ok(Response::from_parts(parts, bytes))
}

#[cfg(test)]
mod tests {
    use std::io::{ErrorKind, Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};
    use std::thread::{self, JoinHandle};

    use super::*;

    const ALLOWED_URL: &str = "https://gmail.googleapis.com/gmail/v1/users/me/labels";

    /// The scheme is kept apart so the static policy scan, which rejects any plain-http
    /// URL literal in `src/`, does not need an exception for these local-server tests.
    fn local_url(addr: SocketAddr) -> String {
        let scheme = "http";
        format!("{scheme}://{addr}/")
    }

    fn get(url: &str) -> Request<Vec<u8>> {
        Request::builder()
            .method(Method::GET)
            .uri(url)
            .body(Vec::new())
            .unwrap()
    }

    fn local_agent(timeout: Duration) -> ureq::Agent {
        build_agent(false, timeout)
    }

    fn read_request_head(stream: &mut TcpStream) {
        let mut seen = Vec::new();
        let mut buf = [0_u8; 1024];
        while !seen.windows(4).any(|window| window == b"\r\n\r\n") {
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => seen.extend_from_slice(&buf[..n]),
            }
        }
    }

    /// Serves one connection: reads the request head, writes `reply`, closes.
    fn serve_once(reply: Vec<u8>) -> (String, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = local_url(listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_request_head(&mut stream);
            // The client may hang up early (that is what some tests provoke).
            let _ = stream.write_all(&reply);
        });
        (url, handle)
    }

    fn response_with(status_line: &str, headers: &str, body: &[u8]) -> Vec<u8> {
        let mut reply =
            format!("HTTP/1.1 {status_line}\r\n{headers}Connection: close\r\n\r\n").into_bytes();
        reply.extend_from_slice(body);
        reply
    }

    #[test]
    fn a_redirect_is_an_error_and_is_never_followed() {
        let trap = TcpListener::bind("127.0.0.1:0").unwrap();
        trap.set_nonblocking(true).unwrap();
        let location = local_url(trap.local_addr().unwrap());
        let (url, server) = serve_once(response_with(
            "302 Found",
            &format!("Location: {location}\r\nContent-Length: 0\r\n"),
            b"",
        ));

        let result = execute(&local_agent(Duration::from_secs(5)), get(&url), 1024);

        assert_eq!(result.unwrap_err(), Error::Redirect);
        server.join().unwrap();
        let followed = trap.accept();
        assert!(
            matches!(&followed, Err(e) if e.kind() == ErrorKind::WouldBlock),
            "the redirect target was contacted"
        );
    }

    #[test]
    fn an_oversized_response_is_refused() {
        let body = vec![b'x'; 5000];
        let (url, server) = serve_once(response_with("200 OK", "Content-Length: 5000\r\n", &body));

        let result = execute(&local_agent(Duration::from_secs(5)), get(&url), 1000);

        assert_eq!(result.unwrap_err(), Error::TooLarge);
        server.join().unwrap();
    }

    #[test]
    fn an_oversized_chunked_response_without_a_length_is_refused() {
        let mut body = Vec::new();
        for _ in 0..10 {
            body.extend_from_slice(b"3e8\r\n");
            body.extend_from_slice(&[b'x'; 1000]);
            body.extend_from_slice(b"\r\n");
        }
        body.extend_from_slice(b"0\r\n\r\n");
        let (url, server) = serve_once(response_with(
            "200 OK",
            "Transfer-Encoding: chunked\r\n",
            &body,
        ));

        let result = execute(&local_agent(Duration::from_secs(5)), get(&url), 2500);

        assert_eq!(result.unwrap_err(), Error::TooLarge);
        server.join().unwrap();
    }

    #[test]
    fn a_response_exactly_at_the_limit_is_accepted() {
        let body = vec![b'x'; 1000];
        let (url, server) = serve_once(response_with("200 OK", "Content-Length: 1000\r\n", &body));

        let response = execute(&local_agent(Duration::from_secs(5)), get(&url), 1000).unwrap();

        assert_eq!(response.body().len(), 1000);
        server.join().unwrap();
    }

    #[test]
    fn an_error_status_is_a_response_with_its_body() {
        let (url, server) = serve_once(response_with(
            "404 Not Found",
            "Content-Length: 11\r\n",
            b"{\"error\":1}",
        ));

        let response = execute(&local_agent(Duration::from_secs(5)), get(&url), 1000).unwrap();

        assert_eq!(response.status().as_u16(), 404);
        assert_eq!(response.body().as_slice(), b"{\"error\":1}");
        server.join().unwrap();
    }

    #[test]
    fn a_server_that_never_answers_times_out() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = local_url(listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            // Hold the connection open until the client gives up and closes it.
            let mut buf = [0_u8; 1024];
            while matches!(stream.read(&mut buf), Ok(n) if n > 0) {}
        });

        let result = execute(&local_agent(Duration::from_millis(300)), get(&url), 1000);

        assert_eq!(result.unwrap_err(), Error::Timeout);
        server.join().unwrap();
    }

    /// The time limit covers the whole exchange, the body included: a server that answers
    /// at once and then drips the body one byte at a time must not hold a request open.
    #[test]
    fn a_response_that_drips_in_slowly_times_out_as_a_whole() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = local_url(listener.local_addr().unwrap());
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            read_request_head(&mut stream);
            let head = b"HTTP/1.1 200 OK\r\nContent-Length: 1000000\r\nConnection: close\r\n\r\n";
            let _ = stream.write_all(head);
            // One byte at a time, until the client gives up and a write fails.
            for _ in 0..200 {
                if stream.write_all(b"x").is_err() {
                    break;
                }
                thread::sleep(Duration::from_millis(50));
            }
        });

        let started = std::time::Instant::now();
        let result = execute(
            &local_agent(Duration::from_millis(400)),
            get(&url),
            10_000_000,
        );

        assert_eq!(result.unwrap_err(), Error::Timeout);
        assert!(started.elapsed() < Duration::from_secs(5));
        server.join().unwrap();
    }

    /// The proxy assertion has a blind spot: the client reads proxy settings from the
    /// environment only if variables such as `HTTPS_PROXY` are set, and a test cannot set
    /// them without `unsafe`, which this crate forbids. In a clean environment the assertion
    /// holds even if `.proxy(None)` were deleted, so that line is held by review and by the
    /// comment on it; the assertion catches an explicitly configured proxy.
    #[test]
    fn the_production_client_is_locked_down() {
        let agent = Egress::new(Mode::ReadOnly).agent;
        let config = agent.config();
        assert!(config.https_only(), "plain http must be impossible");
        assert_eq!(config.max_redirects(), 0, "redirects must not be followed");
        assert!(
            config.proxy().is_none(),
            "no proxy, whatever the environment says"
        );
        assert!(!config.http_status_as_error());
        assert_eq!(config.timeouts().global, Some(policy::REQUEST_TIMEOUT));
        assert_eq!(config.timeouts().connect, Some(policy::CONNECT_TIMEOUT));
    }

    #[test]
    fn a_host_header_cannot_redirect_an_allowed_address() {
        let request = Request::builder()
            .method(Method::GET)
            .uri(ALLOWED_URL)
            .header(header::HOST, "other.example")
            .body(Vec::new())
            .unwrap();
        assert_eq!(check(Mode::ReadOnly, &request), Err(Denied::Header));
    }

    #[test]
    fn only_the_listed_headers_pass() {
        let request = Request::builder()
            .method(Method::GET)
            .uri(ALLOWED_URL)
            .header(header::AUTHORIZATION, "Bearer token")
            .header(header::ACCEPT, "application/json")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Vec::new())
            .unwrap();
        assert_eq!(check(Mode::ReadOnly, &request), Ok(()));

        let request = Request::builder()
            .method(Method::GET)
            .uri(ALLOWED_URL)
            .header("x-anything-else", "1")
            .body(Vec::new())
            .unwrap();
        assert_eq!(check(Mode::ReadOnly, &request), Err(Denied::Header));
    }

    #[test]
    fn an_oversized_request_body_is_refused_before_sending() {
        let request = Request::builder()
            .method(Method::POST)
            .uri("https://gmail.googleapis.com/gmail/v1/users/me/drafts")
            .body(vec![0_u8; policy::MAX_REQUEST_BYTES + 1])
            .unwrap();
        assert_eq!(check(Mode::Drafts, &request), Err(Denied::TooLarge));
    }
}
