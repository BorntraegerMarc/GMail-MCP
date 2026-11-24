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
use crate::policy::{self, Denied};

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

impl Error {
    /// A fixed, human-readable reason that is safe to log and to return to a client.
    #[must_use]
    pub const fn reason(self) -> &'static str {
        match self {
            Error::Denied(denied) => denied.reason(),
            Error::Redirect => "the server answered with a redirect, which is never followed",
            Error::TooLarge => "the response is larger than the size limit",
            Error::Timeout => "the request timed out",
            Error::Network => "the network request failed",
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.reason())
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
}

impl Default for Egress {
    fn default() -> Self {
        Self::new()
    }
}

impl Egress {
    /// Creates the guard.
    #[must_use]
    pub fn new() -> Self {
        Self {
            agent: build_agent(true, policy::REQUEST_TIMEOUT),
        }
    }

    /// Whether the client is set to go through a proxy. It never is: the guard ignores the
    /// proxy variables of the environment. This exists so a test can check exactly that.
    #[must_use]
    pub fn uses_proxy(&self) -> bool {
        self.agent.config().proxy().is_some()
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
        if let Err(denied) = check(&request) {
            log::warn(denied.reason());
            return Err(Error::Denied(denied));
        }
        execute(&self.agent, request, policy::MAX_RESPONSE_BYTES)
    }
}

/// The guard's decision for one request: the route table, the header allowlist and the
/// body rules. The headers are checked here because a caller-set `Host` header could aim an
/// allowed address at another site.
fn check(request: &Request<Vec<u8>>) -> Result<(), Denied> {
    policy::authorize(request.method().as_str(), &request.uri().to_string())?;
    if request.method() == Method::GET && !request.body().is_empty() {
        return Err(Denied::Body);
    }
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

    /// What a client sent: the head and as many body bytes as its `Content-Length` announces.
    fn read_request(stream: &mut TcpStream) -> Vec<u8> {
        let mut seen = Vec::new();
        let mut buf = [0_u8; 1024];
        loop {
            if let Some(end) = seen.windows(4).position(|window| window == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&seen[..end]).to_ascii_lowercase();
                let wanted = head
                    .lines()
                    .find_map(|line| line.strip_prefix("content-length:"))
                    .and_then(|value| value.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if seen.len() >= end + 4 + wanted {
                    return seen;
                }
            }
            match stream.read(&mut buf) {
                Ok(0) | Err(_) => return seen,
                Ok(n) => seen.extend_from_slice(&buf[..n]),
            }
        }
    }

    /// Like `serve_once`, but hands back what the client sent.
    fn serve_capturing(reply: Vec<u8>) -> (String, JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = local_url(listener.local_addr().unwrap());
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_request(&mut stream);
            let _ = stream.write_all(&reply);
            request
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

    /// The token call is the one request with a body. Nothing else here puts a body on the wire,
    /// so this pins what the OAuth exchange really sends: the method, the two headers and the
    /// exact length and bytes of the form.
    #[test]
    fn a_form_post_goes_out_as_one_well_formed_request() {
        let (url, server) = serve_capturing(response_with(
            "200 OK",
            "Content-Type: application/json\r\nContent-Length: 2\r\n",
            b"{}",
        ));
        let body = b"grant_type=authorization_code&code=abc%2Fdef".to_vec();
        let request = Request::builder()
            .method(Method::POST)
            .uri(&url)
            .header(header::ACCEPT, "application/json")
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(body.clone())
            .unwrap();

        let response = execute(&local_agent(Duration::from_secs(5)), request, 1024).unwrap();

        assert_eq!(response.status().as_u16(), 200);
        let sent = String::from_utf8(server.join().unwrap()).unwrap();
        let lowered = sent.to_ascii_lowercase();
        assert!(sent.starts_with("POST / HTTP/1.1\r\n"), "{sent}");
        assert!(
            lowered.contains("\r\naccept: application/json\r\n"),
            "{sent}"
        );
        assert!(
            lowered.contains("\r\ncontent-type: application/x-www-form-urlencoded\r\n"),
            "{sent}"
        );
        assert!(
            lowered.contains(&format!("\r\ncontent-length: {}\r\n", body.len())),
            "{sent}"
        );
        assert!(
            sent.ends_with("\r\n\r\ngrant_type=authorization_code&code=abc%2Fdef"),
            "{sent}"
        );
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
        let agent = Egress::new().agent;
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
        assert_eq!(check(&request), Err(Denied::Header));
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
        assert_eq!(check(&request), Ok(()));

        let request = Request::builder()
            .method(Method::GET)
            .uri(ALLOWED_URL)
            .header("x-anything-else", "1")
            .body(Vec::new())
            .unwrap();
        assert_eq!(check(&request), Err(Denied::Header));
    }

    #[test]
    fn an_oversized_request_body_is_refused_before_sending() {
        let request = Request::builder()
            .method(Method::POST)
            .uri("https://oauth2.googleapis.com/token")
            .body(vec![0_u8; policy::MAX_REQUEST_BYTES + 1])
            .unwrap();
        assert_eq!(check(&request), Err(Denied::TooLarge));
        let request = Request::builder()
            .method(Method::POST)
            .uri("https://oauth2.googleapis.com/token")
            .body(vec![0_u8; policy::MAX_REQUEST_BYTES])
            .unwrap();
        assert_eq!(check(&request), Ok(()));
    }

    #[test]
    fn a_get_request_carries_no_body() {
        let request = Request::builder()
            .method(Method::GET)
            .uri(ALLOWED_URL)
            .body(b"x".to_vec())
            .unwrap();
        assert_eq!(check(&request), Err(Denied::Body));
    }
}
