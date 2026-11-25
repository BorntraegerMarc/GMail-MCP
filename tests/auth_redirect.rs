//! The sign-in listener, the one place the server accepts connections. It binds `127.0.0.1`
//! only, but other programs on the machine can still connect, so it acts on a request only if
//! the request carries the `state` that was issued for this sign-in, and it must not be
//! possible for a stray connection to end the sign-in or to hold the listener for long.
//! Why: docs/decisions/0003-single-egress-allowlist.md, docs/decisions/0015-sign-in-flow.md.

use std::io::{Read, Write};
use std::net::{Ipv4Addr, SocketAddr, TcpStream};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use gmail_mcp::auth::{self, Error};
use gmail_mcp::policy::{
    MAX_REDIRECT_CONNECTIONS, MAX_REDIRECT_HEAD_BYTES, REDIRECT_CONNECTION_TIMEOUT,
};
use oauth2::{AuthorizationCode, CsrfToken};

const STATE: &str = "state-issued-for-this-sign-in";

type Wait = JoinHandle<Result<AuthorizationCode, Error>>;

fn listen(timeout: Duration) -> (SocketAddr, Wait) {
    let listener = auth::bind_loopback().unwrap();
    let address = listener.local_addr().unwrap();
    let state = CsrfToken::new(STATE.to_owned());
    let wait = thread::spawn(move || auth::await_redirect(&listener, &state, timeout));
    (address, wait)
}

fn get(target: &str) -> Vec<u8> {
    format!("GET {target} HTTP/1.1\r\nHost: 127.0.0.1\r\nAccept: text/html\r\n\r\n").into_bytes()
}

/// Sends `request` as it is and returns whatever comes back until the listener closes.
fn exchange(address: SocketAddr, request: &[u8]) -> String {
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    // The listener may hang up before it has read everything (that is what some tests provoke).
    let _ = stream.write_all(request);
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);
    String::from_utf8_lossy(&response).into_owned()
}

fn status(response: &str) -> &str {
    response.lines().next().unwrap_or_default()
}

fn code_of(wait: Wait) -> String {
    wait.join().unwrap().unwrap().secret().clone()
}

#[test]
fn the_listener_is_bound_to_the_loopback_address_only() {
    let listener = auth::bind_loopback().unwrap();
    let address = listener.local_addr().unwrap();
    assert_eq!(address.ip(), Ipv4Addr::LOCALHOST);
    assert_ne!(address.port(), 0);
}

#[test]
fn the_redirect_of_this_sign_in_yields_its_code_and_a_page_that_loads_nothing() {
    let (address, wait) = listen(Duration::from_secs(10));
    let response = exchange(
        address,
        &get(&format!(
            "/?state={STATE}&code=4%2F0Abc-DEF_ghi&scope=anything"
        )),
    );

    assert_eq!(status(&response), "HTTP/1.1 200 OK");
    let lowered = response.to_ascii_lowercase();
    for header in [
        "cache-control: no-store",
        "referrer-policy: no-referrer",
        "x-content-type-options: nosniff",
        "content-security-policy: default-src 'none'",
        "connection: close",
    ] {
        assert!(lowered.contains(header), "missing {header}: {response}");
    }
    assert!(response.contains("You can close this tab"));
    // Nothing of the request may come back to the browser.
    assert!(!response.contains("4%2F0Abc") && !response.contains("4/0Abc"));
    assert_eq!(code_of(wait), "4/0Abc-DEF_ghi");
}

/// Anything else on the machine can connect. A request whose `state` is not this sign-in's
/// is answered with a 400 and changes nothing: the real redirect still goes through.
#[test]
fn a_stray_request_cannot_end_the_sign_in() {
    let (address, wait) = listen(Duration::from_secs(10));
    for stray in [
        "/?code=evil&state=wrong".to_owned(),
        "/?code=evil".to_owned(),
        format!("/?code=evil&state={STATE}x"),
        format!("/?code=evil&state={}", &STATE[..STATE.len() - 1]),
        "/?error=access_denied&state=wrong".to_owned(),
        "/?error=access_denied".to_owned(),
        "/".to_owned(),
        format!("/favicon.ico?state={STATE}&code=evil"),
        format!("/other?state={STATE}&code=evil"),
        format!("//?state={STATE}&code=evil"),
    ] {
        let response = exchange(address, &get(&stray));
        assert_eq!(status(&response), "HTTP/1.1 400 Bad Request", "{stray}");
        assert!(!wait.is_finished(), "{stray} ended the sign-in");
    }
    let response = exchange(address, &get(&format!("/?code=right&state={STATE}")));
    assert_eq!(status(&response), "HTTP/1.1 200 OK");
    assert_eq!(code_of(wait), "right");
}

#[test]
fn a_request_that_is_not_a_plain_get_of_the_redirect_is_ignored() {
    let (address, wait) = listen(Duration::from_secs(10));
    let query = format!("/?code=evil&state={STATE}");
    for request in [
        format!("POST {query} HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n"),
        format!("HEAD {query} HTTP/1.1\r\nHost: x\r\n\r\n"),
        format!("get {query} HTTP/1.1\r\nHost: x\r\n\r\n"),
        format!("GET {query}\r\nHost: x\r\n\r\n"),
        format!("GET {query} HTTP/2.0\r\nHost: x\r\n\r\n"),
        format!("GET {query} HTTP/1.1 extra\r\nHost: x\r\n\r\n"),
        format!("GET  {query} HTTP/1.1\r\nHost: x\r\n\r\n"),
        "\r\n\r\n".to_owned(),
        "garbage\r\n\r\n".to_owned(),
        "GET\r\n\r\n".to_owned(),
    ] {
        let response = exchange(address, request.as_bytes());
        assert_eq!(
            status(&response),
            "HTTP/1.1 400 Bad Request",
            "accepted: {request:?}"
        );
    }
    assert!(!wait.is_finished());
    exchange(address, &get(&format!("/?code=right&state={STATE}")));
    assert_eq!(code_of(wait), "right");
}

/// Parameters that appear twice are ambiguous: the listener and a proxy in front of it could
/// read different ones. Such a request is not acted on.
#[test]
fn a_repeated_parameter_is_ignored() {
    let (address, wait) = listen(Duration::from_secs(10));
    for stray in [
        format!("/?code=one&code=two&state={STATE}"),
        format!("/?code=one&state={STATE}&state=other"),
        format!("/?state=other&state={STATE}&code=one"),
        format!("/?error=a&error=b&state={STATE}"),
    ] {
        let response = exchange(address, &get(&stray));
        assert_eq!(status(&response), "HTTP/1.1 400 Bad Request", "{stray}");
    }
    exchange(address, &get(&format!("/?code=right&state={STATE}")));
    assert_eq!(code_of(wait), "right");
}

#[test]
fn a_code_that_cannot_be_one_is_ignored() {
    let (address, wait) = listen(Duration::from_secs(10));
    let long = "a".repeat(gmail_mcp::policy::MAX_CREDENTIAL_CHARS + 1);
    for code in [
        "",
        "has%20space",
        "new%0Aline",
        "caf%C3%A9",
        "nul%00",
        &long,
    ] {
        let response = exchange(address, &get(&format!("/?code={code}&state={STATE}")));
        assert_eq!(status(&response), "HTTP/1.1 400 Bad Request", "{code}");
    }
    assert!(!wait.is_finished());
    exchange(address, &get(&format!("/?code=right&state={STATE}")));
    assert_eq!(code_of(wait), "right");
}

#[test]
fn a_redirect_that_says_the_user_declined_ends_the_sign_in() {
    let (address, wait) = listen(Duration::from_secs(10));
    let response = exchange(
        address,
        &get(&format!("/?error=access_denied&state={STATE}")),
    );
    assert_eq!(status(&response), "HTTP/1.1 200 OK");
    assert!(response.contains("Access was not granted"));
    assert_eq!(wait.join().unwrap().unwrap_err(), Error::Declined);
}

/// An error and a code together are not something Google sends.
#[test]
fn a_redirect_with_both_a_code_and_an_error_is_ignored() {
    let (address, wait) = listen(Duration::from_secs(10));
    let response = exchange(
        address,
        &get(&format!("/?code=x&error=access_denied&state={STATE}")),
    );
    assert_eq!(status(&response), "HTTP/1.1 400 Bad Request");
    assert!(!wait.is_finished());
    exchange(address, &get(&format!("/?code=right&state={STATE}")));
    assert_eq!(code_of(wait), "right");
}

#[test]
fn a_request_head_that_never_ends_is_cut_off() {
    let (address, wait) = listen(Duration::from_secs(10));
    let mut request = b"GET /?x=".to_vec();
    request.extend(std::iter::repeat_n(b'a', MAX_REDIRECT_HEAD_BYTES * 3));
    let started = Instant::now();
    let response = exchange(address, &request);
    // The 400 may be lost if the listener closed on unread data; what matters is that it let go.
    assert!(response.is_empty() || status(&response) == "HTTP/1.1 400 Bad Request");
    assert!(started.elapsed() < REDIRECT_CONNECTION_TIMEOUT);
    assert!(!wait.is_finished());
    exchange(address, &get(&format!("/?code=right&state={STATE}")));
    assert_eq!(code_of(wait), "right");
}

/// Some browsers open a connection ahead of time and send nothing on it, and anything on the
/// machine can do the same. Connections are served side by side, so such a connection delays
/// nothing: the real redirect behind it is read at once.
#[test]
fn a_connection_that_says_nothing_does_not_delay_the_real_redirect() {
    let (address, wait) = listen(Duration::from_secs(30));
    let silent: Vec<TcpStream> = (0..3)
        .map(|_| TcpStream::connect(address).unwrap())
        .collect();
    thread::sleep(Duration::from_millis(200));

    let started = Instant::now();
    let response = exchange(address, &get(&format!("/?code=right&state={STATE}")));
    let waited = started.elapsed();

    assert_eq!(status(&response), "HTTP/1.1 200 OK");
    assert!(
        waited < Duration::from_secs(2),
        "the silent connections delayed the redirect by {waited:?}"
    );
    assert_eq!(code_of(wait), "right");
    drop(silent);
}

/// A program that opens far more silent connections than the listener keeps pushes its own
/// older ones out, not the browser's redirect, and the redirect is still read at once.
#[test]
fn a_flood_of_silent_connections_cannot_keep_the_real_redirect_waiting() {
    let (address, wait) = listen(Duration::from_secs(30));
    let flood: Vec<TcpStream> = (0..MAX_REDIRECT_CONNECTIONS * 6)
        .map(|_| TcpStream::connect(address).unwrap())
        .collect();
    thread::sleep(Duration::from_millis(300));

    let started = Instant::now();
    let response = exchange(address, &get(&format!("/?code=right&state={STATE}")));
    let waited = started.elapsed();

    assert_eq!(status(&response), "HTTP/1.1 200 OK");
    assert!(
        waited < Duration::from_secs(3),
        "the flood delayed the redirect by {waited:?}"
    );
    assert_eq!(code_of(wait), "right");
    drop(flood);
}

/// Cookies for `127.0.0.1` go to every port, so the browser's redirect can carry a long head.
/// Only the first line counts, so the redirect is still read.
#[test]
fn a_genuine_redirect_with_big_cookies_is_still_read() {
    for cookie_bytes in [3_000, MAX_REDIRECT_HEAD_BYTES * 2] {
        let (address, wait) = listen(Duration::from_secs(10));
        let request = format!(
            "GET /?code=right&state={STATE} HTTP/1.1\r\nHost: 127.0.0.1\r\nCookie: x={}\r\n\r\n",
            "a".repeat(cookie_bytes)
        );
        // With a head longer than the listener reads, it may close before the client has
        // finished sending, so the client's own errors are not what is tested here.
        let _ = exchange(address, request.as_bytes());
        assert_eq!(code_of(wait), "right", "{cookie_bytes} bytes of cookie");
    }
}

/// A request that is refused says so in the page, so a person who opened the address by hand
/// is not left with a blank tab.
#[test]
fn a_refused_request_is_answered_with_a_page_that_says_so() {
    let (address, wait) = listen(Duration::from_secs(10));
    let response = exchange(address, &get("/?code=evil&state=wrong"));
    assert_eq!(status(&response), "HTTP/1.1 400 Bad Request");
    assert!(response.contains("not the sign-in redirect"), "{response}");
    assert!(!response.contains("evil") && !response.contains("wrong"));
    exchange(address, &get(&format!("/?code=right&state={STATE}")));
    assert_eq!(code_of(wait), "right");
}

#[test]
fn without_a_redirect_the_wait_ends_at_the_time_limit() {
    let (_address, wait) = listen(Duration::from_millis(300));
    let started = Instant::now();
    assert_eq!(wait.join().unwrap().unwrap_err(), Error::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(5));
}

/// The code belongs to one sign-in: once it has been handed over, the caller drops the
/// listener and nothing can connect to the port any more.
#[test]
fn the_port_is_closed_once_the_listener_is_dropped() {
    let listener = auth::bind_loopback().unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    assert!(TcpStream::connect(address).is_err());
}

/// A browser sends the whole request at once, but a slow client does not: the head can arrive in
/// pieces after the connection was accepted. The listener waits for the rest, within its time
/// limit, and does not drop a half-read request, whatever mode the accepted socket starts in.
#[test]
fn a_request_that_arrives_in_pieces_is_still_served() {
    let (address, wait) = listen(Duration::from_secs(10));
    let mut stream = TcpStream::connect(address).unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(15)))
        .unwrap();
    let request = get(&format!("/?code=right&state={STATE}"));
    let (first, rest) = request.split_at(10);
    stream.write_all(first).unwrap();
    // Long enough for the listener to have accepted the connection and started to read it.
    thread::sleep(Duration::from_millis(400));
    stream.write_all(rest).unwrap();
    let mut response = Vec::new();
    let _ = stream.read_to_end(&mut response);

    assert_eq!(
        status(&String::from_utf8_lossy(&response)),
        "HTTP/1.1 200 OK"
    );
    assert_eq!(code_of(wait), "right");
}

/// A client that sends one byte every half second keeps its own reads succeeding, but it holds
/// nobody up: the real redirect, which arrives later, is read at once.
#[test]
fn a_client_that_trickles_bytes_holds_nobody_up() {
    let (address, wait) = listen(Duration::from_secs(30));
    let started = Instant::now();
    let dripper = thread::spawn(move || {
        let mut stream = TcpStream::connect(address).unwrap();
        for byte in std::iter::repeat_n(b'a', 200) {
            if stream.write_all(&[byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(500));
        }
    });
    thread::sleep(Duration::from_millis(200));

    let response = exchange(address, &get(&format!("/?code=right&state={STATE}")));
    let served_after = started.elapsed();

    assert_eq!(status(&response), "HTTP/1.1 200 OK");
    assert!(
        served_after < Duration::from_secs(2),
        "the trickling connection held up the redirect: {served_after:?}"
    );
    assert_eq!(code_of(wait), "right");
    // The listener is gone now, so the dripper's next write fails and it ends.
    dripper.join().unwrap();
}

/// The time limit is on the whole connection. Sending a byte every quarter of a second keeps every
/// single read succeeding, so a limit that restarted on each read would never end; the listener
/// must cut the connection off itself, not leave that to the end of the test.
#[test]
fn a_connection_that_trickles_bytes_is_cut_off_when_its_time_is_up() {
    let (address, wait) = listen(Duration::from_secs(30));
    let started = Instant::now();
    let mut stream = TcpStream::connect(address).unwrap();
    let cut_off = loop {
        if stream.write_all(b"a").is_err() {
            break started.elapsed();
        }
        assert!(
            started.elapsed() < REDIRECT_CONNECTION_TIMEOUT + Duration::from_secs(5),
            "the connection was never cut off"
        );
        thread::sleep(Duration::from_millis(250));
    };
    assert!(
        cut_off >= REDIRECT_CONNECTION_TIMEOUT.saturating_sub(Duration::from_secs(1)),
        "cut off after {cut_off:?}, before its time was up"
    );
    assert!(cut_off < REDIRECT_CONNECTION_TIMEOUT + Duration::from_secs(3));
    exchange(address, &get(&format!("/?code=right&state={STATE}")));
    assert_eq!(code_of(wait), "right");
}
