//! Loopback HTTP harness for tests: serves canned or computed
//! responses so transport-facing code runs against a real socket.
//! Plain HTTP exercises everything but the TLS handshake, whose
//! trust decision belongs to the operating system's verifier and has
//! no deterministic fixture.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

const READ_TIMEOUT: Duration = Duration::from_secs(5);

/// Repeats a blocking socket call for as long as signals interrupt
/// it: EINTR arrives in bursts under parallel test load (the client
/// side bounds the same hazard in `transport`), and the harness must
/// not turn a stray signal into a dead server. Unbounded on purpose —
/// `read` stays under [`READ_TIMEOUT`], so a wedged connection still
/// surfaces as a timeout, not an interruption.
fn without_interruptions<T>(
    mut operation: impl FnMut() -> std::io::Result<T>,
) -> std::io::Result<T> {
    loop {
        match operation() {
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            outcome => return outcome,
        }
    }
}

pub fn http_response(
    status: &str,
    content_type: &str,
    body: &[u8],
) -> Vec<u8> {
    let mut response_bytes = format!(
        "HTTP/1.1 {status}\r\ncontent-type: {content_type}\r\n\
         content-length: {}\r\nconnection: close\r\n\r\n",
        body.len()
    )
    .into_bytes();
    response_bytes.extend_from_slice(body);
    response_bytes
}

fn header_end_of(request_bytes: &[u8]) -> Option<usize> {
    request_bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

fn content_length_of(header_text: &str) -> usize {
    header_text
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse().ok())?
        })
        .unwrap_or(0)
}

/// Reads one whole HTTP request — headers, then exactly the body the
/// `content-length` header announces. The client keeps the socket
/// open while it waits for the response, so reading to EOF would
/// deadlock.
fn read_http_request(connection: &mut TcpStream) -> Vec<u8> {
    connection
        .set_read_timeout(Some(READ_TIMEOUT))
        .expect("the read timeout sets");
    let mut request_bytes = Vec::new();
    let mut chunk = [0u8; 4096];
    let expected_length = loop {
        if let Some(header_end) = header_end_of(&request_bytes) {
            let header_text =
                String::from_utf8_lossy(&request_bytes[..header_end]);
            break header_end + content_length_of(&header_text);
        }
        let read_count = without_interruptions(|| connection.read(&mut chunk))
            .expect("the request keeps arriving");
        request_bytes.extend_from_slice(&chunk[..read_count]);
    };
    while request_bytes.len() < expected_length {
        let read_count = without_interruptions(|| connection.read(&mut chunk))
            .expect("the request body keeps arriving");
        request_bytes.extend_from_slice(&chunk[..read_count]);
    }
    request_bytes
}

/// A bound loopback port whose response is chosen later: fixtures
/// that must embed [`OneShotServer::url`] (a certificate's
/// distribution point, say) can be built between binding and
/// responding.
pub struct OneShotServer {
    listener: TcpListener,
    pub url: String,
}

fn bind_listener() -> (TcpListener, String) {
    let listener =
        TcpListener::bind("127.0.0.1:0").expect("a loopback port binds");
    let port = listener.local_addr().expect("the port is known").port();
    (listener, format!("http://127.0.0.1:{port}/tsr"))
}

pub fn bind_one_shot() -> OneShotServer {
    let (listener, url) = bind_listener();
    OneShotServer { listener, url }
}

impl OneShotServer {
    /// Serves exactly one response computed from the request, and
    /// hands the observed request bytes back.
    pub fn respond_via<Handler>(
        self,
        handler: Handler,
    ) -> mpsc::Receiver<Vec<u8>>
    where
        Handler: FnOnce(&[u8]) -> Vec<u8> + Send + 'static,
    {
        let (request_sender, request_receiver) = mpsc::channel();
        thread::spawn(move || {
            let (mut connection, _) =
                without_interruptions(|| self.listener.accept())
                    .expect("the test client connects");
            let request_bytes = read_http_request(&mut connection);
            let response_bytes = handler(&request_bytes);
            request_sender
                .send(request_bytes)
                .expect("the test still listens");
            connection
                .write_all(&response_bytes)
                .expect("the response writes");
        });
        request_receiver
    }

    /// Serves exactly one canned response and hands the observed
    /// request bytes back.
    pub fn respond_with(
        self,
        response_bytes: Vec<u8>,
    ) -> mpsc::Receiver<Vec<u8>> {
        self.respond_via(move |_request_bytes| response_bytes)
    }
}

/// Serves exactly one canned HTTP response on a loopback port and
/// hands the observed request bytes back beside the URL to request.
pub fn serve_once(
    response_bytes: Vec<u8>,
) -> (String, mpsc::Receiver<Vec<u8>>) {
    let server = bind_one_shot();
    let url = server.url.clone();
    let request_receiver = server.respond_with(response_bytes);
    (url, request_receiver)
}

/// Serves every incoming request through `handler`, for fixtures
/// that get fetched more than once (a distribution point named by a
/// certificate, a TSA answering several stamps). The serving thread
/// lives for the rest of the test process.
pub fn serve_repeatedly<Handler>(handler: Handler) -> String
where
    Handler: Fn(&[u8]) -> Vec<u8> + Send + 'static,
{
    let (listener, url) = bind_listener();
    thread::spawn(move || {
        loop {
            let (mut connection, _) =
                without_interruptions(|| listener.accept())
                    .expect("the test client connects");
            let request_bytes = read_http_request(&mut connection);
            connection
                .write_all(&handler(&request_bytes))
                .expect("the response writes");
        }
    });
    url
}
