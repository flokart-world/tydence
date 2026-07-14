//! The live HTTPS transport: the TSA exchange of RFC 3161 §3.4 and
//! the plain fetch that trust material (certificates, CRLs) arrives
//! by.
//!
//! TLS server trust comes from the operating system's verifier, not
//! a bundled root list: transport trust is a deployment property —
//! an isolated environment may interpose an inspection proxy by
//! installing its certificate into the system store — and entirely
//! separate from the evidential trust anchors verification judges
//! against.

use std::time::Duration;
use ureq::Agent;
use ureq::tls::{RootCerts, TlsConfig};

use super::tsp::{TransportFailure, TsaTransport};

// A TSA answers in about a second, and trust material is a few
// kilobytes; the timeout only bounds a wedged exchange.
const EXCHANGE_TIMEOUT: Duration = Duration::from_secs(30);

// A TimeStampResp, a certificate chain and a CRL all measure in
// kilobytes; the cap only bounds a misbehaving server.
const MAX_RESPONSE_BYTES: u64 = 1024 * 1024;

const REQUEST_CONTENT_TYPE: &str = "application/timestamp-query";
const REPLY_CONTENT_TYPE: &str = "application/timestamp-reply";

// EINTR surfaces when a signal lands during a blocking socket call,
// and SA_RESTART in the signal installer cannot prevent it here:
// socket I/O under a receive timeout — the agent sets one — is never
// restarted by the kernel (signal(7)). The retry granularity is the
// whole request, because an interrupted connect cannot be reissued
// on its socket and a half-read response cannot be resumed; both
// exchanges are stateless, so repetition is harmless. The bound
// keeps a signal storm from looping forever; interruptions arrive
// in bursts that reached a dozen on one exchange when measured
// (WSL2, parallel test load, 2026-07), so the bound sits well above
// the deepest observed burst.
const INTERRUPT_RETRIES: usize = 32;

fn is_interrupted(error: &ureq::Error) -> bool {
    matches!(
        error,
        ureq::Error::Io(io_error)
            if io_error.kind() == std::io::ErrorKind::Interrupted
    )
}

fn with_interrupt_retry<T>(
    mut operation: impl FnMut() -> Result<T, ureq::Error>,
) -> Result<T, ureq::Error> {
    let mut remaining = INTERRUPT_RETRIES;
    loop {
        match operation() {
            Err(error) if is_interrupted(&error) && remaining > 0 => {
                remaining -= 1;
            }
            outcome => return outcome,
        }
    }
}

fn standard_agent() -> Agent {
    Agent::config_builder()
        // Non-2xx statuses fail the call before any body is looked
        // at. This is ureq's default, but the fail-closed screening
        // rests on it, so it is declared rather than inherited.
        .http_status_as_error(true)
        .timeout_global(Some(EXCHANGE_TIMEOUT))
        .tls_config(
            TlsConfig::builder()
                .root_certs(RootCerts::PlatformVerifier)
                .build(),
        )
        .build()
        .new_agent()
}

// The declared media type is matched without its parameters:
// RFC 3161 §3.4 names the bare type, and a parameter (a charset,
// say) does not change what the bytes are.
fn is_timestamp_reply(content_type: &str) -> bool {
    let essence = content_type.split(';').next().unwrap_or("");
    essence.trim().eq_ignore_ascii_case(REPLY_CONTENT_TYPE)
}

/// Reads a whole response body under [`MAX_RESPONSE_BYTES`].
fn read_body(
    response: &mut ureq::http::Response<ureq::Body>,
) -> Result<Vec<u8>, ureq::Error> {
    response
        .body_mut()
        .with_config()
        .limit(MAX_RESPONSE_BYTES)
        .read_to_vec()
}

/// Fetches one resource by plain GET: trust material published at a
/// URL, as opposed to the request/response exchange of
/// [`HttpsTransport`]. The URL's scheme is the caller's policy —
/// site URLs are HTTPS by configuration, while CRL distribution
/// points are commonly plain HTTP, their payloads being signed.
pub fn fetch(url: &str) -> Result<Vec<u8>, TransportFailure> {
    let agent = standard_agent();
    with_interrupt_retry(|| {
        let mut response = agent.get(url).call()?;
        read_body(&mut response)
    })
    .map_err(Into::into)
}

/// [`TsaTransport`] over HTTPS: one POST per exchange (RFC 3161
/// §3.4).
#[derive(Debug)]
pub struct HttpsTransport {
    agent: Agent,
    url: String,
}

impl HttpsTransport {
    pub fn new(url: &str) -> Self {
        HttpsTransport {
            agent: standard_agent(),
            url: url.to_string(),
        }
    }
}

impl TsaTransport for HttpsTransport {
    fn exchange(
        &mut self,
        request_bytes: &[u8],
    ) -> Result<Vec<u8>, TransportFailure> {
        let (content_type, body) = with_interrupt_retry(|| {
            let mut response = self
                .agent
                .post(&self.url)
                .header("Content-Type", REQUEST_CONTENT_TYPE)
                .send(request_bytes)?;
            let content_type = response
                .headers()
                .get("content-type")
                .and_then(|value| value.to_str().ok())
                .unwrap_or("")
                .to_string();
            let body = read_body(&mut response)?;
            Ok((content_type, body))
        })?;
        // A reachable URL that is not actually a TSA endpoint (a
        // captive portal, a misconfigured proxy) tends to answer 200
        // with HTML; refusing the declared type here names the real
        // problem instead of a DER parse failure downstream.
        if !is_timestamp_reply(&content_type) {
            return Err(format!(
                "the TSA answered with content type {content_type:?} \
                 where {REPLY_CONTENT_TYPE:?} is required"
            )
            .into());
        }
        Ok(body)
    }
}

#[cfg(test)]
use super::test_http;

#[cfg(test)]
mod tests {
    use super::test_http::{http_response, serve_once};

    use super::*;

    #[test]
    fn the_reply_type_matches_without_its_parameters() {
        assert!(is_timestamp_reply("application/timestamp-reply"));
        assert!(is_timestamp_reply(
            "Application/Timestamp-Reply; charset=binary"
        ));
        assert!(is_timestamp_reply(" application/timestamp-reply "));
    }

    #[test]
    fn other_media_types_are_refused() {
        assert!(!is_timestamp_reply("text/html"));
        assert!(!is_timestamp_reply("application/timestamp-query"));
        assert!(!is_timestamp_reply(""));
    }

    #[test]
    fn an_exchange_posts_the_query_and_returns_the_reply_bytes() {
        let (url, seen_requests) = serve_once(http_response(
            "200 OK",
            REPLY_CONTENT_TYPE,
            b"reply-der",
        ));
        let mut live_tsa = HttpsTransport::new(&url);
        let reply = live_tsa
            .exchange(b"query-der")
            .expect("a well-formed reply returns");
        assert_eq!(reply, b"reply-der");
        let request_bytes = seen_requests
            .recv()
            .expect("the server observed the request");
        let request_text =
            String::from_utf8_lossy(&request_bytes).to_lowercase();
        assert!(request_text.starts_with("post /tsr"));
        assert!(
            request_text.contains("content-type: application/timestamp-query")
        );
    }

    #[test]
    fn a_reply_with_a_foreign_content_type_is_refused() {
        let (url, _seen_requests) = serve_once(http_response(
            "200 OK",
            "text/html",
            b"<html>portal</html>",
        ));
        let mut live_tsa = HttpsTransport::new(&url);
        let exchange_error = live_tsa
            .exchange(b"query-der")
            .expect_err("a foreign content type must be refused");
        assert!(exchange_error.to_string().contains("content type"));
    }

    #[test]
    fn an_error_status_is_refused() {
        let (url, _seen_requests) = serve_once(http_response(
            "500 Internal Server Error",
            REPLY_CONTENT_TYPE,
            b"reply-der",
        ));
        let mut live_tsa = HttpsTransport::new(&url);
        live_tsa
            .exchange(b"query-der")
            .expect_err("an error status must be refused");
    }

    #[test]
    fn a_reply_exceeding_the_size_cap_is_refused() {
        let oversized_body = vec![0u8; MAX_RESPONSE_BYTES as usize + 1];
        let (url, _seen_requests) = serve_once(http_response(
            "200 OK",
            REPLY_CONTENT_TYPE,
            &oversized_body,
        ));
        let mut live_tsa = HttpsTransport::new(&url);
        live_tsa
            .exchange(b"query-der")
            .expect_err("a body beyond the cap must be refused");
    }

    #[test]
    fn an_interrupted_call_is_repeated_within_the_bound() {
        let mut failures_left = INTERRUPT_RETRIES;
        let outcome = with_interrupt_retry(|| match failures_left {
            0 => Ok(b"answer".to_vec()),
            _ => {
                failures_left -= 1;
                Err(ureq::Error::Io(std::io::Error::from(
                    std::io::ErrorKind::Interrupted,
                )))
            }
        });
        assert_eq!(outcome.expect("the retried call answers"), b"answer");
    }

    #[test]
    fn an_endless_signal_storm_fails_instead_of_looping() {
        let mut attempts = 0;
        let outcome: Result<(), ureq::Error> = with_interrupt_retry(|| {
            attempts += 1;
            Err(ureq::Error::Io(std::io::Error::from(
                std::io::ErrorKind::Interrupted,
            )))
        });
        assert!(is_interrupted(&outcome.expect_err("the bound holds")));
        assert_eq!(attempts, INTERRUPT_RETRIES + 1);
    }

    #[test]
    fn other_io_failures_are_not_repeated() {
        let mut attempts = 0;
        let outcome: Result<(), ureq::Error> = with_interrupt_retry(|| {
            attempts += 1;
            Err(ureq::Error::Io(std::io::Error::from(
                std::io::ErrorKind::ConnectionRefused,
            )))
        });
        assert!(outcome.is_err());
        assert_eq!(attempts, 1);
    }

    #[test]
    fn a_fetch_returns_the_body_bytes_whatever_their_type() {
        let (url, _seen_requests) = serve_once(http_response(
            "200 OK",
            "application/pkix-crl",
            b"crl-der",
        ));
        let fetched = fetch(&url).expect("the fetch succeeds");
        assert_eq!(fetched, b"crl-der");
    }
}
