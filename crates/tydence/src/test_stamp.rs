//! Stamping fixture harness for tests: a deterministic loopback TSA
//! answering real `TimeStampReq` exchanges with fixture-authority
//! tokens, and the wiring to stamp a fixture repository against it.
//! Shared by the stamping flow's own tests and the repository audit
//! tests, which judge what the flow seals.

use der::{Decode, Encode};
use gix::refs::transaction::PreviousValue;
use std::fs;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x509_tsp::{TimeStampReq, TimeStampResp, TspVersion};

use super::config;
use super::layout::CONFIG_PATH;
use super::stamp::{CreateError, CreateInputs, CreatedStamp, create_stamp};
use super::test_git::{commit_id_of, init_repository, run_git};
use super::test_http::{http_response, serve_repeatedly};
use super::test_pki;
use super::transport::HttpsTransport;
use super::tsp::{Rfc3161Anchor, StampEnvironment};

pub const FIXED_NONCE: [u8; 8] = [0x5E, 0xED, 0xC0, 0xDE, 0, 0, 0, 0x01];

#[derive(Clone)]
pub struct FixedEnvironment;

impl StampEnvironment for FixedEnvironment {
    fn draw_nonce(&mut self) -> [u8; 8] {
        FIXED_NONCE
    }

    fn now(&self) -> SystemTime {
        UNIX_EPOCH + Duration::from_secs(test_pki::GEN_TIME_UNIX_SECONDS)
    }
}

/// A live TSA over loopback HTTP: parses each request and answers
/// with a granted response whose token echoes the request's imprint
/// and nonce, signed by the fixture authority.
pub fn serve_tsa(authority: test_pki::Authority) -> String {
    serve_repeatedly(move |request_bytes| {
        let body_start = request_bytes
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("the request has headers")
            + 4;
        let request = TimeStampReq::from_der(&request_bytes[body_start..])
            .expect("the body is a TimeStampReq");
        assert_eq!(request.version, TspVersion::V1);
        assert!(request.cert_req);
        let mut tst_info = test_pki::standard_tst_info(b"placeholder");
        tst_info.message_imprint = request.message_imprint;
        tst_info.nonce = request.nonce;
        let content_bytes = test_pki::der_of(&tst_info);
        let mut parts =
            test_pki::standard_token_parts(b"placeholder", &authority);
        parts.attributes = test_pki::standard_attributes(
            &content_bytes,
            &authority.tsa_certificate,
        );
        parts.content_bytes = content_bytes;
        let token_bytes = test_pki::encode_token(&parts, &authority.tsa_key);
        let response = TimeStampResp {
            status: cmpv2::status::PkiStatusInfo {
                status: cmpv2::status::PkiStatus::Accepted,
                status_string: None,
                fail_info: None,
            },
            time_stamp_token: Some(
                cms::content_info::ContentInfo::from_der(&token_bytes)
                    .expect("the token parses back"),
            ),
        };
        http_response(
            "200 OK",
            "application/timestamp-reply",
            &response.to_der().expect("the response encodes"),
        )
    })
}

pub struct Fixture {
    pub tsa_url: String,
    pub crl_der: Vec<u8>,
    pub anchors: Vec<Vec<u8>>,
}

pub fn live_fixture() -> Fixture {
    // The CRL is issued by the root alone, so its bytes do not
    // depend on the TSA certificate that will carry the CDP URL —
    // which unties the knot of the URL existing only after the
    // server binds.
    let crl_der = test_pki::der_of(&test_pki::standard_crl(
        &test_pki::standard_authority(),
    ));
    let served_crl = crl_der.clone();
    let cdp_url = serve_repeatedly(move |_request_bytes| {
        http_response("200 OK", "application/pkix-crl", &served_crl)
    });
    let authority = test_pki::authority_with_crl_distribution(&cdp_url);
    let anchors = vec![test_pki::der_of(&authority.root_certificate)];
    let tsa_url = serve_tsa(authority);
    Fixture {
        tsa_url,
        crl_der,
        anchors,
    }
}

pub fn fixture_signature() -> gix::actor::Signature {
    gix::actor::Signature {
        name: "tydence-test".into(),
        email: "tydence-test@example.invalid".into(),
        time: gix::date::Time::new(test_pki::GEN_TIME_UNIX_SECONDS as i64, 0),
    }
}

// The configuration is HTTPS-only by specification, while the
// loopback fixture speaks plain HTTP (TLS has no deterministic
// fixture). The configuration therefore spells HTTPS, and the test
// anchor undoes the scheme at the same wiring boundary the
// command-line layer owns in live use.
pub fn https_spelling(url: &str) -> String {
    url.replacen("http://", "https://", 1)
}

pub fn test_anchor(
    site: &config::Site,
) -> Rfc3161Anchor<HttpsTransport, FixedEnvironment> {
    let plain_url = site.url.replacen("https://", "http://", 1);
    Rfc3161Anchor {
        transport: HttpsTransport::new(&plain_url),
        environment: FixedEnvironment,
        imprint_algorithm: site.imprint_algorithm,
    }
}

pub fn config_text(tsa_url: &str) -> String {
    format!(
        "Site loop\n\tURL {}\n\tImprint sha256\n\
         Profile solo\n\tUseSite loop\n",
        https_spelling(tsa_url)
    )
}

/// One committed fixture repository holding tracked content and the
/// stamping configuration pointed at the fixture TSA.
pub fn prepare_repository(repository_dir: &Path, fixture: &Fixture) {
    init_repository(repository_dir);
    fs::write(repository_dir.join("work.txt"), b"payload\n")
        .expect("the file writes");
    fs::create_dir_all(repository_dir.join(".tydence"))
        .expect("directories are created");
    fs::write(
        repository_dir.join(CONFIG_PATH),
        config_text(&fixture.tsa_url),
    )
    .expect("the configuration writes");
    run_git(repository_dir, &["add", "-A"]);
    run_git(repository_dir, &["commit", "-q", "-m", "content"]);
}

/// Stamps the fixture repository's HEAD onto its current branch,
/// through the whole live flow against the loopback TSA.
pub fn stamp_head(
    repository_dir: &Path,
    fixture: &Fixture,
) -> Result<CreatedStamp, CreateError> {
    let repository =
        gix::open(repository_dir).expect("fixture repository opens");
    let head = commit_id_of(repository_dir, "HEAD");
    let base_tree_id = repository
        .find_commit(head)
        .expect("HEAD is a commit")
        .tree_id()
        .expect("HEAD has a tree")
        .detach();
    let branch = format!(
        "refs/heads/{}",
        run_git(repository_dir, &["branch", "--show-current"])
    );
    let signature = fixture_signature();
    create_stamp(
        &repository,
        &CreateInputs {
            base_tree_id,
            profile_name: "solo",
            anchor_certificates: &fixture.anchors,
            parent_ids: &[head],
            message: "stamp fixture",
            author: &signature,
            committer: &signature,
            reference_name: &branch,
            expected: PreviousValue::MustExistAndMatch(
                gix::refs::Target::Object(head),
            ),
        },
        |_site_name, site| test_anchor(site),
    )
}
