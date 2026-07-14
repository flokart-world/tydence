//! RFC 3161 Time-Stamp Protocol client.
//!
//! Builds `TimeStampReq` messages, screens `TimeStampResp` messages
//! fail-closed, and hands back the raw `TimeStampToken` DER that gets
//! sealed into `.tydence/tokens/`. Full token verification (CMS
//! signature, certificate chain, revocation) is the verifier's job;
//! the screening here only decides whether a response is worth
//! sealing at all.

use cmpv2::status::{PkiStatus, PkiStatusInfo};
use cms::cert::x509::spki::AlgorithmIdentifier;
use cms::signed_data::SignedData;
use der::asn1::{GeneralizedTime, Int, OctetString};
use der::oid::ObjectIdentifier;
use der::{Any, Decode, Encode};
use sha2::{Digest, Sha256, Sha384, Sha512};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use x509_tsp::{
    MessageImprint, TimeStampReq, TimeStampResp, TspVersion, TstInfo,
};

use super::oids::{
    ID_CT_TST_INFO, ID_SHA_256, ID_SHA_384, ID_SHA_512, ID_SIGNED_DATA,
};

// A genTime far from the local clock signals a broken TSA or local
// clock, and refusing early keeps a questionable seal out of the
// repository. TSA accuracy and NTP drift both sit far below a minute,
// so a minute of divergence already means something is wrong.
const MAX_GEN_TIME_DIVERGENCE: Duration = Duration::from_secs(60);

// Single spelling of the boxed cause type; the role-specific aliases
// and error variants below all expand to it.
type FailureCause = Box<dyn std::error::Error + Send + Sync>;

pub type TransportFailure = FailureCause;

/// The non-granting `PKIStatus` values (RFC 3161 §2.4.2), mirrored
/// locally so the public error surface stays free of cmpv2 types and
/// callers can match the closed set exhaustively.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DenialStatus {
    Rejection,
    Waiting,
    RevocationWarning,
    RevocationNotification,
    KeyUpdateWarning,
}

/// Failure while acquiring a token from an RFC 3161 TSA.
///
/// Every screening decision is fail-closed: a response that cannot be
/// positively matched to the request that produced it is refused.
#[derive(Debug)]
pub enum Error {
    RequestEncoding {
        source: FailureCause,
    },
    Transport {
        source: TransportFailure,
    },
    MalformedResponse {
        source: FailureCause,
    },
    TokenNotGranted {
        status: DenialStatus,
        status_text: Option<String>,
        failure_info: Option<String>,
    },
    MissingToken,
    NotSignedData {
        content_type: String,
    },
    WrongSignerCount {
        count: usize,
    },
    MissingCertificates,
    NotTstInfo {
        econtent_type: String,
    },
    MissingTokenContent,
    UnexpectedExtensions,
    ImprintMismatch,
    NonceMismatch,
    ImplausibleGenTime {
        gen_time: SystemTime,
        local_time: SystemTime,
    },
}

impl std::fmt::Display for Error {
    fn fmt(
        &self,
        formatter: &mut std::fmt::Formatter<'_>,
    ) -> std::fmt::Result {
        match self {
            Self::RequestEncoding { .. } => {
                write!(formatter, "the timestamp request failed to encode")
            }
            Self::Transport { .. } => {
                write!(formatter, "the TSA exchange failed")
            }
            Self::MalformedResponse { .. } => {
                write!(formatter, "the TSA response failed to parse")
            }
            Self::TokenNotGranted {
                status,
                status_text,
                failure_info,
            } => {
                write!(
                    formatter,
                    "the TSA did not grant a token (status {status:?}"
                )?;
                if let Some(text) = status_text {
                    write!(formatter, ", {text:?}")?;
                }
                if let Some(info) = failure_info {
                    write!(formatter, ", {info}")?;
                }
                write!(formatter, ")")
            }
            Self::MissingToken => write!(
                formatter,
                "the TSA granted the request but returned no token"
            ),
            Self::NotSignedData { content_type } => write!(
                formatter,
                "the token is not a CMS SignedData \
                 (content type {content_type})"
            ),
            Self::WrongSignerCount { count } => write!(
                formatter,
                "the token carries {count} signer infos where RFC 3161 \
                 requires exactly one"
            ),
            Self::MissingCertificates => write!(
                formatter,
                "the token carries no TSA certificates although certReq \
                 was set"
            ),
            Self::NotTstInfo { econtent_type } => write!(
                formatter,
                "the token's signed content is not a TSTInfo \
                 (content type {econtent_type})"
            ),
            Self::MissingTokenContent => {
                write!(formatter, "the token's signed content is detached")
            }
            Self::UnexpectedExtensions => write!(
                formatter,
                "the TSTInfo carries extensions, which tydence refuses \
                 to seal"
            ),
            Self::ImprintMismatch => write!(
                formatter,
                "the token's message imprint differs from the one \
                 requested"
            ),
            Self::NonceMismatch => write!(
                formatter,
                "the token's nonce differs from the one requested"
            ),
            Self::ImplausibleGenTime {
                gen_time,
                local_time,
            } => write!(
                formatter,
                "the token's genTime ({gen_time:?}) diverges from the \
                 local clock ({local_time:?}) beyond tolerance"
            ),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::RequestEncoding { source }
            | Self::Transport { source }
            | Self::MalformedResponse { source } => Some(source.as_ref()),
            _ => None,
        }
    }
}

/// Digest family a site uses for its TSA message imprints.
///
/// Only the SHA-2 family appears here: no surveyed TSA accepts SHA-3
/// imprints, and cross-family insurance lives in the manifest's double
/// hashes, not in the imprint.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ImprintAlgorithm {
    Sha256,
    Sha384,
    Sha512,
}

impl ImprintAlgorithm {
    fn digest_oid(self) -> ObjectIdentifier {
        match self {
            Self::Sha256 => ID_SHA_256,
            Self::Sha384 => ID_SHA_384,
            Self::Sha512 => ID_SHA_512,
        }
    }

    // The verifier maps a token's self-declared digest OID back to
    // the family, so both sides of the protocol share one spelling
    // of the supported set.
    pub fn from_digest_oid(oid: ObjectIdentifier) -> Option<Self> {
        [Self::Sha256, Self::Sha384, Self::Sha512]
            .into_iter()
            .find(|algorithm| algorithm.digest_oid() == oid)
    }

    pub fn digest_payload(self, payload: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(payload).to_vec(),
            Self::Sha384 => Sha384::digest(payload).to_vec(),
            Self::Sha512 => Sha512::digest(payload).to_vec(),
        }
    }
}

/// The deterministic injection point requirement N3 mandates for the
/// two ambient inputs of a token acquisition: nonce randomness and
/// the local clock. Live use draws from the operating system; tests
/// and replay fixtures fix both so recorded exchanges stay
/// reproducible. The clock is only a plausibility tripwire against
/// the TSA-asserted genTime, never evidence.
pub trait StampEnvironment {
    fn draw_nonce(&mut self) -> [u8; 8];
    fn now(&self) -> SystemTime;
}

/// One request/response exchange with a TSA, transport-agnostic.
///
/// The live HTTPS transport arrives with the stamping flow; until
/// then the implementations are the in-memory mock TSA and the VCR
/// replay of recorded freeTSA exchanges.
pub trait TsaTransport {
    fn exchange(
        &mut self,
        request_bytes: &[u8],
    ) -> Result<Vec<u8>, TransportFailure>;
}

/// A source of timestamp tokens over some payload (requirement F9).
///
/// The RFC 3161 client is the initial concrete implementation; mock
/// anchors substitute for it in tests, and future anchor kinds slot
/// in behind the same boundary.
pub trait TimestampAnchor {
    type Error: std::error::Error;

    /// Obtains one raw token (DER bytes) covering `payload`.
    fn acquire_token(
        &mut self,
        payload: &[u8],
    ) -> Result<Vec<u8>, Self::Error>;
}

fn encode_nonce(nonce_bytes: [u8; 8]) -> Result<Int, Error> {
    let unsigned = nonce_bytes
        .iter()
        .position(|&byte| byte != 0)
        .map(|first_nonzero| &nonce_bytes[first_nonzero..])
        .unwrap_or(&[0]);
    // DER INTEGER is signed; a leading zero byte keeps a high first
    // bit from flipping the nonce negative.
    let mut content = Vec::with_capacity(unsigned.len() + 1);
    if unsigned[0] & 0x80 != 0 {
        content.push(0);
    }
    content.extend_from_slice(unsigned);
    Int::new(&content).map_err(|encode_error| Error::RequestEncoding {
        source: Box::new(encode_error),
    })
}

fn build_request(
    imprint_algorithm: ImprintAlgorithm,
    payload: &[u8],
    nonce: Int,
) -> Result<TimeStampReq, Error> {
    let digest = imprint_algorithm.digest_payload(payload);
    let hashed_message = OctetString::new(digest).map_err(|encode_error| {
        Error::RequestEncoding {
            source: Box::new(encode_error),
        }
    })?;
    Ok(TimeStampReq {
        version: TspVersion::V1,
        message_imprint: MessageImprint {
            hash_algorithm: AlgorithmIdentifier {
                oid: imprint_algorithm.digest_oid(),
                // RFC 5754 prefers absent parameters for SHA-2, but
                // the openssl lineage most TSAs run writes an explicit
                // NULL; sending NULL matches what they expect to echo.
                parameters: Some(Any::null()),
            },
            hashed_message,
        },
        req_policy: None,
        nonce: Some(nonce),
        // The TSA certificate chain must travel with the token so LTV
        // material can be pinned before sealing.
        cert_req: true,
        extensions: None,
    })
}

// RFC 5754 allows SHA-2 AlgorithmIdentifier parameters to be either
// absent or an explicit NULL, and TSAs re-encode either way; both
// spellings of "no parameters" therefore match, while anything else
// is a real mismatch. The verifier applies the same reading to the
// digest identifiers inside a token.
pub fn is_absent_or_null_parameter(maybe_parameters: &Option<Any>) -> bool {
    match maybe_parameters {
        None => true,
        Some(parameters) => *parameters == Any::null(),
    }
}

fn matches_sent_imprint(
    sent: &MessageImprint,
    received: &MessageImprint,
) -> bool {
    received.hash_algorithm.oid == sent.hash_algorithm.oid
        && is_absent_or_null_parameter(&received.hash_algorithm.parameters)
        && received.hashed_message == sent.hashed_message
}

fn join_status_text(status: &PkiStatusInfo<'_>) -> Option<String> {
    status.status_string.as_ref().map(|free_text| {
        free_text
            .iter()
            .map(|line| line.as_str())
            .collect::<Vec<_>>()
            .join("; ")
    })
}

fn ensure_granted(status: &PkiStatusInfo<'_>) -> Result<(), Error> {
    let denial = match status.status {
        PkiStatus::Accepted | PkiStatus::GrantedWithMods => return Ok(()),
        PkiStatus::Rejection => DenialStatus::Rejection,
        PkiStatus::Waiting => DenialStatus::Waiting,
        PkiStatus::RevocationWarning => DenialStatus::RevocationWarning,
        PkiStatus::RevocationNotification => {
            DenialStatus::RevocationNotification
        }
        PkiStatus::KeyUpdateWarning => DenialStatus::KeyUpdateWarning,
    };
    Err(Error::TokenNotGranted {
        status: denial,
        status_text: join_status_text(status),
        failure_info: status
            .fail_info
            .map(|failure_flags| format!("{failure_flags:?}")),
    })
}

fn ensure_plausible_gen_time(
    gen_time: &GeneralizedTime,
    local_time: SystemTime,
) -> Result<(), Error> {
    let token_time = UNIX_EPOCH + gen_time.to_unix_duration();
    let divergence = match token_time.duration_since(local_time) {
        Ok(token_ahead) => token_ahead,
        Err(token_behind) => token_behind.duration(),
    };
    if divergence > MAX_GEN_TIME_DIVERGENCE {
        return Err(Error::ImplausibleGenTime {
            gen_time: token_time,
            local_time,
        });
    }
    Ok(())
}

fn accept_response(
    request: &TimeStampReq,
    response_bytes: &[u8],
    local_time: SystemTime,
) -> Result<Vec<u8>, Error> {
    let response =
        TimeStampResp::from_der(response_bytes).map_err(|parse_error| {
            Error::MalformedResponse {
                source: Box::new(parse_error),
            }
        })?;
    ensure_granted(&response.status)?;
    let Some(token) = response.time_stamp_token else {
        return Err(Error::MissingToken);
    };
    if token.content_type != ID_SIGNED_DATA {
        return Err(Error::NotSignedData {
            content_type: token.content_type.to_string(),
        });
    }
    let signed_data: SignedData =
        token.content.decode_as().map_err(|parse_error| {
            Error::MalformedResponse {
                source: Box::new(parse_error),
            }
        })?;
    let signer_count = signed_data.signer_infos.0.len();
    if signer_count != 1 {
        return Err(Error::WrongSignerCount {
            count: signer_count,
        });
    }
    let has_certificates = signed_data
        .certificates
        .as_ref()
        .is_some_and(|certificates| !certificates.0.is_empty());
    if !has_certificates {
        return Err(Error::MissingCertificates);
    }
    let encapsulated = &signed_data.encap_content_info;
    if encapsulated.econtent_type != ID_CT_TST_INFO {
        return Err(Error::NotTstInfo {
            econtent_type: encapsulated.econtent_type.to_string(),
        });
    }
    let Some(econtent) = &encapsulated.econtent else {
        return Err(Error::MissingTokenContent);
    };
    let tst_info =
        TstInfo::from_der(econtent.value()).map_err(|parse_error| {
            Error::MalformedResponse {
                source: Box::new(parse_error),
            }
        })?;
    // No surveyed TSA emits TSTInfo extensions; anything that appears
    // could change the token's meaning, so it is refused rather than
    // sealed unexamined.
    if tst_info.extensions.is_some() {
        return Err(Error::UnexpectedExtensions);
    }
    if !matches_sent_imprint(
        &request.message_imprint,
        &tst_info.message_imprint,
    ) {
        return Err(Error::ImprintMismatch);
    }
    if tst_info.nonce != request.nonce {
        return Err(Error::NonceMismatch);
    }
    ensure_plausible_gen_time(&tst_info.gen_time, local_time)?;
    token
        .to_der()
        .map_err(|encode_error| Error::MalformedResponse {
            source: Box::new(encode_error),
        })
}

/// RFC 3161 implementation of [`TimestampAnchor`]: one instance per
/// site, pairing a TSA transport with the site's imprint algorithm.
#[derive(Debug)]
pub struct Rfc3161Anchor<ActualTransport, ActualEnvironment> {
    pub transport: ActualTransport,
    pub environment: ActualEnvironment,
    pub imprint_algorithm: ImprintAlgorithm,
}

impl<ActualTransport, ActualEnvironment> TimestampAnchor
    for Rfc3161Anchor<ActualTransport, ActualEnvironment>
where
    ActualTransport: TsaTransport,
    ActualEnvironment: StampEnvironment,
{
    type Error = Error;

    fn acquire_token(&mut self, payload: &[u8]) -> Result<Vec<u8>, Error> {
        let nonce = encode_nonce(self.environment.draw_nonce())?;
        let request = build_request(self.imprint_algorithm, payload, nonce)?;
        let request_bytes = request.to_der().map_err(|encode_error| {
            Error::RequestEncoding {
                source: Box::new(encode_error),
            }
        })?;
        let response_bytes = self
            .transport
            .exchange(&request_bytes)
            .map_err(|source| Error::Transport { source })?;
        accept_response(&request, &response_bytes, self.environment.now())
    }
}

#[cfg(test)]
use super::transport;

#[cfg(test)]
mod tests {
    use cmpv2::status::PkiFailureInfoValues;
    use cms::cert::x509::ext::pkix::SubjectKeyIdentifier;
    use cms::cert::{CertificateChoices, OtherCertificateFormat};
    use cms::content_info::{CmsVersion, ContentInfo};
    use cms::signed_data::{
        CertificateSet, EncapsulatedContentInfo, SignerIdentifier, SignerInfo,
        SignerInfos,
    };
    use der::Tag;
    use der::asn1::{SetOfVec, Utf8StringRef};
    use std::fs;
    use std::path::Path;

    use super::*;

    const MOCK_PAYLOAD: &[u8] = b"tydence mock payload\n";
    const MOCK_NONCE: [u8; 8] =
        [0x31, 0x4C, 0xFC, 0xE4, 0xE0, 0x65, 0x18, 0x27];
    const MOCK_GEN_TIME_SECONDS: u64 = 1_780_000_000;

    struct FixedEnvironment {
        nonce_bytes: [u8; 8],
        unix_seconds: u64,
    }

    impl StampEnvironment for FixedEnvironment {
        fn draw_nonce(&mut self) -> [u8; 8] {
            self.nonce_bytes
        }

        fn now(&self) -> SystemTime {
            UNIX_EPOCH + Duration::from_secs(self.unix_seconds)
        }
    }

    struct ScriptedTsa<Respond>(Respond);

    impl<Respond> TsaTransport for ScriptedTsa<Respond>
    where
        Respond: FnMut(&[u8]) -> Vec<u8>,
    {
        fn exchange(
            &mut self,
            request_bytes: &[u8],
        ) -> Result<Vec<u8>, TransportFailure> {
            Ok((self.0)(request_bytes))
        }
    }

    struct FailingTsa;

    impl TsaTransport for FailingTsa {
        fn exchange(
            &mut self,
            _request_bytes: &[u8],
        ) -> Result<Vec<u8>, TransportFailure> {
            Err("the wire went dark".into())
        }
    }

    fn sha2_identifier(oid: ObjectIdentifier) -> AlgorithmIdentifier<Any> {
        AlgorithmIdentifier {
            oid,
            parameters: Some(Any::null()),
        }
    }

    fn placeholder_signer_info(key_id_byte: u8) -> SignerInfo {
        SignerInfo {
            version: CmsVersion::V3,
            sid: SignerIdentifier::SubjectKeyIdentifier(SubjectKeyIdentifier(
                OctetString::new(vec![key_id_byte; 20])
                    .expect("key id encodes"),
            )),
            digest_alg: sha2_identifier(ID_SHA_256),
            signed_attrs: None,
            signature_algorithm: sha2_identifier(ID_SHA_256),
            signature: OctetString::new(vec![0xCD; 8])
                .expect("signature encodes"),
            unsigned_attrs: None,
        }
    }

    fn placeholder_certificates() -> CertificateSet {
        let placeholder = CertificateChoices::Other(OtherCertificateFormat {
            other_cert_format: ObjectIdentifier::new_unwrap(
                "1.3.6.1.4.1.99999.1",
            ),
            other_cert: Any::null(),
        });
        let mut choices = SetOfVec::new();
        choices.insert(placeholder).expect("one certificate");
        CertificateSet(choices)
    }

    fn granted_status() -> PkiStatusInfo<'static> {
        PkiStatusInfo {
            status: PkiStatus::Accepted,
            status_string: None,
            fail_info: None,
        }
    }

    fn echoed_tst_info(request_bytes: &[u8]) -> TstInfo {
        let request =
            TimeStampReq::from_der(request_bytes).expect("request parses");
        TstInfo {
            version: TspVersion::V1,
            policy: ObjectIdentifier::new_unwrap("1.2.3.4.1"),
            message_imprint: request.message_imprint,
            serial_number: Int::new(&[0x2A]).expect("serial encodes"),
            gen_time: GeneralizedTime::from_unix_duration(
                Duration::from_secs(MOCK_GEN_TIME_SECONDS),
            )
            .expect("gen time encodes"),
            accuracy: None,
            ordering: false,
            nonce: request.nonce,
            tsa: None,
            extensions: None,
        }
    }

    struct ResponseParts {
        status: PkiStatusInfo<'static>,
        token_type: ObjectIdentifier,
        econtent_type: ObjectIdentifier,
        tst_info: Option<TstInfo>,
        certificates: Option<CertificateSet>,
        signer_infos: Vec<SignerInfo>,
    }

    fn granted_parts(request_bytes: &[u8]) -> ResponseParts {
        ResponseParts {
            status: granted_status(),
            token_type: ID_SIGNED_DATA,
            econtent_type: ID_CT_TST_INFO,
            tst_info: Some(echoed_tst_info(request_bytes)),
            certificates: Some(placeholder_certificates()),
            signer_infos: vec![placeholder_signer_info(0xAB)],
        }
    }

    fn encode_response(parts: ResponseParts) -> Vec<u8> {
        let econtent = parts.tst_info.map(|tst_info| {
            let tst_bytes = tst_info.to_der().expect("TSTInfo encodes");
            Any::new(Tag::OctetString, tst_bytes)
                .expect("TSTInfo wraps into an octet string")
        });
        let mut signer_set = SetOfVec::new();
        for signer_info in parts.signer_infos {
            signer_set.insert(signer_info).expect("signer inserts");
        }
        let mut digest_algorithms = SetOfVec::new();
        digest_algorithms
            .insert(sha2_identifier(ID_SHA_256))
            .expect("digest algorithm inserts");
        let signed_data = SignedData {
            version: CmsVersion::V3,
            digest_algorithms,
            encap_content_info: EncapsulatedContentInfo {
                econtent_type: parts.econtent_type,
                econtent,
            },
            certificates: parts.certificates,
            crls: None,
            signer_infos: SignerInfos(signer_set),
        };
        let response = TimeStampResp {
            status: parts.status,
            time_stamp_token: Some(ContentInfo {
                content_type: parts.token_type,
                content: Any::encode_from(&signed_data)
                    .expect("SignedData wraps"),
            }),
        };
        response.to_der().expect("response encodes")
    }

    fn sha256_anchor<Respond>(
        respond: Respond,
    ) -> Rfc3161Anchor<ScriptedTsa<Respond>, FixedEnvironment>
    where
        Respond: FnMut(&[u8]) -> Vec<u8>,
    {
        Rfc3161Anchor {
            transport: ScriptedTsa(respond),
            environment: FixedEnvironment {
                nonce_bytes: MOCK_NONCE,
                unix_seconds: MOCK_GEN_TIME_SECONDS,
            },
            imprint_algorithm: ImprintAlgorithm::Sha256,
        }
    }

    struct CannedAnchor(Vec<u8>);

    impl TimestampAnchor for CannedAnchor {
        type Error = Error;

        fn acquire_token(
            &mut self,
            _payload: &[u8],
        ) -> Result<Vec<u8>, Error> {
            Ok(self.0.clone())
        }
    }

    fn stamp_through<Anchor: TimestampAnchor>(
        anchor: &mut Anchor,
    ) -> Result<Vec<u8>, Anchor::Error> {
        anchor.acquire_token(MOCK_PAYLOAD)
    }

    const FIXTURE_PAYLOAD: &[u8] = b"tydence freetsa fixture payload\n";
    const SHA256_FIXTURE_NONCE: [u8; 8] =
        [0x5E, 0xED, 0xC0, 0xDE, 0x00, 0x00, 0x02, 0x56];
    const SHA384_FIXTURE_NONCE: [u8; 8] =
        [0x5E, 0xED, 0xC0, 0xDE, 0x00, 0x00, 0x03, 0x84];
    const SHA512_FIXTURE_NONCE: [u8; 8] =
        [0x5E, 0xED, 0xC0, 0xDE, 0x00, 0x00, 0x05, 0x12];

    fn fixture_request_bytes(
        imprint_algorithm: ImprintAlgorithm,
        nonce_bytes: [u8; 8],
    ) -> Vec<u8> {
        let nonce = encode_nonce(nonce_bytes).expect("nonce encodes");
        build_request(imprint_algorithm, FIXTURE_PAYLOAD, nonce)
            .expect("request builds")
            .to_der()
            .expect("request encodes")
    }

    struct ReplayTransport {
        expected_request: Vec<u8>,
        recorded_response: Vec<u8>,
    }

    impl TsaTransport for ReplayTransport {
        fn exchange(
            &mut self,
            request_bytes: &[u8],
        ) -> Result<Vec<u8>, TransportFailure> {
            // Byte equality against the recorded request proves the
            // builder still produces exactly what the live TSA was
            // sent when the cassette was recorded.
            assert_eq!(
                request_bytes,
                self.expected_request.as_slice(),
                "the rebuilt request no longer matches the recording"
            );
            Ok(self.recorded_response.clone())
        }
    }

    const RECORD_CASSETTES_ENV: &str = "TYDENCE_RECORD_FREETSA";

    struct CassettePaths {
        request: std::path::PathBuf,
        response: std::path::PathBuf,
    }

    fn cassette_paths(name: &str) -> CassettePaths {
        let cassette_dir = Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/freetsa");
        CassettePaths {
            request: cassette_dir.join(format!("{name}.tsq")),
            response: cassette_dir.join(format!("{name}.tsr")),
        }
    }

    fn record_freetsa_cassette(paths: &CassettePaths, request_bytes: &[u8]) {
        let cassette_dir = paths
            .request
            .parent()
            .expect("the cassette path has a directory");
        fs::create_dir_all(cassette_dir)
            .expect("the cassette directory is creatable");
        fs::write(&paths.request, request_bytes)
            .expect("the cassette request writes");
        // Recording runs through the in-process transport the
        // stamping flow uses, so a cassette also proves that
        // transport against the live TSA at recording time.
        let mut live_tsa =
            transport::HttpsTransport::new("https://freetsa.org/tsr");
        let response_bytes = live_tsa
            .exchange(request_bytes)
            .expect("the freeTSA recording succeeds");
        fs::write(&paths.response, &response_bytes)
            .expect("the cassette response writes");
    }

    fn read_cassette_file(cassette_file: &Path) -> Vec<u8> {
        fs::read(cassette_file).unwrap_or_else(|read_error| {
            panic!(
                "the freeTSA cassette file {} is unreadable \
                 ({read_error}); rerun the tests once with \
                 {RECORD_CASSETTES_ENV}=1 to record the cassettes over \
                 the network",
                cassette_file.display()
            )
        })
    }

    /// Provides one freeTSA cassette — the VCR-style request/response
    /// pair under `tests/fixtures/freetsa`. The mode is decided by
    /// [`RECORD_CASSETTES_ENV`] alone: when set, the cassette is
    /// re-recorded over the network unconditionally; when unset, the
    /// recorded pair is replayed, and a missing cassette or a request
    /// that no longer matches the recorded one fails with an
    /// instruction to re-record.
    fn freetsa_cassette(
        name: &str,
        imprint_algorithm: ImprintAlgorithm,
        nonce_bytes: [u8; 8],
    ) -> ReplayTransport {
        let paths = cassette_paths(name);
        if std::env::var_os(RECORD_CASSETTES_ENV).is_some() {
            record_freetsa_cassette(
                &paths,
                &fixture_request_bytes(imprint_algorithm, nonce_bytes),
            );
        }
        ReplayTransport {
            expected_request: read_cassette_file(&paths.request),
            recorded_response: read_cassette_file(&paths.response),
        }
    }

    // The replay clock sits on the recorded genTime: the plausibility
    // tripwire aims at live acquisition, and its boundary behavior is
    // pinned by the mock-clock tests above.
    fn recorded_gen_time_seconds(response_bytes: &[u8]) -> u64 {
        let response = TimeStampResp::from_der(response_bytes)
            .expect("the cassette response parses");
        let token = response
            .time_stamp_token
            .expect("the cassette response carries a token");
        let signed_data: SignedData = token
            .content
            .decode_as()
            .expect("the cassette token is a SignedData");
        let econtent = signed_data
            .encap_content_info
            .econtent
            .expect("the cassette token carries its TSTInfo");
        let tst_info = TstInfo::from_der(econtent.value())
            .expect("the cassette TSTInfo parses");
        tst_info.gen_time.to_unix_duration().as_secs()
    }

    fn replay_freetsa_cassette(
        name: &str,
        imprint_algorithm: ImprintAlgorithm,
        nonce_bytes: [u8; 8],
    ) {
        let cassette = freetsa_cassette(name, imprint_algorithm, nonce_bytes);
        let recorded_response = cassette.recorded_response.clone();
        let mut anchor = Rfc3161Anchor {
            transport: cassette,
            environment: FixedEnvironment {
                nonce_bytes,
                unix_seconds: recorded_gen_time_seconds(&recorded_response),
            },
            imprint_algorithm,
        };
        let token = anchor
            .acquire_token(FIXTURE_PAYLOAD)
            .expect("the recorded exchange replays");
        assert!(
            recorded_response
                .windows(token.len())
                .any(|window| window == token.as_slice()),
            "the returned token must be a byte-faithful slice of the \
             recorded response"
        );
    }

    #[test]
    fn a_granted_response_yields_the_token_bytes() {
        let mut anchor = sha256_anchor(|request_bytes| {
            encode_response(granted_parts(request_bytes))
        });
        let token = anchor
            .acquire_token(MOCK_PAYLOAD)
            .expect("an honest exchange yields a token");
        let parsed = ContentInfo::from_der(&token).expect("token parses back");
        assert_eq!(parsed.content_type, ID_SIGNED_DATA);
    }

    #[test]
    fn the_request_carries_imprint_nonce_and_cert_req() {
        let mut anchor = sha256_anchor(|request_bytes| {
            let request =
                TimeStampReq::from_der(request_bytes).expect("request parses");
            assert_eq!(request.version, TspVersion::V1);
            assert_eq!(request.message_imprint.hash_algorithm.oid, ID_SHA_256);
            assert_eq!(
                request.message_imprint.hash_algorithm.parameters,
                Some(Any::null())
            );
            assert_eq!(
                request.message_imprint.hashed_message.as_bytes(),
                Sha256::digest(MOCK_PAYLOAD).as_slice()
            );
            assert_eq!(
                request.nonce,
                Some(encode_nonce(MOCK_NONCE).expect("nonce encodes"))
            );
            assert!(request.cert_req);
            assert!(request.req_policy.is_none());
            assert!(request.extensions.is_none());
            encode_response(granted_parts(request_bytes))
        });
        anchor
            .acquire_token(MOCK_PAYLOAD)
            .expect("the request assertions ran inside the transport");
    }

    #[test]
    fn each_imprint_algorithm_routes_to_its_own_digest() {
        assert_eq!(
            ImprintAlgorithm::Sha256.digest_payload(b"abc"),
            Sha256::digest(b"abc").to_vec()
        );
        assert_eq!(
            ImprintAlgorithm::Sha384.digest_payload(b"abc"),
            Sha384::digest(b"abc").to_vec()
        );
        assert_eq!(
            ImprintAlgorithm::Sha512.digest_payload(b"abc"),
            Sha512::digest(b"abc").to_vec()
        );
    }

    #[test]
    fn each_imprint_algorithm_names_its_own_oid() {
        assert_eq!(
            ImprintAlgorithm::Sha256.digest_oid().to_string(),
            "2.16.840.1.101.3.4.2.1"
        );
        assert_eq!(
            ImprintAlgorithm::Sha384.digest_oid().to_string(),
            "2.16.840.1.101.3.4.2.2"
        );
        assert_eq!(
            ImprintAlgorithm::Sha512.digest_oid().to_string(),
            "2.16.840.1.101.3.4.2.3"
        );
    }

    #[test]
    fn a_high_bit_nonce_encodes_as_a_positive_integer() {
        let nonce =
            encode_nonce([0x80, 0, 0, 0, 0, 0, 0, 1]).expect("nonce encodes");
        assert_eq!(nonce.as_bytes(), &[0x00, 0x80, 0, 0, 0, 0, 0, 0, 1]);
    }

    #[test]
    fn a_nonce_drops_leading_zero_bytes() {
        let nonce = encode_nonce([0, 0, 0, 0, 0, 0, 0x12, 0x34])
            .expect("nonce encodes");
        assert_eq!(nonce.as_bytes(), &[0x12, 0x34]);
    }

    #[test]
    fn a_zero_nonce_encodes_canonically() {
        let nonce = encode_nonce([0; 8]).expect("nonce encodes");
        assert_eq!(nonce.as_bytes(), &[0x00]);
    }

    #[test]
    fn a_rejection_status_fails_closed_with_diagnostics() {
        let mut anchor = sha256_anchor(|_request_bytes| {
            let response = TimeStampResp {
                status: PkiStatusInfo {
                    status: PkiStatus::Rejection,
                    status_string: Some(vec![
                        Utf8StringRef::new("no such policy")
                            .expect("text encodes"),
                    ]),
                    fail_info: Some(
                        PkiFailureInfoValues::UnacceptedPolicy.into(),
                    ),
                },
                time_stamp_token: None,
            };
            response.to_der().expect("response encodes")
        });
        let acquire_error = anchor
            .acquire_token(MOCK_PAYLOAD)
            .expect_err("a rejection must be refused");
        let Error::TokenNotGranted {
            status,
            status_text,
            failure_info,
        } = acquire_error
        else {
            panic!("expected TokenNotGranted, got {acquire_error:?}");
        };
        assert_eq!(status, DenialStatus::Rejection);
        assert_eq!(status_text.as_deref(), Some("no such policy"));
        assert!(failure_info.is_some());
    }

    #[test]
    fn a_waiting_status_fails_closed() {
        let mut anchor = sha256_anchor(|_request_bytes| {
            let response = TimeStampResp {
                status: PkiStatusInfo {
                    status: PkiStatus::Waiting,
                    status_string: None,
                    fail_info: None,
                },
                time_stamp_token: None,
            };
            response.to_der().expect("response encodes")
        });
        let acquire_error = anchor
            .acquire_token(MOCK_PAYLOAD)
            .expect_err("a waiting status must be refused");
        assert!(matches!(
            acquire_error,
            Error::TokenNotGranted {
                status: DenialStatus::Waiting,
                ..
            }
        ));
    }

    #[test]
    fn a_granted_status_without_token_fails_closed() {
        let mut anchor = sha256_anchor(|_request_bytes| {
            let response = TimeStampResp {
                status: granted_status(),
                time_stamp_token: None,
            };
            response.to_der().expect("response encodes")
        });
        let acquire_error = anchor
            .acquire_token(MOCK_PAYLOAD)
            .expect_err("a grant without token must be refused");
        assert!(matches!(acquire_error, Error::MissingToken));
    }

    #[test]
    fn a_token_that_is_not_signed_data_fails_closed() {
        let mut anchor = sha256_anchor(|request_bytes| {
            let mut parts = granted_parts(request_bytes);
            parts.token_type =
                ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
            encode_response(parts)
        });
        let acquire_error = anchor
            .acquire_token(MOCK_PAYLOAD)
            .expect_err("a non-SignedData token must be refused");
        assert!(matches!(acquire_error, Error::NotSignedData { .. }));
    }

    #[test]
    fn a_token_whose_content_is_not_tst_info_fails_closed() {
        let mut anchor = sha256_anchor(|request_bytes| {
            let mut parts = granted_parts(request_bytes);
            parts.econtent_type =
                ObjectIdentifier::new_unwrap("1.2.840.113549.1.7.1");
            encode_response(parts)
        });
        let acquire_error = anchor
            .acquire_token(MOCK_PAYLOAD)
            .expect_err("a non-TSTInfo content must be refused");
        assert!(matches!(acquire_error, Error::NotTstInfo { .. }));
    }

    #[test]
    fn a_detached_token_content_fails_closed() {
        let mut anchor = sha256_anchor(|request_bytes| {
            let mut parts = granted_parts(request_bytes);
            parts.tst_info = None;
            encode_response(parts)
        });
        let acquire_error = anchor
            .acquire_token(MOCK_PAYLOAD)
            .expect_err("a detached content must be refused");
        assert!(matches!(acquire_error, Error::MissingTokenContent));
    }

    #[test]
    fn zero_signer_infos_fail_closed() {
        let mut anchor = sha256_anchor(|request_bytes| {
            let mut parts = granted_parts(request_bytes);
            parts.signer_infos = Vec::new();
            encode_response(parts)
        });
        let acquire_error = anchor
            .acquire_token(MOCK_PAYLOAD)
            .expect_err("zero signers must be refused");
        assert!(matches!(
            acquire_error,
            Error::WrongSignerCount { count: 0 }
        ));
    }

    #[test]
    fn two_signer_infos_fail_closed() {
        let mut anchor = sha256_anchor(|request_bytes| {
            let mut parts = granted_parts(request_bytes);
            parts.signer_infos = vec![
                placeholder_signer_info(0xAB),
                placeholder_signer_info(0xAC),
            ];
            encode_response(parts)
        });
        let acquire_error = anchor
            .acquire_token(MOCK_PAYLOAD)
            .expect_err("two signers must be refused");
        assert!(matches!(
            acquire_error,
            Error::WrongSignerCount { count: 2 }
        ));
    }

    #[test]
    fn a_response_without_certificates_fails_closed() {
        let mut anchor = sha256_anchor(|request_bytes| {
            let mut parts = granted_parts(request_bytes);
            parts.certificates = None;
            encode_response(parts)
        });
        let acquire_error = anchor
            .acquire_token(MOCK_PAYLOAD)
            .expect_err("missing certificates must be refused");
        assert!(matches!(acquire_error, Error::MissingCertificates));
    }

    #[test]
    fn tst_info_extensions_fail_closed() {
        let mut anchor = sha256_anchor(|request_bytes| {
            let mut parts = granted_parts(request_bytes);
            let tst_info = parts.tst_info.as_mut().expect("token present");
            tst_info.extensions = Some(Vec::new());
            encode_response(parts)
        });
        let acquire_error = anchor
            .acquire_token(MOCK_PAYLOAD)
            .expect_err("extensions must be refused");
        assert!(matches!(acquire_error, Error::UnexpectedExtensions));
    }

    #[test]
    fn an_echoed_imprint_with_different_digest_fails_closed() {
        let mut anchor = sha256_anchor(|request_bytes| {
            let mut parts = granted_parts(request_bytes);
            let tst_info = parts.tst_info.as_mut().expect("token present");
            tst_info.message_imprint.hashed_message =
                OctetString::new(vec![0u8; 32]).expect("digest encodes");
            encode_response(parts)
        });
        let acquire_error = anchor
            .acquire_token(MOCK_PAYLOAD)
            .expect_err("a foreign digest must be refused");
        assert!(matches!(acquire_error, Error::ImprintMismatch));
    }

    #[test]
    fn an_echoed_imprint_with_different_algorithm_fails_closed() {
        let mut anchor = sha256_anchor(|request_bytes| {
            let mut parts = granted_parts(request_bytes);
            let tst_info = parts.tst_info.as_mut().expect("token present");
            tst_info.message_imprint.hash_algorithm.oid = ID_SHA_384;
            encode_response(parts)
        });
        let acquire_error = anchor
            .acquire_token(MOCK_PAYLOAD)
            .expect_err("a foreign algorithm must be refused");
        assert!(matches!(acquire_error, Error::ImprintMismatch));
    }

    #[test]
    fn an_absent_digest_parameter_is_accepted() {
        let mut anchor = sha256_anchor(|request_bytes| {
            let mut parts = granted_parts(request_bytes);
            let tst_info = parts.tst_info.as_mut().expect("token present");
            tst_info.message_imprint.hash_algorithm.parameters = None;
            encode_response(parts)
        });
        anchor
            .acquire_token(MOCK_PAYLOAD)
            .expect("RFC 5754 absent parameters are equivalent to NULL");
    }

    #[test]
    fn an_exotic_digest_parameter_fails_closed() {
        let mut anchor = sha256_anchor(|request_bytes| {
            let mut parts = granted_parts(request_bytes);
            let tst_info = parts.tst_info.as_mut().expect("token present");
            tst_info.message_imprint.hash_algorithm.parameters = Some(
                Any::new(Tag::OctetString, vec![0x01])
                    .expect("parameter encodes"),
            );
            encode_response(parts)
        });
        let acquire_error = anchor
            .acquire_token(MOCK_PAYLOAD)
            .expect_err("an exotic parameter must be refused");
        assert!(matches!(acquire_error, Error::ImprintMismatch));
    }

    #[test]
    fn a_missing_nonce_fails_closed() {
        let mut anchor = sha256_anchor(|request_bytes| {
            let mut parts = granted_parts(request_bytes);
            let tst_info = parts.tst_info.as_mut().expect("token present");
            tst_info.nonce = None;
            encode_response(parts)
        });
        let acquire_error = anchor
            .acquire_token(MOCK_PAYLOAD)
            .expect_err("a dropped nonce must be refused");
        assert!(matches!(acquire_error, Error::NonceMismatch));
    }

    #[test]
    fn a_different_nonce_fails_closed() {
        let mut anchor = sha256_anchor(|request_bytes| {
            let mut parts = granted_parts(request_bytes);
            let tst_info = parts.tst_info.as_mut().expect("token present");
            tst_info.nonce = Some(Int::new(&[0x7F]).expect("nonce encodes"));
            encode_response(parts)
        });
        let acquire_error = anchor
            .acquire_token(MOCK_PAYLOAD)
            .expect_err("a wrong nonce must be refused");
        assert!(matches!(acquire_error, Error::NonceMismatch));
    }

    #[test]
    fn a_gen_time_within_tolerance_is_accepted() {
        let mut anchor = sha256_anchor(|request_bytes| {
            encode_response(granted_parts(request_bytes))
        });
        anchor.environment.unix_seconds = MOCK_GEN_TIME_SECONDS + 60;
        anchor
            .acquire_token(MOCK_PAYLOAD)
            .expect("divergence exactly at the tolerance is accepted");
    }

    #[test]
    fn a_gen_time_far_from_the_local_clock_fails_closed() {
        let mut anchor = sha256_anchor(|request_bytes| {
            encode_response(granted_parts(request_bytes))
        });
        anchor.environment.unix_seconds = MOCK_GEN_TIME_SECONDS + 61;
        let acquire_error = anchor
            .acquire_token(MOCK_PAYLOAD)
            .expect_err("one second beyond the tolerance must be refused");
        assert!(matches!(acquire_error, Error::ImplausibleGenTime { .. }));
    }

    #[test]
    fn a_transport_failure_surfaces_as_a_transport_error() {
        let mut anchor = Rfc3161Anchor {
            transport: FailingTsa,
            environment: FixedEnvironment {
                nonce_bytes: MOCK_NONCE,
                unix_seconds: MOCK_GEN_TIME_SECONDS,
            },
            imprint_algorithm: ImprintAlgorithm::Sha256,
        };
        let acquire_error = anchor
            .acquire_token(MOCK_PAYLOAD)
            .expect_err("a dead wire must surface");
        assert!(matches!(acquire_error, Error::Transport { .. }));
    }

    #[test]
    fn trailing_bytes_after_the_response_fail_closed() {
        let mut anchor = sha256_anchor(|request_bytes| {
            let mut response_bytes =
                encode_response(granted_parts(request_bytes));
            response_bytes.push(0x00);
            response_bytes
        });
        let acquire_error = anchor
            .acquire_token(MOCK_PAYLOAD)
            .expect_err("trailing bytes must be refused");
        assert!(matches!(acquire_error, Error::MalformedResponse { .. }));
    }

    #[test]
    fn any_anchor_implementation_substitutes_behind_the_trait() {
        let mut canned = CannedAnchor(vec![0xC0, 0xFF, 0xEE]);
        let token =
            stamp_through(&mut canned).expect("the canned token returns");
        assert_eq!(token, vec![0xC0, 0xFF, 0xEE]);
    }

    #[test]
    fn the_freetsa_sha256_cassette_replays_end_to_end() {
        replay_freetsa_cassette(
            "sha256",
            ImprintAlgorithm::Sha256,
            SHA256_FIXTURE_NONCE,
        );
    }

    #[test]
    fn the_freetsa_sha384_cassette_replays_end_to_end() {
        replay_freetsa_cassette(
            "sha384",
            ImprintAlgorithm::Sha384,
            SHA384_FIXTURE_NONCE,
        );
    }

    #[test]
    fn the_freetsa_sha512_cassette_replays_end_to_end() {
        replay_freetsa_cassette(
            "sha512",
            ImprintAlgorithm::Sha512,
            SHA512_FIXTURE_NONCE,
        );
    }
}
