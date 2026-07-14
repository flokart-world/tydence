//! Revocation status at genTime, judged against the historical CRL
//! snapshots sealed with the stamp (stamping specification §7
//! check 3).
//!
//! The reference moment is always the token's genTime — the verifier
//! has no clock of its own. A certificate revoked before genTime
//! never qualifies. One revoked after genTime still qualifies when
//! the recorded reason rules out key compromise, which is what lets
//! a token outlive its certificate (RFC 3161 §4); any reason that
//! leaves compromise possible — including an absent one — fails
//! closed.

use der::Encode;
use std::fmt;
use std::time::SystemTime;
use x509_cert::Certificate;
use x509_cert::crl::{CertificateList, RevokedCert};
use x509_cert::ext::pkix::{CrlReason, KeyUsage};

use super::x509::{
    ExtensionError, RawSignature, decode_extension, verify_issued_signature,
};

/// CRL revocation reasons (RFC 5280 §5.3.1), mirrored locally so the
/// public error surface stays free of x509-cert types and callers
/// can match the closed set exhaustively.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RevocationReason {
    Unspecified,
    KeyCompromise,
    CaCompromise,
    AffiliationChanged,
    Superseded,
    CessationOfOperation,
    CertificateHold,
    RemoveFromCrl,
    PrivilegeWithdrawn,
    AaCompromise,
}

impl From<CrlReason> for RevocationReason {
    fn from(reason: CrlReason) -> Self {
        match reason {
            CrlReason::Unspecified => Self::Unspecified,
            CrlReason::KeyCompromise => Self::KeyCompromise,
            CrlReason::CaCompromise => Self::CaCompromise,
            CrlReason::AffiliationChanged => Self::AffiliationChanged,
            CrlReason::Superseded => Self::Superseded,
            CrlReason::CessationOfOperation => Self::CessationOfOperation,
            CrlReason::CertificateHold => Self::CertificateHold,
            CrlReason::RemoveFromCRL => Self::RemoveFromCrl,
            CrlReason::PrivilegeWithdrawn => Self::PrivilegeWithdrawn,
            CrlReason::AaCompromise => Self::AaCompromise,
        }
    }
}

/// The reasons that leave the certificate's key uncompromised, so a
/// token made before the revocation keeps its standing.
const TOLERATED_AFTER_GEN_TIME: &[RevocationReason] = &[
    RevocationReason::AffiliationChanged,
    RevocationReason::Superseded,
    RevocationReason::CessationOfOperation,
    RevocationReason::PrivilegeWithdrawn,
];

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Error {
    /// The issuer certificate's key usage rules out CRL signing, so
    /// no CRL it signed can be admitted.
    IssuerCannotSignCrls,
    /// No admissible CRL covers genTime, leaving the status
    /// undecidable.
    NoUsableCrl,
    /// The certificate was revoked at or before genTime.
    RevokedAtGenTime { revocation_date: SystemTime },
    /// The certificate was revoked after genTime for a reason — or
    /// with no reason — that leaves key compromise possible.
    DisqualifyingRevocation { reason: Option<RevocationReason> },
    /// A CRL entry for the certificate carries a critical extension
    /// this implementation cannot judge.
    CriticalEntryExtension,
    /// A CRL entry for the certificate is malformed.
    MalformedEntry { source: ExtensionError },
    /// The issuer certificate's own extensions are malformed, so its
    /// fitness to sign CRLs cannot be judged.
    MalformedIssuer { source: ExtensionError },
}

impl fmt::Display for Error {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IssuerCannotSignCrls => write!(
                formatter,
                "the issuer's key usage does not allow CRL signing"
            ),
            Self::NoUsableCrl => write!(
                formatter,
                "no admissible CRL covers the token's genTime"
            ),
            Self::RevokedAtGenTime { revocation_date } => write!(
                formatter,
                "the certificate was already revoked at genTime \
                 (revoked {revocation_date:?})"
            ),
            Self::DisqualifyingRevocation { reason } => write!(
                formatter,
                "the certificate's revocation ({reason:?}) does not rule \
                 out key compromise"
            ),
            Self::CriticalEntryExtension => write!(
                formatter,
                "a CRL entry carries an unsupported critical extension"
            ),
            Self::MalformedEntry { source } => {
                write!(formatter, "a CRL entry is malformed ({source})")
            }
            Self::MalformedIssuer { source } => write!(
                formatter,
                "the issuer certificate's extensions are malformed \
                 ({source})"
            ),
        }
    }
}

impl std::error::Error for Error {}

/// The certificate whose status is asked for, the certificate that
/// issued it (and whose key must have signed any admissible CRL),
/// and the token's genTime.
#[derive(Clone, Copy, Debug)]
pub struct RevocationSubject<'a> {
    pub certificate: &'a Certificate,
    pub issuer: &'a Certificate,
    pub gen_time: SystemTime,
}

/// Whether this CRL is admissible evidence about certificates the
/// issuer signed: issued under the same name, signed by the issuer's
/// key, internally consistent, and free of critical extensions this
/// implementation cannot judge (indirect and delta CRLs announce
/// themselves that way).
fn is_admissible(crl: &CertificateList, issuer: &Certificate) -> bool {
    let tbs = &crl.tbs_cert_list;
    if tbs.issuer != issuer.tbs_certificate.subject {
        return false;
    }
    if tbs.signature != crl.signature_algorithm {
        return false;
    }
    let carries_critical_extension = tbs
        .crl_extensions
        .iter()
        .flatten()
        .any(|extension| extension.critical);
    if carries_critical_extension {
        return false;
    }
    let Ok(message) = tbs.to_der() else {
        return false;
    };
    let Some(signature_bytes) = crl.signature.as_bytes() else {
        return false;
    };
    let signature = RawSignature {
        algorithm: &crl.signature_algorithm,
        bytes: signature_bytes,
    };
    verify_issued_signature(&message, &signature, issuer).is_ok()
}

/// Whether the CRL decides the status at genTime. Two readings both
/// reduce to this window: a CRL current at genTime (thisUpdate ≤
/// genTime ≤ nextUpdate), and a later snapshot sealed by a renewal
/// stamp (genTime < thisUpdate), which still lists every revocation
/// that could concern the certificate as long as it was issued
/// before the certificate expired. A CRL with no nextUpdate bounds
/// nothing and decides nothing.
fn decides_at_gen_time(
    crl: &CertificateList,
    subject: &RevocationSubject<'_>,
) -> bool {
    let Some(next_update) = &crl.tbs_cert_list.next_update else {
        return false;
    };
    let expiry = subject
        .certificate
        .tbs_certificate
        .validity
        .not_after
        .to_system_time();
    subject.gen_time <= next_update.to_system_time()
        && crl.tbs_cert_list.this_update.to_system_time() <= expiry
}

fn judge_entry(
    entry: &RevokedCert,
    gen_time: SystemTime,
) -> Result<(), Error> {
    let carries_critical_extension = entry
        .crl_entry_extensions
        .iter()
        .flatten()
        .any(|extension| extension.critical);
    if carries_critical_extension {
        return Err(Error::CriticalEntryExtension);
    }
    let reason =
        decode_extension::<CrlReason>(entry.crl_entry_extensions.as_ref())
            .map_err(|source| Error::MalformedEntry { source })?
            .map(|decoded| RevocationReason::from(decoded.value));
    let revocation_date = entry.revocation_date.to_system_time();
    if revocation_date <= gen_time {
        return Err(Error::RevokedAtGenTime { revocation_date });
    }
    let tolerated = reason.is_some_and(|known_reason| {
        TOLERATED_AFTER_GEN_TIME.contains(&known_reason)
    });
    if tolerated {
        Ok(())
    } else {
        Err(Error::DisqualifyingRevocation { reason })
    }
}

/// Judges the certificate's revocation status at genTime against the
/// supplied CRL snapshots, fail-closed: with no admissible CRL
/// deciding the moment, the status is undecidable and the check
/// fails. Adverse entries are judged on every admissible CRL, not
/// only the deciding ones.
pub fn ensure_unrevoked(
    subject: &RevocationSubject<'_>,
    crls: &[CertificateList],
) -> Result<(), Error> {
    // RFC 5280 §4.2.1.3: cRLSign is the bit that authorizes signing
    // CRLs. An absent extension restricts nothing.
    let issuer_key_usage = decode_extension::<KeyUsage>(
        subject.issuer.tbs_certificate.extensions.as_ref(),
    )
    .map_err(|source| Error::MalformedIssuer { source })?;
    let grants_crl_signing = issuer_key_usage
        .map(|decoded| decoded.value.crl_sign())
        .unwrap_or(true);
    if !grants_crl_signing {
        return Err(Error::IssuerCannotSignCrls);
    }
    let mut decided = false;
    for crl in crls {
        if !is_admissible(crl, subject.issuer) {
            continue;
        }
        let serial = &subject.certificate.tbs_certificate.serial_number;
        let entries = crl.tbs_cert_list.revoked_certificates.iter().flatten();
        for entry in entries {
            if &entry.serial_number == serial {
                judge_entry(entry, subject.gen_time)?;
            }
        }
        decided = decided || decides_at_gen_time(crl, subject);
    }
    if decided {
        Ok(())
    } else {
        Err(Error::NoUsableCrl)
    }
}

#[cfg(test)]
use super::test_pki;

#[cfg(test)]
mod tests {
    use x509_cert::ext::pkix::KeyUsages;

    use super::*;

    fn subject_of(authority: &test_pki::Authority) -> RevocationSubject<'_> {
        RevocationSubject {
            certificate: &authority.tsa_certificate,
            issuer: &authority.root_certificate,
            gen_time: test_pki::gen_time_moment(),
        }
    }

    fn crl_with_entries(
        authority: &test_pki::Authority,
        entries: Vec<x509_cert::crl::RevokedCert>,
    ) -> CertificateList {
        let mut blueprint = test_pki::standard_crl_blueprint();
        blueprint.entries = entries;
        test_pki::issue_crl(
            blueprint,
            &authority.root_certificate,
            &authority.root_key,
        )
    }

    fn verdict_for_entry(
        revoked_at_offset_seconds: i64,
        reason: Option<CrlReason>,
    ) -> Result<(), Error> {
        let authority = test_pki::standard_authority();
        let revoked_at = test_pki::moment_at(
            test_pki::GEN_TIME_UNIX_SECONDS
                .checked_add_signed(revoked_at_offset_seconds)
                .expect("offsets stay in range"),
        );
        let crls = vec![crl_with_entries(
            &authority,
            vec![test_pki::revoked_entry(2, revoked_at, reason)],
        )];
        ensure_unrevoked(&subject_of(&authority), &crls)
    }

    #[test]
    fn an_unlisted_certificate_clears_against_a_current_crl() {
        let authority = test_pki::standard_authority();
        let crls = vec![test_pki::standard_crl(&authority)];
        assert_eq!(ensure_unrevoked(&subject_of(&authority), &crls), Ok(()));
    }

    #[test]
    fn no_crl_at_all_is_undecidable() {
        let authority = test_pki::standard_authority();
        assert_eq!(
            ensure_unrevoked(&subject_of(&authority), &[]),
            Err(Error::NoUsableCrl)
        );
    }

    #[test]
    fn a_revocation_at_gen_time_disqualifies_whatever_the_reason() {
        assert_eq!(
            verdict_for_entry(0, Some(CrlReason::CessationOfOperation)),
            Err(Error::RevokedAtGenTime {
                revocation_date: test_pki::gen_time_moment(),
            })
        );
    }

    #[test]
    fn a_later_benign_revocation_keeps_the_certificate() {
        let offset =
            i64::try_from(test_pki::HOUR_SECONDS).expect("offsets fit");
        assert_eq!(
            verdict_for_entry(offset, Some(CrlReason::CessationOfOperation)),
            Ok(())
        );
        assert_eq!(
            verdict_for_entry(offset, Some(CrlReason::Superseded)),
            Ok(())
        );
        assert_eq!(
            verdict_for_entry(offset, Some(CrlReason::AffiliationChanged)),
            Ok(())
        );
        assert_eq!(
            verdict_for_entry(offset, Some(CrlReason::PrivilegeWithdrawn)),
            Ok(())
        );
    }

    #[test]
    fn a_later_compromise_revocation_disqualifies() {
        let offset =
            i64::try_from(test_pki::HOUR_SECONDS).expect("offsets fit");
        assert_eq!(
            verdict_for_entry(offset, Some(CrlReason::KeyCompromise)),
            Err(Error::DisqualifyingRevocation {
                reason: Some(RevocationReason::KeyCompromise),
            })
        );
    }

    #[test]
    fn a_later_revocation_without_a_reason_disqualifies() {
        let offset =
            i64::try_from(test_pki::HOUR_SECONDS).expect("offsets fit");
        assert_eq!(
            verdict_for_entry(offset, None),
            Err(Error::DisqualifyingRevocation { reason: None })
        );
    }

    #[test]
    fn a_certificate_hold_disqualifies() {
        let offset =
            i64::try_from(test_pki::HOUR_SECONDS).expect("offsets fit");
        assert_eq!(
            verdict_for_entry(offset, Some(CrlReason::CertificateHold)),
            Err(Error::DisqualifyingRevocation {
                reason: Some(RevocationReason::CertificateHold),
            })
        );
    }

    #[test]
    fn a_stale_crl_decides_nothing() {
        let authority = test_pki::standard_authority();
        let mut blueprint = test_pki::standard_crl_blueprint();
        blueprint.this_update_unix_seconds =
            test_pki::GEN_TIME_UNIX_SECONDS - 400 * test_pki::DAY_SECONDS;
        blueprint.next_update_unix_seconds = Some(
            test_pki::GEN_TIME_UNIX_SECONDS - 300 * test_pki::DAY_SECONDS,
        );
        let crls = vec![test_pki::issue_crl(
            blueprint,
            &authority.root_certificate,
            &authority.root_key,
        )];
        assert_eq!(
            ensure_unrevoked(&subject_of(&authority), &crls),
            Err(Error::NoUsableCrl)
        );
    }

    #[test]
    fn a_later_snapshot_still_decides() {
        // The renewal-stamp reading: a CRL issued after genTime and
        // before the certificate's expiry still lists any revocation
        // that could concern it.
        let authority = test_pki::standard_authority();
        let mut blueprint = test_pki::standard_crl_blueprint();
        blueprint.this_update_unix_seconds =
            test_pki::GEN_TIME_UNIX_SECONDS + 100 * test_pki::DAY_SECONDS;
        blueprint.next_update_unix_seconds = Some(
            test_pki::GEN_TIME_UNIX_SECONDS + 200 * test_pki::DAY_SECONDS,
        );
        let crls = vec![test_pki::issue_crl(
            blueprint,
            &authority.root_certificate,
            &authority.root_key,
        )];
        assert_eq!(ensure_unrevoked(&subject_of(&authority), &crls), Ok(()));
    }

    #[test]
    fn a_crl_without_next_update_decides_nothing() {
        let authority = test_pki::standard_authority();
        let mut blueprint = test_pki::standard_crl_blueprint();
        blueprint.next_update_unix_seconds = None;
        let crls = vec![test_pki::issue_crl(
            blueprint,
            &authority.root_certificate,
            &authority.root_key,
        )];
        assert_eq!(
            ensure_unrevoked(&subject_of(&authority), &crls),
            Err(Error::NoUsableCrl)
        );
    }

    #[test]
    fn a_crl_signed_by_a_stranger_is_not_admissible() {
        let authority = test_pki::standard_authority();
        let crl = test_pki::issue_crl(
            test_pki::standard_crl_blueprint(),
            &authority.root_certificate,
            &test_pki::signing_key_from_seed(0x77),
        );
        assert_eq!(
            ensure_unrevoked(&subject_of(&authority), &[crl]),
            Err(Error::NoUsableCrl)
        );
    }

    #[test]
    fn a_crl_with_a_critical_extension_is_not_admissible() {
        let authority = test_pki::standard_authority();
        let mut blueprint = test_pki::standard_crl_blueprint();
        // An issuing-distribution-point-style critical extension
        // announces scoping this implementation cannot judge.
        blueprint.extensions = Some(vec![test_pki::extension_of(
            &x509_cert::ext::pkix::SubjectKeyIdentifier(
                der::asn1::OctetString::new(vec![1, 2, 3])
                    .expect("short octet strings encode"),
            ),
            true,
        )]);
        let crls = vec![test_pki::issue_crl(
            blueprint,
            &authority.root_certificate,
            &authority.root_key,
        )];
        assert_eq!(
            ensure_unrevoked(&subject_of(&authority), &crls),
            Err(Error::NoUsableCrl)
        );
    }

    #[test]
    fn an_adverse_entry_on_a_stale_crl_still_disqualifies() {
        let authority = test_pki::standard_authority();
        let mut stale_blueprint = test_pki::standard_crl_blueprint();
        stale_blueprint.this_update_unix_seconds =
            test_pki::GEN_TIME_UNIX_SECONDS - 400 * test_pki::DAY_SECONDS;
        stale_blueprint.next_update_unix_seconds = Some(
            test_pki::GEN_TIME_UNIX_SECONDS - 300 * test_pki::DAY_SECONDS,
        );
        stale_blueprint.entries = vec![test_pki::revoked_entry(
            2,
            test_pki::moment_at(
                test_pki::GEN_TIME_UNIX_SECONDS + test_pki::HOUR_SECONDS,
            ),
            Some(CrlReason::KeyCompromise),
        )];
        let crls = vec![
            test_pki::issue_crl(
                stale_blueprint,
                &authority.root_certificate,
                &authority.root_key,
            ),
            test_pki::standard_crl(&authority),
        ];
        assert_eq!(
            ensure_unrevoked(&subject_of(&authority), &crls),
            Err(Error::DisqualifyingRevocation {
                reason: Some(RevocationReason::KeyCompromise),
            })
        );
    }

    #[test]
    fn an_issuer_unable_to_sign_crls_is_refused() {
        let root_key = test_pki::signing_key_from_seed(0x11);
        let crippled_root = test_pki::issue_certificate(
            test_pki::CertificateBlueprint {
                serial_byte: 1,
                issuer: test_pki::parse_name(test_pki::ROOT_NAME),
                subject: test_pki::parse_name(test_pki::ROOT_NAME),
                key_info: test_pki::key_info_of(&root_key),
                validity: test_pki::standard_validity(),
                extensions: vec![test_pki::extension_of(
                    &KeyUsage(KeyUsages::KeyCertSign.into()),
                    true,
                )],
            },
            &root_key,
        );
        let authority = test_pki::standard_authority();
        let subject = RevocationSubject {
            certificate: &authority.tsa_certificate,
            issuer: &crippled_root,
            gen_time: test_pki::gen_time_moment(),
        };
        assert_eq!(
            ensure_unrevoked(&subject, &[]),
            Err(Error::IssuerCannotSignCrls)
        );
    }
}
