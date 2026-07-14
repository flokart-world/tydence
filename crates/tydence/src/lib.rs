//! RFC 3161 trusted timestamps for git-managed data.
//!
//! The proof is carried by manifests and timestamp tokens; git provides
//! transport and organization.

mod audit;
mod claims;
mod config;
mod deposits;
mod ess;
mod hex;
mod layout;
mod manifest;
mod oids;
mod snapshot;
mod staging;
mod stamp;
mod transport;
mod trust;
mod tsp;
mod verify;

#[cfg(test)]
mod test_git;
#[cfg(test)]
mod test_http;
#[cfg(test)]
mod test_pki;
#[cfg(test)]
mod test_stamp;

// gix types (ObjectId, Repository, Signature, ...) appear throughout
// the public signatures, which makes gix a public dependency of this
// crate; the re-export lets consumers name those types at the exact
// version tydence was built against instead of guessing one.
pub use gix;

pub use audit::{
    Audit, AuditInputs, ClaimFailure, ClaimVerdict, Error as AuditError,
    run as audit_repository,
};
pub use claims::Error as ClaimsError;
pub use config::{Error as ConfigError, Site};
pub use deposits::Error as DepositsError;
pub use manifest::{
    AnchorSpec, BindingEdge, BindingGroup, BindingOrderError, Entry, FileMode,
    MalformedField, Manifest, ManifestParseError, PastToken, PayloadHashes,
    UnprintableField, hash_payload, parse_manifest,
};
pub use snapshot::{
    Error as SnapshotError, run as enumerate_entries_from_snapshot,
};
pub use staging::{
    Error as StagingError, drop_artifacts, stage_deposits, staged_artifacts,
};
pub use stamp::{
    AcquireError, BindError, CreateError, CreateInputs, CreatedStamp,
    LtvError, OsEnvironment, SealError, SiteFailure, create_stamp,
    live_anchor,
};
pub use transport::HttpsTransport;
pub use trust::{Error as TrustError, load_anchor_file};
pub use tsp::{
    DenialStatus, Error as TspError, ImprintAlgorithm, Rfc3161Anchor,
    StampEnvironment, TimestampAnchor, TransportFailure, TsaTransport,
};
pub use verify::{
    AcceptedToken, BindingError, BoundStamp, BoundToken, ChainError,
    Disagreement, Error as StampError, ExtensionError, NormalizeError,
    RejectedToken, RevocationError, RevocationReason, SiteToken, StampInputs,
    StampSummary, TokenError, TokenSummary, TreeError, TrustData,
    VerificationBasis, derive_binding_edges, verify_binding_linkage,
    verify_binding_order, verify_stamp, verify_token, verify_tree_agreement,
};
