//! Stamp verification (stamping specification §7): the four checks
//! and the combined fail-closed verdict. The verdict itself lives in
//! [`stamp`]; the other modules each carry one check or the plumbing
//! shared between them.

use super::ess;
use super::manifest;
use super::oids;
use super::tsp;

#[cfg(test)]
use super::{test_pki, transport};

mod binding;
mod path;
mod revocation;
mod stamp;
mod token;
mod tree;
mod x509;

pub use binding::{
    BoundStamp, BoundToken, Error as BindingError, derive_binding_edges,
    verify_binding_linkage, verify_binding_order,
};
pub use path::Error as ChainError;
pub use revocation::{Error as RevocationError, RevocationReason};
pub use stamp::{
    AcceptedToken, Error, RejectedToken, SiteToken, StampInputs, StampSummary,
    run as verify_stamp,
};
pub use token::{
    Error as TokenError, TokenSummary, TrustData, VerificationBasis,
    verify_token,
};
pub use tree::{
    Disagreement, Error as TreeError, run as verify_tree_agreement,
};
pub use x509::{ExtensionError, NormalizeError};
