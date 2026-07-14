//! The stamping flow (stamping specification §5): fixing the
//! manifest, acquiring one fully verified token per selected site,
//! and sealing everything into a stamp commit. Assembled bottom-up;
//! [`acquire`] is the token-acquisition core, and the git-facing
//! orchestration arrives with the rest of the flow.

use super::claims;
use super::config;
use super::hex;
use super::layout;
use super::manifest;
use super::oids;
use super::snapshot;
use super::transport;
use super::trust;
use super::tsp;
use super::verify;

#[cfg(test)]
use super::{test_git, test_http, test_pki, test_stamp};

mod acquire;
mod bind;
mod create;
mod ltv;
mod seal;

pub use acquire::{Error as AcquireError, SiteFailure};
pub use bind::Error as BindError;
pub use create::{
    CreateInputs, CreatedStamp, Error as CreateError, OsEnvironment,
    live_anchor, run as create_stamp,
};
pub use ltv::Error as LtvError;
pub use seal::Error as SealError;
