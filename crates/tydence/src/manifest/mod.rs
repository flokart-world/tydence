//! The tydence manifest: generation, canonical serialization and
//! parsing of the format specified in `docs/stamping.md`.

use super::hex;

mod hash;
mod model;
mod order;
mod parse;
mod path;

pub use hash::run as hash_payload;
pub use model::{
    AnchorSpec, BindingGroup, Entry, FileMode, MalformedField, Manifest,
    PastToken, PayloadHashes, UnprintableField,
};
pub use order::{
    BindingEdge, Error as BindingOrderError, run as order_binding_groups,
};
pub use parse::{Error as ManifestParseError, run as parse_manifest};
