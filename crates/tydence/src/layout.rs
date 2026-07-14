//! Where the stamp artifacts live in a tree (stamping specification
//! §3), spelled once for snapshot exclusion, binding discovery and
//! sealing alike.

pub const CONFIG_PATH: &str = ".tydence/config";
pub const MANIFEST_PATH: &str = ".tydence/manifest";
pub const TOKENS_PATH: &str = ".tydence/tokens";
pub const TOKEN_FILE_SUFFIX: &str = ".tsr";
pub const LTV_CERTS_PATH: &str = ".tydence/ltv/certs";
pub const LTV_CRLS_PATH: &str = ".tydence/ltv/crls";
pub const CHAIN_FILE_SUFFIX: &str = ".cer";
pub const CRL_FILE_SUFFIX: &str = ".crl";

// Git's tree-entry mode of a regular file, which is the only mode
// §3 allows an artifact file to carry. Readers compare the raw bits
// for the fail-closed reason the snapshot enumeration documents:
// kind() would classify a nonstandard historical blob mode (100664
// from old git, say) as regular and silently accept it.
pub const REGULAR_FILE_MODE: u16 = 0o100644;
