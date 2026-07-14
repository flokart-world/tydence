use sha2::{Digest, Sha256};
use sha3::Sha3_256;

use super::model::PayloadHashes;

/// Feeds one payload into every hash family manifest format v1
/// carries and produces its [`PayloadHashes`], for content too
/// large to hold in memory at once.
#[derive(Default)]
pub struct PayloadHasher {
    sha256: Sha256,
    sha3_256: Sha3_256,
}

impl PayloadHasher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn update(&mut self, payload_bytes: &[u8]) {
        self.sha256.update(payload_bytes);
        self.sha3_256.update(payload_bytes);
    }

    pub fn finalize(self) -> PayloadHashes {
        PayloadHashes {
            sha256: self.sha256.finalize().into(),
            sha3_256: self.sha3_256.finalize().into(),
        }
    }
}

/// Hashes one in-memory payload in every hash family manifest
/// format v1 carries.
pub fn run(payload_bytes: &[u8]) -> PayloadHashes {
    let mut hasher = PayloadHasher::new();
    hasher.update(payload_bytes);
    hasher.finalize()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(hash_bytes: [u8; 32]) -> String {
        hash_bytes
            .iter()
            .map(|hash_byte| format!("{hash_byte:02x}"))
            .collect()
    }

    #[test]
    fn the_empty_payload_matches_the_published_test_vectors() {
        let hashes = run(b"");
        assert_eq!(
            hex(hashes.sha256),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(hashes.sha3_256),
            "a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a"
        );
    }

    #[test]
    fn a_known_payload_matches_the_published_test_vectors() {
        let hashes = run(b"abc");
        assert_eq!(
            hex(hashes.sha256),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(hashes.sha3_256),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
    }

    #[test]
    fn incremental_updates_equal_one_shot_hashing() {
        let mut hasher = PayloadHasher::new();
        hasher.update(b"ab");
        hasher.update(b"c");
        assert_eq!(hasher.finalize(), run(b"abc"));
    }
}
