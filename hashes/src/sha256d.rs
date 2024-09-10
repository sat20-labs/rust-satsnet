// SPDX-License-Identifier: CC0-1.0

//! SHA256d implementation (double SHA256).

use core::ops::Index;
use core::slice::SliceIndex;

use crate::sha256;

crate::internal_macros::hash_type! {
    256,
    true,
    "Output of the SHA256d hash function."
}

/// Engine to compute SHA256d hash function.
#[derive(Clone)]
pub struct HashEngine(sha256::HashEngine);

impl HashEngine {
    /// Creates a new SHA256d hash engine.
    pub const fn new() -> Self {
        Self(sha256::HashEngine::new())
    }
}

impl Default for HashEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::HashEngine for HashEngine {
    const BLOCK_SIZE: usize = 64; // Same as sha256::HashEngine::BLOCK_SIZE;
    fn input(&mut self, data: &[u8]) {
        self.0.input(data)
    }
    fn n_bytes_hashed(&self) -> usize {
        self.0.n_bytes_hashed()
    }
}

fn from_engine(e: HashEngine) -> Hash {
    let sha2 = sha256::Hash::from_engine(e.0);
    let sha2d = sha256::Hash::hash(&sha2[..]);

    let mut ret = [0; 32];
    ret.copy_from_slice(&sha2d[..]);
    Hash(ret)
}
