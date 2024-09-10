// SPDX-License-Identifier: CC0-1.0
//
// This module is largely copied from the rust-crypto ripemd.rs file;
// while rust-crypto is licensed under Apache, that file specifically
// was written entirely by Andrew Poelstra, who is re-licensing its
// contents here as CC0.

//! HASH160 (SHA256 then RIPEMD160) implementation.

use core::ops::Index;
use core::slice::SliceIndex;

use crate::{ripemd160, sha256};

crate::internal_macros::hash_type! {
    160,
    false,
    "Output of the Bitcoin HASH160 hash function. (RIPEMD160(SHA256))"
}

/// Engine to compute HASH160 hash function.
#[derive(Clone)]
pub struct HashEngine(sha256::HashEngine);

impl HashEngine {
    /// Creates a new HASH160 hash engine.
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
    let rmd = ripemd160::Hash::hash(&sha2[..]);

    let mut ret = [0; 20];
    ret.copy_from_slice(&rmd[..]);
    Hash(ret)
}
