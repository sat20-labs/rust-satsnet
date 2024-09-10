// SPDX-License-Identifier: CC0-1.0

//! SHA512_256 implementation.
//!
//! SHA512/256 is a hash function that uses the sha512 algorithm but it truncates
//! the output to 256 bits. It has different initial constants than sha512 so it
//! produces an entirely different hash compared to sha512. More information at
//! <https://eprint.iacr.org/2010/548.pdf>.

use core::ops::Index;
use core::slice::SliceIndex;

use crate::sha512;

crate::internal_macros::hash_type! {
    256,
    false,
    "Output of the SHA512/256 hash function.\n\nSHA512/256 is a hash function that uses the sha512 algorithm but it truncates the output to 256 bits. It has different initial constants than sha512 so it produces an entirely different hash compared to sha512. More information at <https://eprint.iacr.org/2010/548.pdf>."
}

fn from_engine(e: HashEngine) -> Hash {
    let mut ret = [0; 32];
    ret.copy_from_slice(&sha512::from_engine(e.0)[..32]);
    Hash(ret)
}

/// Engine to compute SHA512/256 hash function.
///
/// SHA512/256 is a hash function that uses the sha512 algorithm but it truncates
/// the output to 256 bits. It has different initial constants than sha512 so it
/// produces an entirely different hash compared to sha512. More information at
/// <https://eprint.iacr.org/2010/548.pdf>.
#[derive(Clone)]
pub struct HashEngine(sha512::HashEngine);

impl HashEngine {
    /// Creates a new SHA512/256 hash engine.
    pub const fn new() -> Self {
        Self(sha512::HashEngine::sha512_256())
    }
}

impl Default for HashEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl crate::HashEngine for HashEngine {
    const BLOCK_SIZE: usize = sha512::BLOCK_SIZE;

    fn n_bytes_hashed(&self) -> usize {
        self.0.n_bytes_hashed()
    }

    fn input(&mut self, inp: &[u8]) {
        self.0.input(inp);
    }
}
