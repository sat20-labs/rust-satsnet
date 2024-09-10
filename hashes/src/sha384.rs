// SPDX-License-Identifier: CC0-1.0

//! SHA384 implementation.

use core::ops::Index;
use core::slice::SliceIndex;
use core::str;

use crate::{sha512, FromSliceError};

crate::internal_macros::hash_type! {
    384,
    false,
    "Output of the SHA384 hash function."
}

fn from_engine(e: HashEngine) -> Hash {
    let mut ret = [0; 48];
    ret.copy_from_slice(&sha512::from_engine(e.0)[..48]);
    Hash(ret)
}

/// Engine to compute SHA384 hash function.
#[derive(Clone)]
pub struct HashEngine(sha512::HashEngine);

impl Default for HashEngine {
    #[rustfmt::skip]
    fn default() -> Self {
        HashEngine(sha512::HashEngine::sha384())
    }
}

impl crate::HashEngine for HashEngine {
    type MidState = [u8; 64];

    fn midstate(&self) -> [u8; 64] {
        self.0.midstate()
    }

    const BLOCK_SIZE: usize = sha512::BLOCK_SIZE;

    fn n_bytes_hashed(&self) -> usize {
        self.0.n_bytes_hashed()
    }

    fn input(&mut self, inp: &[u8]) {
        self.0.input(inp);
    }
}
