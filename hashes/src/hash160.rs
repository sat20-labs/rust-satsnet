// SPDX-License-Identifier: CC0-1.0
//
// This module is largely copied from the rust-crypto ripemd.rs file;
// while rust-crypto is licensed under Apache, that file specifically
// was written entirely by Andrew Poelstra, who is re-licensing its
// contents here as CC0.

//! HASH160 (SHA256 then RIPEMD160) implementation.
//!

use core::ops::Index;
use core::slice::SliceIndex;
use core::str;

use crate::{ripemd160, sha256, FromSliceError};

crate::internal_macros::hash_type! {
    160,
    false,
    "Output of the Bitcoin HASH160 hash function. (RIPEMD160(SHA256))"
}

type HashEngine = sha256::HashEngine;

fn from_engine(e: HashEngine) -> Hash {
    use crate::Hash as _;

    let sha2 = sha256::Hash::from_engine(e);
    let rmd = ripemd160::Hash::hash(&sha2[..]);

    let mut ret = [0; 20];
    ret.copy_from_slice(&rmd[..]);
    Hash(ret)
}
