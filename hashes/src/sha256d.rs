// SPDX-License-Identifier: CC0-1.0

//! SHA256d implementation (double SHA256).
//!

use core::ops::Index;
use core::slice::SliceIndex;
use core::str;

use crate::{sha256, FromSliceError};

crate::internal_macros::hash_type! {
    256,
    true,
    "Output of the SHA256d hash function."
}

type HashEngine = sha256::HashEngine;

fn from_engine(e: sha256::HashEngine) -> Hash {
    use crate::Hash as _;

    let sha2 = sha256::Hash::from_engine(e);
    let sha2d = sha256::Hash::hash(&sha2[..]);

    let mut ret = [0; 32];
    ret.copy_from_slice(&sha2d[..]);
    Hash(ret)
}
