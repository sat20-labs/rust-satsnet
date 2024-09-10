// SPDX-License-Identifier: CC0-1.0

//! SipHash 2-4 implementation.

use core::ops::Index;
use core::slice::SliceIndex;
use core::{cmp, mem, ptr};

use crate::HashEngine as _;

crate::internal_macros::hash_type_no_default! {
    64,
    false,
    "Output of the SipHash24 hash function."
}

#[cfg(not(hashes_fuzz))]
fn from_engine(e: HashEngine) -> Hash {
    Hash::from_u64(Hash::from_engine_to_u64(e))
}

#[cfg(hashes_fuzz)]
fn from_engine(e: HashEngine) -> Hash {
    let state = e.state.clone();
    Hash::from_u64(state.v0 ^ state.v1 ^ state.v2 ^ state.v3)
}

macro_rules! compress {
    ($state:expr) => {{
        compress!($state.v0, $state.v1, $state.v2, $state.v3)
    }};
    ($v0:expr, $v1:expr, $v2:expr, $v3:expr) => {{
        $v0 = $v0.wrapping_add($v1);
        $v1 = $v1.rotate_left(13);
        $v1 ^= $v0;
        $v0 = $v0.rotate_left(32);
        $v2 = $v2.wrapping_add($v3);
        $v3 = $v3.rotate_left(16);
        $v3 ^= $v2;
        $v0 = $v0.wrapping_add($v3);
        $v3 = $v3.rotate_left(21);
        $v3 ^= $v0;
        $v2 = $v2.wrapping_add($v1);
        $v1 = $v1.rotate_left(17);
        $v1 ^= $v2;
        $v2 = $v2.rotate_left(32);
    }};
}

/// Load an integer of the desired type from a byte stream, in LE order. Uses
/// `copy_nonoverlapping` to let the compiler generate the most efficient way
/// to load it from a possibly unaligned address.
///
/// Unsafe because: unchecked indexing at `i..i+size_of(int_ty)`.
macro_rules! load_int_le {
    ($buf:expr, $i:expr, $int_ty:ident) => {{
        debug_assert!($i + mem::size_of::<$int_ty>() <= $buf.len());
        let mut data = 0 as $int_ty;
        ptr::copy_nonoverlapping(
            $buf.get_unchecked($i),
            &mut data as *mut _ as *mut u8,
            mem::size_of::<$int_ty>(),
        );
        data.to_le()
    }};
}

/// Internal state of the [`HashEngine`].
#[derive(Debug, Clone)]
pub struct State {
    // v0, v2 and v1, v3 show up in pairs in the algorithm,
    // and simd implementations of SipHash will use vectors
    // of v02 and v13. By placing them in this order in the struct,
    // the compiler can pick up on just a few simd optimizations by itself.
    v0: u64,
    v2: u64,
    v1: u64,
    v3: u64,
}

/// Engine to compute the SipHash24 hash function.
#[derive(Debug, Clone)]
pub struct HashEngine {
    k0: u64,
    k1: u64,
    length: usize, // how many bytes we've processed
    state: State,  // hash State
    tail: u64,     // unprocessed bytes le
    ntail: usize,  // how many bytes in tail are valid
}

impl HashEngine {
    /// Creates a new SipHash24 engine with keys.
    #[inline]
    pub const fn with_keys(k0: u64, k1: u64) -> HashEngine {
        HashEngine {
            k0,
            k1,
            length: 0,
            state: State {
                v0: k0 ^ 0x736f6d6570736575,
                v1: k1 ^ 0x646f72616e646f6d,
                v2: k0 ^ 0x6c7967656e657261,
                v3: k1 ^ 0x7465646279746573,
            },
            tail: 0,
            ntail: 0,
        }
    }

    /// Retrieves the keys of this engine.
    pub fn keys(&self) -> (u64, u64) {
        (self.k0, self.k1)
    }

    #[inline]
    fn c_rounds(state: &mut State) {
        compress!(state);
        compress!(state);
    }

    #[inline]
    fn d_rounds(state: &mut State) {
        compress!(state);
        compress!(state);
        compress!(state);
        compress!(state);
    }
}

impl crate::HashEngine for HashEngine {
    const BLOCK_SIZE: usize = 8;

    #[inline]
    fn input(&mut self, msg: &[u8]) {
        let length = msg.len();
        self.length += length;

        let mut needed = 0;

        if self.ntail != 0 {
            needed = 8 - self.ntail;
            self.tail |= unsafe { u8to64_le(msg, 0, cmp::min(length, needed)) } << (8 * self.ntail);
            if length < needed {
                self.ntail += length;
                return;
            } else {
                self.state.v3 ^= self.tail;
                HashEngine::c_rounds(&mut self.state);
                self.state.v0 ^= self.tail;
                self.ntail = 0;
            }
        }

        // Buffered tail is now flushed, process new input.
        let len = length - needed;
        let left = len & 0x7;

        let mut i = needed;
        while i < len - left {
            let mi = unsafe { load_int_le!(msg, i, u64) };

            self.state.v3 ^= mi;
            HashEngine::c_rounds(&mut self.state);
            self.state.v0 ^= mi;

            i += 8;
        }

        self.tail = unsafe { u8to64_le(msg, i, left) };
        self.ntail = left;
    }

    fn n_bytes_hashed(&self) -> usize {
        self.length
    }
}

impl Hash {
    /// Hashes the given data with an engine with the provided keys.
    pub fn hash_with_keys(k0: u64, k1: u64, data: &[u8]) -> Hash {
        let mut engine = HashEngine::with_keys(k0, k1);
        engine.input(data);
        Hash::from_engine(engine)
    }

    /// Hashes the given data directly to u64 with an engine with the provided keys.
    pub fn hash_to_u64_with_keys(k0: u64, k1: u64, data: &[u8]) -> u64 {
        let mut engine = HashEngine::with_keys(k0, k1);
        engine.input(data);
        Hash::from_engine_to_u64(engine)
    }

    /// Produces a hash as `u64` from the current state of a given engine.
    #[inline]
    pub fn from_engine_to_u64(e: HashEngine) -> u64 {
        let mut state = e.state;

        let b: u64 = ((e.length as u64 & 0xff) << 56) | e.tail;

        state.v3 ^= b;
        HashEngine::c_rounds(&mut state);
        state.v0 ^= b;

        state.v2 ^= 0xff;
        HashEngine::d_rounds(&mut state);

        state.v0 ^ state.v1 ^ state.v2 ^ state.v3
    }

    /// Returns the (little endian) 64-bit integer representation of the hash value.
    #[deprecated(since = "TBD", note = "use `to_u64` instead")]
    pub fn as_u64(&self) -> u64 {
        self.to_u64()
    }

    /// Returns the (little endian) 64-bit integer representation of the hash value.
    pub fn to_u64(self) -> u64 {
        u64::from_le_bytes(self.0)
    }

    /// Creates a hash from its (little endian) 64-bit integer representation.
    pub fn from_u64(hash: u64) -> Hash {
        Hash(hash.to_le_bytes())
    }
}

/// Load an u64 using up to 7 bytes of a byte slice.
///
/// Unsafe because: unchecked indexing at `start..start+len`.
#[inline]
unsafe fn u8to64_le(buf: &[u8], start: usize, len: usize) -> u64 {
    debug_assert!(len < 8);
    let mut i = 0; // current byte index (from LSB) in the output u64
    let mut out = 0;
    if i + 3 < len {
        out = u64::from(load_int_le!(buf, start + i, u32));
        i += 4;
    }
    if i + 1 < len {
        out |= u64::from(load_int_le!(buf, start + i, u16)) << (i * 8);
        i += 2
    }
    if i < len {
        out |= u64::from(*buf.get_unchecked(start + i)) << (i * 8);
        i += 1;
    }
    debug_assert_eq!(i, len);
    out
}
