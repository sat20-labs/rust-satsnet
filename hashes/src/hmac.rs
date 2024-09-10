// SPDX-License-Identifier: CC0-1.0

// This module is largely copied from the rust-crypto ripemd.rs file;
// while rust-crypto is licensed under Apache, that file specifically
// was written entirely by Andrew Poelstra, who is re-licensing its
// contents here as CC0.

//! Hash-based Message Authentication Code (HMAC).
//!

use core::{borrow, fmt, ops, str};

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{FromSliceError, Hash, HashEngine};

/// A hash computed from a RFC 2104 HMAC. Parameterized by the underlying hash function.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Hmac<T: Hash>(T);

#[cfg(feature = "schemars")]
impl<T: Hash + schemars::JsonSchema> schemars::JsonSchema for Hmac<T> {
    fn is_referenceable() -> bool {
        <T as schemars::JsonSchema>::is_referenceable()
    }

    fn schema_name() -> std::string::String {
        <T as schemars::JsonSchema>::schema_name()
    }

    fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        <T as schemars::JsonSchema>::json_schema(gen)
    }
}

impl<T: Hash + str::FromStr> str::FromStr for Hmac<T> {
    type Err = <T as str::FromStr>::Err;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Hmac(str::FromStr::from_str(s)?))
    }
}

/// Pair of underlying hash midstates which represent the current state of an `HmacEngine`.
pub struct HmacMidState<T: Hash> {
    /// Midstate of the inner hash engine
    pub inner: <T::Engine as HashEngine>::MidState,
    /// Midstate of the outer hash engine
    pub outer: <T::Engine as HashEngine>::MidState,
}

/// Pair of underlying hash engines, used for the inner and outer hash of HMAC.
#[derive(Clone)]
pub struct HmacEngine<T: Hash> {
    iengine: T::Engine,
    oengine: T::Engine,
}

impl<T: Hash> Default for HmacEngine<T> {
    fn default() -> Self {
        HmacEngine::new(&[])
    }
}

impl<T: Hash> HmacEngine<T> {
    /// Constructs a new keyed HMAC from `key`.
    ///
    /// We only support underlying hashes whose block sizes are ≤ 128 bytes.
    ///
    /// # Panics
    ///
    /// Larger hashes will result in a panic.
    pub fn new(key: &[u8]) -> HmacEngine<T> {
        debug_assert!(T::Engine::BLOCK_SIZE <= 128);

        let mut ipad = [0x36u8; 128];
        let mut opad = [0x5cu8; 128];
        let mut ret = HmacEngine {
            iengine: <T as Hash>::engine(),
            oengine: <T as Hash>::engine(),
        };

        if key.len() > T::Engine::BLOCK_SIZE {
            let hash = <T as Hash>::hash(key);
            for (b_i, b_h) in ipad.iter_mut().zip(&hash[..]) {
                *b_i ^= *b_h;
            }
            for (b_o, b_h) in opad.iter_mut().zip(&hash[..]) {
                *b_o ^= *b_h;
            }
        } else {
            for (b_i, b_h) in ipad.iter_mut().zip(key) {
                *b_i ^= *b_h;
            }
            for (b_o, b_h) in opad.iter_mut().zip(key) {
                *b_o ^= *b_h;
            }
        };

        HashEngine::input(&mut ret.iengine, &ipad[..T::Engine::BLOCK_SIZE]);
        HashEngine::input(&mut ret.oengine, &opad[..T::Engine::BLOCK_SIZE]);
        ret
    }

    /// A special constructor giving direct access to the underlying "inner" and "outer" engines.
    pub fn from_inner_engines(iengine: T::Engine, oengine: T::Engine) -> HmacEngine<T> {
        HmacEngine { iengine, oengine }
    }
}

impl<T: Hash> HashEngine for HmacEngine<T> {
    type MidState = HmacMidState<T>;

    fn midstate(&self) -> Self::MidState {
        HmacMidState {
            inner: self.iengine.midstate(),
            outer: self.oengine.midstate(),
        }
    }

    const BLOCK_SIZE: usize = T::Engine::BLOCK_SIZE;

    fn n_bytes_hashed(&self) -> usize {
        self.iengine.n_bytes_hashed()
    }

    fn input(&mut self, buf: &[u8]) {
        self.iengine.input(buf)
    }
}

impl<T: Hash> fmt::Debug for Hmac<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl<T: Hash> fmt::Display for Hmac<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl<T: Hash> fmt::LowerHex for Hmac<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl<T: Hash> ops::Index<usize> for Hmac<T> {
    type Output = u8;
    fn index(&self, index: usize) -> &u8 {
        &self.0[index]
    }
}

impl<T: Hash> ops::Index<ops::Range<usize>> for Hmac<T> {
    type Output = [u8];
    fn index(&self, index: ops::Range<usize>) -> &[u8] {
        &self.0[index]
    }
}

impl<T: Hash> ops::Index<ops::RangeFrom<usize>> for Hmac<T> {
    type Output = [u8];
    fn index(&self, index: ops::RangeFrom<usize>) -> &[u8] {
        &self.0[index]
    }
}

impl<T: Hash> ops::Index<ops::RangeTo<usize>> for Hmac<T> {
    type Output = [u8];
    fn index(&self, index: ops::RangeTo<usize>) -> &[u8] {
        &self.0[index]
    }
}

impl<T: Hash> ops::Index<ops::RangeFull> for Hmac<T> {
    type Output = [u8];
    fn index(&self, index: ops::RangeFull) -> &[u8] {
        &self.0[index]
    }
}

impl<T: Hash> borrow::Borrow<[u8]> for Hmac<T> {
    fn borrow(&self) -> &[u8] {
        &self[..]
    }
}

impl<T: Hash> Hash for Hmac<T> {
    type Engine = HmacEngine<T>;
    type Bytes = T::Bytes;

    fn from_engine(mut e: HmacEngine<T>) -> Hmac<T> {
        let ihash = T::from_engine(e.iengine);
        e.oengine.input(&ihash[..]);
        let ohash = T::from_engine(e.oengine);
        Hmac(ohash)
    }

    const LEN: usize = T::LEN;

    fn from_slice(sl: &[u8]) -> Result<Hmac<T>, FromSliceError> {
        T::from_slice(sl).map(Hmac)
    }

    fn to_byte_array(self) -> Self::Bytes {
        self.0.to_byte_array()
    }

    fn as_byte_array(&self) -> &Self::Bytes {
        self.0.as_byte_array()
    }

    fn from_byte_array(bytes: T::Bytes) -> Self {
        Hmac(T::from_byte_array(bytes))
    }

    fn all_zeros() -> Self {
        let zeros = T::all_zeros();
        Hmac(zeros)
    }
}

#[cfg(feature = "serde")]
impl<T: Hash + Serialize> Serialize for Hmac<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        Serialize::serialize(&self.0, s)
    }
}

#[cfg(feature = "serde")]
impl<'de, T: Hash + Deserialize<'de>> Deserialize<'de> for Hmac<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Hmac<T>, D::Error> {
        let bytes = Deserialize::deserialize(d)?;
        Ok(Hmac(bytes))
    }
}
