// SPDX-License-Identifier: CC0-1.0

// This module is largely copied from the rust-crypto ripemd.rs file;
// while rust-crypto is licensed under Apache, that file specifically
// was written entirely by Andrew Poelstra, who is re-licensing its
// contents here as CC0.

//! Hash-based Message Authentication Code (HMAC).

use core::{convert, fmt, str};

#[cfg(feature = "serde")]
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::{FromSliceError, GeneralHash, Hash, HashEngine};

/// A hash computed from a RFC 2104 HMAC. Parameterized by the underlying hash function.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Hmac<T: GeneralHash>(T);

#[cfg(feature = "schemars")]
impl<T: GeneralHash + schemars::JsonSchema> schemars::JsonSchema for Hmac<T> {
    fn is_referenceable() -> bool {
        <T as schemars::JsonSchema>::is_referenceable()
    }

    fn schema_name() -> alloc::string::String {
        <T as schemars::JsonSchema>::schema_name()
    }

    fn json_schema(gen: &mut schemars::gen::SchemaGenerator) -> schemars::schema::Schema {
        <T as schemars::JsonSchema>::json_schema(gen)
    }
}

impl<T: GeneralHash + str::FromStr> str::FromStr for Hmac<T> {
    type Err = <T as str::FromStr>::Err;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(Hmac(str::FromStr::from_str(s)?))
    }
}

/// Pair of underlying hash engines, used for the inner and outer hash of HMAC.
#[derive(Clone)]
pub struct HmacEngine<T: GeneralHash> {
    iengine: T::Engine,
    oengine: T::Engine,
}

impl<T: GeneralHash> Default for HmacEngine<T>
where
    <T as GeneralHash>::Engine: Default,
{
    fn default() -> Self {
        HmacEngine::new(&[])
    }
}

impl<T: GeneralHash> HmacEngine<T> {
    /// Constructs a new keyed HMAC from `key`.
    ///
    /// We only support underlying hashes whose block sizes are ≤ 128 bytes.
    ///
    /// # Panics
    ///
    /// Larger hashes will result in a panic.
    pub fn new(key: &[u8]) -> HmacEngine<T>
    where
        <T as GeneralHash>::Engine: Default,
    {
        debug_assert!(T::Engine::BLOCK_SIZE <= 128);

        let mut ipad = [0x36u8; 128];
        let mut opad = [0x5cu8; 128];
        let mut ret = HmacEngine {
            iengine: <T as GeneralHash>::engine(),
            oengine: <T as GeneralHash>::engine(),
        };

        if key.len() > T::Engine::BLOCK_SIZE {
            let hash = <T as GeneralHash>::hash(key);
            let hash = hash.as_byte_array().as_ref();
            for (b_i, b_h) in ipad.iter_mut().zip(hash) {
                *b_i ^= *b_h;
            }
            for (b_o, b_h) in opad.iter_mut().zip(hash) {
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

impl<T: GeneralHash> HashEngine for HmacEngine<T> {
    const BLOCK_SIZE: usize = T::Engine::BLOCK_SIZE;

    fn n_bytes_hashed(&self) -> usize {
        self.iengine.n_bytes_hashed()
    }

    fn input(&mut self, buf: &[u8]) {
        self.iengine.input(buf)
    }
}

impl<T: GeneralHash> fmt::Debug for Hmac<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Debug::fmt(&self.0, f)
    }
}

impl<T: GeneralHash> fmt::Display for Hmac<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

impl<T: GeneralHash> fmt::LowerHex for Hmac<T> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl<T: GeneralHash> convert::AsRef<[u8]> for Hmac<T> {
    // Calling as_byte_array is more reliable
    fn as_ref(&self) -> &[u8] {
        self.0.as_byte_array().as_ref()
    }
}

impl<T: GeneralHash> GeneralHash for Hmac<T> {
    type Engine = HmacEngine<T>;

    fn from_engine(mut e: HmacEngine<T>) -> Hmac<T> {
        let ihash = T::from_engine(e.iengine);
        e.oengine.input(ihash.as_byte_array().as_ref());
        let ohash = T::from_engine(e.oengine);
        Hmac(ohash)
    }
}

impl<T: GeneralHash> Hash for Hmac<T> {
    type Bytes = T::Bytes;

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
}

#[cfg(feature = "serde")]
impl<T: GeneralHash + Serialize> Serialize for Hmac<T> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        Serialize::serialize(&self.0, s)
    }
}

#[cfg(feature = "serde")]
impl<'de, T: GeneralHash + Deserialize<'de>> Deserialize<'de> for Hmac<T> {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Hmac<T>, D::Error> {
        let bytes = Deserialize::deserialize(d)?;
        Ok(Hmac(bytes))
    }
}
