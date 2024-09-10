// SPDX-License-Identifier: CC0-1.0

//! HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
//!
//! Implementation based on RFC5869, but the interface is scoped
//! to BIP324's requirements.

#[cfg(feature = "alloc")]
use alloc::vec;
#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::fmt;

use crate::{GeneralHash, HashEngine, Hmac, HmacEngine, IsByteArray};

/// Output keying material max length multiple.
const MAX_OUTPUT_BLOCKS: usize = 255;

/// Size of output exceeds maximum length allowed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct MaxLengthError {
    max: usize,
}

impl fmt::Display for MaxLengthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "exceeds {} byte max output material limit", self.max)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for MaxLengthError {}

/// HMAC-based Extract-and-Expand Key Derivation Function (HKDF).
pub struct Hkdf<T: GeneralHash> {
    /// Pseudorandom key based on the extract step.
    prk: Hmac<T>,
}

impl<T: GeneralHash> Hkdf<T>
where
    <T as GeneralHash>::Engine: Default,
{
    /// Initialize a HKDF by performing the extract step.
    pub fn new(salt: &[u8], ikm: &[u8]) -> Self {
        let mut hmac_engine: HmacEngine<T> = HmacEngine::new(salt);
        hmac_engine.input(ikm);
        Self { prk: Hmac::from_engine(hmac_engine) }
    }

    /// Expand the key to generate output key material in okm.
    ///
    /// Expand may be called multiple times to derive multiple keys,
    /// but the info must be independent from the ikm for security.
    pub fn expand(&self, info: &[u8], okm: &mut [u8]) -> Result<(), MaxLengthError> {
        // Length of output keying material in bytes must be less than 255 * hash length.
        if okm.len() > (MAX_OUTPUT_BLOCKS * T::Bytes::LEN) {
            return Err(MaxLengthError { max: MAX_OUTPUT_BLOCKS * T::Bytes::LEN });
        }

        // Counter starts at "1" based on RFC5869 spec and is committed to in the hash.
        let mut counter = 1u8;
        // Ceiling calculation for the total number of blocks (iterations) required for the expand.
        let total_blocks = (okm.len() + T::Bytes::LEN - 1) / T::Bytes::LEN;

        while counter <= total_blocks as u8 {
            let mut hmac_engine: HmacEngine<T> = HmacEngine::new(self.prk.as_ref());

            // First block does not have a previous block,
            // all other blocks include last block in the HMAC input.
            if counter != 1u8 {
                let previous_start_index = (counter as usize - 2) * T::Bytes::LEN;
                let previous_end_index = (counter as usize - 1) * T::Bytes::LEN;
                hmac_engine.input(&okm[previous_start_index..previous_end_index]);
            }
            hmac_engine.input(info);
            hmac_engine.input(&[counter]);

            let t = Hmac::from_engine(hmac_engine);
            let start_index = (counter as usize - 1) * T::Bytes::LEN;
            // Last block might not take full hash length.
            let end_index = if counter == (total_blocks as u8) {
                okm.len()
            } else {
                counter as usize * T::Bytes::LEN
            };

            okm[start_index..end_index].copy_from_slice(&t.as_ref()[0..(end_index - start_index)]);

            counter += 1;
        }

        Ok(())
    }

    /// Expand the key to specified length.
    ///
    /// Expand may be called multiple times to derive multiple keys,
    /// but the info must be independent from the ikm for security.
    #[cfg(feature = "alloc")]
    pub fn expand_to_len(&self, info: &[u8], len: usize) -> Result<Vec<u8>, MaxLengthError> {
        let mut okm = vec![0u8; len];
        self.expand(info, &mut okm)?;
        Ok(okm)
    }
}
