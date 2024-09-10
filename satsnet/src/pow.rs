// SPDX-License-Identifier: CC0-1.0

//! Proof-of-work related integer types.
//!
//! Provides the [`Work`] and [`Target`] types that are used in proof-of-work calculations. The
//! functions here are designed to be fast, by that we mean it is safe to use them to check headers.
//!

use core::cmp;
use core::fmt::{self, LowerHex, UpperHex};
use core::ops::{Add, Div, Mul, Not, Rem, Shl, Shr, Sub};

use io::{BufRead, Write};

use units::parse;

use crate::blockdata::block::BlockHash;
use crate::consensus::encode::{self, Decodable, Encodable};
use crate::consensus::Params;
use crate::error::{
    ContainsPrefixError, MissingPrefixError, ParseIntError, PrefixedHexError, UnprefixedHexError,
};

/// Implement traits and methods shared by `Target` and `Work`.
macro_rules! do_impl {
    ($ty:ident) => {
        impl $ty {
            #[doc = "Creates `"]
            #[doc = stringify!($ty)]
            #[doc = "` from a prefixed hex string."]
            pub fn from_hex(s: &str) -> Result<Self, PrefixedHexError> {
                Ok($ty(U256::from_hex(s)?))
            }

            #[doc = "Creates `"]
            #[doc = stringify!($ty)]
            #[doc = "` from an unprefixed hex string."]
            pub fn from_unprefixed_hex(s: &str) -> Result<Self, UnprefixedHexError> {
                Ok($ty(U256::from_unprefixed_hex(s)?))
            }

            #[doc = "Creates `"]
            #[doc = stringify!($ty)]
            #[doc = "` from a big-endian byte array."]
            #[inline]
            pub fn from_be_bytes(bytes: [u8; 32]) -> $ty {
                $ty(U256::from_be_bytes(bytes))
            }

            #[doc = "Creates `"]
            #[doc = stringify!($ty)]
            #[doc = "` from a little-endian byte array."]
            #[inline]
            pub fn from_le_bytes(bytes: [u8; 32]) -> $ty {
                $ty(U256::from_le_bytes(bytes))
            }

            #[doc = "Converts `"]
            #[doc = stringify!($ty)]
            #[doc = "` to a big-endian byte array."]
            #[inline]
            pub fn to_be_bytes(self) -> [u8; 32] {
                self.0.to_be_bytes()
            }

            #[doc = "Converts `"]
            #[doc = stringify!($ty)]
            #[doc = "` to a little-endian byte array."]
            #[inline]
            pub fn to_le_bytes(self) -> [u8; 32] {
                self.0.to_le_bytes()
            }
        }

        impl fmt::Display for $ty {
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter) -> core::fmt::Result {
                fmt::Display::fmt(&self.0, f)
            }
        }

        impl fmt::LowerHex for $ty {
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter) -> core::fmt::Result {
                fmt::LowerHex::fmt(&self.0, f)
            }
        }

        impl fmt::UpperHex for $ty {
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter) -> core::fmt::Result {
                fmt::UpperHex::fmt(&self.0, f)
            }
        }
    };
}

/// A 256 bit integer representing work.
///
/// Work is a measure of how difficult it is to find a hash below a given [`Target`].
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Work(U256);

impl Work {
    /// Converts this [`Work`] to [`Target`].
    pub fn to_target(self) -> Target {
        Target(self.0.inverse())
    }

    /// Returns log2 of this work.
    ///
    /// The result inherently suffers from a loss of precision and is, therefore, meant to be
    /// used mainly for informative and displaying purposes, similarly to Bitcoin Core's
    /// `log2_work` output in its logs.
    #[cfg(feature = "std")]
    pub fn log2(self) -> f64 {
        self.0.to_f64().log2()
    }
}
do_impl!(Work);

impl Add for Work {
    type Output = Work;
    fn add(self, rhs: Self) -> Self {
        Work(self.0 + rhs.0)
    }
}

impl Sub for Work {
    type Output = Work;
    fn sub(self, rhs: Self) -> Self {
        Work(self.0 - rhs.0)
    }
}

/// A 256 bit integer representing target.
///
/// The SHA-256 hash of a block's header must be lower than or equal to the current target for the
/// block to be accepted by the network. The lower the target, the more difficult it is to generate
/// a block. (See also [`Work`].)
///
/// ref: <https://en.bitcoin.it/wiki/Target>
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct Target(U256);

impl Target {
    /// When parsing nBits, Bitcoin Core converts a negative target threshold into a target of zero.
    pub const ZERO: Target = Target(U256::ZERO);
    /// The maximum possible target.
    ///
    /// This value is used to calculate difficulty, which is defined as how difficult the current
    /// target makes it to find a block relative to how difficult it would be at the highest
    /// possible target. Remember highest target == lowest difficulty.
    ///
    /// ref: <https://en.bitcoin.it/wiki/Target>
    // In Bitcoind this is ~(u256)0 >> 32 stored as a floating-point type so it gets truncated, hence
    // the low 208 bits are all zero.
    pub const MAX: Self = Target(U256(0xFFFF_u128 << (208 - 128), 0));

    /// The maximum **attainable** target value on mainnet.
    ///
    /// Not all target values are attainable because consensus code uses the compact format to
    /// represent targets (see [`CompactTarget`]).
    pub const MAX_ATTAINABLE_MAINNET: Self = Target(U256(0xFFFF_u128 << (208 - 128), 0));

    /// The proof of work limit on testnet.
    // Taken from Bitcoin Core but had lossy conversion to/from compact form.
    // https://github.com/bitcoin/bitcoin/blob/8105bce5b384c72cf08b25b7c5343622754e7337/src/kernel/chainparams.cpp#L208
    pub const MAX_ATTAINABLE_TESTNET: Self = Target(U256(0xFFFF_u128 << (208 - 128), 0));

    /// The proof of work limit on regtest.
    // Taken from Bitcoin Core but had lossy conversion to/from compact form.
    // https://github.com/bitcoin/bitcoin/blob/8105bce5b384c72cf08b25b7c5343622754e7337/src/kernel/chainparams.cpp#L411
    pub const MAX_ATTAINABLE_REGTEST: Self = Target(U256(0x7FFF_FF00u128 << 96, 0));

    /// The proof of work limit on signet.
    // Taken from Bitcoin Core but had lossy conversion to/from compact form.
    // https://github.com/bitcoin/bitcoin/blob/8105bce5b384c72cf08b25b7c5343622754e7337/src/kernel/chainparams.cpp#L348
    pub const MAX_ATTAINABLE_SIGNET: Self = Target(U256(0x0377_ae00 << 80, 0));

    /// Computes the [`Target`] value from a compact representation.
    ///
    /// ref: <https://developer.bitcoin.org/reference/block_chain.html#target-nbits>
    pub fn from_compact(c: CompactTarget) -> Target {
        let bits = c.0;
        // This is a floating-point "compact" encoding originally used by
        // OpenSSL, which satoshi put into consensus code, so we're stuck
        // with it. The exponent needs to have 3 subtracted from it, hence
        // this goofy decoding code. 3 is due to 3 bytes in the mantissa.
        let (mant, expt) = {
            let unshifted_expt = bits >> 24;
            if unshifted_expt <= 3 {
                ((bits & 0xFFFFFF) >> (8 * (3 - unshifted_expt as usize)), 0)
            } else {
                (bits & 0xFFFFFF, 8 * ((bits >> 24) - 3))
            }
        };

        // The mantissa is signed but may not be negative.
        if mant > 0x7F_FFFF {
            Target::ZERO
        } else {
            Target(U256::from(mant) << expt)
        }
    }

    /// Computes the compact value from a [`Target`] representation.
    ///
    /// The compact form is by definition lossy, this means that
    /// `t == Target::from_compact(t.to_compact_lossy())` does not always hold.
    pub fn to_compact_lossy(self) -> CompactTarget {
        let mut size = (self.0.bits() + 7) / 8;
        let mut compact = if size <= 3 {
            (self.0.low_u64() << (8 * (3 - size))) as u32
        } else {
            let bn = self.0 >> (8 * (size - 3));
            bn.low_u32()
        };

        if (compact & 0x0080_0000) != 0 {
            compact >>= 8;
            size += 1;
        }

        CompactTarget(compact | (size << 24))
    }

    /// Returns true if block hash is less than or equal to this [`Target`].
    ///
    /// Proof-of-work validity for a block requires the hash of the block to be less than or equal
    /// to the target.
    #[cfg_attr(all(test, mutate), mutate)]
    pub fn is_met_by(&self, hash: BlockHash) -> bool {
        use hashes::Hash;
        let hash = U256::from_le_bytes(hash.to_byte_array());
        hash <= self.0
    }

    /// Converts this [`Target`] to [`Work`].
    ///
    /// "Work" is defined as the work done to mine a block with this target value (recorded in the
    /// block header in compact form as nBits). This is not the same as the difficulty to mine a
    /// block with this target (see `Self::difficulty`).
    pub fn to_work(self) -> Work {
        Work(self.0.inverse())
    }

    /// Computes the popular "difficulty" measure for mining.
    ///
    /// Difficulty represents how difficult the current target makes it to find a block, relative to
    /// how difficult it would be at the highest possible target (highest target == lowest difficulty).
    ///
    /// For example, a difficulty of 6,695,826 means that at a given hash rate, it will, on average,
    /// take ~6.6 million times as long to find a valid block as it would at a difficulty of 1, or
    /// alternatively, it will take, again on average, ~6.6 million times as many hashes to find a
    /// valid block
    ///
    /// # Note
    ///
    /// Difficulty is calculated using the following algorithm `max / current` where [max] is
    /// defined for the Bitcoin network and `current` is the current [target] for this block. As
    /// such, a low target implies a high difficulty. Since [`Target`] is represented as a 256 bit
    /// integer but `difficulty()` returns only 128 bits this means for targets below approximately
    /// `0xffff_ffff_ffff_ffff_ffff_ffff` `difficulty()` will saturate at `u128::MAX`.
    ///
    /// # Panics
    ///
    /// Panics if `self` is zero (divide by zero).
    ///
    /// [max]: Target::max
    /// [target]: crate::blockdata::block::Header::target
    #[cfg_attr(all(test, mutate), mutate)]
    pub fn difficulty(&self, params: impl AsRef<Params>) -> u128 {
        // Panic here may be eaiser to debug than during the actual division.
        assert_ne!(self.0, U256::ZERO, "divide by zero");

        let max = params.as_ref().max_attainable_target;
        let d = max.0 / self.0;
        d.saturating_to_u128()
    }

    /// Computes the popular "difficulty" measure for mining and returns a float value of f64.
    ///
    /// See [`difficulty`] for details.
    ///
    /// # Returns
    ///
    /// Returns [`f64::INFINITY`] if `self` is zero (caused by divide by zero).
    ///
    /// [`difficulty`]: Target::difficulty
    #[cfg_attr(all(test, mutate), mutate)]
    pub fn difficulty_float(&self) -> f64 {
        TARGET_MAX_F64 / self.0.to_f64()
    }

    /// Computes the minimum valid [`Target`] threshold allowed for a block in which a difficulty
    /// adjustment occurs.
    #[deprecated(since = "0.32.0", note = "use min_transition_threshold instead")]
    pub fn min_difficulty_transition_threshold(&self) -> Self {
        self.min_transition_threshold()
    }

    /// Computes the maximum valid [`Target`] threshold allowed for a block in which a difficulty
    /// adjustment occurs.
    #[deprecated(since = "0.32.0", note = "use max_transition_threshold instead")]
    pub fn max_difficulty_transition_threshold(&self) -> Self {
        self.max_transition_threshold_unchecked()
    }

    /// Computes the minimum valid [`Target`] threshold allowed for a block in which a difficulty
    /// adjustment occurs.
    ///
    /// The difficulty can only decrease or increase by a factor of 4 max on each difficulty
    /// adjustment period.
    ///
    /// # Returns
    ///
    /// In line with Bitcoin Core this function may return a target value of zero.
    pub fn min_transition_threshold(&self) -> Self {
        Self(self.0 >> 2)
    }

    /// Computes the maximum valid [`Target`] threshold allowed for a block in which a difficulty
    /// adjustment occurs.
    ///
    /// The difficulty can only decrease or increase by a factor of 4 max on each difficulty
    /// adjustment period.
    ///
    /// We also check that the calculated target is not greater than the maximum allowed target,
    /// this value is network specific - hence the `params` parameter.
    pub fn max_transition_threshold(&self, params: impl AsRef<Params>) -> Self {
        let max_attainable = params.as_ref().max_attainable_target;
        cmp::min(self.max_transition_threshold_unchecked(), max_attainable)
    }

    /// Computes the maximum valid [`Target`] threshold allowed for a block in which a difficulty
    /// adjustment occurs.
    ///
    /// The difficulty can only decrease or increase by a factor of 4 max on each difficulty
    /// adjustment period.
    ///
    /// # Returns
    ///
    /// This function may return a value greater than the maximum allowed target for this network.
    ///
    /// The return value should be checked against [`Params::max_attainable_target`] or use one of
    /// the `Target::MAX_ATTAINABLE_FOO` constants.
    pub fn max_transition_threshold_unchecked(&self) -> Self {
        Self(self.0 << 2)
    }
}
do_impl!(Target);

/// Encoding of 256-bit target as 32-bit float.
///
/// This is used to encode a target into the block header. Satoshi made this part of consensus code
/// in the original version of Bitcoin, likely copying an idea from OpenSSL.
///
/// OpenSSL's bignum (BN) type has an encoding, which is even called "compact" as in bitcoin, which
/// is exactly this format.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
pub struct CompactTarget(u32);

impl CompactTarget {
    /// Creates a `CompactTarget` from an prefixed hex string.
    pub fn from_hex(s: &str) -> Result<Self, PrefixedHexError> {
        let stripped = if let Some(stripped) = s.strip_prefix("0x") {
            stripped
        } else if let Some(stripped) = s.strip_prefix("0X") {
            stripped
        } else {
            return Err(MissingPrefixError::new(s).into());
        };

        let target = parse::hex_u32(stripped)?;
        Ok(Self::from_consensus(target))
    }

    /// Creates a `CompactTarget` from an unprefixed hex string.
    pub fn from_unprefixed_hex(s: &str) -> Result<Self, UnprefixedHexError> {
        if s.starts_with("0x") || s.starts_with("0X") {
            return Err(ContainsPrefixError::new(s).into());
        }
        let lock_time = parse::hex_u32(s)?;
        Ok(Self::from_consensus(lock_time))
    }

    /// Creates a [`CompactTarget`] from a consensus encoded `u32`.
    pub fn from_consensus(bits: u32) -> Self {
        Self(bits)
    }

    /// Returns the consensus encoded `u32` representation of this [`CompactTarget`].
    pub fn to_consensus(self) -> u32 {
        self.0
    }
}

impl From<CompactTarget> for Target {
    fn from(c: CompactTarget) -> Self {
        Target::from_compact(c)
    }
}

impl Encodable for CompactTarget {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }
}

impl Decodable for CompactTarget {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        u32::consensus_decode(r).map(CompactTarget)
    }
}

impl LowerHex for CompactTarget {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        LowerHex::fmt(&self.0, f)
    }
}

impl UpperHex for CompactTarget {
    #[inline]
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        UpperHex::fmt(&self.0, f)
    }
}

/// Big-endian 256 bit integer type.
// (high, low): u.0 contains the high bits, u.1 contains the low bits.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
struct U256(u128, u128);

impl U256 {
    const MAX: U256 = U256(
        0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
        0xffff_ffff_ffff_ffff_ffff_ffff_ffff_ffff,
    );

    const ZERO: U256 = U256(0, 0);

    const ONE: U256 = U256(0, 1);

    /// Creates a `U256` from a prefixed hex string.
    fn from_hex(s: &str) -> Result<Self, PrefixedHexError> {
        let stripped = if let Some(stripped) = s.strip_prefix("0x") {
            stripped
        } else if let Some(stripped) = s.strip_prefix("0X") {
            stripped
        } else {
            return Err(MissingPrefixError::new(s).into());
        };
        Ok(U256::from_hex_internal(stripped)?)
    }

    /// Creates a `U256` from an unprefixed hex string.
    fn from_unprefixed_hex(s: &str) -> Result<Self, UnprefixedHexError> {
        if s.starts_with("0x") || s.starts_with("0X") {
            return Err(ContainsPrefixError::new(s).into());
        }
        Ok(U256::from_hex_internal(s)?)
    }

    // Caller to ensure `s` does not contain a prefix.
    fn from_hex_internal(s: &str) -> Result<Self, ParseIntError> {
        let (high, low) = if s.len() < 32 {
            let low = parse::hex_u128(s)?;
            (0, low)
        } else {
            let high_len = s.len() - 32;
            let high_s = &s[..high_len];
            let low_s = &s[high_len..];

            let high = parse::hex_u128(high_s)?;
            let low = parse::hex_u128(low_s)?;
            (high, low)
        };

        Ok(U256(high, low))
    }

    /// Creates `U256` from a big-endian array of `u8`s.
    #[cfg_attr(all(test, mutate), mutate)]
    fn from_be_bytes(a: [u8; 32]) -> U256 {
        let (high, low) = split_in_half(a);
        let big = u128::from_be_bytes(high);
        let little = u128::from_be_bytes(low);
        U256(big, little)
    }

    /// Creates a `U256` from a little-endian array of `u8`s.
    #[cfg_attr(all(test, mutate), mutate)]
    fn from_le_bytes(a: [u8; 32]) -> U256 {
        let (high, low) = split_in_half(a);
        let little = u128::from_le_bytes(high);
        let big = u128::from_le_bytes(low);
        U256(big, little)
    }

    /// Converts `U256` to a big-endian array of `u8`s.
    #[cfg_attr(all(test, mutate), mutate)]
    fn to_be_bytes(self) -> [u8; 32] {
        let mut out = [0; 32];
        out[..16].copy_from_slice(&self.0.to_be_bytes());
        out[16..].copy_from_slice(&self.1.to_be_bytes());
        out
    }

    /// Converts `U256` to a little-endian array of `u8`s.
    #[cfg_attr(all(test, mutate), mutate)]
    fn to_le_bytes(self) -> [u8; 32] {
        let mut out = [0; 32];
        out[..16].copy_from_slice(&self.1.to_le_bytes());
        out[16..].copy_from_slice(&self.0.to_le_bytes());
        out
    }

    /// Calculates 2^256 / (x + 1) where x is a 256 bit unsigned integer.
    ///
    /// 2**256 / (x + 1) == ~x / (x + 1) + 1
    ///
    /// (Equation shamelessly stolen from bitcoind)
    fn inverse(&self) -> U256 {
        // We should never have a target/work of zero so this doesn't matter
        // that much but we define the inverse of 0 as max.
        if self.is_zero() {
            return U256::MAX;
        }
        // We define the inverse of 1 as max.
        if self.is_one() {
            return U256::MAX;
        }
        // We define the inverse of max as 1.
        if self.is_max() {
            return U256::ONE;
        }

        let ret = !*self / self.wrapping_inc();
        ret.wrapping_inc()
    }

    #[cfg_attr(all(test, mutate), mutate)]
    fn is_zero(&self) -> bool {
        self.0 == 0 && self.1 == 0
    }

    #[cfg_attr(all(test, mutate), mutate)]
    fn is_one(&self) -> bool {
        self.0 == 0 && self.1 == 1
    }

    #[cfg_attr(all(test, mutate), mutate)]
    fn is_max(&self) -> bool {
        self.0 == u128::MAX && self.1 == u128::MAX
    }

    /// Returns the low 32 bits.
    fn low_u32(&self) -> u32 {
        self.low_u128() as u32
    }

    /// Returns the low 64 bits.
    fn low_u64(&self) -> u64 {
        self.low_u128() as u64
    }

    /// Returns the low 128 bits.
    fn low_u128(&self) -> u128 {
        self.1
    }

    /// Returns this `U256` as a `u128` saturating to `u128::MAX` if `self` is too big.
    // Matagen gives false positive because >= and > both return u128::MAX
    fn saturating_to_u128(&self) -> u128 {
        if *self > U256::from(u128::MAX) {
            u128::MAX
        } else {
            self.low_u128()
        }
    }

    /// Returns the least number of bits needed to represent the number.
    #[cfg_attr(all(test, mutate), mutate)]
    fn bits(&self) -> u32 {
        if self.0 > 0 {
            256 - self.0.leading_zeros()
        } else {
            128 - self.1.leading_zeros()
        }
    }

    /// Wrapping multiplication by `u64`.
    ///
    /// # Returns
    ///
    /// The multiplication result along with a boolean indicating whether an arithmetic overflow
    /// occurred. If an overflow occurred then the wrapped value is returned.
    // mutagen false pos mul_u64: replace `|` with `^` (XOR is same as OR when combined with <<)
    // mutagen false pos mul_u64: replace `|` with `^`
    #[cfg_attr(all(test, mutate), mutate)]
    fn mul_u64(self, rhs: u64) -> (U256, bool) {
        let mut carry: u128 = 0;
        let mut split_le = [
            self.1 as u64,
            (self.1 >> 64) as u64,
            self.0 as u64,
            (self.0 >> 64) as u64,
        ];

        for word in &mut split_le {
            // This will not overflow, for proof see https://github.com/rust-bitcoin/rust-bitcoin/pull/1496#issuecomment-1365938572
            let n = carry + u128::from(rhs) * u128::from(*word);

            *word = n as u64; // Intentional truncation, save the low bits
            carry = n >> 64; // and carry the high bits.
        }

        let low = u128::from(split_le[0]) | u128::from(split_le[1]) << 64;
        let high = u128::from(split_le[2]) | u128::from(split_le[3]) << 64;
        (Self(high, low), carry != 0)
    }

    /// Calculates quotient and remainder.
    ///
    /// # Returns
    ///
    /// (quotient, remainder)
    ///
    /// # Panics
    ///
    /// If `rhs` is zero.
    #[cfg_attr(all(test, mutate), mutate)]
    fn div_rem(self, rhs: Self) -> (Self, Self) {
        let mut sub_copy = self;
        let mut shift_copy = rhs;
        let mut ret = [0u128; 2];

        let my_bits = self.bits();
        let your_bits = rhs.bits();

        // Check for division by 0
        assert!(your_bits != 0, "attempted to divide {} by zero", self);

        // Early return in case we are dividing by a larger number than us
        if my_bits < your_bits {
            return (U256::ZERO, sub_copy);
        }

        // Bitwise long division
        let mut shift = my_bits - your_bits;
        shift_copy = shift_copy << shift;
        loop {
            if sub_copy >= shift_copy {
                ret[1 - (shift / 128) as usize] |= 1 << (shift % 128);
                sub_copy = sub_copy.wrapping_sub(shift_copy);
            }
            shift_copy = shift_copy >> 1;
            if shift == 0 {
                break;
            }
            shift -= 1;
        }

        (U256(ret[0], ret[1]), sub_copy)
    }

    /// Calculates `self` + `rhs`
    ///
    /// Returns a tuple of the addition along with a boolean indicating whether an arithmetic
    /// overflow would occur. If an overflow would have occurred then the wrapped value is returned.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[cfg_attr(all(test, mutate), mutate)]
    fn overflowing_add(self, rhs: Self) -> (Self, bool) {
        let mut ret = U256::ZERO;
        let mut ret_overflow = false;

        let (high, overflow) = self.0.overflowing_add(rhs.0);
        ret.0 = high;
        ret_overflow |= overflow;

        let (low, overflow) = self.1.overflowing_add(rhs.1);
        ret.1 = low;
        if overflow {
            let (high, overflow) = ret.0.overflowing_add(1);
            ret.0 = high;
            ret_overflow |= overflow;
        }

        (ret, ret_overflow)
    }

    /// Calculates `self` - `rhs`
    ///
    /// Returns a tuple of the subtraction along with a boolean indicating whether an arithmetic
    /// overflow would occur. If an overflow would have occurred then the wrapped value is returned.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[cfg_attr(all(test, mutate), mutate)]
    fn overflowing_sub(self, rhs: Self) -> (Self, bool) {
        let ret = self.wrapping_add(!rhs).wrapping_add(Self::ONE);
        let overflow = rhs > self;
        (ret, overflow)
    }

    /// Calculates the multiplication of `self` and `rhs`.
    ///
    /// Returns a tuple of the multiplication along with a boolean
    /// indicating whether an arithmetic overflow would occur. If an
    /// overflow would have occurred then the wrapped value is returned.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[cfg_attr(all(test, mutate), mutate)]
    fn overflowing_mul(self, rhs: Self) -> (Self, bool) {
        let mut ret = U256::ZERO;
        let mut ret_overflow = false;

        for i in 0..3 {
            let to_mul = (rhs >> (64 * i)).low_u64();
            let (mul_res, _) = self.mul_u64(to_mul);
            ret = ret.wrapping_add(mul_res << (64 * i));
        }

        let to_mul = (rhs >> 192).low_u64();
        let (mul_res, overflow) = self.mul_u64(to_mul);
        ret_overflow |= overflow;
        let (sum, overflow) = ret.overflowing_add(mul_res);
        ret = sum;
        ret_overflow |= overflow;

        (ret, ret_overflow)
    }

    /// Wrapping (modular) addition. Computes `self + rhs`, wrapping around at the boundary of the
    /// type.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn wrapping_add(self, rhs: Self) -> Self {
        let (ret, _overflow) = self.overflowing_add(rhs);
        ret
    }

    /// Wrapping (modular) subtraction. Computes `self - rhs`, wrapping around at the boundary of
    /// the type.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    fn wrapping_sub(self, rhs: Self) -> Self {
        let (ret, _overflow) = self.overflowing_sub(rhs);
        ret
    }

    /// Returns `self` incremented by 1 wrapping around at the boundary of the type.
    #[must_use = "this returns the result of the increment, without modifying the original"]
    #[cfg_attr(all(test, mutate), mutate)]
    fn wrapping_inc(&self) -> U256 {
        let mut ret = U256::ZERO;

        ret.1 = self.1.wrapping_add(1);
        if ret.1 == 0 {
            ret.0 = self.0.wrapping_add(1);
        } else {
            ret.0 = self.0;
        }
        ret
    }

    /// Panic-free bitwise shift-left; yields `self << mask(rhs)`, where `mask` removes any
    /// high-order bits of `rhs` that would cause the shift to exceed the bitwidth of the type.
    ///
    /// Note that this is *not* the same as a rotate-left; the RHS of a wrapping shift-left is
    /// restricted to the range of the type, rather than the bits shifted out of the LHS being
    /// returned to the other end. We do not currently support `rotate_left`.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[cfg_attr(all(test, mutate), mutate)]
    fn wrapping_shl(self, rhs: u32) -> Self {
        let shift = rhs & 0x000000ff;

        let mut ret = U256::ZERO;
        let word_shift = shift >= 128;
        let bit_shift = shift % 128;

        if word_shift {
            ret.0 = self.1 << bit_shift
        } else {
            ret.0 = self.0 << bit_shift;
            if bit_shift > 0 {
                ret.0 += self.1.wrapping_shr(128 - bit_shift);
            }
            ret.1 = self.1 << bit_shift;
        }
        ret
    }

    /// Panic-free bitwise shift-right; yields `self >> mask(rhs)`, where `mask` removes any
    /// high-order bits of `rhs` that would cause the shift to exceed the bitwidth of the type.
    ///
    /// Note that this is *not* the same as a rotate-right; the RHS of a wrapping shift-right is
    /// restricted to the range of the type, rather than the bits shifted out of the LHS being
    /// returned to the other end. We do not currently support `rotate_right`.
    #[must_use = "this returns the result of the operation, without modifying the original"]
    #[cfg_attr(all(test, mutate), mutate)]
    fn wrapping_shr(self, rhs: u32) -> Self {
        let shift = rhs & 0x000000ff;

        let mut ret = U256::ZERO;
        let word_shift = shift >= 128;
        let bit_shift = shift % 128;

        if word_shift {
            ret.1 = self.0 >> bit_shift
        } else {
            ret.0 = self.0 >> bit_shift;
            ret.1 = self.1 >> bit_shift;
            if bit_shift > 0 {
                ret.1 += self.0.wrapping_shl(128 - bit_shift);
            }
        }
        ret
    }

    /// Format `self` to `f` as a decimal when value is known to be non-zero.
    fn fmt_decimal(&self, f: &mut fmt::Formatter) -> fmt::Result {
        const DIGITS: usize = 78; // U256::MAX has 78 base 10 digits.
        const TEN: U256 = U256(0, 10);

        let mut buf = [0_u8; DIGITS];
        let mut i = DIGITS - 1; // We loop backwards.
        let mut cur = *self;

        loop {
            let digit = (cur % TEN).low_u128() as u8; // Cast after rem 10 is lossless.
            buf[i] = digit + b'0';
            cur = cur / TEN;
            if cur.is_zero() {
                break;
            }
            i -= 1;
        }
        let s = core::str::from_utf8(&buf[i..]).expect("digits 0-9 are valid UTF8");
        f.pad_integral(true, "", s)
    }

    /// Convert self to f64.
    #[inline]
    fn to_f64(self) -> f64 {
        // Reference: https://blog.m-ou.se/floats/
        // Step 1: Get leading zeroes
        let leading_zeroes = 256 - self.bits();
        // Step 2: Get msb to be farthest left bit
        let left_aligned = self.wrapping_shl(leading_zeroes);
        // Step 3: Shift msb to fit in lower 53 bits (128-53=75) to get the mantissa
        // * Shifting the border of the 2 u128s to line up with mantissa and dropped bits
        let middle_aligned = left_aligned >> 75;
        // * This is the 53 most significant bits as u128
        let mantissa = middle_aligned.0;
        // Step 4: Dropped bits (except for last 75 bits) are all in the second u128.
        // Bitwise OR the rest of the bits into it, preserving the highest bit,
        // so we take the lower 75 bits of middle_aligned.1 and mix it in. (See blog for explanation)
        let dropped_bits = middle_aligned.1 | (left_aligned.1 & 0x7FF_FFFF_FFFF_FFFF_FFFF);
        // Step 5: The msb of the dropped bits has been preserved, and all other bits
        // if any were set, would be set somewhere in the other 127 bits.
        // If msb of dropped bits is 0, it is mantissa + 0
        // If msb of dropped bits is 1, it is mantissa + 0 only if mantissa lowest bit is 0
        // and other bits of the dropped bits are all 0.
        // (This is why we only care if the other non-msb dropped bits are all 0 or not,
        // so we can just OR them to make sure any bits show up somewhere.)
        let mantissa =
            (mantissa + ((dropped_bits - (dropped_bits >> 127 & !mantissa)) >> 127)) as u64;
        // Step 6: Calculate the exponent
        // If self is 0, exponent should be 0 (special meaning) and mantissa will end up 0 too
        // Otherwise, (255 - n) + 1022 so it simplifies to 1277 - n
        // 1023 and 1022 are the cutoffs for the exponent having the msb next to the decimal point
        let exponent = if self == Self::ZERO {
            0
        } else {
            1277 - leading_zeroes as u64
        };
        // Step 7: sign bit is always 0, exponent is shifted into place
        // Use addition instead of bitwise OR to saturate the exponent if mantissa overflows
        f64::from_bits((exponent << 52) + mantissa)
    }
}

// Target::MAX as a float value. Calculated with U256::to_f64.
// This is validated in the unit tests as well.
const TARGET_MAX_F64: f64 = 2.695953529101131e67;

impl<T: Into<u128>> From<T> for U256 {
    fn from(x: T) -> Self {
        U256(0, x.into())
    }
}

impl Add for U256 {
    type Output = Self;
    fn add(self, rhs: Self) -> Self {
        let (res, overflow) = self.overflowing_add(rhs);
        debug_assert!(!overflow, "Addition of U256 values overflowed");
        res
    }
}

impl Sub for U256 {
    type Output = Self;
    fn sub(self, rhs: Self) -> Self {
        let (res, overflow) = self.overflowing_sub(rhs);
        debug_assert!(!overflow, "Subtraction of U256 values overflowed");
        res
    }
}

impl Mul for U256 {
    type Output = Self;
    fn mul(self, rhs: Self) -> Self {
        let (res, overflow) = self.overflowing_mul(rhs);
        debug_assert!(!overflow, "Multiplication of U256 values overflowed");
        res
    }
}

impl Div for U256 {
    type Output = Self;
    fn div(self, rhs: Self) -> Self {
        self.div_rem(rhs).0
    }
}

impl Rem for U256 {
    type Output = Self;
    fn rem(self, rhs: Self) -> Self {
        self.div_rem(rhs).1
    }
}

impl Not for U256 {
    type Output = Self;

    fn not(self) -> Self {
        U256(!self.0, !self.1)
    }
}

impl Shl<u32> for U256 {
    type Output = Self;
    fn shl(self, shift: u32) -> U256 {
        self.wrapping_shl(shift)
    }
}

impl Shr<u32> for U256 {
    type Output = Self;
    fn shr(self, shift: u32) -> U256 {
        self.wrapping_shr(shift)
    }
}

impl fmt::Display for U256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.is_zero() {
            f.pad_integral(true, "", "0")
        } else {
            self.fmt_decimal(f)
        }
    }
}

impl fmt::Debug for U256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:#x}", self)
    }
}

macro_rules! impl_hex {
    ($hex:ident, $case:expr) => {
        impl $hex for U256 {
            fn fmt(&self, f: &mut fmt::Formatter) -> core::fmt::Result {
                hex::fmt_hex_exact!(f, 32, &self.to_be_bytes(), $case)
            }
        }
    };
}
impl_hex!(LowerHex, hex::Case::Lower);
impl_hex!(UpperHex, hex::Case::Upper);

#[cfg(feature = "serde")]
impl crate::serde::Serialize for U256 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: crate::serde::Serializer,
    {
        struct DisplayHex(U256);

        impl fmt::Display for DisplayHex {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                write!(f, "{:x}", self.0)
            }
        }

        if serializer.is_human_readable() {
            serializer.collect_str(&DisplayHex(*self))
        } else {
            let bytes = self.to_be_bytes();
            serializer.serialize_bytes(&bytes)
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> crate::serde::Deserialize<'de> for U256 {
    fn deserialize<D: crate::serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        use hex::FromHex;

        use crate::serde::de;

        if d.is_human_readable() {
            struct HexVisitor;

            impl<'de> de::Visitor<'de> for HexVisitor {
                type Value = U256;

                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    f.write_str("a 32 byte ASCII hex string")
                }

                fn visit_str<E>(self, s: &str) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    if s.len() != 64 {
                        return Err(de::Error::invalid_length(s.len(), &self));
                    }

                    let b = <[u8; 32]>::from_hex(s)
                        .map_err(|_| de::Error::invalid_value(de::Unexpected::Str(s), &self))?;

                    Ok(U256::from_be_bytes(b))
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: de::Error,
                {
                    if let Ok(hex) = core::str::from_utf8(v) {
                        let b = <[u8; 32]>::from_hex(hex).map_err(|_| {
                            de::Error::invalid_value(de::Unexpected::Str(hex), &self)
                        })?;

                        Ok(U256::from_be_bytes(b))
                    } else {
                        Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self))
                    }
                }
            }
            d.deserialize_str(HexVisitor)
        } else {
            struct BytesVisitor;

            impl<'de> serde::de::Visitor<'de> for BytesVisitor {
                type Value = U256;

                fn expecting(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
                    f.write_str("a sequence of bytes")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    let b = v
                        .try_into()
                        .map_err(|_| de::Error::invalid_length(v.len(), &self))?;
                    Ok(U256::from_be_bytes(b))
                }
            }

            d.deserialize_bytes(BytesVisitor)
        }
    }
}

/// Splits a 32 byte array into two 16 byte arrays.
fn split_in_half(a: [u8; 32]) -> ([u8; 16], [u8; 16]) {
    let mut high = [0_u8; 16];
    let mut low = [0_u8; 16];

    high.copy_from_slice(&a[..16]);
    low.copy_from_slice(&a[16..]);

    (high, low)
}

#[cfg(kani)]
impl kani::Arbitrary for U256 {
    fn any() -> Self {
        let high: u128 = kani::any();
        let low: u128 = kani::any();
        Self(high, low)
    }
}

#[cfg(kani)]
mod verification {
    use super::*;

    #[kani::unwind(5)] // mul_u64 loops over 4 64 bit ints so use one more than 4
    #[kani::proof]
    fn check_mul_u64() {
        let x: U256 = kani::any();
        let y: u64 = kani::any();

        let _ = x.mul_u64(y);
    }
}
