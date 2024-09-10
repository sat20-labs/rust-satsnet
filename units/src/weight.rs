// SPDX-License-Identifier: CC0-1.0

//! Implements `Weight` and associated features.

use core::fmt;
use core::ops::{Add, AddAssign, Div, DivAssign, Mul, MulAssign, Sub, SubAssign};

#[cfg(feature = "serde")]
use serde::{Deserialize, Serialize};

/// The factor that non-witness serialization data is multiplied by during weight calculation.
pub const WITNESS_SCALE_FACTOR: usize = 4;

/// Represents block weight - the weight of a transaction or block.
///
/// This is an integer newtype representing weigth in `wu`. It provides protection against mixing
/// up the types as well as basic formatting features.
#[derive(Debug, Copy, Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct Weight(u64);

impl Weight {
    /// 0 wu.
    ///
    /// Equivalent to [`MIN`](Self::MIN), may better express intent in some contexts.
    pub const ZERO: Weight = Weight(0);

    /// Minimum possible value (0 wu).
    ///
    /// Equivalent to [`ZERO`](Self::ZERO), may better express intent in some contexts.
    pub const MIN: Weight = Weight(u64::MIN);

    /// Maximum possible value.
    pub const MAX: Weight = Weight(u64::MAX);

    /// The factor that non-witness serialization data is multiplied by during weight calculation.
    pub const WITNESS_SCALE_FACTOR: u64 = WITNESS_SCALE_FACTOR as u64;

    /// The maximum allowed weight for a block, see BIP 141 (network rule).
    pub const MAX_BLOCK: Weight = Weight(4_000_000);

    /// The minimum transaction weight for a valid serialized transaction.
    pub const MIN_TRANSACTION: Weight = Weight(Self::WITNESS_SCALE_FACTOR * 60);

    /// Directly constructs `Weight` from weight units.
    pub const fn from_wu(wu: u64) -> Self {
        Weight(wu)
    }

    /// Directly constructs `Weight` from usize weight units.
    pub const fn from_wu_usize(wu: usize) -> Self {
        Weight(wu as u64)
    }

    /// Constructs `Weight` from kilo weight units returning `None` if an overflow occurred.
    pub fn from_kwu(wu: u64) -> Option<Self> {
        wu.checked_mul(1000).map(Weight)
    }

    /// Constructs `Weight` from virtual bytes, returning `None` on overflow.
    pub fn from_vb(vb: u64) -> Option<Self> {
        vb.checked_mul(Self::WITNESS_SCALE_FACTOR)
            .map(Weight::from_wu)
    }

    /// Constructs `Weight` from virtual bytes panicking on overflow.
    ///
    /// # Panics
    ///
    /// If the conversion from virtual bytes overflows.
    pub const fn from_vb_unwrap(vb: u64) -> Weight {
        match vb.checked_mul(Self::WITNESS_SCALE_FACTOR) {
            Some(weight) => Weight(weight),
            None => {
                // When MSRV is 1.57+ we can use `panic!()`.
                #[allow(unconditional_panic)]
                #[allow(clippy::let_unit_value)]
                #[allow(clippy::out_of_bounds_indexing)]
                let _int_overflow_scaling_weight = [(); 0][1];
                Weight(0)
            }
        }
    }

    /// Constructs `Weight` from virtual bytes without an overflow check.
    pub const fn from_vb_unchecked(vb: u64) -> Self {
        Weight::from_wu(vb * 4)
    }

    /// Constructs `Weight` from witness size.
    pub const fn from_witness_data_size(witness_size: u64) -> Self {
        Weight(witness_size)
    }

    /// Constructs `Weight` from non-witness size.
    pub const fn from_non_witness_data_size(non_witness_size: u64) -> Self {
        Weight(non_witness_size * Self::WITNESS_SCALE_FACTOR)
    }

    /// Returns raw weight units.
    ///
    /// Can be used instead of `into()` to avoid inference issues.
    pub const fn to_wu(self) -> u64 {
        self.0
    }

    /// Converts to kilo weight units rounding down.
    pub const fn to_kwu_floor(self) -> u64 {
        self.0 / 1000
    }

    /// Converts to vB rounding down.
    pub const fn to_vbytes_floor(self) -> u64 {
        self.0 / Self::WITNESS_SCALE_FACTOR
    }

    /// Converts to vB rounding up.
    pub const fn to_vbytes_ceil(self) -> u64 {
        (self.0 + Self::WITNESS_SCALE_FACTOR - 1) / Self::WITNESS_SCALE_FACTOR
    }

    /// Checked addition.
    ///
    /// Computes `self + rhs` returning `None` if an overflow occurred.
    pub fn checked_add(self, rhs: Self) -> Option<Self> {
        self.0.checked_add(rhs.0).map(Self)
    }

    /// Checked subtraction.
    ///
    /// Computes `self - rhs` returning `None` if an overflow occurred.
    pub fn checked_sub(self, rhs: Self) -> Option<Self> {
        self.0.checked_sub(rhs.0).map(Self)
    }

    /// Checked multiplication.
    ///
    /// Computes `self * rhs` returning `None` if an overflow occurred.
    pub fn checked_mul(self, rhs: u64) -> Option<Self> {
        self.0.checked_mul(rhs).map(Self)
    }

    /// Checked division.
    ///
    /// Computes `self / rhs` returning `None` if `rhs == 0`.
    pub fn checked_div(self, rhs: u64) -> Option<Self> {
        self.0.checked_div(rhs).map(Self)
    }

    /// Scale by witness factor.
    ///
    /// Computes `self * WITNESS_SCALE_FACTOR` returning `None` if an overflow occurred.
    pub fn scale_by_witness_factor(self) -> Option<Self> {
        Self::checked_mul(self, Self::WITNESS_SCALE_FACTOR)
    }
}

/// Alternative will display the unit.
impl fmt::Display for Weight {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            write!(f, "{} wu", self.0)
        } else {
            fmt::Display::fmt(&self.0, f)
        }
    }
}

impl From<Weight> for u64 {
    fn from(value: Weight) -> Self {
        value.to_wu()
    }
}

impl Add for Weight {
    type Output = Weight;

    fn add(self, rhs: Weight) -> Self::Output {
        Weight(self.0 + rhs.0)
    }
}

impl AddAssign for Weight {
    fn add_assign(&mut self, rhs: Self) {
        self.0 += rhs.0
    }
}

impl Sub for Weight {
    type Output = Weight;

    fn sub(self, rhs: Weight) -> Self::Output {
        Weight(self.0 - rhs.0)
    }
}

impl SubAssign for Weight {
    fn sub_assign(&mut self, rhs: Self) {
        self.0 -= rhs.0
    }
}

impl Mul<u64> for Weight {
    type Output = Weight;

    fn mul(self, rhs: u64) -> Self::Output {
        Weight(self.0 * rhs)
    }
}

impl Mul<Weight> for u64 {
    type Output = Weight;

    fn mul(self, rhs: Weight) -> Self::Output {
        Weight(self * rhs.0)
    }
}

impl MulAssign<u64> for Weight {
    fn mul_assign(&mut self, rhs: u64) {
        self.0 *= rhs
    }
}

impl Div<u64> for Weight {
    type Output = Weight;

    fn div(self, rhs: u64) -> Self::Output {
        Weight(self.0 / rhs)
    }
}

impl Div<Weight> for Weight {
    type Output = u64;

    fn div(self, rhs: Weight) -> Self::Output {
        self.to_wu() / rhs.to_wu()
    }
}

impl DivAssign<u64> for Weight {
    fn div_assign(&mut self, rhs: u64) {
        self.0 /= rhs
    }
}

impl core::iter::Sum for Weight {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = Self>,
    {
        Weight(iter.map(Weight::to_wu).sum())
    }
}

impl<'a> core::iter::Sum<&'a Weight> for Weight {
    fn sum<I>(iter: I) -> Self
    where
        I: Iterator<Item = &'a Weight>,
    {
        iter.cloned().sum()
    }
}

crate::impl_parse_str_from_int_infallible!(Weight, u64, from_wu);
