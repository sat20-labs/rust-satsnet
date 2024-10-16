// SPDX-License-Identifier: CC0-1.0

//! Signature hash implementation (used in transaction signing).
//!
//! Efficient implementation of the algorithm to compute the message to be signed according to
//! [Bip341](https://github.com/bitcoin/bips/blob/150ab6f5c3aca9da05fccc5b435e9667853407f4/bip-0341.mediawiki),
//! [Bip143](https://github.com/bitcoin/bips/blob/99701f68a88ce33b2d0838eb84e115cef505b4c2/bip-0143.mediawiki)
//! and legacy (before Bip143).
//!
//! Computing signature hashes is required to sign a transaction and this module is designed to
//! handle its complexity efficiently. Computing these hashes is as simple as creating
//! [`SighashCache`] and calling its methods.

use core::{fmt, str};

use hashes::{hash_newtype, sha256, sha256d, sha256t_hash_newtype, Hash};
use internals::write_err;
use io::Write;

use crate::blockdata::witness::Witness;
use crate::consensus::{encode, Encodable};
use crate::prelude::*;
use crate::taproot::{LeafVersion, TapLeafHash, TAPROOT_ANNEX_PREFIX};
use crate::{transaction, Amount, Script, ScriptBuf, Sequence, Transaction, TxIn, TxOut};

/// Used for signature hash for invalid use of SIGHASH_SINGLE.
#[rustfmt::skip]
pub(crate) const UINT256_ONE: [u8; 32] = [
    1, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
];

macro_rules! impl_message_from_hash {
    ($ty:ident) => {
        impl From<$ty> for secp256k1::Message {
            fn from(hash: $ty) -> secp256k1::Message {
                secp256k1::Message::from_digest(hash.to_byte_array())
            }
        }
    };
}

hash_newtype! {
    /// Hash of a transaction according to the legacy signature algorithm.
    #[hash_newtype(forward)]
    pub struct LegacySighash(sha256d::Hash);

    /// Hash of a transaction according to the segwit version 0 signature algorithm.
    #[hash_newtype(forward)]
    pub struct SegwitV0Sighash(sha256d::Hash);
}

impl_message_from_hash!(LegacySighash);
impl_message_from_hash!(SegwitV0Sighash);

sha256t_hash_newtype! {
    pub struct TapSighashTag = hash_str("TapSighash");

    /// Taproot-tagged hash with tag \"TapSighash\".
    ///
    /// This hash type is used for computing taproot signature hash."
    #[hash_newtype(forward)]
    pub struct TapSighash(_);
}

impl_message_from_hash!(TapSighash);

/// Efficiently calculates signature hash message for legacy, segwit and taproot inputs.
#[derive(Debug)]
pub struct SighashCache<T: Borrow<Transaction>> {
    /// Access to transaction required for transaction introspection. Moreover, type
    /// `T: Borrow<Transaction>` allows us to use borrowed and mutable borrowed types,
    /// the latter in particular is necessary for [`SighashCache::witness_mut`].
    tx: T,

    /// Common cache for taproot and segwit inputs, `None` for legacy inputs.
    common_cache: Option<CommonCache>,

    /// Cache for segwit v0 inputs (the result of another round of sha256 on `common_cache`).
    segwit_cache: Option<SegwitCache>,

    /// Cache for taproot v1 inputs.
    taproot_cache: Option<TaprootCache>,
}

/// Common values cached between segwit and taproot inputs.
#[derive(Debug)]
struct CommonCache {
    prevouts: sha256::Hash,
    sequences: sha256::Hash,

    /// In theory `outputs` could be an `Option` since `SIGHASH_NONE` and `SIGHASH_SINGLE` do not
    /// need it, but since `SIGHASH_ALL` is by far the most used variant we don't bother.
    outputs: sha256::Hash,
}

/// Values cached for segwit inputs, equivalent to [`CommonCache`] plus another round of `sha256`.
#[derive(Debug)]
struct SegwitCache {
    prevouts: sha256d::Hash,
    sequences: sha256d::Hash,
    outputs: sha256d::Hash,
}

/// Values cached for taproot inputs.
#[derive(Debug)]
struct TaprootCache {
    amounts: sha256::Hash,
    script_pubkeys: sha256::Hash,
}

/// Contains outputs of previous transactions. In the case [`TapSighashType`] variant is
/// `SIGHASH_ANYONECANPAY`, [`Prevouts::One`] may be used.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Prevouts<'u, T>
where
    T: 'u + Borrow<TxOut>,
{
    /// `One` variant allows provision of the single prevout needed. It's useful, for example, when
    /// modifier `SIGHASH_ANYONECANPAY` is provided, only prevout of the current input is needed.
    /// The first `usize` argument is the input index this [`TxOut`] is referring to.
    One(usize, T),
    /// When `SIGHASH_ANYONECANPAY` is not provided, or when the caller is giving all prevouts so
    /// the same variable can be used for multiple inputs.
    All(&'u [T]),
}

const KEY_VERSION_0: u8 = 0u8;

/// Information related to the script path spending.
///
/// This can be hashed into a [`TapLeafHash`].
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ScriptPath<'s> {
    script: &'s Script,
    leaf_version: LeafVersion,
}

/// Hashtype of an input's signature, encoded in the last byte of the signature.
/// Fixed values so they can be cast as integer types for encoding.
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum TapSighashType {
    /// 0x0: Used when not explicitly specified, defaults to [`TapSighashType::All`]
    Default = 0x00,
    /// 0x1: Sign all outputs.
    All = 0x01,
    /// 0x2: Sign no outputs --- anyone can choose the destination.
    None = 0x02,
    /// 0x3: Sign the output whose index matches this input's index. If none exists,
    /// sign the hash `0000000000000000000000000000000000000000000000000000000000000001`.
    /// (This rule is probably an unintentional C++ism, but it's consensus so we have
    /// to follow it.)
    Single = 0x03,
    /// 0x81: Sign all outputs but only this input.
    AllPlusAnyoneCanPay = 0x81,
    /// 0x82: Sign no outputs and only this input.
    NonePlusAnyoneCanPay = 0x82,
    /// 0x83: Sign one output and only this input (see `Single` for what "one output" means).
    SinglePlusAnyoneCanPay = 0x83,
}
#[cfg(feature = "serde")]
crate::serde_utils::serde_string_impl!(TapSighashType, "a TapSighashType data");

impl fmt::Display for TapSighashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use TapSighashType::*;

        let s = match self {
            Default => "SIGHASH_DEFAULT",
            All => "SIGHASH_ALL",
            None => "SIGHASH_NONE",
            Single => "SIGHASH_SINGLE",
            AllPlusAnyoneCanPay => "SIGHASH_ALL|SIGHASH_ANYONECANPAY",
            NonePlusAnyoneCanPay => "SIGHASH_NONE|SIGHASH_ANYONECANPAY",
            SinglePlusAnyoneCanPay => "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY",
        };
        f.write_str(s)
    }
}

impl str::FromStr for TapSighashType {
    type Err = SighashTypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use TapSighashType::*;

        match s {
            "SIGHASH_DEFAULT" => Ok(Default),
            "SIGHASH_ALL" => Ok(All),
            "SIGHASH_NONE" => Ok(None),
            "SIGHASH_SINGLE" => Ok(Single),
            "SIGHASH_ALL|SIGHASH_ANYONECANPAY" => Ok(AllPlusAnyoneCanPay),
            "SIGHASH_NONE|SIGHASH_ANYONECANPAY" => Ok(NonePlusAnyoneCanPay),
            "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY" => Ok(SinglePlusAnyoneCanPay),
            _ => Err(SighashTypeParseError { unrecognized: s.to_owned() }),
        }
    }
}

impl<'u, T> Prevouts<'u, T>
where
    T: Borrow<TxOut>,
{
    fn check_all(&self, tx: &Transaction) -> Result<(), PrevoutsSizeError> {
        if let Prevouts::All(prevouts) = self {
            if prevouts.len() != tx.input.len() {
                return Err(PrevoutsSizeError);
            }
        }
        Ok(())
    }

    fn get_all(&self) -> Result<&[T], PrevoutsKindError> {
        match self {
            Prevouts::All(prevouts) => Ok(*prevouts),
            _ => Err(PrevoutsKindError),
        }
    }

    fn get(&self, input_index: usize) -> Result<&TxOut, PrevoutsIndexError> {
        match self {
            Prevouts::One(index, prevout) =>
                if input_index == *index {
                    Ok(prevout.borrow())
                } else {
                    Err(PrevoutsIndexError::InvalidOneIndex)
                },
            Prevouts::All(prevouts) => prevouts
                .get(input_index)
                .map(|x| x.borrow())
                .ok_or(PrevoutsIndexError::InvalidAllIndex),
        }
    }
}

/// The number of supplied prevouts differs from the number of inputs in the transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PrevoutsSizeError;

impl fmt::Display for PrevoutsSizeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "number of supplied prevouts differs from the number of inputs in transaction")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PrevoutsSizeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// A single prevout was been provided but all prevouts are needed without `ANYONECANPAY`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct PrevoutsKindError;

impl fmt::Display for PrevoutsKindError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "single prevout provided but all prevouts are needed without `ANYONECANPAY`")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PrevoutsKindError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// [`Prevouts`] index related errors.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum PrevoutsIndexError {
    /// Invalid index when accessing a [`Prevouts::One`] kind.
    InvalidOneIndex,
    /// Invalid index when accessing a [`Prevouts::All`] kind.
    InvalidAllIndex,
}

internals::impl_from_infallible!(PrevoutsIndexError);

impl fmt::Display for PrevoutsIndexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use PrevoutsIndexError::*;

        match *self {
            InvalidOneIndex => write!(f, "invalid index when accessing a Prevouts::One kind"),
            InvalidAllIndex => write!(f, "invalid index when accessing a Prevouts::All kind"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for PrevoutsIndexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use PrevoutsIndexError::*;

        match *self {
            InvalidOneIndex | InvalidAllIndex => None,
        }
    }
}

impl<'s> ScriptPath<'s> {
    /// Creates a new `ScriptPath` structure.
    pub fn new(script: &'s Script, leaf_version: LeafVersion) -> Self {
        ScriptPath { script, leaf_version }
    }
    /// Creates a new `ScriptPath` structure using default leaf version value.
    pub fn with_defaults(script: &'s Script) -> Self { Self::new(script, LeafVersion::TapScript) }
    /// Computes the leaf hash for this `ScriptPath`.
    pub fn leaf_hash(&self) -> TapLeafHash {
        let mut enc = TapLeafHash::engine();

        self.leaf_version
            .to_consensus()
            .consensus_encode(&mut enc)
            .expect("writing to hash enging should never fail");
        self.script.consensus_encode(&mut enc).expect("writing to hash enging should never fail");

        TapLeafHash::from_engine(enc)
    }
}

impl<'s> From<ScriptPath<'s>> for TapLeafHash {
    fn from(script_path: ScriptPath<'s>) -> TapLeafHash { script_path.leaf_hash() }
}

/// Hashtype of an input's signature, encoded in the last byte of the signature.
///
/// Fixed values so they can be cast as integer types for encoding (see also
/// [`TapSighashType`]).
#[derive(PartialEq, Eq, Debug, Copy, Clone, Hash)]
pub enum EcdsaSighashType {
    /// 0x1: Sign all outputs.
    All = 0x01,
    /// 0x2: Sign no outputs --- anyone can choose the destination.
    None = 0x02,
    /// 0x3: Sign the output whose index matches this input's index. If none exists,
    /// sign the hash `0000000000000000000000000000000000000000000000000000000000000001`.
    /// (This rule is probably an unintentional C++ism, but it's consensus so we have
    /// to follow it.)
    Single = 0x03,
    /// 0x81: Sign all outputs but only this input.
    AllPlusAnyoneCanPay = 0x81,
    /// 0x82: Sign no outputs and only this input.
    NonePlusAnyoneCanPay = 0x82,
    /// 0x83: Sign one output and only this input (see `Single` for what "one output" means).
    SinglePlusAnyoneCanPay = 0x83,
}
#[cfg(feature = "serde")]
crate::serde_utils::serde_string_impl!(EcdsaSighashType, "a EcdsaSighashType data");

impl fmt::Display for EcdsaSighashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use EcdsaSighashType::*;

        let s = match self {
            All => "SIGHASH_ALL",
            None => "SIGHASH_NONE",
            Single => "SIGHASH_SINGLE",
            AllPlusAnyoneCanPay => "SIGHASH_ALL|SIGHASH_ANYONECANPAY",
            NonePlusAnyoneCanPay => "SIGHASH_NONE|SIGHASH_ANYONECANPAY",
            SinglePlusAnyoneCanPay => "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY",
        };
        f.write_str(s)
    }
}

impl str::FromStr for EcdsaSighashType {
    type Err = SighashTypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use EcdsaSighashType::*;

        match s {
            "SIGHASH_ALL" => Ok(All),
            "SIGHASH_NONE" => Ok(None),
            "SIGHASH_SINGLE" => Ok(Single),
            "SIGHASH_ALL|SIGHASH_ANYONECANPAY" => Ok(AllPlusAnyoneCanPay),
            "SIGHASH_NONE|SIGHASH_ANYONECANPAY" => Ok(NonePlusAnyoneCanPay),
            "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY" => Ok(SinglePlusAnyoneCanPay),
            _ => Err(SighashTypeParseError { unrecognized: s.to_owned() }),
        }
    }
}

impl EcdsaSighashType {
    /// Splits the sighash flag into the "real" sighash flag and the ANYONECANPAY boolean.
    pub(crate) fn split_anyonecanpay_flag(self) -> (EcdsaSighashType, bool) {
        use EcdsaSighashType::*;

        match self {
            All => (All, false),
            None => (None, false),
            Single => (Single, false),
            AllPlusAnyoneCanPay => (All, true),
            NonePlusAnyoneCanPay => (None, true),
            SinglePlusAnyoneCanPay => (Single, true),
        }
    }

    /// Creates a [`EcdsaSighashType`] from a raw `u32`.
    ///
    /// **Note**: this replicates consensus behaviour, for current standardness rules correctness
    /// you probably want [`Self::from_standard`].
    ///
    /// This might cause unexpected behavior because it does not roundtrip. That is,
    /// `EcdsaSighashType::from_consensus(n) as u32 != n` for non-standard values of `n`. While
    /// verifying signatures, the user should retain the `n` and use it compute the signature hash
    /// message.
    pub fn from_consensus(n: u32) -> EcdsaSighashType {
        use EcdsaSighashType::*;

        // In Bitcoin Core, the SignatureHash function will mask the (int32) value with
        // 0x1f to (apparently) deactivate ACP when checking for SINGLE and NONE bits.
        // We however want to be matching also against on ACP-masked ALL, SINGLE, and NONE.
        // So here we re-activate ACP.
        let mask = 0x1f | 0x80;
        match n & mask {
            // "real" sighashes
            0x01 => All,
            0x02 => None,
            0x03 => Single,
            0x81 => AllPlusAnyoneCanPay,
            0x82 => NonePlusAnyoneCanPay,
            0x83 => SinglePlusAnyoneCanPay,
            // catchalls
            x if x & 0x80 == 0x80 => AllPlusAnyoneCanPay,
            _ => All,
        }
    }

    /// Creates a [`EcdsaSighashType`] from a raw `u32`.
    ///
    /// # Errors
    ///
    /// If `n` is a non-standard sighash value.
    pub fn from_standard(n: u32) -> Result<EcdsaSighashType, NonStandardSighashTypeError> {
        use EcdsaSighashType::*;

        match n {
            // Standard sighashes, see https://github.com/bitcoin/bitcoin/blob/b805dbb0b9c90dadef0424e5b3bf86ac308e103e/src/script/interpreter.cpp#L189-L198
            0x01 => Ok(All),
            0x02 => Ok(None),
            0x03 => Ok(Single),
            0x81 => Ok(AllPlusAnyoneCanPay),
            0x82 => Ok(NonePlusAnyoneCanPay),
            0x83 => Ok(SinglePlusAnyoneCanPay),
            non_standard => Err(NonStandardSighashTypeError(non_standard)),
        }
    }

    /// Converts [`EcdsaSighashType`] to a `u32` sighash flag.
    ///
    /// The returned value is guaranteed to be a valid according to standardness rules.
    pub fn to_u32(self) -> u32 { self as u32 }
}

impl From<EcdsaSighashType> for TapSighashType {
    fn from(s: EcdsaSighashType) -> Self {
        use TapSighashType::*;

        match s {
            EcdsaSighashType::All => All,
            EcdsaSighashType::None => None,
            EcdsaSighashType::Single => Single,
            EcdsaSighashType::AllPlusAnyoneCanPay => AllPlusAnyoneCanPay,
            EcdsaSighashType::NonePlusAnyoneCanPay => NonePlusAnyoneCanPay,
            EcdsaSighashType::SinglePlusAnyoneCanPay => SinglePlusAnyoneCanPay,
        }
    }
}

impl TapSighashType {
    /// Breaks the sighash flag into the "real" sighash flag and the `SIGHASH_ANYONECANPAY` boolean.
    pub(crate) fn split_anyonecanpay_flag(self) -> (TapSighashType, bool) {
        use TapSighashType::*;

        match self {
            Default => (Default, false),
            All => (All, false),
            None => (None, false),
            Single => (Single, false),
            AllPlusAnyoneCanPay => (All, true),
            NonePlusAnyoneCanPay => (None, true),
            SinglePlusAnyoneCanPay => (Single, true),
        }
    }

    /// Constructs a [`TapSighashType`] from a raw `u8`.
    pub fn from_consensus_u8(sighash_type: u8) -> Result<Self, InvalidSighashTypeError> {
        use TapSighashType::*;

        Ok(match sighash_type {
            0x00 => Default,
            0x01 => All,
            0x02 => None,
            0x03 => Single,
            0x81 => AllPlusAnyoneCanPay,
            0x82 => NonePlusAnyoneCanPay,
            0x83 => SinglePlusAnyoneCanPay,
            x => return Err(InvalidSighashTypeError(x.into())),
        })
    }
}

/// Integer is not a consensus valid sighash type.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidSighashTypeError(pub u32);

impl fmt::Display for InvalidSighashTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "invalid sighash type {}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidSighashTypeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// This type is consensus valid but an input including it would prevent the transaction from
/// being relayed on today's Bitcoin network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NonStandardSighashTypeError(pub u32);

impl fmt::Display for NonStandardSighashTypeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "non-standard sighash type {}", self.0)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for NonStandardSighashTypeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Error returned for failure during parsing one of the sighash types.
///
/// This is currently returned for unrecognized sighash strings.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SighashTypeParseError {
    /// The unrecognized string we attempted to parse.
    pub unrecognized: String,
}

impl fmt::Display for SighashTypeParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "unrecognized SIGHASH string '{}'", self.unrecognized)
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SighashTypeParseError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

impl<R: Borrow<Transaction>> SighashCache<R> {
    /// Constructs a new `SighashCache` from an unsigned transaction.
    ///
    /// The sighash components are computed in a lazy manner when required. For the generated
    /// sighashes to be valid, no fields in the transaction may change except for script_sig and
    /// witness.
    pub fn new(tx: R) -> Self {
        SighashCache { tx, common_cache: None, taproot_cache: None, segwit_cache: None }
    }

    /// Returns the reference to the cached transaction.
    pub fn transaction(&self) -> &Transaction { self.tx.borrow() }

    /// Destroys the cache and recovers the stored transaction.
    pub fn into_transaction(self) -> R { self.tx }

    /// Encodes the BIP341 signing data for any flag type into a given object implementing the
    /// [`io::Write`] trait.
    pub fn taproot_encode_signing_data_to<W: Write + ?Sized, T: Borrow<TxOut>>(
        &mut self,
        writer: &mut W,
        input_index: usize,
        prevouts: &Prevouts<T>,
        annex: Option<Annex>,
        leaf_hash_code_separator: Option<(TapLeafHash, u32)>,
        sighash_type: TapSighashType,
    ) -> Result<(), SigningDataError<TaprootError>> {
        prevouts.check_all(self.tx.borrow()).map_err(SigningDataError::sighash)?;

        let (sighash, anyone_can_pay) = sighash_type.split_anyonecanpay_flag();

        // epoch
        0u8.consensus_encode(writer)?;

        // * Control:
        // hash_type (1).
        (sighash_type as u8).consensus_encode(writer)?;

        // * Transaction Data:
        // nVersion (4): the nVersion of the transaction.
        self.tx.borrow().version.consensus_encode(writer)?;

        // nLockTime (4): the nLockTime of the transaction.
        self.tx.borrow().lock_time.consensus_encode(writer)?;

        // If the hash_type & 0x80 does not equal SIGHASH_ANYONECANPAY:
        //     sha_prevouts (32): the SHA256 of the serialization of all input outpoints.
        //     sha_amounts (32): the SHA256 of the serialization of all spent output amounts.
        //     sha_scriptpubkeys (32): the SHA256 of the serialization of all spent output scriptPubKeys.
        //     sha_sequences (32): the SHA256 of the serialization of all input nSequence.
        if !anyone_can_pay {
            self.common_cache().prevouts.consensus_encode(writer)?;
            self.taproot_cache(prevouts.get_all().map_err(SigningDataError::sighash)?)
                .amounts
                .consensus_encode(writer)?;
            self.taproot_cache(prevouts.get_all().map_err(SigningDataError::sighash)?)
                .script_pubkeys
                .consensus_encode(writer)?;
            self.common_cache().sequences.consensus_encode(writer)?;
        }

        // If hash_type & 3 does not equal SIGHASH_NONE or SIGHASH_SINGLE:
        //     sha_outputs (32): the SHA256 of the serialization of all outputs in CTxOut format.
        if sighash != TapSighashType::None && sighash != TapSighashType::Single {
            self.common_cache().outputs.consensus_encode(writer)?;
        }

        // * Data about this input:
        // spend_type (1): equal to (ext_flag * 2) + annex_present, where annex_present is 0
        // if no annex is present, or 1 otherwise
        let mut spend_type = 0u8;
        if annex.is_some() {
            spend_type |= 1u8;
        }
        if leaf_hash_code_separator.is_some() {
            spend_type |= 2u8;
        }
        spend_type.consensus_encode(writer)?;

        // If hash_type & 0x80 equals SIGHASH_ANYONECANPAY:
        //      outpoint (36): the COutPoint of this input (32-byte hash + 4-byte little-endian).
        //      amount (8): value of the previous output spent by this input.
        //      scriptPubKey (35): scriptPubKey of the previous output spent by this input, serialized as script inside CTxOut. Its size is always 35 bytes.
        //      nSequence (4): nSequence of this input.
        if anyone_can_pay {
            let txin = &self.tx.borrow().tx_in(input_index).map_err(SigningDataError::sighash)?;
            let previous_output = prevouts.get(input_index).map_err(SigningDataError::sighash)?;
            txin.previous_output.consensus_encode(writer)?;
            previous_output.value.consensus_encode(writer)?;
            previous_output.script_pubkey.consensus_encode(writer)?;
            txin.sequence.consensus_encode(writer)?;
        } else {
            (input_index as u32).consensus_encode(writer)?;
        }

        // If an annex is present (the lowest bit of spend_type is set):
        //      sha_annex (32): the SHA256 of (compact_size(size of annex) || annex), where annex
        //      includes the mandatory 0x50 prefix.
        if let Some(annex) = annex {
            let mut enc = sha256::Hash::engine();
            annex.consensus_encode(&mut enc)?;
            let hash = sha256::Hash::from_engine(enc);
            hash.consensus_encode(writer)?;
        }

        // * Data about this output:
        // If hash_type & 3 equals SIGHASH_SINGLE:
        //      sha_single_output (32): the SHA256 of the corresponding output in CTxOut format.
        if sighash == TapSighashType::Single {
            let mut enc = sha256::Hash::engine();
            self.tx
                .borrow()
                .output
                .get(input_index)
                .ok_or(TaprootError::SingleMissingOutput(SingleMissingOutputError {
                    input_index,
                    outputs_length: self.tx.borrow().output.len(),
                }))
                .map_err(SigningDataError::Sighash)?
                .consensus_encode(&mut enc)?;
            let hash = sha256::Hash::from_engine(enc);
            hash.consensus_encode(writer)?;
        }

        //     if (scriptpath):
        //         ss += TaggedHash("TapLeaf", bytes([leaf_ver]) + ser_string(script))
        //         ss += bytes([0])
        //         ss += struct.pack("<i", codeseparator_pos)
        if let Some((hash, code_separator_pos)) = leaf_hash_code_separator {
            hash.as_byte_array().consensus_encode(writer)?;
            KEY_VERSION_0.consensus_encode(writer)?;
            code_separator_pos.consensus_encode(writer)?;
        }

        Ok(())
    }

    /// Computes the BIP341 sighash for any flag type.
    pub fn taproot_signature_hash<T: Borrow<TxOut>>(
        &mut self,
        input_index: usize,
        prevouts: &Prevouts<T>,
        annex: Option<Annex>,
        leaf_hash_code_separator: Option<(TapLeafHash, u32)>,
        sighash_type: TapSighashType,
    ) -> Result<TapSighash, TaprootError> {
        let mut enc = TapSighash::engine();
        self.taproot_encode_signing_data_to(
            &mut enc,
            input_index,
            prevouts,
            annex,
            leaf_hash_code_separator,
            sighash_type,
        )
        .map_err(SigningDataError::unwrap_sighash)?;
        Ok(TapSighash::from_engine(enc))
    }

    /// Computes the BIP341 sighash for a key spend.
    pub fn taproot_key_spend_signature_hash<T: Borrow<TxOut>>(
        &mut self,
        input_index: usize,
        prevouts: &Prevouts<T>,
        sighash_type: TapSighashType,
    ) -> Result<TapSighash, TaprootError> {
        let mut enc = TapSighash::engine();
        self.taproot_encode_signing_data_to(
            &mut enc,
            input_index,
            prevouts,
            None,
            None,
            sighash_type,
        )
        .map_err(SigningDataError::unwrap_sighash)?;
        Ok(TapSighash::from_engine(enc))
    }

    /// Computes the BIP341 sighash for a script spend.
    ///
    /// Assumes the default `OP_CODESEPARATOR` position of `0xFFFFFFFF`. Custom values can be
    /// provided through the more fine-grained API of [`SighashCache::taproot_encode_signing_data_to`].
    pub fn taproot_script_spend_signature_hash<S: Into<TapLeafHash>, T: Borrow<TxOut>>(
        &mut self,
        input_index: usize,
        prevouts: &Prevouts<T>,
        leaf_hash: S,
        sighash_type: TapSighashType,
    ) -> Result<TapSighash, TaprootError> {
        let mut enc = TapSighash::engine();
        self.taproot_encode_signing_data_to(
            &mut enc,
            input_index,
            prevouts,
            None,
            Some((leaf_hash.into(), 0xFFFFFFFF)),
            sighash_type,
        )
        .map_err(SigningDataError::unwrap_sighash)?;
        Ok(TapSighash::from_engine(enc))
    }

    /// Encodes the BIP143 signing data for any flag type into a given object implementing the
    /// [`std::io::Write`] trait.
    ///
    /// `script_code` is dependent on the type of the spend transaction. For p2wpkh use
    /// [`Script::p2wpkh_script_code`], for p2wsh just pass in the witness script. (Also see
    /// [`Self::p2wpkh_signature_hash`] and [`SighashCache::p2wsh_signature_hash`].)
    pub fn segwit_v0_encode_signing_data_to<W: Write + ?Sized>(
        &mut self,
        writer: &mut W,
        input_index: usize,
        script_code: &Script,
        value: Amount,
        sighash_type: EcdsaSighashType,
    ) -> Result<(), SigningDataError<transaction::InputsIndexError>> {
        let zero_hash = sha256d::Hash::all_zeros();

        let (sighash, anyone_can_pay) = sighash_type.split_anyonecanpay_flag();

        self.tx.borrow().version.consensus_encode(writer)?;

        if !anyone_can_pay {
            self.segwit_cache().prevouts.consensus_encode(writer)?;
        } else {
            zero_hash.consensus_encode(writer)?;
        }

        if !anyone_can_pay
            && sighash != EcdsaSighashType::Single
            && sighash != EcdsaSighashType::None
        {
            self.segwit_cache().sequences.consensus_encode(writer)?;
        } else {
            zero_hash.consensus_encode(writer)?;
        }

        {
            let txin = &self.tx.borrow().tx_in(input_index).map_err(SigningDataError::sighash)?;
            txin.previous_output.consensus_encode(writer)?;
            script_code.consensus_encode(writer)?;
            value.consensus_encode(writer)?;
            txin.sequence.consensus_encode(writer)?;
        }

        if sighash != EcdsaSighashType::Single && sighash != EcdsaSighashType::None {
            self.segwit_cache().outputs.consensus_encode(writer)?;
        } else if sighash == EcdsaSighashType::Single && input_index < self.tx.borrow().output.len()
        {
            let mut single_enc = LegacySighash::engine();
            self.tx.borrow().output[input_index].consensus_encode(&mut single_enc)?;
            let hash = LegacySighash::from_engine(single_enc);
            writer.write_all(&hash[..])?;
        } else {
            writer.write_all(&zero_hash[..])?;
        }

        self.tx.borrow().lock_time.consensus_encode(writer)?;
        sighash_type.to_u32().consensus_encode(writer)?;
        Ok(())
    }

    /// Computes the BIP143 sighash to spend a p2wpkh transaction for any flag type.
    ///
    /// `script_pubkey` is the `scriptPubkey` (native segwit) of the spend transaction
    /// ([`TxOut::script_pubkey`]) or the `redeemScript` (wrapped segwit).
    pub fn p2wpkh_signature_hash(
        &mut self,
        input_index: usize,
        script_pubkey: &Script,
        value: Amount,
        sighash_type: EcdsaSighashType,
    ) -> Result<SegwitV0Sighash, P2wpkhError> {
        let script_code = script_pubkey.p2wpkh_script_code().ok_or(P2wpkhError::NotP2wpkhScript)?;

        let mut enc = SegwitV0Sighash::engine();
        self.segwit_v0_encode_signing_data_to(
            &mut enc,
            input_index,
            &script_code,
            value,
            sighash_type,
        )
        .map_err(SigningDataError::unwrap_sighash)?;
        Ok(SegwitV0Sighash::from_engine(enc))
    }

    /// Computes the BIP143 sighash to spend a p2wsh transaction for any flag type.
    pub fn p2wsh_signature_hash(
        &mut self,
        input_index: usize,
        witness_script: &Script,
        value: Amount,
        sighash_type: EcdsaSighashType,
    ) -> Result<SegwitV0Sighash, transaction::InputsIndexError> {
        let mut enc = SegwitV0Sighash::engine();
        self.segwit_v0_encode_signing_data_to(
            &mut enc,
            input_index,
            witness_script,
            value,
            sighash_type,
        )
        .map_err(SigningDataError::unwrap_sighash)?;
        Ok(SegwitV0Sighash::from_engine(enc))
    }

    /// Encodes the legacy signing data from which a signature hash for a given input index with a
    /// given sighash flag can be computed.
    ///
    /// To actually produce a scriptSig, this hash needs to be run through an ECDSA signer, the
    /// [`EcdsaSighashType`] appended to the resulting sig, and a script written around this, but
    /// this is the general (and hard) part.
    ///
    /// The `sighash_type` supports an arbitrary `u32` value, instead of just [`EcdsaSighashType`],
    /// because internally 4 bytes are being hashed, even though only the lowest byte is appended to
    /// signature in a transaction.
    ///
    /// # Warning
    ///
    /// - Does NOT attempt to support OP_CODESEPARATOR. In general this would require evaluating
    /// `script_pubkey` to determine which separators get evaluated and which don't, which we don't
    /// have the information to determine.
    /// - Does NOT handle the sighash single bug (see "Return type" section)
    ///
    /// # Returns
    ///
    /// This function can't handle the SIGHASH_SINGLE bug internally, so it returns [`EncodeSigningDataResult`]
    /// that must be handled by the caller (see [`EncodeSigningDataResult::is_sighash_single_bug`]).
    pub fn legacy_encode_signing_data_to<W: Write + ?Sized, U: Into<u32>>(
        &self,
        writer: &mut W,
        input_index: usize,
        script_pubkey: &Script,
        sighash_type: U,
    ) -> EncodeSigningDataResult<SigningDataError<transaction::InputsIndexError>> {
        // Validate input_index.
        if let Err(e) = self.tx.borrow().tx_in(input_index) {
            return EncodeSigningDataResult::WriteResult(Err(SigningDataError::Sighash(e)));
        }
        let sighash_type: u32 = sighash_type.into();

        if is_invalid_use_of_sighash_single(
            sighash_type,
            input_index,
            self.tx.borrow().output.len(),
        ) {
            // We cannot correctly handle the SIGHASH_SINGLE bug here because usage of this function
            // will result in the data written to the writer being hashed, however the correct
            // handling of the SIGHASH_SINGLE bug is to return the 'one array' - either implement
            // this behaviour manually or use `signature_hash()`.
            return EncodeSigningDataResult::SighashSingleBug;
        }

        fn encode_signing_data_to_inner<W: Write + ?Sized>(
            self_: &Transaction,
            writer: &mut W,
            input_index: usize,
            script_pubkey: &Script,
            sighash_type: u32,
        ) -> Result<(), io::Error> {
            let (sighash, anyone_can_pay) =
                EcdsaSighashType::from_consensus(sighash_type).split_anyonecanpay_flag();

            // Build tx to sign
            let mut tx = Transaction {
                version: self_.version,
                lock_time: self_.lock_time,
                input: vec![],
                output: vec![],
            };
            // Add all inputs necessary..
            if anyone_can_pay {
                tx.input = vec![TxIn {
                    previous_output: self_.input[input_index].previous_output,
                    script_sig: script_pubkey.to_owned(),
                    sequence: self_.input[input_index].sequence,
                    witness: Witness::default(),
                }];
            } else {
                tx.input = Vec::with_capacity(self_.input.len());
                for (n, input) in self_.input.iter().enumerate() {
                    tx.input.push(TxIn {
                        previous_output: input.previous_output,
                        script_sig: if n == input_index {
                            script_pubkey.to_owned()
                        } else {
                            ScriptBuf::new()
                        },
                        sequence: if n != input_index
                            && (sighash == EcdsaSighashType::Single
                                || sighash == EcdsaSighashType::None)
                        {
                            Sequence::ZERO
                        } else {
                            input.sequence
                        },
                        witness: Witness::default(),
                    });
                }
            }
            // ..then all outputs
            tx.output = match sighash {
                EcdsaSighashType::All => self_.output.clone(),
                EcdsaSighashType::Single => {
                    let output_iter = self_
                        .output
                        .iter()
                        .take(input_index + 1) // sign all outputs up to and including this one, but erase
                        .enumerate() // all of them except for this one
                        .map(|(n, out)| if n == input_index { out.clone() } else { TxOut::NULL });
                    output_iter.collect()
                }
                EcdsaSighashType::None => vec![],
                _ => unreachable!(),
            };
            // hash the result
            tx.consensus_encode(writer)?;
            sighash_type.to_le_bytes().consensus_encode(writer)?;
            Ok(())
        }

        EncodeSigningDataResult::WriteResult(
            encode_signing_data_to_inner(
                self.tx.borrow(),
                writer,
                input_index,
                script_pubkey,
                sighash_type,
            )
            .map_err(Into::into),
        )
    }

    /// Computes a legacy signature hash for a given input index with a given sighash flag.
    ///
    /// To actually produce a scriptSig, this hash needs to be run through an ECDSA signer, the
    /// [`EcdsaSighashType`] appended to the resulting sig, and a script written around this, but
    /// this is the general (and hard) part.
    ///
    /// The `sighash_type` supports an arbitrary `u32` value, instead of just [`EcdsaSighashType`],
    /// because internally 4 bytes are being hashed, even though only the lowest byte is appended to
    /// signature in a transaction.
    ///
    /// This function correctly handles the sighash single bug by returning the 'one array'. The
    /// sighash single bug becomes exploitable when one tries to sign a transaction with
    /// `SIGHASH_SINGLE` and there is not a corresponding output with the same index as the input.
    ///
    /// # Warning
    ///
    /// Does NOT attempt to support OP_CODESEPARATOR. In general this would require evaluating
    /// `script_pubkey` to determine which separators get evaluated and which don't, which we don't
    /// have the information to determine.
    pub fn legacy_signature_hash(
        &self,
        input_index: usize,
        script_pubkey: &Script,
        sighash_type: u32,
    ) -> Result<LegacySighash, transaction::InputsIndexError> {
        let mut engine = LegacySighash::engine();
        match self
            .legacy_encode_signing_data_to(&mut engine, input_index, script_pubkey, sighash_type)
            .is_sighash_single_bug()
        {
            Ok(true) => Ok(LegacySighash::from_byte_array(UINT256_ONE)),
            Ok(false) => Ok(LegacySighash::from_engine(engine)),
            Err(e) => Err(e.unwrap_sighash()),
        }
    }

    #[inline]
    fn common_cache(&mut self) -> &CommonCache {
        Self::common_cache_minimal_borrow(&mut self.common_cache, self.tx.borrow())
    }

    fn common_cache_minimal_borrow<'a>(
        common_cache: &'a mut Option<CommonCache>,
        tx: &Transaction,
    ) -> &'a CommonCache {
        common_cache.get_or_insert_with(|| {
            let mut enc_prevouts = sha256::Hash::engine();
            let mut enc_sequences = sha256::Hash::engine();
            for txin in tx.input.iter() {
                txin.previous_output.consensus_encode(&mut enc_prevouts).unwrap();
                txin.sequence.consensus_encode(&mut enc_sequences).unwrap();
            }
            CommonCache {
                prevouts: sha256::Hash::from_engine(enc_prevouts),
                sequences: sha256::Hash::from_engine(enc_sequences),
                outputs: {
                    let mut enc = sha256::Hash::engine();
                    for txout in tx.output.iter() {
                        txout.consensus_encode(&mut enc).unwrap();
                    }
                    sha256::Hash::from_engine(enc)
                },
            }
        })
    }

    fn segwit_cache(&mut self) -> &SegwitCache {
        let common_cache = &mut self.common_cache;
        let tx = self.tx.borrow();
        self.segwit_cache.get_or_insert_with(|| {
            let common_cache = Self::common_cache_minimal_borrow(common_cache, tx);
            SegwitCache {
                prevouts: common_cache.prevouts.hash_again(),
                sequences: common_cache.sequences.hash_again(),
                outputs: common_cache.outputs.hash_again(),
            }
        })
    }

    fn taproot_cache<T: Borrow<TxOut>>(&mut self, prevouts: &[T]) -> &TaprootCache {
        self.taproot_cache.get_or_insert_with(|| {
            let mut enc_amounts = sha256::Hash::engine();
            let mut enc_script_pubkeys = sha256::Hash::engine();
            for prevout in prevouts {
                prevout.borrow().value.consensus_encode(&mut enc_amounts).unwrap();
                prevout.borrow().script_pubkey.consensus_encode(&mut enc_script_pubkeys).unwrap();
            }
            TaprootCache {
                amounts: sha256::Hash::from_engine(enc_amounts),
                script_pubkeys: sha256::Hash::from_engine(enc_script_pubkeys),
            }
        })
    }
}

impl<R: BorrowMut<Transaction>> SighashCache<R> {
    /// Allows modification of witnesses.
    ///
    /// As a lint against accidental changes to the transaction that would invalidate the cache and
    /// signatures, `SighashCache` borrows the Transaction so that modifying it is not possible
    /// without hacks with `UnsafeCell` (which is hopefully a strong indication that something is
    /// wrong). However modifying witnesses never invalidates the cache and is actually useful - one
    /// usually wants to put the signature generated for an input into the witness of that input.
    ///
    /// This method allows doing exactly that if the transaction is owned by the `SighashCache` or
    /// borrowed mutably.
    ///
    /// # Examples
    ///
    /// ```compile_fail
    /// let mut sighasher = SighashCache::new(&mut tx_to_sign);
    /// let sighash = sighasher.p2wpkh_signature_hash(input_index, &utxo.script_pubkey, amount, sighash_type)?;
    ///
    /// let signature = {
    ///     // Sign the sighash using secp256k1
    /// };
    ///
    /// *sighasher.witness_mut(input_index).unwrap() = Witness::p2wpkh(&signature, &pk);
    /// ```
    ///
    /// For full signing code see the [`segwit v0`] and [`taproot`] signing examples.
    ///
    /// [`segwit v0`]: <https://github.com/rust-bitcoin/rust-bitcoin/blob/master/bitcoin/examples/sign-tx-segwit-v0.rs>
    /// [`taproot`]: <https://github.com/rust-bitcoin/rust-bitcoin/blob/master/bitcoin/examples/sign-tx-taproot.rs>
    pub fn witness_mut(&mut self, input_index: usize) -> Option<&mut Witness> {
        self.tx.borrow_mut().input.get_mut(input_index).map(|i| &mut i.witness)
    }
}

/// The `Annex` struct is a slice wrapper enforcing first byte is `0x50`.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Annex<'a>(&'a [u8]);

impl<'a> Annex<'a> {
    /// Creates a new `Annex` struct checking the first byte is `0x50`.
    pub fn new(annex_bytes: &'a [u8]) -> Result<Self, AnnexError> {
        use AnnexError::*;

        match annex_bytes.first() {
            Some(&TAPROOT_ANNEX_PREFIX) => Ok(Annex(annex_bytes)),
            Some(other) => Err(IncorrectPrefix(*other)),
            None => Err(Empty),
        }
    }

    /// Returns the Annex bytes data (including first byte `0x50`).
    pub fn as_bytes(&self) -> &[u8] { self.0 }
}

impl<'a> Encodable for Annex<'a> {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        encode::consensus_encode_with_size(self.0, w)
    }
}

/// Error computing a taproot sighash.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum TaprootError {
    /// Index out of bounds when accessing transaction input vector.
    InputsIndex(transaction::InputsIndexError),
    /// Using `SIGHASH_SINGLE` requires an output at the same index is the input.
    SingleMissingOutput(SingleMissingOutputError),
    /// Prevouts size error.
    PrevoutsSize(PrevoutsSizeError),
    /// Prevouts index error.
    PrevoutsIndex(PrevoutsIndexError),
    /// Prevouts kind error.
    PrevoutsKind(PrevoutsKindError),
    /// Invalid Sighash type.
    InvalidSighashType(u32),
}

internals::impl_from_infallible!(TaprootError);

impl fmt::Display for TaprootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use TaprootError::*;

        match *self {
            InputsIndex(ref e) => write_err!(f, "inputs index"; e),
            SingleMissingOutput(ref e) => write_err!(f, "sighash single"; e),
            PrevoutsSize(ref e) => write_err!(f, "prevouts size"; e),
            PrevoutsIndex(ref e) => write_err!(f, "prevouts index"; e),
            PrevoutsKind(ref e) => write_err!(f, "prevouts kind"; e),
            InvalidSighashType(hash_ty) => write!(f, "invalid taproot sighash type : {} ", hash_ty),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for TaprootError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use TaprootError::*;

        match *self {
            InputsIndex(ref e) => Some(e),
            SingleMissingOutput(ref e) => Some(e),
            PrevoutsSize(ref e) => Some(e),
            PrevoutsIndex(ref e) => Some(e),
            PrevoutsKind(ref e) => Some(e),
            InvalidSighashType(_) => None,
        }
    }
}

impl From<transaction::InputsIndexError> for TaprootError {
    fn from(e: transaction::InputsIndexError) -> Self { Self::InputsIndex(e) }
}

impl From<PrevoutsSizeError> for TaprootError {
    fn from(e: PrevoutsSizeError) -> Self { Self::PrevoutsSize(e) }
}

impl From<PrevoutsKindError> for TaprootError {
    fn from(e: PrevoutsKindError) -> Self { Self::PrevoutsKind(e) }
}

impl From<PrevoutsIndexError> for TaprootError {
    fn from(e: PrevoutsIndexError) -> Self { Self::PrevoutsIndex(e) }
}

/// Error computing a P2WPKH sighash.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum P2wpkhError {
    /// Error computing the sighash.
    Sighash(transaction::InputsIndexError),
    /// Script is not a witness program for a p2wpkh output.
    NotP2wpkhScript,
}

internals::impl_from_infallible!(P2wpkhError);

impl From<transaction::InputsIndexError> for P2wpkhError {
    fn from(value: transaction::InputsIndexError) -> Self { P2wpkhError::Sighash(value) }
}

impl fmt::Display for P2wpkhError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use P2wpkhError::*;

        match *self {
            Sighash(ref e) => write_err!(f, "error encoding segwit v0 signing data"; e),
            NotP2wpkhScript => write!(f, "script is not a script pubkey for a p2wpkh output"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for P2wpkhError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use P2wpkhError::*;

        match *self {
            Sighash(ref e) => Some(e),
            NotP2wpkhScript => None,
        }
    }
}

/// Using `SIGHASH_SINGLE` requires an output at the same index as the input.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct SingleMissingOutputError {
    /// Input index.
    pub input_index: usize,
    /// Length of the output vector.
    pub outputs_length: usize,
}

impl fmt::Display for SingleMissingOutputError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "sighash single requires an output at the same index as the input \
             (input index: {}, outputs length: {})",
            self.input_index, self.outputs_length
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for SingleMissingOutputError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> { None }
}

/// Annex must be at least one byte long and the first bytes must be `0x50`.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum AnnexError {
    /// The annex is empty.
    Empty,
    /// Incorrect prefix byte in the annex.
    IncorrectPrefix(u8),
}

internals::impl_from_infallible!(AnnexError);

impl fmt::Display for AnnexError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        use AnnexError::*;

        match *self {
            Empty => write!(f, "the annex is empty"),
            IncorrectPrefix(byte) =>
                write!(f, "incorrect prefix byte in the annex {:02x}, expecting 0x50", byte),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for AnnexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use AnnexError::*;

        match *self {
            Empty | IncorrectPrefix(_) => None,
        }
    }
}

fn is_invalid_use_of_sighash_single(sighash: u32, input_index: usize, outputs_len: usize) -> bool {
    let ty = EcdsaSighashType::from_consensus(sighash);
    ty == EcdsaSighashType::Single && input_index >= outputs_len
}

/// Result of [`SighashCache::legacy_encode_signing_data_to`].
///
/// This type forces the caller to handle SIGHASH_SINGLE bug case.
///
/// This corner case can't be expressed using standard `Result`,
/// in a way that is both convenient and not-prone to accidental
/// mistakes (like calling `.expect("writer never fails")`).
#[must_use]
pub enum EncodeSigningDataResult<E> {
    /// Input data is an instance of `SIGHASH_SINGLE` bug
    SighashSingleBug,
    /// Operation performed normally.
    WriteResult(Result<(), E>),
}

impl<E> EncodeSigningDataResult<E> {
    /// Checks for SIGHASH_SINGLE bug returning error if the writer failed.
    ///
    /// This method is provided for easy and correct handling of the result because
    /// SIGHASH_SINGLE bug is a special case that must not be ignored nor cause panicking.
    /// Since the data is usually written directly into a hasher which never fails,
    /// the recommended pattern to handle this is:
    ///
    /// ```rust
    /// # use satsnet::consensus::deserialize;
    /// # use satsnet::hashes::{Hash, hex::FromHex};
    /// # use satsnet::sighash::{LegacySighash, SighashCache};
    /// # use satsnet::Transaction;
    /// # let mut writer = LegacySighash::engine();
    /// # let input_index = 0;
    /// # let script_pubkey = satsnet::ScriptBuf::new();
    /// # let sighash_u32 = 0u32;
    /// # const SOME_TX: &'static str = "0100000001a15d57094aa7a21a28cb20b59aab8fc7d1149a3bdbcddba9c622e4f5f6a99ece010000006c493046022100f93bb0e7d8db7bd46e40132d1f8242026e045f03a0efe71bbb8e3f475e970d790221009337cd7f1f929f00cc6ff01f03729b069a7c21b59b1736ddfee5db5946c5da8c0121033b9b137ee87d5a812d6f506efdd37f0affa7ffc310711c06c7f3e097c9447c52ffffffff0100e1f505000000001976a9140389035a9225b3839e2bbf32d826a1e222031fd888ac00000000";
    /// # let raw_tx = Vec::from_hex(SOME_TX).unwrap();
    /// # let tx: Transaction = deserialize(&raw_tx).unwrap();
    /// let cache = SighashCache::new(&tx);
    /// if cache.legacy_encode_signing_data_to(&mut writer, input_index, &script_pubkey, sighash_u32)
    ///         .is_sighash_single_bug()
    ///         .expect("writer can't fail") {
    ///     // use a hash value of "1", instead of computing the actual hash due to SIGHASH_SINGLE bug
    /// }
    /// ```
    pub fn is_sighash_single_bug(self) -> Result<bool, E> {
        match self {
            EncodeSigningDataResult::SighashSingleBug => Ok(true),
            EncodeSigningDataResult::WriteResult(Ok(())) => Ok(false),
            EncodeSigningDataResult::WriteResult(Err(e)) => Err(e),
        }
    }

    /// Maps a `Result<T, E>` to `Result<T, F>` by applying a function to a
    /// contained [`Err`] value, leaving an [`Ok`] value untouched.
    ///
    /// Like [`Result::map_err`].
    pub fn map_err<E2, F>(self, f: F) -> EncodeSigningDataResult<E2>
    where
        F: FnOnce(E) -> E2,
    {
        match self {
            EncodeSigningDataResult::SighashSingleBug => EncodeSigningDataResult::SighashSingleBug,
            EncodeSigningDataResult::WriteResult(Err(e)) =>
                EncodeSigningDataResult::WriteResult(Err(f(e))),
            EncodeSigningDataResult::WriteResult(Ok(o)) =>
                EncodeSigningDataResult::WriteResult(Ok(o)),
        }
    }
}

/// Error returned when writing signing data fails.
#[derive(Debug)]
pub enum SigningDataError<E> {
    /// Can happen only when using `*_encode_signing_*` methods with custom writers, engines
    /// like those used in `*_signature_hash` methods do not error.
    Io(io::Error),
    /// An argument to the called sighash function was invalid.
    Sighash(E),
}

internals::impl_from_infallible!(SigningDataError<E>);

impl<E> SigningDataError<E> {
    /// Returns the sighash variant, panicking if it's IO.
    ///
    /// This is used when encoding to hash engine when we know that IO doesn't fail.
    fn unwrap_sighash(self) -> E {
        match self {
            Self::Sighash(error) => error,
            Self::Io(error) => panic!("hash engine error {}", error),
        }
    }

    fn sighash<E2: Into<E>>(error: E2) -> Self { Self::Sighash(error.into()) }
}

// We cannot simultaneously impl `From<E>`. it was determined that this alternative requires less
// manual `map_err` calls.
impl<E> From<io::Error> for SigningDataError<E> {
    fn from(value: io::Error) -> Self { Self::Io(value) }
}

impl<E: fmt::Display> fmt::Display for SigningDataError<E> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Io(error) => write_err!(f, "failed to write sighash data"; error),
            Self::Sighash(error) => write_err!(f, "failed to compute sighash data"; error),
        }
    }
}

#[cfg(feature = "std")]
impl<E: std::error::Error + 'static> std::error::Error for SigningDataError<E> {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            SigningDataError::Io(error) => Some(error),
            SigningDataError::Sighash(error) => Some(error),
        }
    }
}