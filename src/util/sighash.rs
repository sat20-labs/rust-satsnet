// Rust Bitcoin Library
// Written in 2021 by
//   The rust-bitcoin developers
//
// To the extent possible under law, the author(s) have dedicated all
// copyright and related and neighboring rights to this software to
// the public domain worldwide. This software is distributed without
// any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication
// along with this software.
// If not, see <http://creativecommons.org/publicdomain/zero/1.0/>.
//

//! Generalized, efficient, signature hash implementation.
//!
//! Implementation of the algorithm to compute the message to be signed according to
//! [Bip341](https://github.com/bitcoin/bips/blob/150ab6f5c3aca9da05fccc5b435e9667853407f4/bip-0341.mediawiki),
//! [Bip143](https://github.com/bitcoin/bips/blob/99701f68a88ce33b2d0838eb84e115cef505b4c2/bip-0143.mediawiki)
//! and legacy (before Bip143).
//!

use prelude::*;

pub use blockdata::transaction::{EcdsaSighashType, SighashTypeParseError};
use blockdata::witness::Witness;
use consensus::{encode, Encodable};
use core::{str, fmt};
use core::ops::{Deref, DerefMut};
use core::borrow::Borrow;
use hashes::{sha256, sha256d, Hash};
use io;
use util::taproot::{TapLeafHash, TAPROOT_ANNEX_PREFIX, TapSighashHash};
use Sighash;
use {Script, Transaction, TxOut};

use super::taproot::LeafVersion;

/// Efficiently calculates signature hash message for legacy, segwit and taproot inputs.
#[derive(Debug)]
pub struct SighashCache<T: Deref<Target=Transaction>> {
    /// Access to transaction required for various introspection, moreover type
    /// `T: Deref<Target=Transaction>` allows to accept borrow and mutable borrow, the
    /// latter in particular is necessary for [`SighashCache::witness_mut`]
    tx: T,

    /// Common cache for taproot and segwit inputs. It's an option because it's not needed for legacy inputs
    common_cache: Option<CommonCache>,

    /// Cache for segwit v0 inputs, it's the result of another round of sha256 on `common_cache`
    segwit_cache: Option<SegwitCache>,

    /// Cache for taproot v1 inputs
    taproot_cache: Option<TaprootCache>,
}

/// Values cached common between segwit and taproot inputs
#[derive(Debug)]
struct CommonCache {
    prevouts: sha256::Hash,
    sequences: sha256::Hash,

    /// in theory, `outputs` could be `Option` since `NONE` and `SINGLE` doesn't need it, but since
    /// `ALL` is the mostly used variant by large, we don't bother
    outputs: sha256::Hash,
}

/// Values cached for segwit inputs, it's equal to [`CommonCache`] plus another round of `sha256`
#[derive(Debug)]
struct SegwitCache {
    prevouts: sha256d::Hash,
    sequences: sha256d::Hash,
    outputs: sha256d::Hash,
}

/// Values cached for taproot inputs
#[derive(Debug)]
struct TaprootCache {
    amounts: sha256::Hash,
    script_pubkeys: sha256::Hash,
}

/// Contains outputs of previous transactions.
/// In the case [`SchnorrSighashType`] variant is `ANYONECANPAY`, [`Prevouts::One`] may be provided
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Prevouts<'u, T> where T: 'u + Borrow<TxOut> {
    /// `One` variant allows to provide the single Prevout needed. It's useful for example
    /// when modifier `ANYONECANPAY` is provided, only prevout of the current input is needed.
    /// The first `usize` argument is the input index this [`TxOut`] is referring to.
    One(usize, T),
    /// When `ANYONECANPAY` is not provided, or the caller is handy giving all prevouts so the same
    /// variable can be used for multiple inputs.
    All(&'u [T]),
}

const KEY_VERSION_0: u8 = 0u8;

/// Information related to the script path spending
///
/// This can be hashed into a [`TapLeafHash`].
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub struct ScriptPath<'s> {
    script: &'s Script,
    leaf_version: LeafVersion,
}

/// Hashtype of an input's signature, encoded in the last byte of the signature
/// Fixed values so they can be casted as integer types for encoding
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum SchnorrSighashType {
    /// 0x0: Used when not explicitly specified, defaulting to [`SchnorrSighashType::All`]
    Default = 0x00,
    /// 0x1: Sign all outputs
    All = 0x01,
    /// 0x2: Sign no outputs --- anyone can choose the destination
    None = 0x02,
    /// 0x3: Sign the output whose index matches this input's index. If none exists,
    /// sign the hash `0000000000000000000000000000000000000000000000000000000000000001`.
    /// (This rule is probably an unintentional C++ism, but it's consensus so we have
    /// to follow it.)
    Single = 0x03,
    /// 0x81: Sign all outputs but only this input
    AllPlusAnyoneCanPay = 0x81,
    /// 0x82: Sign no outputs and only this input
    NonePlusAnyoneCanPay = 0x82,
    /// 0x83: Sign one output and only this input (see `Single` for what "one output" means)
    SinglePlusAnyoneCanPay = 0x83,

    /// Reserved for future use, `#[non_exhaustive]` is not available with current MSRV
    Reserved = 0xFF,
}
serde_string_impl!(SchnorrSighashType, "a SchnorrSighashType data");

impl fmt::Display for SchnorrSighashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            SchnorrSighashType::Default => "SIGHASH_DEFAULT",
            SchnorrSighashType::All => "SIGHASH_ALL",
            SchnorrSighashType::None => "SIGHASH_NONE",
            SchnorrSighashType::Single => "SIGHASH_SINGLE",
            SchnorrSighashType::AllPlusAnyoneCanPay => "SIGHASH_ALL|SIGHASH_ANYONECANPAY",
            SchnorrSighashType::NonePlusAnyoneCanPay => "SIGHASH_NONE|SIGHASH_ANYONECANPAY",
            SchnorrSighashType::SinglePlusAnyoneCanPay => "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY",
            SchnorrSighashType::Reserved => "SIGHASH_RESERVED",
        };
        f.write_str(s)
    }
}

impl str::FromStr for SchnorrSighashType {
    type Err = SighashTypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "SIGHASH_DEFAULT" => Ok(SchnorrSighashType::Default),
            "SIGHASH_ALL" => Ok(SchnorrSighashType::All),
            "SIGHASH_NONE" => Ok(SchnorrSighashType::None),
            "SIGHASH_SINGLE" => Ok(SchnorrSighashType::Single),
            "SIGHASH_ALL|SIGHASH_ANYONECANPAY" => Ok(SchnorrSighashType::AllPlusAnyoneCanPay),
            "SIGHASH_NONE|SIGHASH_ANYONECANPAY" => Ok(SchnorrSighashType::NonePlusAnyoneCanPay),
            "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY" => Ok(SchnorrSighashType::SinglePlusAnyoneCanPay),
            "SIGHASH_RESERVED" => Ok(SchnorrSighashType::Reserved),
            _ => Err(SighashTypeParseError{ unrecognized: s.to_owned() }),
        }
    }
}

/// Possible errors in computing the signature message
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
pub enum Error {
    /// Could happen only by using `*_encode_signing_*` methods with custom writers, engines writers
    /// like the ones used in methods `*_signature_hash` don't error
    Io(io::ErrorKind),

    /// Requested index is greater or equal than the number of inputs in the transaction
    IndexOutOfInputsBounds {
        /// Requested index
        index: usize,
        /// Number of transaction inputs
        inputs_size: usize,
    },

    /// Using SIGHASH_SINGLE without a "corresponding output" (an output with the same index as the
    /// input being verified) is a validation failure
    SingleWithoutCorrespondingOutput {
        /// Requested index
        index: usize,
        /// Number of transaction outputs
        outputs_size: usize,
    },

    /// There are mismatches in the number of prevouts provided compared with the number of
    /// inputs in the transaction
    PrevoutsSize,

    /// Requested a prevout index which is greater than the number of prevouts provided or a
    /// [`Prevouts::One`] with different index
    PrevoutIndex,

    /// A single prevout has been provided but all prevouts are needed without `ANYONECANPAY`
    PrevoutKind,

    /// Annex must be at least one byte long and the first bytes must be `0x50`
    WrongAnnex,

    /// Invalid Sighash type
    InvalidSighashType(u32),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(ref e) => write!(f, "Writer errored: {:?}", e),
            Error::IndexOutOfInputsBounds { index, inputs_size } => write!(f, "Requested index ({}) is greater or equal than the number of transaction inputs ({})", index, inputs_size),
            Error::SingleWithoutCorrespondingOutput { index, outputs_size } => write!(f, "SIGHASH_SINGLE for input ({}) haven't a corresponding output (#outputs:{})", index, outputs_size),
            Error::PrevoutsSize => write!(f, "Number of supplied prevouts differs from the number of inputs in transaction"),
            Error::PrevoutIndex => write!(f, "The index requested is greater than available prevouts or different from the provided [Provided::Anyone] index"),
            Error::PrevoutKind => write!(f, "A single prevout has been provided but all prevouts are needed without `ANYONECANPAY`"),
            Error::WrongAnnex => write!(f, "Annex must be at least one byte long and the first bytes must be `0x50`"),
            Error::InvalidSighashType(hash_ty) => write!(f, "Invalid schnorr Signature hash type : {} ", hash_ty),
        }
    }
}

#[cfg(feature = "std")]
impl ::std::error::Error for Error {}

impl<'u, T> Prevouts<'u, T> where T: Borrow<TxOut> {
    fn check_all(&self, tx: &Transaction) -> Result<(), Error> {
        if let Prevouts::All(prevouts) = self {
            if prevouts.len() != tx.input.len() {
                return Err(Error::PrevoutsSize);
            }
        }
        Ok(())
    }

    fn get_all(&self) -> Result<&[T], Error> {
        match self {
            Prevouts::All(prevouts) => Ok(*prevouts),
            _ => Err(Error::PrevoutKind),
        }
    }

    fn get(&self, input_index: usize) -> Result<&TxOut, Error> {
        match self {
            Prevouts::One(index, prevout) => {
                if input_index == *index {
                    Ok(prevout.borrow())
                } else {
                    Err(Error::PrevoutIndex)
                }
            }
            Prevouts::All(prevouts) => prevouts
                .get(input_index)
                .map(|x| x.borrow())
                .ok_or(Error::PrevoutIndex),
        }
    }
}

impl<'s> ScriptPath<'s> {
    /// Create a new ScriptPath structure
    pub fn new(script: &'s Script, leaf_version: LeafVersion) -> Self {
        ScriptPath {
            script,
            leaf_version,
        }
    }
    /// Create a new ScriptPath structure using default leaf version value
    pub fn with_defaults(script: &'s Script) -> Self {
        Self::new(script, LeafVersion::TapScript)
    }
    /// Compute the leaf hash
    pub fn leaf_hash(&self) -> TapLeafHash {
        let mut enc = TapLeafHash::engine();

        self.leaf_version.to_consensus().consensus_encode(&mut enc).expect("Writing to hash enging should never fail");
        self.script.consensus_encode(&mut enc).expect("Writing to hash enging should never fail");

        TapLeafHash::from_engine(enc)
    }
}

impl<'s> From<ScriptPath<'s>> for TapLeafHash {
    fn from(script_path: ScriptPath<'s>) -> TapLeafHash {
        script_path.leaf_hash()
    }
}

impl From<EcdsaSighashType> for SchnorrSighashType {
    fn from(s: EcdsaSighashType) -> Self {
        match s {
            EcdsaSighashType::All => SchnorrSighashType::All,
            EcdsaSighashType::None => SchnorrSighashType::None,
            EcdsaSighashType::Single => SchnorrSighashType::Single,
            EcdsaSighashType::AllPlusAnyoneCanPay => SchnorrSighashType::AllPlusAnyoneCanPay,
            EcdsaSighashType::NonePlusAnyoneCanPay => SchnorrSighashType::NonePlusAnyoneCanPay,
            EcdsaSighashType::SinglePlusAnyoneCanPay => SchnorrSighashType::SinglePlusAnyoneCanPay,
        }
    }
}

impl SchnorrSighashType {
    /// Break the sighash flag into the "real" sighash flag and the ANYONECANPAY boolean
    pub(crate) fn split_anyonecanpay_flag(self) -> (SchnorrSighashType, bool) {
        match self {
            SchnorrSighashType::Default => (SchnorrSighashType::Default, false),
            SchnorrSighashType::All => (SchnorrSighashType::All, false),
            SchnorrSighashType::None => (SchnorrSighashType::None, false),
            SchnorrSighashType::Single => (SchnorrSighashType::Single, false),
            SchnorrSighashType::AllPlusAnyoneCanPay => (SchnorrSighashType::All, true),
            SchnorrSighashType::NonePlusAnyoneCanPay => (SchnorrSighashType::None, true),
            SchnorrSighashType::SinglePlusAnyoneCanPay => (SchnorrSighashType::Single, true),
            SchnorrSighashType::Reserved => (SchnorrSighashType::Reserved, false),
        }
    }

    /// Create a [`SchnorrSighashType`] from raw `u8`
    pub fn from_u8(hash_ty: u8) -> Result<Self, Error> {
        match hash_ty {
            0x00 => Ok(SchnorrSighashType::Default),
            0x01 => Ok(SchnorrSighashType::All),
            0x02 => Ok(SchnorrSighashType::None),
            0x03 => Ok(SchnorrSighashType::Single),
            0x81 => Ok(SchnorrSighashType::AllPlusAnyoneCanPay),
            0x82 => Ok(SchnorrSighashType::NonePlusAnyoneCanPay),
            0x83 => Ok(SchnorrSighashType::SinglePlusAnyoneCanPay),
            0xFF => Ok(SchnorrSighashType::Reserved),
            x => Err(Error::InvalidSighashType(x as u32)),
        }
    }
}

impl<R: Deref<Target=Transaction>> SighashCache<R> {
    /// Compute the sighash components from an unsigned transaction and auxiliary
    /// in a lazy manner when required.
    /// For the generated sighashes to be valid, no fields in the transaction may change except for
    /// script_sig and witnesses.
    pub fn new(tx: R) -> Self {
        SighashCache {
            tx,
            common_cache: None,
            taproot_cache: None,
            segwit_cache: None,
        }
    }

    /// Encode the BIP341 signing data for any flag type into a given object implementing a
    /// io::Write trait.
    pub fn taproot_encode_signing_data_to<Write: io::Write, T: Borrow<TxOut>>(
        &mut self,
        mut writer: Write,
        input_index: usize,
        prevouts: &Prevouts<T>,
        annex: Option<Annex>,
        leaf_hash_code_separator: Option<(TapLeafHash, u32)>,
        sighash_type: SchnorrSighashType,
    ) -> Result<(), Error> {
        prevouts.check_all(&self.tx)?;

        let (sighash, anyone_can_pay) = sighash_type.split_anyonecanpay_flag();

        // epoch
        0u8.consensus_encode(&mut writer)?;

        // * Control:
        // hash_type (1).
        (sighash_type as u8).consensus_encode(&mut writer)?;

        // * Transaction Data:
        // nVersion (4): the nVersion of the transaction.
        self.tx.version.consensus_encode(&mut writer)?;

        // nLockTime (4): the nLockTime of the transaction.
        self.tx.lock_time.consensus_encode(&mut writer)?;

        // If the hash_type & 0x80 does not equal SIGHASH_ANYONECANPAY:
        //     sha_prevouts (32): the SHA256 of the serialization of all input outpoints.
        //     sha_amounts (32): the SHA256 of the serialization of all spent output amounts.
        //     sha_scriptpubkeys (32): the SHA256 of the serialization of all spent output scriptPubKeys.
        //     sha_sequences (32): the SHA256 of the serialization of all input nSequence.
        if !anyone_can_pay {
            self.common_cache().prevouts.consensus_encode(&mut writer)?;
            self.taproot_cache(prevouts.get_all()?)
                .amounts
                .consensus_encode(&mut writer)?;
            self.taproot_cache(prevouts.get_all()?)
                .script_pubkeys
                .consensus_encode(&mut writer)?;
            self.common_cache()
                .sequences
                .consensus_encode(&mut writer)?;
        }

        // If hash_type & 3 does not equal SIGHASH_NONE or SIGHASH_SINGLE:
        //     sha_outputs (32): the SHA256 of the serialization of all outputs in CTxOut format.
        if sighash != SchnorrSighashType::None && sighash != SchnorrSighashType::Single {
            self.common_cache().outputs.consensus_encode(&mut writer)?;
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
        spend_type.consensus_encode(&mut writer)?;

        // If hash_type & 0x80 equals SIGHASH_ANYONECANPAY:
        //      outpoint (36): the COutPoint of this input (32-byte hash + 4-byte little-endian).
        //      amount (8): value of the previous output spent by this input.
        //      scriptPubKey (35): scriptPubKey of the previous output spent by this input, serialized as script inside CTxOut. Its size is always 35 bytes.
        //      nSequence (4): nSequence of this input.
        if anyone_can_pay {
            let txin =
                &self
                    .tx
                    .input
                    .get(input_index)
                    .ok_or_else(|| Error::IndexOutOfInputsBounds {
                        index: input_index,
                        inputs_size: self.tx.input.len(),
                    })?;
            let previous_output = prevouts.get(input_index)?;
            txin.previous_output.consensus_encode(&mut writer)?;
            previous_output.value.consensus_encode(&mut writer)?;
            previous_output
                .script_pubkey
                .consensus_encode(&mut writer)?;
            txin.sequence.consensus_encode(&mut writer)?;
        } else {
            (input_index as u32).consensus_encode(&mut writer)?;
        }

        // If an annex is present (the lowest bit of spend_type is set):
        //      sha_annex (32): the SHA256 of (compact_size(size of annex) || annex), where annex
        //      includes the mandatory 0x50 prefix.
        if let Some(annex) = annex {
            let mut enc = sha256::Hash::engine();
            annex.consensus_encode(&mut enc)?;
            let hash = sha256::Hash::from_engine(enc);
            hash.consensus_encode(&mut writer)?;
        }

        // * Data about this output:
        // If hash_type & 3 equals SIGHASH_SINGLE:
        //      sha_single_output (32): the SHA256 of the corresponding output in CTxOut format.
        if sighash == SchnorrSighashType::Single {
            let mut enc = sha256::Hash::engine();
            self.tx
                .output
                .get(input_index)
                .ok_or_else(|| Error::SingleWithoutCorrespondingOutput {
                    index: input_index,
                    outputs_size: self.tx.output.len(),
                })?
                .consensus_encode(&mut enc)?;
            let hash = sha256::Hash::from_engine(enc);
            hash.consensus_encode(&mut writer)?;
        }

        //     if (scriptpath):
        //         ss += TaggedHash("TapLeaf", bytes([leaf_ver]) + ser_string(script))
        //         ss += bytes([0])
        //         ss += struct.pack("<i", codeseparator_pos)
        if let Some((hash, code_separator_pos)) = leaf_hash_code_separator {
            hash.into_inner().consensus_encode(&mut writer)?;
            KEY_VERSION_0.consensus_encode(&mut writer)?;
            code_separator_pos.consensus_encode(&mut writer)?;
        }

        Ok(())
    }

    /// Compute the BIP341 sighash for any flag type.
    pub fn taproot_signature_hash<T: Borrow<TxOut>>(
        &mut self,
        input_index: usize,
        prevouts: &Prevouts<T>,
        annex: Option<Annex>,
        leaf_hash_code_separator: Option<(TapLeafHash, u32)>,
        sighash_type: SchnorrSighashType,
    ) -> Result<TapSighashHash, Error> {
        let mut enc = TapSighashHash::engine();
        self.taproot_encode_signing_data_to(
            &mut enc,
            input_index,
            prevouts,
            annex,
            leaf_hash_code_separator,
            sighash_type,
        )?;
        Ok(TapSighashHash::from_engine(enc))
    }

    /// Compute the BIP341 sighash for a key spend
    pub fn taproot_key_spend_signature_hash<T: Borrow<TxOut>>(
        &mut self,
        input_index: usize,
        prevouts: &Prevouts<T>,
        sighash_type: SchnorrSighashType,
    ) -> Result<TapSighashHash, Error> {
        let mut enc = TapSighashHash::engine();
        self.taproot_encode_signing_data_to(
            &mut enc,
            input_index,
            prevouts,
            None,
            None,
            sighash_type,
        )?;
        Ok(TapSighashHash::from_engine(enc))
    }

    /// Compute the BIP341 sighash for a script spend
    ///
    /// Assumes the default `OP_CODESEPARATOR` position of `0xFFFFFFFF`. Custom values can be
    /// provided through the more fine-grained API of [`SighashCache::taproot_encode_signing_data_to`].
    pub fn taproot_script_spend_signature_hash<S: Into<TapLeafHash>, T: Borrow<TxOut>>(
        &mut self,
        input_index: usize,
        prevouts: &Prevouts<T>,
        leaf_hash: S,
        sighash_type: SchnorrSighashType,
    ) -> Result<TapSighashHash, Error> {
        let mut enc = TapSighashHash::engine();
        self.taproot_encode_signing_data_to(
            &mut enc,
            input_index,
            prevouts,
            None,
            Some((leaf_hash.into(), 0xFFFFFFFF)),
            sighash_type,
        )?;
        Ok(TapSighashHash::from_engine(enc))
    }

    /// Encode the BIP143 signing data for any flag type into a given object implementing a
    /// [`std::io::Write`] trait.
    pub fn segwit_encode_signing_data_to<Write: io::Write>(
        &mut self,
        mut writer: Write,
        input_index: usize,
        script_code: &Script,
        value: u64,
        sighash_type: EcdsaSighashType,
    ) -> Result<(), Error> {
        let zero_hash = sha256d::Hash::default();

        let (sighash, anyone_can_pay) = sighash_type.split_anyonecanpay_flag();

        self.tx.version.consensus_encode(&mut writer)?;

        if !anyone_can_pay {
            self.segwit_cache().prevouts.consensus_encode(&mut writer)?;
        } else {
            zero_hash.consensus_encode(&mut writer)?;
        }

        if !anyone_can_pay
            && sighash != EcdsaSighashType::Single
            && sighash != EcdsaSighashType::None
        {
            self.segwit_cache()
                .sequences
                .consensus_encode(&mut writer)?;
        } else {
            zero_hash.consensus_encode(&mut writer)?;
        }

        {
            let txin =
                &self
                    .tx
                    .input
                    .get(input_index)
                    .ok_or_else(|| Error::IndexOutOfInputsBounds {
                        index: input_index,
                        inputs_size: self.tx.input.len(),
                    })?;

            txin.previous_output.consensus_encode(&mut writer)?;
            script_code.consensus_encode(&mut writer)?;
            value.consensus_encode(&mut writer)?;
            txin.sequence.consensus_encode(&mut writer)?;
        }

        if sighash != EcdsaSighashType::Single && sighash != EcdsaSighashType::None {
            self.segwit_cache().outputs.consensus_encode(&mut writer)?;
        } else if sighash == EcdsaSighashType::Single && input_index < self.tx.output.len() {
            let mut single_enc = Sighash::engine();
            self.tx.output[input_index].consensus_encode(&mut single_enc)?;
            Sighash::from_engine(single_enc).consensus_encode(&mut writer)?;
        } else {
            zero_hash.consensus_encode(&mut writer)?;
        }

        self.tx.lock_time.consensus_encode(&mut writer)?;
        sighash_type.to_u32().consensus_encode(&mut writer)?;
        Ok(())
    }

    /// Compute the BIP143 sighash for any flag type.
    pub fn segwit_signature_hash(
        &mut self,
        input_index: usize,
        script_code: &Script,
        value: u64,
        sighash_type: EcdsaSighashType,
    ) -> Result<Sighash, Error> {
        let mut enc = Sighash::engine();
        self.segwit_encode_signing_data_to(
            &mut enc,
            input_index,
            script_code,
            value,
            sighash_type,
        )?;
        Ok(Sighash::from_engine(enc))
    }

    /// Encode the legacy signing data for any flag type into a given object implementing a
    /// [`std::io::Write`] trait. Internally calls [`Transaction::encode_signing_data_to`]
    pub fn legacy_encode_signing_data_to<Write: io::Write, U: Into<u32>>(
        &self,
        mut writer: Write,
        input_index: usize,
        script_pubkey: &Script,
        sighash_type: U,
    ) -> Result<(), Error> {
        if input_index >= self.tx.input.len() {
            return Err(Error::IndexOutOfInputsBounds {
                index: input_index,
                inputs_size: self.tx.input.len(),
            });
        }
        self.tx
            .encode_signing_data_to(&mut writer, input_index, script_pubkey, sighash_type.into())
            .expect("writers don't error");
        Ok(())
    }

    /// Computes the legacy sighash for any sighash type.
    pub fn legacy_signature_hash(
        &self,
        input_index: usize,
        script_pubkey: &Script,
        sighash_type: u32,
    ) -> Result<Sighash, Error> {
        let mut enc = Sighash::engine();
        self.legacy_encode_signing_data_to(&mut enc, input_index, script_pubkey, sighash_type)?;
        Ok(Sighash::from_engine(enc))
    }

    #[inline]
    fn common_cache(&mut self) -> &CommonCache {
        Self::common_cache_minimal_borrow(&mut self.common_cache, &self.tx)
    }

    fn common_cache_minimal_borrow<'a>(
        common_cache: &'a mut Option<CommonCache>,
        tx: &R,
    ) -> &'a CommonCache {
        common_cache.get_or_insert_with(|| {
            let mut enc_prevouts = sha256::Hash::engine();
            let mut enc_sequences = sha256::Hash::engine();
            for txin in tx.input.iter() {
                txin.previous_output
                    .consensus_encode(&mut enc_prevouts)
                    .unwrap();
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
        let tx = &self.tx;
        self.segwit_cache.get_or_insert_with(|| {
            let common_cache = Self::common_cache_minimal_borrow(common_cache, tx);
            SegwitCache {
                prevouts: sha256d::Hash::from_inner(
                    sha256::Hash::hash(&common_cache.prevouts).into_inner(),
                ),
                sequences: sha256d::Hash::from_inner(
                    sha256::Hash::hash(&common_cache.sequences).into_inner(),
                ),
                outputs: sha256d::Hash::from_inner(
                    sha256::Hash::hash(&common_cache.outputs).into_inner(),
                ),
            }
        })
    }

    fn taproot_cache<T: Borrow<TxOut>>(&mut self, prevouts: &[T]) -> &TaprootCache
    {
        self.taproot_cache.get_or_insert_with(|| {
            let mut enc_amounts = sha256::Hash::engine();
            let mut enc_script_pubkeys = sha256::Hash::engine();
            for prevout in prevouts {
                prevout.borrow().value.consensus_encode(&mut enc_amounts).unwrap();
                prevout
                    .borrow()
                    .script_pubkey
                    .consensus_encode(&mut enc_script_pubkeys)
                    .unwrap();
            }
            TaprootCache {
                amounts: sha256::Hash::from_engine(enc_amounts),
                script_pubkeys: sha256::Hash::from_engine(enc_script_pubkeys),
            }
        })
    }
}

impl<R: DerefMut<Target=Transaction>> SighashCache<R> {
    /// When the SighashCache is initialized with a mutable reference to a transaction instead of a
    /// regular reference, this method is available to allow modification to the witnesses.
    ///
    /// This allows in-line signing such as
    /// ```
    /// use bitcoin::blockdata::transaction::{Transaction, EcdsaSighashType};
    /// use bitcoin::util::sighash::SighashCache;
    /// use bitcoin::Script;
    ///
    /// let mut tx_to_sign = Transaction { version: 2, lock_time: 0, input: Vec::new(), output: Vec::new() };
    /// let input_count = tx_to_sign.input.len();
    ///
    /// let mut sig_hasher = SighashCache::new(&mut tx_to_sign);
    /// for inp in 0..input_count {
    ///     let prevout_script = Script::new();
    ///     let _sighash = sig_hasher.segwit_signature_hash(inp, &prevout_script, 42, EcdsaSighashType::All);
    ///     // ... sign the sighash
    ///     sig_hasher.witness_mut(inp).unwrap().push(&Vec::new());
    /// }
    /// ```
    pub fn witness_mut(&mut self, input_index: usize) -> Option<&mut Witness> {
        self.tx.input.get_mut(input_index).map(|i| &mut i.witness)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Error::Io(e.kind())
    }
}

/// The `Annex` struct is a slice wrapper enforcing first byte to be `0x50`.
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct Annex<'a>(&'a [u8]);

impl<'a> Annex<'a> {
    /// Creates a new `Annex` struct checking the first byte is `0x50`
    pub fn new(annex_bytes: &'a [u8]) -> Result<Self, Error> {
        if annex_bytes.first() == Some(&TAPROOT_ANNEX_PREFIX) {
            Ok(Annex(annex_bytes))
        } else {
            Err(Error::WrongAnnex)
        }
    }

    /// Returns the Annex bytes data (including first byte `0x50`)
    pub fn as_bytes(&self) -> &[u8] {
        &*self.0
    }
}

impl<'a> Encodable for Annex<'a> {
    fn consensus_encode<W: io::Write>(&self, writer: W) -> Result<usize, io::Error> {
        encode::consensus_encode_with_size(self.0, writer)
    }
}

