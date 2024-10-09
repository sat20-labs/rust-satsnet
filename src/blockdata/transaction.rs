// Rust Bitcoin Library
// Written in 2014 by
//     Andrew Poelstra <apoelstra@wpsoftware.net>
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

//! Bitcoin transactions.
//!
//! A transaction describes a transfer of money. It consumes previously-unspent
//! transaction outputs and produces new ones, satisfying the condition to spend
//! the old outputs (typically a digital signature with a specific key must be
//! provided) and defining the condition to spend the new ones. The use of digital
//! signatures ensures that coins cannot be spent by unauthorized parties.
//!
//! This module provides the structures and functions needed to support transactions.
//!

use prelude::*;

use io;
use core::{fmt, str, default::Default};
#[cfg(feature = "std")] use std::error;

use hashes::{self, Hash, sha256d};
use hashes::hex::FromHex;

use util::endian;
use blockdata::constants::WITNESS_SCALE_FACTOR;
#[cfg(feature="bitcoinconsensus")] use blockdata::script;
use blockdata::script::Script;
use blockdata::witness::Witness;
use consensus::{encode, Decodable, Encodable};
use consensus::encode::MAX_VEC_SIZE;
use hash_types::{Sighash, Txid, Wtxid};
use VarInt;

#[cfg(doc)]
use util::sighash::SchnorrSighashType;

/// Used for signature hash for invalid use of SIGHASH_SINGLE.
const UINT256_ONE: [u8; 32] = [
    1, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0
];

/// A reference to a transaction output.
#[derive(Copy, Clone, Debug, Eq, Hash, PartialEq, PartialOrd, Ord)]
pub struct OutPoint {
    /// The referenced transaction's txid.
    pub txid: Txid,
    /// The index of the referenced output in its transaction's vout.
    pub vout: u32,
}
serde_struct_human_string_impl!(OutPoint, "an OutPoint", txid, vout);

impl OutPoint {
    /// Creates a new [`OutPoint`].
    #[inline]
    pub fn new(txid: Txid, vout: u32) -> OutPoint {
        OutPoint { txid, vout }
    }

    /// Creates a "null" `OutPoint`.
    ///
    /// This value is used for coinbase transactions because they don't have any previous outputs.
    #[inline]
    pub fn null() -> OutPoint {
        OutPoint {
            txid: Default::default(),
            vout: u32::max_value(),
        }
    }

    /// Checks if an `OutPoint` is "null".
    ///
    /// # Examples
    ///
    /// ```rust
    /// use bitcoin::blockdata::constants::genesis_block;
    /// use bitcoin::network::constants::Network;
    ///
    /// let block = genesis_block(Network::Bitcoin);
    /// let tx = &block.txdata[0];
    ///
    /// // Coinbase transactions don't have any previous output.
    /// assert!(tx.input[0].previous_output.is_null());
    /// ```
    #[inline]
    pub fn is_null(&self) -> bool {
        *self == OutPoint::null()
    }
}

impl Default for OutPoint {
    fn default() -> Self {
        OutPoint::null()
    }
}

impl fmt::Display for OutPoint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}:{}", self.txid, self.vout)
    }
}

/// An error in parsing an OutPoint.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum ParseOutPointError {
    /// Error in TXID part.
    Txid(hashes::hex::Error),
    /// Error in vout part.
    Vout(::core::num::ParseIntError),
    /// Error in general format.
    Format,
    /// Size exceeds max.
    TooLong,
    /// Vout part is not strictly numeric without leading zeroes.
    VoutNotCanonical,
}

impl fmt::Display for ParseOutPointError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ParseOutPointError::Txid(ref e) => write!(f, "error parsing TXID: {}", e),
            ParseOutPointError::Vout(ref e) => write!(f, "error parsing vout: {}", e),
            ParseOutPointError::Format => write!(f, "OutPoint not in <txid>:<vout> format"),
            ParseOutPointError::TooLong => write!(f, "vout should be at most 10 digits"),
            ParseOutPointError::VoutNotCanonical => write!(f, "no leading zeroes or + allowed in vout part"),
        }
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl error::Error for ParseOutPointError {
    fn cause(&self) -> Option<&dyn  error::Error> {
        match *self {
            ParseOutPointError::Txid(ref e) => Some(e),
            ParseOutPointError::Vout(ref e) => Some(e),
            _ => None,
        }
    }
}

/// Parses a string-encoded transaction index (vout).
/// Does not permit leading zeroes or non-digit characters.
fn parse_vout(s: &str) -> Result<u32, ParseOutPointError> {
    if s.len() > 1 {
        let first = s.chars().next().unwrap();
        if first == '0' || first == '+' {
            return Err(ParseOutPointError::VoutNotCanonical);
        }
    }
    s.parse().map_err(ParseOutPointError::Vout)
}

impl ::core::str::FromStr for OutPoint {
    type Err = ParseOutPointError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s.len() > 75 { // 64 + 1 + 10
            return Err(ParseOutPointError::TooLong);
        }
        let find = s.find(':');
        if find == None || find != s.rfind(':') {
            return Err(ParseOutPointError::Format);
        }
        let colon = find.unwrap();
        if colon == 0 || colon == s.len() - 1 {
            return Err(ParseOutPointError::Format);
        }
        Ok(OutPoint {
            txid: Txid::from_hex(&s[..colon]).map_err(ParseOutPointError::Txid)?,
            vout: parse_vout(&s[colon+1..])?,
        })
    }
}

/// A transaction input, which defines old coins to be consumed
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TxIn {
    /// The reference to the previous output that is being used an an input.
    pub previous_output: OutPoint,
    /// The script which pushes values on the stack which will cause
    /// the referenced output's script to be accepted.
    pub script_sig: Script,
    /// The sequence number, which suggests to miners which of two
    /// conflicting transactions should be preferred, or 0xFFFFFFFF
    /// to ignore this feature. This is generally never used since
    /// the miner behaviour cannot be enforced.
    pub sequence: u32,
    /// Witness data: an array of byte-arrays.
    /// Note that this field is *not* (de)serialized with the rest of the TxIn in
    /// Encodable/Decodable, as it is (de)serialized at the end of the full
    /// Transaction. It *is* (de)serialized with the rest of the TxIn in other
    /// (de)serialization routines.
    pub witness: Witness
}

impl Default for TxIn {
    fn default() -> TxIn {
        TxIn {
            previous_output: OutPoint::default(),
            script_sig: Script::new(),
            sequence: u32::max_value(),
            witness: Witness::default(),
        }
    }
}

/// A range of satoshi values.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct SatsRange {
    /// The start of the range in satoshis.
    pub start: u64,
    /// The size of the range in satoshis.
    pub size: u64,
}

impl Encodable for SatsRange {
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.start.consensus_encode(&mut s)?;
        len += self.size.consensus_encode(s)?;
        Ok(len)
    }
}

impl Decodable for SatsRange {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        Ok(SatsRange {
            start: Decodable::consensus_decode(&mut d)?,
            size: Decodable::consensus_decode(d)?,
        })
    }
}


/// A transaction output, which defines new coins to be created from old ones.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct TxOut {
    /// The value of the output, in satoshis.
    pub value: u64,
    /// The script which must be satisfied for the output to be spent.
    pub script_pubkey: Script,
    /// Sats index range for the output
    pub sats_ranges: Vec<SatsRange>,
}

// This is used as a "null txout" in consensus signing code.
impl Default for TxOut {
    fn default() -> TxOut {
        TxOut { value: 0xffffffffffffffff, script_pubkey: Script::new(), sats_ranges: Vec::new(), }
        // TxOut { value: 0xffffffffffffffff, script_pubkey: Script::new(), }
    }
}

/// A Bitcoin transaction, which describes an authenticated movement of coins.
///
/// If any inputs have nonempty witnesses, the entire transaction is serialized
/// in the post-BIP141 Segwit format which includes a list of witnesses. If all
/// inputs have empty witnesses, the transaction is serialized in the pre-BIP141
/// format.
///
/// There is one major exception to this: to avoid deserialization ambiguity,
/// if the transaction has no inputs, it is serialized in the BIP141 style. Be
/// aware that this differs from the transaction format in PSBT, which _never_
/// uses BIP141. (Ordinarily there is no conflict, since in PSBT transactions
/// are always unsigned and therefore their inputs have empty witnesses.)
///
/// The specific ambiguity is that Segwit uses the flag bytes `0001` where an old
/// serializer would read the number of transaction inputs. The old serializer
/// would interpret this as "no inputs, one output", which means the transaction
/// is invalid, and simply reject it. Segwit further specifies that this encoding
/// should *only* be used when some input has a nonempty witness; that is,
/// witness-less transactions should be encoded in the traditional format.
///
/// However, in protocols where transactions may legitimately have 0 inputs, e.g.
/// when parties are cooperatively funding a transaction, the "00 means Segwit"
/// heuristic does not work. Since Segwit requires such a transaction be encoded
/// in the original transaction format (since it has no inputs and therefore
/// no input witnesses), a traditionally encoded transaction may have the `0001`
/// Segwit flag in it, which confuses most Segwit parsers including the one in
/// Bitcoin Core.
///
/// We therefore deviate from the spec by always using the Segwit witness encoding
/// for 0-input transactions, which results in unambiguously parseable transactions.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
pub struct Transaction {
    /// The protocol version, is currently expected to be 1 or 2 (BIP 68).
    pub version: i32,
    /// Block number before which this transaction is valid, or 0 for valid immediately.
    pub lock_time: u32,
    /// List of transaction inputs.
    pub input: Vec<TxIn>,
    /// List of transaction outputs.
    pub output: Vec<TxOut>,
}

impl Transaction {
    /// Computes a "normalized TXID" which does not include any signatures.
    /// This gives a way to identify a transaction that is "the same" as
    /// another in the sense of having same inputs and outputs.
    pub fn ntxid(&self) -> sha256d::Hash {
        let cloned_tx = Transaction {
            version: self.version,
            lock_time: self.lock_time,
            input: self.input.iter().map(|txin| TxIn { script_sig: Script::new(), witness: Witness::default(), .. *txin }).collect(),
            output: self.output.clone(),
        };
        cloned_tx.txid().into()
    }

    /// Computes the txid. For non-segwit transactions this will be identical
    /// to the output of `wtxid()`, but for segwit transactions,
    /// this will give the correct txid (not including witnesses) while `wtxid`
    /// will also hash witnesses.
    pub fn txid(&self) -> Txid {
        let mut enc = Txid::engine();
        self.version.consensus_encode(&mut enc).expect("engines don't error");
        self.input.consensus_encode(&mut enc).expect("engines don't error");
        self.output.consensus_encode(&mut enc).expect("engines don't error");
        self.lock_time.consensus_encode(&mut enc).expect("engines don't error");
        Txid::from_engine(enc)
    }

    /// Computes SegWit-version of the transaction id (wtxid). For transaction with the witness
    /// data this hash includes witness, for pre-witness transaction it is equal to the normal
    /// value returned by txid() function.
    pub fn wtxid(&self) -> Wtxid {
        let mut enc = Wtxid::engine();
        self.consensus_encode(&mut enc).expect("engines don't error");
        Wtxid::from_engine(enc)
    }

    /// Encodes the signing data from which a signature hash for a given input index with a given
    /// sighash flag can be computed.
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
    /// - Does NOT handle the sighash single bug, you should either handle that manually or use
    /// [`Self::signature_hash()`] instead.
    ///
    /// # Panics
    ///
    /// If `input_index` is out of bounds (greater than or equal to `self.input.len()`).
    pub fn encode_signing_data_to<Write: io::Write, U: Into<u32>>(
        &self,
        mut writer: Write,
        input_index: usize,
        script_pubkey: &Script,
        sighash_type: U,
    ) -> Result<(), encode::Error> {
        let sighash_type: u32 = sighash_type.into();
        assert!(input_index < self.input.len());  // Panic on OOB

        if self.is_invalid_use_of_sighash_single(sighash_type, input_index) {
            // We cannot correctly handle the SIGHASH_SINGLE bug here because usage of this function
            // will result in the data written to the writer being hashed, however the correct
            // handling of the SIGHASH_SINGLE bug is to return the 'one array' - either implement
            // this behaviour manually or use `signature_hash()`.
            writer.write(b"[not a transaction] SIGHASH_SINGLE bug")?;
            return Ok(())
        }

        let (sighash, anyone_can_pay) = EcdsaSighashType::from_consensus(sighash_type).split_anyonecanpay_flag();

        // Build tx to sign
        let mut tx = Transaction {
            version: self.version,
            lock_time: self.lock_time,
            input: vec![],
            output: vec![],
        };
        // Add all inputs necessary..
        if anyone_can_pay {
            tx.input = vec![TxIn {
                previous_output: self.input[input_index].previous_output,
                script_sig: script_pubkey.clone(),
                sequence: self.input[input_index].sequence,
                witness: Witness::default(),
            }];
        } else {
            tx.input = Vec::with_capacity(self.input.len());
            for (n, input) in self.input.iter().enumerate() {
                tx.input.push(TxIn {
                    previous_output: input.previous_output,
                    script_sig: if n == input_index { script_pubkey.clone() } else { Script::new() },
                    sequence: if n != input_index && (sighash == EcdsaSighashType::Single || sighash == EcdsaSighashType::None) { 0 } else { input.sequence },
                    witness: Witness::default(),
                });
            }
        }
        // ..then all outputs
        tx.output = match sighash {
            EcdsaSighashType::All => self.output.clone(),
            EcdsaSighashType::Single => {
                let output_iter = self.output.iter()
                                      .take(input_index + 1)  // sign all outputs up to and including this one, but erase
                                      .enumerate()            // all of them except for this one
                                      .map(|(n, out)| if n == input_index { out.clone() } else { TxOut::default() });
                output_iter.collect()
            }
            EcdsaSighashType::None => vec![],
            _ => unreachable!()
        };
        // hash the result
        tx.consensus_encode(&mut writer)?;
        let sighash_arr = endian::u32_to_array_le(sighash_type);
        sighash_arr.consensus_encode(&mut writer)?;
        Ok(())
    }

    /// Computes a signature hash for a given input index with a given sighash flag.
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
    ///
    /// # Panics
    ///
    /// If `input_index` is out of bounds (greater than or equal to `self.input.len()`).
    pub fn signature_hash(
        &self,
        input_index: usize,
        script_pubkey: &Script,
        sighash_u32: u32
    ) -> Sighash {
        if self.is_invalid_use_of_sighash_single(sighash_u32, input_index) {
            return Sighash::from_slice(&UINT256_ONE).expect("const-size array");
        }

        let mut engine = Sighash::engine();
        self.encode_signing_data_to(&mut engine, input_index, script_pubkey, sighash_u32)
            .expect("engines don't error");
        Sighash::from_engine(engine)
    }

    fn is_invalid_use_of_sighash_single(&self, sighash: u32, input_index: usize) -> bool {
        let ty = EcdsaSighashType::from_consensus(sighash);
        ty == EcdsaSighashType::Single && input_index >= self.output.len()
    }

    /// Returns the "weight" of this transaction, as defined by BIP141.
    #[inline]
    #[deprecated(since = "0.28.0", note = "Please use `transaction::weight` instead.")]
    pub fn get_weight(&self) -> usize {
        self.weight()
    }

    /// Returns the "weight" of this transaction, as defined by BIP141.
    ///
    /// For transactions with an empty witness, this is simply the consensus-serialized size times
    /// four. For transactions with a witness, this is the non-witness consensus-serialized size
    /// multiplied by three plus the with-witness consensus-serialized size.
    #[inline]
    pub fn weight(&self) -> usize {
        self.scaled_size(WITNESS_SCALE_FACTOR)
    }

    /// Returns the regular byte-wise consensus-serialized size of this transaction.
    #[inline]
    #[deprecated(since = "0.28.0", note = "Please use `transaction::size` instead.")]
    pub fn get_size(&self) -> usize {
        self.size()
    }

    /// Returns the regular byte-wise consensus-serialized size of this transaction.
    #[inline]
    pub fn size(&self) -> usize {
        self.scaled_size(1)
    }

    /// Returns the "virtual size" (vsize) of this transaction.
    #[inline]
    #[deprecated(since = "0.28.0", note = "Please use `transaction::vsize` instead.")]
    pub fn get_vsize(&self) -> usize {
        self.vsize()
    }

    /// Returns the "virtual size" (vsize) of this transaction.
    ///
    /// Will be `ceil(weight / 4.0)`. Note this implements the virtual size as per [`BIP141`], which
    /// is different to what is implemented in Bitcoin Core. The computation should be the same for
    /// any remotely sane transaction, and a standardness-rule-correct version is available in the
    /// [`policy`] module.
    ///
    /// [`BIP141`]: https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki
    /// [`policy`]: ../policy/mod.rs.html
    #[inline]
    pub fn vsize(&self) -> usize {
        let weight = self.weight();
        (weight + WITNESS_SCALE_FACTOR - 1) / WITNESS_SCALE_FACTOR
    }

    /// Returns the size of this transaction excluding the witness data.
    #[deprecated(since = "0.28.0", note = "Please use `transaction::strippedsize` instead.")]
    pub fn get_strippedsize(&self) -> usize {
        self.strippedsize()
    }

    /// Returns the size of this transaction excluding the witness data.
    pub fn strippedsize(&self) -> usize {
        let mut input_size = 0;
        for input in &self.input {
            input_size += 32 + 4 + 4 + // outpoint (32+4) + nSequence
                VarInt(input.script_sig.len() as u64).len() +
                input.script_sig.len();
        }
        let mut output_size = 0;
        for output in &self.output {
            output_size += 8 + // value
                VarInt(output.script_pubkey.len() as u64).len() +
                output.script_pubkey.len();
        }
        let non_input_size =
        // version:
        4 +
        // count varints:
        VarInt(self.input.len() as u64).len() +
        VarInt(self.output.len() as u64).len() +
        output_size +
        // lock_time
        4;
        non_input_size + input_size
    }

    /// Internal utility function for size/weight functions.
    fn scaled_size(&self, scale_factor: usize) -> usize {
        let mut input_weight = 0;
        let mut inputs_with_witnesses = 0;
        for input in &self.input {
            input_weight += scale_factor*(32 + 4 + 4 + // outpoint (32+4) + nSequence
                VarInt(input.script_sig.len() as u64).len() +
                input.script_sig.len());
            if !input.witness.is_empty() {
                inputs_with_witnesses += 1;
                input_weight += input.witness.serialized_len();
            }
        }
        let mut output_size = 0;
        for output in &self.output {
            output_size += 8 + // value
                VarInt(output.script_pubkey.len() as u64).len() +
                output.script_pubkey.len();
        }
        let non_input_size =
        // version:
        4 +
        // count varints:
        VarInt(self.input.len() as u64).len() +
        VarInt(self.output.len() as u64).len() +
        output_size +
        // lock_time
        4;
        if inputs_with_witnesses == 0 {
            non_input_size * scale_factor + input_weight
        } else {
            non_input_size * scale_factor + input_weight + self.input.len() - inputs_with_witnesses + 2
        }
    }

    /// Shorthand for [`Self::verify_with_flags`] with flag [`bitcoinconsensus::VERIFY_ALL`].
    #[cfg(feature="bitcoinconsensus")]
    #[cfg_attr(docsrs, doc(cfg(feature = "bitcoinconsensus")))]
    pub fn verify<S>(&self, spent: S) -> Result<(), script::Error>
    where
        S: FnMut(&OutPoint) -> Option<TxOut>
    {
        self.verify_with_flags(spent, ::bitcoinconsensus::VERIFY_ALL)
    }

    /// Verify that this transaction is able to spend its inputs.
    /// The `spent` closure should not return the same [`TxOut`] twice!
    #[cfg(feature="bitcoinconsensus")]
    #[cfg_attr(docsrs, doc(cfg(feature = "bitcoinconsensus")))]
    pub fn verify_with_flags<S, F>(&self, mut spent: S, flags: F) -> Result<(), script::Error>
    where
        S: FnMut(&OutPoint) -> Option<TxOut>,
        F: Into<u32>
    {
        let tx = encode::serialize(&*self);
        let flags: u32 = flags.into();
        for (idx, input) in self.input.iter().enumerate() {
            if let Some(output) = spent(&input.previous_output) {
                output.script_pubkey.verify_with_flags(idx, ::Amount::from_sat(output.value), tx.as_slice(), flags)?;
            } else {
                return Err(script::Error::UnknownSpentOutput(input.previous_output.clone()));
            }
        }
        Ok(())
    }

    /// Is this a coin base transaction?
    pub fn is_coin_base(&self) -> bool {
        self.input.len() == 1 && self.input[0].previous_output.is_null()
    }

    /// Returns `true` if the transaction itself opted in to be BIP-125-replaceable (RBF). This
    /// **does not** cover the case where a transaction becomes replaceable due to ancestors being
    /// RBF.
    pub fn is_explicitly_rbf(&self) -> bool {
        self.input.iter().any(|input| input.sequence < (0xffffffff - 1))
    }
}

impl_consensus_encoding!(TxOut, value, sats_ranges, script_pubkey);

impl Encodable for OutPoint {
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        let len = self.txid.consensus_encode(&mut s)?;
        Ok(len + self.vout.consensus_encode(s)?)
    }
}
impl Decodable for OutPoint {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        Ok(OutPoint {
            txid: Decodable::consensus_decode(&mut d)?,
            vout: Decodable::consensus_decode(d)?,
        })
    }
}

impl Encodable for TxIn {
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.previous_output.consensus_encode(&mut s)?;
        len += self.script_sig.consensus_encode(&mut s)?;
        len += self.sequence.consensus_encode(s)?;
        Ok(len)
    }
}
impl Decodable for TxIn {
    fn consensus_decode<D: io::Read>(mut d: D) -> Result<Self, encode::Error> {
        Ok(TxIn {
            previous_output: Decodable::consensus_decode(&mut d)?,
            script_sig: Decodable::consensus_decode(&mut d)?,
            sequence: Decodable::consensus_decode(d)?,
            witness: Witness::default(),
        })
    }
}

impl Encodable for Transaction {
    fn consensus_encode<S: io::Write>(&self, mut s: S) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.version.consensus_encode(&mut s)?;
        // To avoid serialization ambiguity, no inputs means we use BIP141 serialization (see
        // `Transaction` docs for full explanation).
        let mut have_witness = self.input.is_empty();
        for input in &self.input {
            if !input.witness.is_empty() {
                have_witness = true;
                break;
            }
        }
        if !have_witness {
            len += self.input.consensus_encode(&mut s)?;
            len += self.output.consensus_encode(&mut s)?;
        } else {
            len += 0u8.consensus_encode(&mut s)?;
            len += 1u8.consensus_encode(&mut s)?;
            len += self.input.consensus_encode(&mut s)?;
            len += self.output.consensus_encode(&mut s)?;
            for input in &self.input {
                len += input.witness.consensus_encode(&mut s)?;
            }
        }
        len += self.lock_time.consensus_encode(s)?;
        Ok(len)
    }
}

impl Decodable for Transaction {
    fn consensus_decode<D: io::Read>(d: D) -> Result<Self, encode::Error> {
        let mut d = d.take(MAX_VEC_SIZE as u64);
        let version = i32::consensus_decode(&mut d)?;
        let input = Vec::<TxIn>::consensus_decode(&mut d)?;
        // segwit
        if input.is_empty() {
            let segwit_flag = u8::consensus_decode(&mut d)?;
            match segwit_flag {
                // BIP144 input witnesses
                1 => {
                    let mut input = Vec::<TxIn>::consensus_decode(&mut d)?;
                    let output = Vec::<TxOut>::consensus_decode(&mut d)?;
                    for txin in input.iter_mut() {
                        txin.witness = Decodable::consensus_decode(&mut d)?;
                    }
                    if !input.is_empty() && input.iter().all(|input| input.witness.is_empty()) {
                        Err(encode::Error::ParseFailed("witness flag set but no witnesses present"))
                    } else {
                        Ok(Transaction {
                            version,
                            input,
                            output,
                            lock_time: Decodable::consensus_decode(d)?,
                        })
                    }
                }
                // We don't support anything else
                x => Err(encode::Error::UnsupportedSegwitFlag(x)),
            }
        // non-segwit
        } else {
            Ok(Transaction {
                version,
                input,
                output: Decodable::consensus_decode(&mut d)?,
                lock_time: Decodable::consensus_decode(d)?,
            })
        }
    }
}

/// This type is consensus valid but an input including it would prevent the transaction from
/// being relayed on today's Bitcoin network.
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct NonStandardSighashType(pub u32);

impl fmt::Display for NonStandardSighashType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Non standard sighash type {}", self.0)
    }
}

#[cfg(feature = "std")]
#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
impl error::Error for NonStandardSighashType {}

/// Legacy Hashtype of an input's signature
#[deprecated(since = "0.28.0", note = "Please use [`EcdsaSighashType`] instead")]
pub type SigHashType = EcdsaSighashType;

/// Hashtype of an input's signature, encoded in the last byte of the signature.
///
/// Fixed values so they can be cast as integer types for encoding (see also
/// [`SchnorrSighashType`]).
#[derive(PartialEq, Eq, Debug, Copy, Clone)]
pub enum EcdsaSighashType {
    /// 0x1: Sign all outputs.
    All		= 0x01,
    /// 0x2: Sign no outputs --- anyone can choose the destination.
    None	= 0x02,
    /// 0x3: Sign the output whose index matches this input's index. If none exists,
    /// sign the hash `0000000000000000000000000000000000000000000000000000000000000001`.
    /// (This rule is probably an unintentional C++ism, but it's consensus so we have
    /// to follow it.)
    Single	= 0x03,
    /// 0x81: Sign all outputs but only this input.
    AllPlusAnyoneCanPay		= 0x81,
    /// 0x82: Sign no outputs and only this input.
    NonePlusAnyoneCanPay	= 0x82,
    /// 0x83: Sign one output and only this input (see `Single` for what "one output" means).
    SinglePlusAnyoneCanPay	= 0x83
}
serde_string_impl!(EcdsaSighashType, "a EcdsaSighashType data");

impl fmt::Display for EcdsaSighashType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            EcdsaSighashType::All => "SIGHASH_ALL",
            EcdsaSighashType::None => "SIGHASH_NONE",
            EcdsaSighashType::Single => "SIGHASH_SINGLE",
            EcdsaSighashType::AllPlusAnyoneCanPay => "SIGHASH_ALL|SIGHASH_ANYONECANPAY",
            EcdsaSighashType::NonePlusAnyoneCanPay => "SIGHASH_NONE|SIGHASH_ANYONECANPAY",
            EcdsaSighashType::SinglePlusAnyoneCanPay => "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY",
        };
        f.write_str(s)
    }
}

impl str::FromStr for EcdsaSighashType {
    type Err = SighashTypeParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "SIGHASH_ALL" => Ok(EcdsaSighashType::All),
            "SIGHASH_NONE" => Ok(EcdsaSighashType::None),
            "SIGHASH_SINGLE" => Ok(EcdsaSighashType::Single),
            "SIGHASH_ALL|SIGHASH_ANYONECANPAY" => Ok(EcdsaSighashType::AllPlusAnyoneCanPay),
            "SIGHASH_NONE|SIGHASH_ANYONECANPAY" => Ok(EcdsaSighashType::NonePlusAnyoneCanPay),
            "SIGHASH_SINGLE|SIGHASH_ANYONECANPAY" => Ok(EcdsaSighashType::SinglePlusAnyoneCanPay),
            _ => Err(SighashTypeParseError { unrecognized: s.to_owned() }),
        }
    }
}

impl EcdsaSighashType {
    /// Splits the sighash flag into the "real" sighash flag and the ANYONECANPAY boolean.
    pub(crate) fn split_anyonecanpay_flag(self) -> (EcdsaSighashType, bool) {
        match self {
            EcdsaSighashType::All => (EcdsaSighashType::All, false),
            EcdsaSighashType::None => (EcdsaSighashType::None, false),
            EcdsaSighashType::Single => (EcdsaSighashType::Single, false),
            EcdsaSighashType::AllPlusAnyoneCanPay => (EcdsaSighashType::All, true),
            EcdsaSighashType::NonePlusAnyoneCanPay => (EcdsaSighashType::None, true),
            EcdsaSighashType::SinglePlusAnyoneCanPay => (EcdsaSighashType::Single, true)
        }
    }

    /// Creates a [`EcdsaSighashType`] from a raw `u32`.
    #[deprecated(since="0.28.0", note="please use `from_consensus`")]
    pub fn from_u32_consensus(n: u32) -> EcdsaSighashType {
        EcdsaSighashType::from_consensus(n)
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
        // In Bitcoin Core, the SignatureHash function will mask the (int32) value with
        // 0x1f to (apparently) deactivate ACP when checking for SINGLE and NONE bits.
        // We however want to be matching also against on ACP-masked ALL, SINGLE, and NONE.
        // So here we re-activate ACP.
        let mask = 0x1f | 0x80;
        match n & mask {
            // "real" sighashes
            0x01 => EcdsaSighashType::All,
            0x02 => EcdsaSighashType::None,
            0x03 => EcdsaSighashType::Single,
            0x81 => EcdsaSighashType::AllPlusAnyoneCanPay,
            0x82 => EcdsaSighashType::NonePlusAnyoneCanPay,
            0x83 => EcdsaSighashType::SinglePlusAnyoneCanPay,
            // catchalls
            x if x & 0x80 == 0x80 => EcdsaSighashType::AllPlusAnyoneCanPay,
            _ => EcdsaSighashType::All
        }
    }

    /// Creates a [`EcdsaSighashType`] from a raw `u32`.
    #[deprecated(since="0.28.0", note="please use `from_standard`")]
    pub fn from_u32_standard(n: u32) -> Result<EcdsaSighashType, NonStandardSighashType> {
        EcdsaSighashType::from_standard(n)
    }

    /// Creates a [`EcdsaSighashType`] from a raw `u32`.
    ///
    /// # Errors
    ///
    /// If `n` is a non-standard sighash value.
    pub fn from_standard(n: u32) -> Result<EcdsaSighashType, NonStandardSighashType> {
        match n {
            // Standard sighashes, see https://github.com/bitcoin/bitcoin/blob/b805dbb0b9c90dadef0424e5b3bf86ac308e103e/src/script/interpreter.cpp#L189-L198
            0x01 => Ok(EcdsaSighashType::All),
            0x02 => Ok(EcdsaSighashType::None),
            0x03 => Ok(EcdsaSighashType::Single),
            0x81 => Ok(EcdsaSighashType::AllPlusAnyoneCanPay),
            0x82 => Ok(EcdsaSighashType::NonePlusAnyoneCanPay),
            0x83 => Ok(EcdsaSighashType::SinglePlusAnyoneCanPay),
            non_standard => Err(NonStandardSighashType(non_standard))
        }
    }

    /// Converts [`EcdsaSighashType`] to a `u32` sighash flag.
    ///
    /// The returned value is guaranteed to be a valid according to standardness rules.
    pub fn to_u32(self) -> u32 { self as u32 }
}

/// Error returned for failure during parsing one of the sighash types.
///
/// This is currently returned for unrecognized sighash strings.
#[derive(Debug, Clone)]
pub struct SighashTypeParseError {
    /// The unrecognized string we attempted to parse.
    pub unrecognized: String,
}

impl fmt::Display for SighashTypeParseError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "Unrecognized SIGHASH string '{}'", self.unrecognized)
    }
}

#[cfg_attr(docsrs, doc(cfg(feature = "std")))]
#[cfg(feature = "std")]
impl ::std::error::Error for SighashTypeParseError {}
