// SPDX-License-Identifier: CC0-1.0

//! BIP152 Compact Blocks.
//!
//! Implementation of compact blocks data structure and algorithms.

use core::{convert, fmt, mem};
#[cfg(feature = "std")]
use std::error;

use hashes::{sha256, siphash24};
use internals::{impl_array_newtype, ToU64 as _};
use io::{BufRead, Write};

use crate::consensus::encode::{self, Decodable, Encodable, VarInt};
use crate::internal_macros::{impl_array_newtype_stringify, impl_consensus_encoding};
use crate::prelude::Vec;
use crate::transaction::TxIdentifier;
use crate::{block, Block, BlockHash, Transaction};

/// A BIP-152 error
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// An unknown version number was used.
    UnknownVersion,
    /// The prefill slice provided was invalid.
    InvalidPrefill,
}

internals::impl_from_infallible!(Error);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            Error::UnknownVersion => write!(f, "an unknown version number was used"),
            Error::InvalidPrefill => write!(f, "the prefill slice provided was invalid"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use self::Error::*;

        match *self {
            UnknownVersion | InvalidPrefill => None,
        }
    }
}

/// A [`PrefilledTransaction`] structure is used in [`HeaderAndShortIds`] to
/// provide a list of a few transactions explicitly.
#[derive(PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
pub struct PrefilledTransaction {
    /// The index of the transaction in the block.
    ///
    /// This field is differentially encoded relative to the previous
    /// prefilled transaction as described as follows:
    ///
    /// > Several uses of CompactSize below are "differentially encoded". For
    /// > these, instead of using raw indexes, the number encoded is the
    /// > difference between the current index and the previous index, minus one.
    /// > For example, a first index of 0 implies a real index of 0, a second
    /// > index of 0 thereafter refers to a real index of 1, etc.
    pub idx: u16,
    /// The actual transaction.
    pub tx: Transaction,
}

impl convert::AsRef<Transaction> for PrefilledTransaction {
    fn as_ref(&self) -> &Transaction {
        &self.tx
    }
}

impl Encodable for PrefilledTransaction {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        Ok(VarInt::from(self.idx).consensus_encode(w)? + self.tx.consensus_encode(w)?)
    }
}

impl Decodable for PrefilledTransaction {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let idx = VarInt::consensus_decode(r)?.0;
        let idx = u16::try_from(idx)
            .map_err(|_| encode::Error::ParseFailed("BIP152 prefilled tx index out of bounds"))?;
        let tx = Transaction::consensus_decode(r)?;
        Ok(PrefilledTransaction { idx, tx })
    }
}

/// Short transaction IDs are used to represent a transaction without sending a full 256-bit hash.
#[derive(PartialEq, Eq, Clone, Copy, Hash, Default, PartialOrd, Ord)]
pub struct ShortId([u8; 6]);
impl_array_newtype!(ShortId, u8, 6);
impl_array_newtype_stringify!(ShortId, 6);

impl ShortId {
    /// Calculates the SipHash24 keys used to calculate short IDs.
    pub fn calculate_siphash_keys(header: &block::Header, nonce: u64) -> (u64, u64) {
        // 1. single-SHA256 hashing the block header with the nonce appended (in little-endian)
        let h = {
            let mut engine = sha256::Hash::engine();
            header.consensus_encode(&mut engine).expect("engines don't error");
            nonce.consensus_encode(&mut engine).expect("engines don't error");
            sha256::Hash::from_engine(engine)
        };

        // 2. Running SipHash-2-4 with the input being the transaction ID and the keys (k0/k1)
        // set to the first two little-endian 64-bit integers from the above hash, respectively.
        (
            u64::from_le_bytes(h[0..8].try_into().expect("8 byte slice")),
            u64::from_le_bytes(h[8..16].try_into().expect("8 byte slice")),
        )
    }

    /// Calculates the short ID with the given (w)txid and using the provided SipHash keys.
    pub fn with_siphash_keys<T: TxIdentifier>(txid: &T, siphash_keys: (u64, u64)) -> ShortId {
        // 2. Running SipHash-2-4 with the input being the transaction ID and the keys (k0/k1)
        // set to the first two little-endian 64-bit integers from the above hash, respectively.
        let hash = siphash24::Hash::hash_with_keys(siphash_keys.0, siphash_keys.1, txid.as_ref());

        // 3. Dropping the 2 most significant bytes from the SipHash output to make it 6 bytes.
        let mut id = ShortId([0; 6]);
        id.0.copy_from_slice(&hash[0..6]);
        id
    }
}

impl Encodable for ShortId {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.0.consensus_encode(w)
    }
}

impl Decodable for ShortId {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<ShortId, encode::Error> {
        Ok(ShortId(Decodable::consensus_decode(r)?))
    }
}

/// A structure to relay a block header, short IDs, and a select few transactions.
///
/// A [`HeaderAndShortIds`] structure is used to relay a block header, the short
/// transactions IDs used for matching already-available transactions, and a
/// select few transactions which we expect a peer may be missing.
#[derive(PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
pub struct HeaderAndShortIds {
    /// The header of the block being provided.
    pub header: block::Header,
    ///  A nonce for use in short transaction ID calculations.
    pub nonce: u64,
    ///  The short transaction IDs calculated from the transactions
    ///  which were not provided explicitly in prefilled_txs.
    pub short_ids: Vec<ShortId>,
    ///  Used to provide the coinbase transaction and a select few
    ///  which we expect a peer may be missing.
    pub prefilled_txs: Vec<PrefilledTransaction>,
}

impl Decodable for HeaderAndShortIds {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let header_short_ids = HeaderAndShortIds {
            header: Decodable::consensus_decode(r)?,
            nonce: Decodable::consensus_decode(r)?,
            short_ids: Decodable::consensus_decode(r)?,
            prefilled_txs: Decodable::consensus_decode(r)?,
        };
        match header_short_ids.short_ids.len().checked_add(header_short_ids.prefilled_txs.len()) {
            Some(x) if x <= u16::MAX.into() => Ok(header_short_ids),
            _ => Err(encode::Error::ParseFailed("indexes overflowed 16 bits")),
        }
    }
}

impl Encodable for HeaderAndShortIds {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.header.consensus_encode(w)?;
        len += self.nonce.consensus_encode(w)?;
        len += self.short_ids.consensus_encode(w)?;
        len += self.prefilled_txs.consensus_encode(w)?;
        Ok(len)
    }
}

impl HeaderAndShortIds {
    /// Creates a new [`HeaderAndShortIds`] from a full block.
    ///
    /// The version number must be either 1 or 2.
    ///
    /// The `prefill` slice indicates which transactions should be prefilled in
    /// the block. It should contain the indexes in the block of the txs to
    /// prefill. It must be ordered. 0 should not be included as the
    /// coinbase tx is always prefilled.
    ///
    /// > Nodes SHOULD NOT use the same nonce across multiple different blocks.
    pub fn from_block(
        block: &Block,
        nonce: u64,
        version: u32,
        mut prefill: &[usize],
    ) -> Result<HeaderAndShortIds, Error> {
        if version != 1 && version != 2 {
            return Err(Error::UnknownVersion);
        }

        let siphash_keys = ShortId::calculate_siphash_keys(&block.header, nonce);

        let mut prefilled = Vec::with_capacity(prefill.len() + 1); // +1 for coinbase tx
        let mut short_ids = Vec::with_capacity(block.txdata.len() - prefill.len());
        let mut last_prefill = 0;
        for (idx, tx) in block.txdata.iter().enumerate() {
            // Check if we should prefill this tx.
            let prefill_tx = if prefill.first() == Some(&idx) {
                prefill = &prefill[1..];
                true
            } else {
                idx == 0 // Always prefill coinbase.
            };

            if prefill_tx {
                let diff_idx = idx - last_prefill;
                last_prefill = idx + 1;
                prefilled.push(PrefilledTransaction {
                    idx: diff_idx as u16,
                    tx: match version {
                        // >  As encoded in "tx" messages sent in response to getdata MSG_TX
                        1 => {
                            // strip witness for version 1
                            let mut no_witness = tx.clone();
                            no_witness.input.iter_mut().for_each(|i| i.witness.clear());
                            no_witness
                        }
                        // > Transactions inside cmpctblock messages (both those used as direct
                        // > announcement and those in response to getdata) and in blocktxn should
                        // > include witness data, using the same format as responses to getdata
                        // > MSG_WITNESS_TX, specified in BIP144.
                        2 => tx.clone(),
                        _ => unreachable!(),
                    },
                });
            } else {
                match version {
                    1 => {
                        short_ids.push(ShortId::with_siphash_keys(&tx.compute_txid(), siphash_keys))
                    }
                    2 => short_ids
                        .push(ShortId::with_siphash_keys(&tx.compute_wtxid(), siphash_keys)),
                    _ => unreachable!(),
                }
            }
        }

        if !prefill.is_empty() {
            return Err(Error::InvalidPrefill);
        }

        Ok(HeaderAndShortIds {
            header: block.header,
            nonce,
            // Provide coinbase prefilled.
            prefilled_txs: prefilled,
            short_ids,
        })
    }
}

/// A [`BlockTransactionsRequest`] structure is used to list transaction indexes
/// in a block being requested.
#[derive(PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
pub struct BlockTransactionsRequest {
    ///  The blockhash of the block which the transactions being requested are in.
    pub block_hash: BlockHash,
    ///  The indexes of the transactions being requested in the block.
    ///
    ///  Warning: Encoding panics with [`u64::MAX`] values. See [`BlockTransactionsRequest::consensus_encode()`]
    pub indexes: Vec<u64>,
}

impl Encodable for BlockTransactionsRequest {
    /// # Panics
    ///
    /// Panics if the index overflows [`u64::MAX`]. This happens when [`BlockTransactionsRequest::indexes`]
    /// contains an entry with the value [`u64::MAX`] as `u64` overflows during differential encoding.
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = self.block_hash.consensus_encode(w)?;
        // Manually encode indexes because they are differentially encoded VarInts.
        len += VarInt(self.indexes.len().to_u64()).consensus_encode(w)?;
        let mut last_idx = 0;
        for idx in &self.indexes {
            len += VarInt(*idx - last_idx).consensus_encode(w)?;
            last_idx = *idx + 1; // can panic here
        }
        Ok(len)
    }
}

impl Decodable for BlockTransactionsRequest {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(BlockTransactionsRequest {
            block_hash: BlockHash::consensus_decode(r)?,
            indexes: {
                // Manually decode indexes because they are differentially encoded VarInts.
                let nb_indexes = VarInt::consensus_decode(r)?.0 as usize;

                // Since the number of indices ultimately represent transactions,
                // we can limit the number of indices to the maximum number of
                // transactions that would be allowed in a vector.
                let byte_size = (nb_indexes)
                    .checked_mul(mem::size_of::<Transaction>())
                    .ok_or(encode::Error::ParseFailed("invalid length"))?;
                if byte_size > encode::MAX_VEC_SIZE {
                    return Err(encode::Error::OversizedVectorAllocation {
                        requested: byte_size,
                        max: encode::MAX_VEC_SIZE,
                    });
                }

                let mut indexes = Vec::with_capacity(nb_indexes);
                let mut last_index: u64 = 0;
                for _ in 0..nb_indexes {
                    let differential: VarInt = Decodable::consensus_decode(r)?;
                    last_index = match last_index.checked_add(differential.0) {
                        Some(i) => i,
                        None => return Err(encode::Error::ParseFailed("block index overflow")),
                    };
                    indexes.push(last_index);
                    last_index = match last_index.checked_add(1) {
                        Some(i) => i,
                        None => return Err(encode::Error::ParseFailed("block index overflow")),
                    };
                }
                indexes
            },
        })
    }
}

/// A transaction index is requested that is out of range from the
/// corresponding block.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TxIndexOutOfRangeError(u64);

impl fmt::Display for TxIndexOutOfRangeError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "a transaction index is requested that is \
            out of range from the corresponding block: {}",
            self.0,
        )
    }
}

#[cfg(feature = "std")]
impl error::Error for TxIndexOutOfRangeError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

/// A [`BlockTransactions`] structure is used to provide some of the transactions
/// in a block, as requested.
#[derive(PartialEq, Eq, Clone, Debug, PartialOrd, Ord, Hash)]
pub struct BlockTransactions {
    ///  The blockhash of the block which the transactions being provided are in.
    pub block_hash: BlockHash,
    ///  The transactions provided.
    pub transactions: Vec<Transaction>,
}
impl_consensus_encoding!(BlockTransactions, block_hash, transactions);

impl BlockTransactions {
    /// Constructs a [`BlockTransactions`] from a [`BlockTransactionsRequest`] and
    /// the corresponding full [`Block`] by providing all requested transactions.
    pub fn from_request(
        request: &BlockTransactionsRequest,
        block: &Block,
    ) -> Result<BlockTransactions, TxIndexOutOfRangeError> {
        Ok(BlockTransactions {
            block_hash: request.block_hash,
            transactions: {
                let mut txs = Vec::with_capacity(request.indexes.len());
                for idx in &request.indexes {
                    if *idx >= block.txdata.len().to_u64() {
                        return Err(TxIndexOutOfRangeError(*idx));
                    }
                    txs.push(block.txdata[*idx as usize].clone());
                }
                txs
            },
        })
    }
}
