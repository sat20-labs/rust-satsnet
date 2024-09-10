// SPDX-License-Identifier: CC0-1.0

//! Bitcoin consensus-encodable types.
//!
//! This is basically a replacement of the `Encodable` trait which does
//! normalization of endianness etc., to ensure that the encoding matches
//! the network consensus encoding.
//!
//! Essentially, anything that must go on the _disk_ or _network_ must be
//! encoded using the `Encodable` trait, since this data must be the same for
//! all systems. Any data going to the _user_ e.g., over JSONRPC, should use the
//! ordinary `Encodable` trait. (This should also be the same across systems, of
//! course, but has some critical differences from the network format e.g.,
//! scripts come with an opcode decode, hashes are big-endian, numbers are
//! typically big-endian decimals, etc.)
//!

use core::{fmt, mem, u32};

use hashes::{sha256, sha256d, Hash};
use hex::error::{InvalidCharError, OddLengthStringError};
use internals::write_err;
use io::{BufRead, Cursor, Read, Write};

use crate::bip152::{PrefilledTransaction, ShortId};
use crate::bip158::{FilterHash, FilterHeader};
use crate::blockdata::block::{self, BlockHash, TxMerkleNode};
use crate::blockdata::transaction::{Transaction, TxIn, TxOut};
use crate::consensus::{DecodeError, IterReader};
#[cfg(feature = "std")]
use crate::p2p::{
    address::{AddrV2Message, Address},
    message_blockdata::Inventory,
};
use crate::prelude::*;
use crate::taproot::TapLeafHash;

/// Encoding error.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// And I/O error.
    Io(io::Error),
    /// Tried to allocate an oversized vector.
    OversizedVectorAllocation {
        /// The capacity requested.
        requested: usize,
        /// The maximum capacity.
        max: usize,
    },
    /// Checksum was invalid.
    InvalidChecksum {
        /// The expected checksum.
        expected: [u8; 4],
        /// The invalid checksum.
        actual: [u8; 4],
    },
    /// VarInt was encoded in a non-minimal way.
    NonMinimalVarInt,
    /// Parsing error.
    ParseFailed(&'static str),
    /// Unsupported Segwit flag.
    UnsupportedSegwitFlag(u8),
}

internals::impl_from_infallible!(Error);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            Io(ref e) => write_err!(f, "IO error"; e),
            OversizedVectorAllocation {
                requested: ref r,
                max: ref m,
            } => write!(
                f,
                "allocation of oversized vector: requested {}, maximum {}",
                r, m
            ),
            InvalidChecksum {
                expected: ref e,
                actual: ref a,
            } => write!(
                f,
                "invalid checksum: expected {:x}, actual {:x}",
                e.as_hex(),
                a.as_hex()
            ),
            NonMinimalVarInt => write!(f, "non-minimal varint"),
            ParseFailed(ref s) => write!(f, "parse failed: {}", s),
            UnsupportedSegwitFlag(ref swflag) => {
                write!(f, "unsupported segwit version: {}", swflag)
            }
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match self {
            Io(e) => Some(e),
            OversizedVectorAllocation { .. }
            | InvalidChecksum { .. }
            | NonMinimalVarInt
            | ParseFailed(_)
            | UnsupportedSegwitFlag(_) => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(error: io::Error) -> Self {
        Error::Io(error)
    }
}

/// Hex deserialization error.
#[derive(Debug)]
pub enum FromHexError {
    /// Purported hex string had odd length.
    OddLengthString(OddLengthStringError),
    /// Decoding error.
    Decode(DecodeError<InvalidCharError>),
}

impl fmt::Display for FromHexError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use FromHexError::*;

        match *self {
            OddLengthString(ref e) => {
                write_err!(f, "odd length, failed to create bytes from hex"; e)
            }
            Decode(ref e) => write_err!(f, "decoding error"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FromHexError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use FromHexError::*;

        match *self {
            OddLengthString(ref e) => Some(e),
            Decode(ref e) => Some(e),
        }
    }
}

impl From<OddLengthStringError> for FromHexError {
    #[inline]
    fn from(e: OddLengthStringError) -> Self {
        Self::OddLengthString(e)
    }
}

/// Encodes an object into a vector.
pub fn serialize<T: Encodable + ?Sized>(data: &T) -> Vec<u8> {
    let mut encoder = Vec::new();
    let len = data
        .consensus_encode(&mut encoder)
        .expect("in-memory writers don't error");
    debug_assert_eq!(len, encoder.len());
    encoder
}

/// Encodes an object into a hex-encoded string.
pub fn serialize_hex<T: Encodable + ?Sized>(data: &T) -> String {
    serialize(data).to_lower_hex_string()
}

/// Deserializes an object from a vector, will error if said deserialization
/// doesn't consume the entire vector.
pub fn deserialize<T: Decodable>(data: &[u8]) -> Result<T, Error> {
    let (rv, consumed) = deserialize_partial(data)?;

    // Fail if data are not consumed entirely.
    if consumed == data.len() {
        Ok(rv)
    } else {
        Err(Error::ParseFailed(
            "data not consumed entirely when explicitly deserializing",
        ))
    }
}

/// Deserialize any decodable type from a hex string, will error if said deserialization
/// doesn't consume the entire vector.
pub fn deserialize_hex<T: Decodable>(hex: &str) -> Result<T, FromHexError> {
    let iter = hex::HexSliceToBytesIter::new(hex)?;
    let reader = IterReader::new(iter);
    Ok(reader.decode().map_err(FromHexError::Decode)?)
}

/// Deserializes an object from a vector, but will not report an error if said deserialization
/// doesn't consume the entire vector.
pub fn deserialize_partial<T: Decodable>(data: &[u8]) -> Result<(T, usize), Error> {
    let mut decoder = Cursor::new(data);
    let rv = Decodable::consensus_decode_from_finite_reader(&mut decoder)?;
    let consumed = decoder.position() as usize;

    Ok((rv, consumed))
}

/// Extensions of `Write` to encode data as per Bitcoin consensus.
pub trait WriteExt: Write {
    /// Outputs a 64-bit unsigned integer.
    fn emit_u64(&mut self, v: u64) -> Result<(), io::Error>;
    /// Outputs a 32-bit unsigned integer.
    fn emit_u32(&mut self, v: u32) -> Result<(), io::Error>;
    /// Outputs a 16-bit unsigned integer.
    fn emit_u16(&mut self, v: u16) -> Result<(), io::Error>;
    /// Outputs an 8-bit unsigned integer.
    fn emit_u8(&mut self, v: u8) -> Result<(), io::Error>;

    /// Outputs a 64-bit signed integer.
    fn emit_i64(&mut self, v: i64) -> Result<(), io::Error>;
    /// Outputs a 32-bit signed integer.
    fn emit_i32(&mut self, v: i32) -> Result<(), io::Error>;
    /// Outputs a 16-bit signed integer.
    fn emit_i16(&mut self, v: i16) -> Result<(), io::Error>;
    /// Outputs an 8-bit signed integer.
    fn emit_i8(&mut self, v: i8) -> Result<(), io::Error>;

    /// Outputs a boolean.
    fn emit_bool(&mut self, v: bool) -> Result<(), io::Error>;

    /// Outputs a byte slice.
    fn emit_slice(&mut self, v: &[u8]) -> Result<(), io::Error>;
}

/// Extensions of `Read` to decode data as per Bitcoin consensus.
pub trait ReadExt: Read {
    /// Reads a 64-bit unsigned integer.
    fn read_u64(&mut self) -> Result<u64, Error>;
    /// Reads a 32-bit unsigned integer.
    fn read_u32(&mut self) -> Result<u32, Error>;
    /// Reads a 16-bit unsigned integer.
    fn read_u16(&mut self) -> Result<u16, Error>;
    /// Reads an 8-bit unsigned integer.
    fn read_u8(&mut self) -> Result<u8, Error>;

    /// Reads a 64-bit signed integer.
    fn read_i64(&mut self) -> Result<i64, Error>;
    /// Reads a 32-bit signed integer.
    fn read_i32(&mut self) -> Result<i32, Error>;
    /// Reads a 16-bit signed integer.
    fn read_i16(&mut self) -> Result<i16, Error>;
    /// Reads an 8-bit signed integer.
    fn read_i8(&mut self) -> Result<i8, Error>;

    /// Reads a boolean.
    fn read_bool(&mut self) -> Result<bool, Error>;

    /// Reads a byte slice.
    fn read_slice(&mut self, slice: &mut [u8]) -> Result<(), Error>;
}

macro_rules! encoder_fn {
    ($name:ident, $val_type:ty) => {
        #[inline]
        fn $name(&mut self, v: $val_type) -> core::result::Result<(), io::Error> {
            self.write_all(&v.to_le_bytes())
        }
    };
}

macro_rules! decoder_fn {
    ($name:ident, $val_type:ty, $byte_len: expr) => {
        #[inline]
        fn $name(&mut self) -> core::result::Result<$val_type, Error> {
            let mut val = [0; $byte_len];
            self.read_exact(&mut val[..]).map_err(Error::Io)?;
            Ok(<$val_type>::from_le_bytes(val))
        }
    };
}

impl<W: Write + ?Sized> WriteExt for W {
    encoder_fn!(emit_u64, u64);
    encoder_fn!(emit_u32, u32);
    encoder_fn!(emit_u16, u16);
    encoder_fn!(emit_i64, i64);
    encoder_fn!(emit_i32, i32);
    encoder_fn!(emit_i16, i16);

    #[inline]
    fn emit_i8(&mut self, v: i8) -> Result<(), io::Error> {
        self.write_all(&[v as u8])
    }
    #[inline]
    fn emit_u8(&mut self, v: u8) -> Result<(), io::Error> {
        self.write_all(&[v])
    }
    #[inline]
    fn emit_bool(&mut self, v: bool) -> Result<(), io::Error> {
        self.write_all(&[v as u8])
    }
    #[inline]
    fn emit_slice(&mut self, v: &[u8]) -> Result<(), io::Error> {
        self.write_all(v)
    }
}

impl<R: Read + ?Sized> ReadExt for R {
    decoder_fn!(read_u64, u64, 8);
    decoder_fn!(read_u32, u32, 4);
    decoder_fn!(read_u16, u16, 2);
    decoder_fn!(read_i64, i64, 8);
    decoder_fn!(read_i32, i32, 4);
    decoder_fn!(read_i16, i16, 2);

    #[inline]
    fn read_u8(&mut self) -> Result<u8, Error> {
        let mut slice = [0u8; 1];
        self.read_exact(&mut slice)?;
        Ok(slice[0])
    }
    #[inline]
    fn read_i8(&mut self) -> Result<i8, Error> {
        let mut slice = [0u8; 1];
        self.read_exact(&mut slice)?;
        Ok(slice[0] as i8)
    }
    #[inline]
    fn read_bool(&mut self) -> Result<bool, Error> {
        ReadExt::read_i8(self).map(|bit| bit != 0)
    }
    #[inline]
    fn read_slice(&mut self, slice: &mut [u8]) -> Result<(), Error> {
        self.read_exact(slice).map_err(Error::Io)
    }
}

/// Maximum size, in bytes, of a vector we are allowed to decode.
pub const MAX_VEC_SIZE: usize = 4_000_000;

/// Data which can be encoded in a consensus-consistent way.
pub trait Encodable {
    /// Encodes an object with a well-defined format.
    ///
    /// # Returns
    ///
    /// The number of bytes written on success. The only errors returned are errors propagated from
    /// the writer.
    fn consensus_encode<W: Write + ?Sized>(&self, writer: &mut W) -> Result<usize, io::Error>;
}

/// Data which can be encoded in a consensus-consistent way.
pub trait Decodable: Sized {
    /// Decode `Self` from a size-limited reader.
    ///
    /// Like `consensus_decode` but relies on the reader being limited in the amount of data it
    /// returns, e.g. by being wrapped in [`std::io::Take`].
    ///
    /// Failing to abide to this requirement might lead to memory exhaustion caused by malicious
    /// inputs.
    ///
    /// Users should default to `consensus_decode`, but when data to be decoded is already in a byte
    /// vector of a limited size, calling this function directly might be marginally faster (due to
    /// avoiding extra checks).
    ///
    /// ### Rules for trait implementations
    ///
    /// * Simple types that that have a fixed size (own and member fields), don't have to overwrite
    ///   this method, or be concern with it.
    /// * Types that deserialize using externally provided length should implement it:
    ///   * Make `consensus_decode` forward to `consensus_decode_bytes_from_finite_reader` with the
    ///     reader wrapped by `Take`. Failure to do so, without other forms of memory exhaustion
    ///     protection might lead to resource exhaustion vulnerability.
    ///   * Put a max cap on things like `Vec::with_capacity` to avoid oversized allocations, and
    ///     rely on the reader running out of data, and collections reallocating on a legitimately
    ///     oversized input data, instead of trying to enforce arbitrary length limits.
    /// * Types that contain other types that implement custom
    ///   `consensus_decode_from_finite_reader`, should also implement it applying same rules, and
    ///   in addition make sure to call `consensus_decode_from_finite_reader` on all members, to
    ///   avoid creating redundant `Take` wrappers. Failure to do so might result only in a tiny
    ///   performance hit.
    #[inline]
    fn consensus_decode_from_finite_reader<R: BufRead + ?Sized>(
        reader: &mut R,
    ) -> Result<Self, Error> {
        // This method is always strictly less general than, `consensus_decode`, so it's safe and
        // make sense to default to just calling it. This way most types, that don't care about
        // protecting against resource exhaustion due to malicious input, can just ignore it.
        Self::consensus_decode(reader)
    }

    /// Decode an object with a well-defined format.
    ///
    /// This is the method that should be implemented for a typical, fixed sized type
    /// implementing this trait. Default implementation is wrapping the reader
    /// in [`crate::io::Take`] to limit the input size to [`MAX_VEC_SIZE`], and forwards the call to
    /// [`Self::consensus_decode_from_finite_reader`], which is convenient
    /// for types that override [`Self::consensus_decode_from_finite_reader`]
    /// instead.
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(reader: &mut R) -> Result<Self, Error> {
        Self::consensus_decode_from_finite_reader(&mut reader.take(MAX_VEC_SIZE as u64))
    }
}

/// A variable-length unsigned integer.
#[derive(PartialEq, Eq, PartialOrd, Ord, Clone, Debug)]
pub struct VarInt(pub u64);

/// Data and a 4-byte checksum.
#[derive(PartialEq, Eq, Clone, Debug)]
pub struct CheckedData {
    data: Vec<u8>,
    checksum: [u8; 4],
}

impl CheckedData {
    /// Creates a new `CheckedData` computing the checksum of given data.
    pub fn new(data: Vec<u8>) -> Self {
        let checksum = sha2_checksum(&data);
        Self { data, checksum }
    }

    /// Returns a reference to the raw data without the checksum.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Returns the raw data without the checksum.
    pub fn into_data(self) -> Vec<u8> {
        self.data
    }

    /// Returns the checksum of the data.
    pub fn checksum(&self) -> [u8; 4] {
        self.checksum
    }
}

// Primitive types
macro_rules! impl_int_encodable {
    ($ty:ident, $meth_dec:ident, $meth_enc:ident) => {
        impl Decodable for $ty {
            #[inline]
            fn consensus_decode<R: BufRead + ?Sized>(
                r: &mut R,
            ) -> core::result::Result<Self, Error> {
                ReadExt::$meth_dec(r)
            }
        }
        impl Encodable for $ty {
            #[inline]
            fn consensus_encode<W: Write + ?Sized>(
                &self,
                w: &mut W,
            ) -> core::result::Result<usize, io::Error> {
                w.$meth_enc(*self)?;
                Ok(mem::size_of::<$ty>())
            }
        }
    };
}

impl_int_encodable!(u8, read_u8, emit_u8);
impl_int_encodable!(u16, read_u16, emit_u16);
impl_int_encodable!(u32, read_u32, emit_u32);
impl_int_encodable!(u64, read_u64, emit_u64);
impl_int_encodable!(i8, read_i8, emit_i8);
impl_int_encodable!(i16, read_i16, emit_i16);
impl_int_encodable!(i32, read_i32, emit_i32);
impl_int_encodable!(i64, read_i64, emit_i64);

#[allow(clippy::len_without_is_empty)] // VarInt has on concept of 'is_empty'.
impl VarInt {
    /// Returns the number of bytes this varint contributes to a transaction size.
    ///
    /// Returns 1 for 0..=0xFC, 3 for 0xFD..=(2^16-1), 5 for 0x10000..=(2^32-1), and 9 otherwise.
    #[inline]
    pub const fn size(&self) -> usize {
        match self.0 {
            0..=0xFC => 1,
            0xFD..=0xFFFF => 3,
            0x10000..=0xFFFFFFFF => 5,
            _ => 9,
        }
    }
}

/// Implements `From<T> for VarInt`.
///
/// `VarInt`s are consensus encoded as `u64`s so we store them as such. Casting from any integer size smaller than or equal to `u64` is always safe and the cast value is correctly handled by `consensus_encode`.
macro_rules! impl_var_int_from {
    ($($ty:tt),*) => {
        $(
            /// Creates a `VarInt` from a `usize` by casting the to a `u64`.
            impl From<$ty> for VarInt {
                fn from(x: $ty) -> Self { VarInt(x as u64) }
            }
        )*
    }
}
impl_var_int_from!(u8, u16, u32, u64, usize);

impl Encodable for VarInt {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        match self.0 {
            0..=0xFC => {
                (self.0 as u8).consensus_encode(w)?;
                Ok(1)
            }
            0xFD..=0xFFFF => {
                w.emit_u8(0xFD)?;
                (self.0 as u16).consensus_encode(w)?;
                Ok(3)
            }
            0x10000..=0xFFFFFFFF => {
                w.emit_u8(0xFE)?;
                (self.0 as u32).consensus_encode(w)?;
                Ok(5)
            }
            _ => {
                w.emit_u8(0xFF)?;
                self.0.consensus_encode(w)?;
                Ok(9)
            }
        }
    }
}

impl Decodable for VarInt {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, Error> {
        let n = ReadExt::read_u8(r)?;
        match n {
            0xFF => {
                let x = ReadExt::read_u64(r)?;
                if x < 0x100000000 {
                    Err(self::Error::NonMinimalVarInt)
                } else {
                    Ok(VarInt::from(x))
                }
            }
            0xFE => {
                let x = ReadExt::read_u32(r)?;
                if x < 0x10000 {
                    Err(self::Error::NonMinimalVarInt)
                } else {
                    Ok(VarInt::from(x))
                }
            }
            0xFD => {
                let x = ReadExt::read_u16(r)?;
                if x < 0xFD {
                    Err(self::Error::NonMinimalVarInt)
                } else {
                    Ok(VarInt::from(x))
                }
            }
            n => Ok(VarInt::from(n)),
        }
    }
}

impl Encodable for bool {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        w.emit_bool(*self)?;
        Ok(1)
    }
}

impl Decodable for bool {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<bool, Error> {
        ReadExt::read_bool(r)
    }
}

impl Encodable for String {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let b = self.as_bytes();
        let vi_len = VarInt(b.len() as u64).consensus_encode(w)?;
        w.emit_slice(b)?;
        Ok(vi_len + b.len())
    }
}

impl Decodable for String {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<String, Error> {
        String::from_utf8(Decodable::consensus_decode(r)?)
            .map_err(|_| self::Error::ParseFailed("String was not valid UTF8"))
    }
}

impl Encodable for Cow<'static, str> {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let b = self.as_bytes();
        let vi_len = VarInt(b.len() as u64).consensus_encode(w)?;
        w.emit_slice(b)?;
        Ok(vi_len + b.len())
    }
}

impl Decodable for Cow<'static, str> {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Cow<'static, str>, Error> {
        String::from_utf8(Decodable::consensus_decode(r)?)
            .map_err(|_| self::Error::ParseFailed("String was not valid UTF8"))
            .map(Cow::Owned)
    }
}

macro_rules! impl_array {
    ( $size:literal ) => {
        impl Encodable for [u8; $size] {
            #[inline]
            fn consensus_encode<W: WriteExt + ?Sized>(
                &self,
                w: &mut W,
            ) -> core::result::Result<usize, io::Error> {
                w.emit_slice(&self[..])?;
                Ok(self.len())
            }
        }

        impl Decodable for [u8; $size] {
            #[inline]
            fn consensus_decode<R: BufRead + ?Sized>(
                r: &mut R,
            ) -> core::result::Result<Self, Error> {
                let mut ret = [0; $size];
                r.read_slice(&mut ret)?;
                Ok(ret)
            }
        }
    };
}

impl_array!(2);
impl_array!(4);
impl_array!(6);
impl_array!(8);
impl_array!(10);
impl_array!(12);
impl_array!(16);
impl_array!(32);
impl_array!(33);

impl Decodable for [u16; 8] {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, Error> {
        let mut res = [0; 8];
        for item in &mut res {
            *item = Decodable::consensus_decode(r)?;
        }
        Ok(res)
    }
}

impl Encodable for [u16; 8] {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        for c in self.iter() {
            c.consensus_encode(w)?;
        }
        Ok(16)
    }
}

macro_rules! impl_vec {
    ($type: ty) => {
        impl Encodable for Vec<$type> {
            #[inline]
            fn consensus_encode<W: Write + ?Sized>(
                &self,
                w: &mut W,
            ) -> core::result::Result<usize, io::Error> {
                let mut len = 0;
                len += VarInt(self.len() as u64).consensus_encode(w)?;
                for c in self.iter() {
                    len += c.consensus_encode(w)?;
                }
                Ok(len)
            }
        }

        impl Decodable for Vec<$type> {
            #[inline]
            fn consensus_decode_from_finite_reader<R: BufRead + ?Sized>(
                r: &mut R,
            ) -> core::result::Result<Self, Error> {
                let len = VarInt::consensus_decode_from_finite_reader(r)?.0;
                // Do not allocate upfront more items than if the sequence of type
                // occupied roughly quarter a block. This should never be the case
                // for normal data, but even if that's not true - `push` will just
                // reallocate.
                // Note: OOM protection relies on reader eventually running out of
                // data to feed us.
                let max_capacity = MAX_VEC_SIZE / 4 / mem::size_of::<$type>();
                let mut ret = Vec::with_capacity(core::cmp::min(len as usize, max_capacity));
                for _ in 0..len {
                    ret.push(Decodable::consensus_decode_from_finite_reader(r)?);
                }
                Ok(ret)
            }
        }
    };
}
impl_vec!(BlockHash);
impl_vec!(block::Header);
impl_vec!(FilterHash);
impl_vec!(FilterHeader);
impl_vec!(TxMerkleNode);
impl_vec!(Transaction);
impl_vec!(TxOut);
impl_vec!(TxIn);
impl_vec!(Vec<u8>);
impl_vec!(u64);
impl_vec!(TapLeafHash);
impl_vec!(VarInt);
impl_vec!(ShortId);
impl_vec!(PrefilledTransaction);

#[cfg(feature = "std")]
impl_vec!(Inventory);
#[cfg(feature = "std")]
impl_vec!((u32, Address));
#[cfg(feature = "std")]
impl_vec!(AddrV2Message);

pub(crate) fn consensus_encode_with_size<W: Write + ?Sized>(
    data: &[u8],
    w: &mut W,
) -> Result<usize, io::Error> {
    let vi_len = VarInt(data.len() as u64).consensus_encode(w)?;
    w.emit_slice(data)?;
    Ok(vi_len + data.len())
}

struct ReadBytesFromFiniteReaderOpts {
    len: usize,
    chunk_size: usize,
}

/// Read `opts.len` bytes from reader, where `opts.len` could potentially be malicious.
///
/// This function relies on reader being bound in amount of data
/// it returns for OOM protection. See [`Decodable::consensus_decode_from_finite_reader`].
#[inline]
fn read_bytes_from_finite_reader<D: Read + ?Sized>(
    d: &mut D,
    mut opts: ReadBytesFromFiniteReaderOpts,
) -> Result<Vec<u8>, Error> {
    let mut ret = vec![];

    assert_ne!(opts.chunk_size, 0);

    while opts.len > 0 {
        let chunk_start = ret.len();
        let chunk_size = core::cmp::min(opts.len, opts.chunk_size);
        let chunk_end = chunk_start + chunk_size;
        ret.resize(chunk_end, 0u8);
        d.read_slice(&mut ret[chunk_start..chunk_end])?;
        opts.len -= chunk_size;
    }

    Ok(ret)
}

impl Encodable for Vec<u8> {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        consensus_encode_with_size(self, w)
    }
}

impl Decodable for Vec<u8> {
    #[inline]
    fn consensus_decode_from_finite_reader<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, Error> {
        let len = VarInt::consensus_decode(r)?.0 as usize;
        // most real-world vec of bytes data, wouldn't be larger than 128KiB
        let opts = ReadBytesFromFiniteReaderOpts {
            len,
            chunk_size: 128 * 1024,
        };
        read_bytes_from_finite_reader(r, opts)
    }
}

impl Encodable for Box<[u8]> {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        consensus_encode_with_size(self, w)
    }
}

impl Decodable for Box<[u8]> {
    #[inline]
    fn consensus_decode_from_finite_reader<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, Error> {
        <Vec<u8>>::consensus_decode_from_finite_reader(r).map(From::from)
    }
}

/// Does a double-SHA256 on `data` and returns the first 4 bytes.
fn sha2_checksum(data: &[u8]) -> [u8; 4] {
    let checksum = <sha256d::Hash as Hash>::hash(data);
    [checksum[0], checksum[1], checksum[2], checksum[3]]
}

impl Encodable for CheckedData {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        u32::try_from(self.data.len())
            .expect("network message use u32 as length")
            .consensus_encode(w)?;
        self.checksum().consensus_encode(w)?;
        w.emit_slice(&self.data)?;
        Ok(8 + self.data.len())
    }
}

impl Decodable for CheckedData {
    #[inline]
    fn consensus_decode_from_finite_reader<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, Error> {
        let len = u32::consensus_decode_from_finite_reader(r)? as usize;

        let checksum = <[u8; 4]>::consensus_decode_from_finite_reader(r)?;
        let opts = ReadBytesFromFiniteReaderOpts {
            len,
            chunk_size: MAX_VEC_SIZE,
        };
        let data = read_bytes_from_finite_reader(r, opts)?;
        let expected_checksum = sha2_checksum(&data);
        if expected_checksum != checksum {
            Err(self::Error::InvalidChecksum {
                expected: expected_checksum,
                actual: checksum,
            })
        } else {
            Ok(CheckedData { data, checksum })
        }
    }
}

impl<'a, T: Encodable> Encodable for &'a T {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        (**self).consensus_encode(w)
    }
}

impl<'a, T: Encodable> Encodable for &'a mut T {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        (**self).consensus_encode(w)
    }
}

impl<T: Encodable> Encodable for rc::Rc<T> {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        (**self).consensus_encode(w)
    }
}

/// Note: This will fail to compile on old Rust for targets that don't support atomics
#[cfg(any(not(rust_v_1_60), target_has_atomic = "ptr"))]
impl<T: Encodable> Encodable for sync::Arc<T> {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        (**self).consensus_encode(w)
    }
}

macro_rules! tuple_encode {
    ($($x:ident),*) => {
        impl <$($x: Encodable),*> Encodable for ($($x),*) {
            #[inline]
            #[allow(non_snake_case)]
            fn consensus_encode<W: Write + ?Sized>(
                &self,
                w: &mut W,
            ) -> core::result::Result<usize, io::Error> {
                let &($(ref $x),*) = self;
                let mut len = 0;
                $(len += $x.consensus_encode(w)?;)*
                Ok(len)
            }
        }

        impl<$($x: Decodable),*> Decodable for ($($x),*) {
            #[inline]
            #[allow(non_snake_case)]
            fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> core::result::Result<Self, Error> {
                Ok(($({let $x = Decodable::consensus_decode(r)?; $x }),*))
            }
        }
    };
}

tuple_encode!(T0, T1);
tuple_encode!(T0, T1, T2);
tuple_encode!(T0, T1, T2, T3);
tuple_encode!(T0, T1, T2, T3, T4);
tuple_encode!(T0, T1, T2, T3, T4, T5);
tuple_encode!(T0, T1, T2, T3, T4, T5, T6);
tuple_encode!(T0, T1, T2, T3, T4, T5, T6, T7);

impl Encodable for sha256d::Hash {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.as_byte_array().consensus_encode(w)
    }
}

impl Decodable for sha256d::Hash {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, Error> {
        Ok(Self::from_byte_array(
            <<Self as Hash>::Bytes>::consensus_decode(r)?,
        ))
    }
}

impl Encodable for sha256::Hash {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.as_byte_array().consensus_encode(w)
    }
}

impl Decodable for sha256::Hash {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, Error> {
        Ok(Self::from_byte_array(
            <<Self as Hash>::Bytes>::consensus_decode(r)?,
        ))
    }
}

impl Encodable for TapLeafHash {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.as_byte_array().consensus_encode(w)
    }
}

impl Decodable for TapLeafHash {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, Error> {
        Ok(Self::from_byte_array(
            <<Self as Hash>::Bytes>::consensus_decode(r)?,
        ))
    }
}
