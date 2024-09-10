// SPDX-License-Identifier: CC0-1.0

//! Bitcoin keys.
//!
//! This module provides keys used in Bitcoin that can be roundtrip
//! (de)serialized.

use core::fmt::{self, Write as _};
use core::ops;
use core::str::FromStr;

use hashes::{hash160, Hash};
use hex::{FromHex, HexToArrayError};
use internals::array_vec::ArrayVec;
use internals::write_err;
use io::{Read, Write};

use crate::blockdata::script::ScriptBuf;
use crate::crypto::ecdsa;
use crate::internal_macros::impl_asref_push_bytes;
use crate::network::NetworkKind;
use crate::prelude::*;
use crate::taproot::{TapNodeHash, TapTweakHash};

#[rustfmt::skip]                // Keep public re-exports separate.
pub use secp256k1::{constants, Keypair, Parity, Secp256k1, Verification, XOnlyPublicKey};

#[cfg(feature = "rand-std")]
pub use secp256k1::rand;

/// A Bitcoin ECDSA public key
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PublicKey {
    /// Whether this public key should be serialized as compressed
    pub compressed: bool,
    /// The actual ECDSA key
    pub inner: secp256k1::PublicKey,
}

impl PublicKey {
    /// Constructs compressed ECDSA public key from the provided generic Secp256k1 public key
    pub fn new(key: impl Into<secp256k1::PublicKey>) -> PublicKey {
        PublicKey {
            compressed: true,
            inner: key.into(),
        }
    }

    /// Constructs uncompressed (legacy) ECDSA public key from the provided generic Secp256k1
    /// public key
    pub fn new_uncompressed(key: impl Into<secp256k1::PublicKey>) -> PublicKey {
        PublicKey {
            compressed: false,
            inner: key.into(),
        }
    }

    fn with_serialized<R, F: FnOnce(&[u8]) -> R>(&self, f: F) -> R {
        if self.compressed {
            f(&self.inner.serialize())
        } else {
            f(&self.inner.serialize_uncompressed())
        }
    }

    /// Returns bitcoin 160-bit hash of the public key
    pub fn pubkey_hash(&self) -> PubkeyHash {
        self.with_serialized(PubkeyHash::hash)
    }

    /// Returns bitcoin 160-bit hash of the public key for witness program
    pub fn wpubkey_hash(&self) -> Result<WPubkeyHash, UncompressedPublicKeyError> {
        if self.compressed {
            Ok(WPubkeyHash::from_byte_array(
                hash160::Hash::hash(&self.inner.serialize()).to_byte_array(),
            ))
        } else {
            Err(UncompressedPublicKeyError)
        }
    }

    /// Returns the script code used to spend a P2WPKH input.
    pub fn p2wpkh_script_code(&self) -> Result<ScriptBuf, UncompressedPublicKeyError> {
        let key = CompressedPublicKey::try_from(*self)?;
        Ok(key.p2wpkh_script_code())
    }

    /// Write the public key into a writer
    pub fn write_into<W: Write + ?Sized>(&self, writer: &mut W) -> Result<(), io::Error> {
        self.with_serialized(|bytes| writer.write_all(bytes))
    }

    /// Read the public key from a reader
    ///
    /// This internally reads the first byte before reading the rest, so
    /// use of a `BufReader` is recommended.
    pub fn read_from<R: Read + ?Sized>(reader: &mut R) -> Result<Self, io::Error> {
        let mut bytes = [0; 65];

        reader.read_exact(&mut bytes[0..1])?;
        let bytes = if bytes[0] < 4 {
            &mut bytes[..33]
        } else {
            &mut bytes[..65]
        };

        reader.read_exact(&mut bytes[1..])?;
        Self::from_slice(bytes).map_err(|e| {
            // Need a static string for no-std io
            #[cfg(feature = "std")]
            let reason = e;
            #[cfg(not(feature = "std"))]
            let reason = match e {
                FromSliceError::Secp256k1(_) => "secp256k1 error",
                FromSliceError::InvalidKeyPrefix(_) => "invalid key prefix",
                FromSliceError::InvalidLength(_) => "invalid length",
            };
            io::Error::new(io::ErrorKind::InvalidData, reason)
        })
    }

    /// Serialize the public key to bytes
    pub fn to_bytes(self) -> Vec<u8> {
        let mut buf = Vec::new();
        self.write_into(&mut buf).expect("vecs don't error");
        buf
    }

    /// Serialize the public key into a `SortKey`.
    ///
    /// `SortKey` is not too useful by itself, but it can be used to sort a
    /// `[PublicKey]` slice using `sort_unstable_by_key`, `sort_by_cached_key`,
    /// `sort_by_key`, or any of the other `*_by_key` methods on slice.
    /// Pass the method into the sort method directly. (ie. `PublicKey::to_sort_key`)
    ///
    /// This method of sorting is in line with Bitcoin Core's implementation of
    /// sorting keys for output descriptors such as `sortedmulti()`.
    ///
    /// If every `PublicKey` in the slice is `compressed == true` then this will sort
    /// the keys in a
    /// [BIP67](https://github.com/bitcoin/bips/blob/master/bip-0067.mediawiki)
    /// compliant way.
    ///
    /// # Example: Using with `sort_unstable_by_key`
    ///
    /// ```rust
    /// use std::str::FromStr;
    /// use bitcoin::PublicKey;
    ///
    /// let pk = |s| PublicKey::from_str(s).unwrap();
    ///
    /// let mut unsorted = [
    ///     pk("04c4b0bbb339aa236bff38dbe6a451e111972a7909a126bc424013cba2ec33bc38e98ac269ffe028345c31ac8d0a365f29c8f7e7cfccac72f84e1acd02bc554f35"),
    ///     pk("038f47dcd43ba6d97fc9ed2e3bba09b175a45fac55f0683e8cf771e8ced4572354"),
    ///     pk("028bde91b10013e08949a318018fedbd896534a549a278e220169ee2a36517c7aa"),
    ///     pk("04c4b0bbb339aa236bff38dbe6a451e111972a7909a126bc424013cba2ec33bc3816753d96001fd7cba3ce5372f5c9a0d63708183033538d07b1e532fc43aaacfa"),
    ///     pk("032b8324c93575034047a52e9bca05a46d8347046b91a032eff07d5de8d3f2730b"),
    ///     pk("045d753414fa292ea5b8f56e39cfb6a0287b2546231a5cb05c4b14ab4b463d171f5128148985b23eccb1e2905374873b1f09b9487f47afa6b1f2b0083ac8b4f7e8"),
    ///     pk("0234dd69c56c36a41230d573d68adeae0030c9bc0bf26f24d3e1b64c604d293c68"),
    /// ];
    /// let sorted = [
    ///     // These first 4 keys are in a BIP67 compatible sorted order
    ///     // (since they are compressed)
    ///     pk("0234dd69c56c36a41230d573d68adeae0030c9bc0bf26f24d3e1b64c604d293c68"),
    ///     pk("028bde91b10013e08949a318018fedbd896534a549a278e220169ee2a36517c7aa"),
    ///     pk("032b8324c93575034047a52e9bca05a46d8347046b91a032eff07d5de8d3f2730b"),
    ///     pk("038f47dcd43ba6d97fc9ed2e3bba09b175a45fac55f0683e8cf771e8ced4572354"),
    ///     // Uncompressed keys are not BIP67 compliant, but are sorted
    ///     // after compressed keys in Bitcoin Core using `sortedmulti()`
    ///     pk("045d753414fa292ea5b8f56e39cfb6a0287b2546231a5cb05c4b14ab4b463d171f5128148985b23eccb1e2905374873b1f09b9487f47afa6b1f2b0083ac8b4f7e8"),
    ///     pk("04c4b0bbb339aa236bff38dbe6a451e111972a7909a126bc424013cba2ec33bc3816753d96001fd7cba3ce5372f5c9a0d63708183033538d07b1e532fc43aaacfa"),
    ///     pk("04c4b0bbb339aa236bff38dbe6a451e111972a7909a126bc424013cba2ec33bc38e98ac269ffe028345c31ac8d0a365f29c8f7e7cfccac72f84e1acd02bc554f35"),
    /// ];
    ///
    /// unsorted.sort_unstable_by_key(|k| PublicKey::to_sort_key(*k));
    ///
    /// assert_eq!(unsorted, sorted);
    /// ```
    pub fn to_sort_key(self) -> SortKey {
        if self.compressed {
            let buf = ArrayVec::from_slice(&self.inner.serialize());
            SortKey(buf)
        } else {
            let buf = ArrayVec::from_slice(&self.inner.serialize_uncompressed());
            SortKey(buf)
        }
    }

    /// Deserialize a public key from a slice
    pub fn from_slice(data: &[u8]) -> Result<PublicKey, FromSliceError> {
        let compressed = match data.len() {
            33 => true,
            65 => false,
            len => {
                return Err(FromSliceError::InvalidLength(len));
            }
        };

        if !compressed && data[0] != 0x04 {
            return Err(FromSliceError::InvalidKeyPrefix(data[0]));
        }

        Ok(PublicKey {
            compressed,
            inner: secp256k1::PublicKey::from_slice(data)?,
        })
    }

    /// Computes the public key as supposed to be used with this secret
    pub fn from_private_key<C: secp256k1::Signing>(
        secp: &Secp256k1<C>,
        sk: &PrivateKey,
    ) -> PublicKey {
        sk.public_key(secp)
    }

    /// Checks that `sig` is a valid ECDSA signature for `msg` using this public key.
    pub fn verify<C: secp256k1::Verification>(
        &self,
        secp: &Secp256k1<C>,
        msg: &secp256k1::Message,
        sig: &ecdsa::Signature,
    ) -> Result<(), secp256k1::Error> {
        secp.verify_ecdsa(msg, &sig.signature, &self.inner)
    }
}

impl From<secp256k1::PublicKey> for PublicKey {
    fn from(pk: secp256k1::PublicKey) -> PublicKey {
        PublicKey::new(pk)
    }
}

impl From<PublicKey> for XOnlyPublicKey {
    fn from(pk: PublicKey) -> XOnlyPublicKey {
        pk.inner.into()
    }
}

/// An opaque return type for PublicKey::to_sort_key
#[derive(Debug, Hash, PartialEq, Eq, PartialOrd, Ord, Clone, Copy)]
pub struct SortKey(ArrayVec<u8, 65>);

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.with_serialized(|bytes| fmt::Display::fmt(&bytes.as_hex(), f))
    }
}

impl FromStr for PublicKey {
    type Err = ParsePublicKeyError;
    fn from_str(s: &str) -> Result<PublicKey, ParsePublicKeyError> {
        use HexToArrayError::*;

        match s.len() {
            66 => {
                let bytes = <[u8; 33]>::from_hex(s).map_err(|e| match e {
                    InvalidChar(e) => ParsePublicKeyError::InvalidChar(e.invalid_char()),
                    InvalidLength(_) => unreachable!("length checked already"),
                })?;
                Ok(PublicKey::from_slice(&bytes)?)
            }
            130 => {
                let bytes = <[u8; 65]>::from_hex(s).map_err(|e| match e {
                    InvalidChar(e) => ParsePublicKeyError::InvalidChar(e.invalid_char()),
                    InvalidLength(_) => unreachable!("length checked already"),
                })?;
                Ok(PublicKey::from_slice(&bytes)?)
            }
            len => Err(ParsePublicKeyError::InvalidHexLength(len)),
        }
    }
}

hashes::hash_newtype! {
    /// A hash of a public key.
    pub struct PubkeyHash(hash160::Hash);
    /// SegWit version of a public key hash.
    pub struct WPubkeyHash(hash160::Hash);
}
impl_asref_push_bytes!(PubkeyHash, WPubkeyHash);

impl From<PublicKey> for PubkeyHash {
    fn from(key: PublicKey) -> PubkeyHash {
        key.pubkey_hash()
    }
}

impl From<&PublicKey> for PubkeyHash {
    fn from(key: &PublicKey) -> PubkeyHash {
        key.pubkey_hash()
    }
}

/// An always-compressed Bitcoin ECDSA public key
#[derive(Debug, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct CompressedPublicKey(pub secp256k1::PublicKey);

impl CompressedPublicKey {
    /// Returns bitcoin 160-bit hash of the public key
    pub fn pubkey_hash(&self) -> PubkeyHash {
        PubkeyHash::hash(&self.to_bytes())
    }

    /// Returns bitcoin 160-bit hash of the public key for witness program
    pub fn wpubkey_hash(&self) -> WPubkeyHash {
        WPubkeyHash::from_byte_array(hash160::Hash::hash(&self.to_bytes()).to_byte_array())
    }

    /// Returns the script code used to spend a P2WPKH input.
    pub fn p2wpkh_script_code(&self) -> ScriptBuf {
        ScriptBuf::p2wpkh_script_code(self.wpubkey_hash())
    }

    /// Write the public key into a writer
    pub fn write_into<W: io::Write + ?Sized>(&self, writer: &mut W) -> Result<(), io::Error> {
        writer.write_all(&self.to_bytes())
    }

    /// Read the public key from a reader
    ///
    /// This internally reads the first byte before reading the rest, so
    /// use of a `BufReader` is recommended.
    pub fn read_from<R: io::Read + ?Sized>(reader: &mut R) -> Result<Self, io::Error> {
        let mut bytes = [0; 33];

        reader.read_exact(&mut bytes)?;
        #[allow(unused_variables)] // e when std not enabled
        Self::from_slice(&bytes).map_err(|e| {
            // Need a static string for no-std io
            #[cfg(feature = "std")]
            let reason = e;
            #[cfg(not(feature = "std"))]
            let reason = "secp256k1 error";
            io::Error::new(io::ErrorKind::InvalidData, reason)
        })
    }

    /// Serializes the public key.
    ///
    /// As the type name suggests, the key is serialzied in compressed format.
    ///
    /// Note that this can be used as a sort key to get BIP67-compliant sorting.
    /// That's why this type doesn't have the `to_sort_key` method - it would duplicate this one.
    pub fn to_bytes(&self) -> [u8; 33] {
        self.0.serialize()
    }

    /// Deserialize a public key from a slice
    pub fn from_slice(data: &[u8]) -> Result<Self, secp256k1::Error> {
        secp256k1::PublicKey::from_slice(data).map(CompressedPublicKey)
    }

    /// Computes the public key as supposed to be used with this secret
    pub fn from_private_key<C: secp256k1::Signing>(
        secp: &Secp256k1<C>,
        sk: &PrivateKey,
    ) -> Result<Self, UncompressedPublicKeyError> {
        sk.public_key(secp).try_into()
    }

    /// Checks that `sig` is a valid ECDSA signature for `msg` using this public key.
    pub fn verify<C: secp256k1::Verification>(
        &self,
        secp: &Secp256k1<C>,
        msg: &secp256k1::Message,
        sig: &ecdsa::Signature,
    ) -> Result<(), secp256k1::Error> {
        Ok(secp.verify_ecdsa(msg, &sig.signature, &self.0)?)
    }
}

impl fmt::Display for CompressedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.to_bytes().as_hex(), f)
    }
}

impl FromStr for CompressedPublicKey {
    type Err = ParseCompressedPublicKeyError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        CompressedPublicKey::from_slice(&<[u8; 33]>::from_hex(s)?).map_err(Into::into)
    }
}

impl TryFrom<PublicKey> for CompressedPublicKey {
    type Error = UncompressedPublicKeyError;

    fn try_from(value: PublicKey) -> Result<Self, Self::Error> {
        if value.compressed {
            Ok(CompressedPublicKey(value.inner))
        } else {
            Err(UncompressedPublicKeyError)
        }
    }
}

impl From<CompressedPublicKey> for PublicKey {
    fn from(value: CompressedPublicKey) -> Self {
        PublicKey::new(value.0)
    }
}

impl From<CompressedPublicKey> for XOnlyPublicKey {
    fn from(pk: CompressedPublicKey) -> Self {
        pk.0.into()
    }
}

impl From<CompressedPublicKey> for PubkeyHash {
    fn from(key: CompressedPublicKey) -> Self {
        key.pubkey_hash()
    }
}

impl From<&CompressedPublicKey> for PubkeyHash {
    fn from(key: &CompressedPublicKey) -> Self {
        key.pubkey_hash()
    }
}

impl From<CompressedPublicKey> for WPubkeyHash {
    fn from(key: CompressedPublicKey) -> Self {
        key.wpubkey_hash()
    }
}

impl From<&CompressedPublicKey> for WPubkeyHash {
    fn from(key: &CompressedPublicKey) -> Self {
        key.wpubkey_hash()
    }
}

/// A Bitcoin ECDSA private key
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub struct PrivateKey {
    /// Whether this private key should be serialized as compressed
    pub compressed: bool,
    /// The network kind on which this key should be used
    pub network: NetworkKind,
    /// The actual ECDSA key
    pub inner: secp256k1::SecretKey,
}

impl PrivateKey {
    /// Constructs new compressed ECDSA private key using the secp256k1 algorithm and
    /// a secure random number generator.
    #[cfg(feature = "rand-std")]
    pub fn generate(network: impl Into<NetworkKind>) -> PrivateKey {
        let secret_key = secp256k1::SecretKey::new(&mut rand::thread_rng());
        PrivateKey::new(secret_key, network.into())
    }
    /// Constructs compressed ECDSA private key from the provided generic Secp256k1 private key
    /// and the specified network
    pub fn new(key: secp256k1::SecretKey, network: impl Into<NetworkKind>) -> PrivateKey {
        PrivateKey {
            compressed: true,
            network: network.into(),
            inner: key,
        }
    }

    /// Constructs uncompressed (legacy) ECDSA private key from the provided generic Secp256k1
    /// private key and the specified network
    pub fn new_uncompressed(
        key: secp256k1::SecretKey,
        network: impl Into<NetworkKind>,
    ) -> PrivateKey {
        PrivateKey {
            compressed: false,
            network: network.into(),
            inner: key,
        }
    }

    /// Creates a public key from this private key
    pub fn public_key<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>) -> PublicKey {
        PublicKey {
            compressed: self.compressed,
            inner: secp256k1::PublicKey::from_secret_key(secp, &self.inner),
        }
    }

    /// Serialize the private key to bytes
    pub fn to_bytes(self) -> Vec<u8> {
        self.inner[..].to_vec()
    }

    /// Deserialize a private key from a slice
    pub fn from_slice(
        data: &[u8],
        network: impl Into<NetworkKind>,
    ) -> Result<PrivateKey, secp256k1::Error> {
        Ok(PrivateKey::new(
            secp256k1::SecretKey::from_slice(data)?,
            network,
        ))
    }

    /// Format the private key to WIF format.
    #[rustfmt::skip]
    pub fn fmt_wif(&self, fmt: &mut dyn fmt::Write) -> fmt::Result {
        let mut ret = [0; 34];
        ret[0] = if self.network.is_mainnet() { 128 } else { 239 };

        ret[1..33].copy_from_slice(&self.inner[..]);
        let privkey = if self.compressed {
            ret[33] = 1;
            base58::encode_check(&ret[..])
        } else {
            base58::encode_check(&ret[..33])
        };
        fmt.write_str(&privkey)
    }

    /// Get WIF encoding of this private key.
    pub fn to_wif(self) -> String {
        let mut buf = String::new();
        buf.write_fmt(format_args!("{}", self)).unwrap();
        buf.shrink_to_fit();
        buf
    }

    /// Parse WIF encoded private key.
    pub fn from_wif(wif: &str) -> Result<PrivateKey, FromWifError> {
        let data = base58::decode_check(wif)?;

        let compressed = match data.len() {
            33 => false,
            34 => true,
            length => {
                return Err(InvalidBase58PayloadLengthError { length }.into());
            }
        };

        let network = match data[0] {
            128 => NetworkKind::Main,
            239 => NetworkKind::Test,
            invalid => {
                return Err(InvalidAddressVersionError { invalid }.into());
            }
        };

        Ok(PrivateKey {
            compressed,
            network,
            inner: secp256k1::SecretKey::from_slice(&data[1..33])?,
        })
    }
}

impl fmt::Display for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.fmt_wif(f)
    }
}

impl FromStr for PrivateKey {
    type Err = FromWifError;
    fn from_str(s: &str) -> Result<PrivateKey, FromWifError> {
        PrivateKey::from_wif(s)
    }
}

impl ops::Index<ops::RangeFull> for PrivateKey {
    type Output = [u8];
    fn index(&self, _: ops::RangeFull) -> &[u8] {
        &self.inner[..]
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for PrivateKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PrivateKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<PrivateKey, D::Error> {
        struct WifVisitor;

        impl<'de> serde::de::Visitor<'de> for WifVisitor {
            type Value = PrivateKey;

            fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                formatter.write_str("an ASCII WIF string")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if let Ok(s) = core::str::from_utf8(v) {
                    PrivateKey::from_str(s).map_err(E::custom)
                } else {
                    Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self))
                }
            }

            fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                PrivateKey::from_str(v).map_err(E::custom)
            }
        }

        d.deserialize_str(WifVisitor)
    }
}

#[cfg(feature = "serde")]
#[allow(clippy::collapsible_else_if)] // Aids readability.
impl serde::Serialize for PublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            self.with_serialized(|bytes| s.serialize_bytes(bytes))
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for PublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<PublicKey, D::Error> {
        if d.is_human_readable() {
            struct HexVisitor;

            impl<'de> serde::de::Visitor<'de> for HexVisitor {
                type Value = PublicKey;

                fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                    formatter.write_str("an ASCII hex string")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    if let Ok(hex) = core::str::from_utf8(v) {
                        PublicKey::from_str(hex).map_err(E::custom)
                    } else {
                        Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self))
                    }
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    PublicKey::from_str(v).map_err(E::custom)
                }
            }
            d.deserialize_str(HexVisitor)
        } else {
            struct BytesVisitor;

            impl<'de> serde::de::Visitor<'de> for BytesVisitor {
                type Value = PublicKey;

                fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                    formatter.write_str("a bytestring")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    PublicKey::from_slice(v).map_err(E::custom)
                }
            }

            d.deserialize_bytes(BytesVisitor)
        }
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for CompressedPublicKey {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.collect_str(self)
        } else {
            s.serialize_bytes(&self.to_bytes())
        }
    }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for CompressedPublicKey {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        if d.is_human_readable() {
            struct HexVisitor;

            impl<'de> serde::de::Visitor<'de> for HexVisitor {
                type Value = CompressedPublicKey;

                fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                    formatter.write_str("a 66 digits long ASCII hex string")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    if let Ok(hex) = core::str::from_utf8(v) {
                        CompressedPublicKey::from_str(hex).map_err(E::custom)
                    } else {
                        Err(E::invalid_value(::serde::de::Unexpected::Bytes(v), &self))
                    }
                }

                fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    CompressedPublicKey::from_str(v).map_err(E::custom)
                }
            }
            d.deserialize_str(HexVisitor)
        } else {
            struct BytesVisitor;

            impl<'de> serde::de::Visitor<'de> for BytesVisitor {
                type Value = CompressedPublicKey;

                fn expecting(&self, formatter: &mut core::fmt::Formatter) -> core::fmt::Result {
                    formatter.write_str("a bytestring")
                }

                fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
                where
                    E: serde::de::Error,
                {
                    CompressedPublicKey::from_slice(v).map_err(E::custom)
                }
            }

            d.deserialize_bytes(BytesVisitor)
        }
    }
}
/// Untweaked BIP-340 X-coord-only public key
pub type UntweakedPublicKey = XOnlyPublicKey;

/// Tweaked BIP-340 X-coord-only public key
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct TweakedPublicKey(XOnlyPublicKey);

impl fmt::LowerHex for TweakedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::LowerHex::fmt(&self.0, f)
    }
}

impl fmt::Display for TweakedPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Untweaked BIP-340 key pair
pub type UntweakedKeypair = Keypair;

/// Tweaked BIP-340 key pair
///
/// # Examples
/// ```
/// # #[cfg(feature = "rand-std")] {
/// # use bitcoin::key::{Keypair, TweakedKeypair, TweakedPublicKey};
/// # use bitcoin::secp256k1::{rand, Secp256k1};
/// # let secp = Secp256k1::new();
/// # let keypair = TweakedKeypair::dangerous_assume_tweaked(Keypair::new(&secp, &mut rand::thread_rng()));
/// // There are various conversion methods available to get a tweaked pubkey from a tweaked keypair.
/// let (_pk, _parity) = keypair.public_parts();
/// let _pk  = TweakedPublicKey::from_keypair(keypair);
/// let _pk = TweakedPublicKey::from(keypair);
/// # }
/// ```
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Debug)]
#[cfg_attr(feature = "serde", derive(Serialize, Deserialize))]
#[cfg_attr(feature = "serde", serde(crate = "actual_serde"))]
#[cfg_attr(feature = "serde", serde(transparent))]
pub struct TweakedKeypair(Keypair);

/// A trait for tweaking BIP340 key types (x-only public keys and key pairs).
pub trait TapTweak {
    /// Tweaked key type with optional auxiliary information
    type TweakedAux;
    /// Tweaked key type
    type TweakedKey;

    /// Tweaks an untweaked key with corresponding public key value and optional script tree merkle
    /// root. For the [`Keypair`] type this also tweaks the private key in the pair.
    ///
    /// This is done by using the equation Q = P + H(P|c)G, where
    ///  * Q is the tweaked public key
    ///  * P is the internal public key
    ///  * H is the hash function
    ///  * c is the commitment data
    ///  * G is the generator point
    ///
    /// # Returns
    /// The tweaked key and its parity.
    fn tap_tweak<C: Verification>(
        self,
        secp: &Secp256k1<C>,
        merkle_root: Option<TapNodeHash>,
    ) -> Self::TweakedAux;

    /// Directly converts an [`UntweakedPublicKey`] to a [`TweakedPublicKey`]
    ///
    /// This method is dangerous and can lead to loss of funds if used incorrectly.
    /// Specifically, in multi-party protocols a peer can provide a value that allows them to steal.
    fn dangerous_assume_tweaked(self) -> Self::TweakedKey;
}

impl TapTweak for UntweakedPublicKey {
    type TweakedAux = (TweakedPublicKey, Parity);
    type TweakedKey = TweakedPublicKey;

    /// Tweaks an untweaked public key with corresponding public key value and optional script tree
    /// merkle root.
    ///
    /// This is done by using the equation Q = P + H(P|c)G, where
    ///  * Q is the tweaked public key
    ///  * P is the internal public key
    ///  * H is the hash function
    ///  * c is the commitment data
    ///  * G is the generator point
    ///
    /// # Returns
    /// The tweaked key and its parity.
    fn tap_tweak<C: Verification>(
        self,
        secp: &Secp256k1<C>,
        merkle_root: Option<TapNodeHash>,
    ) -> (TweakedPublicKey, Parity) {
        let tweak = TapTweakHash::from_key_and_tweak(self, merkle_root).to_scalar();
        let (output_key, parity) = self.add_tweak(secp, &tweak).expect("Tap tweak failed");

        debug_assert!(self.tweak_add_check(secp, &output_key, parity, tweak));
        (TweakedPublicKey(output_key), parity)
    }

    fn dangerous_assume_tweaked(self) -> TweakedPublicKey {
        TweakedPublicKey(self)
    }
}

impl TapTweak for UntweakedKeypair {
    type TweakedAux = TweakedKeypair;
    type TweakedKey = TweakedKeypair;

    /// Tweaks private and public keys within an untweaked [`Keypair`] with corresponding public key
    /// value and optional script tree merkle root.
    ///
    /// This is done by tweaking private key within the pair using the equation q = p + H(P|c), where
    ///  * q is the tweaked private key
    ///  * p is the internal private key
    ///  * H is the hash function
    ///  * c is the commitment data
    /// The public key is generated from a private key by multiplying with generator point, Q = qG.
    ///
    /// # Returns
    /// The tweaked key and its parity.
    fn tap_tweak<C: Verification>(
        self,
        secp: &Secp256k1<C>,
        merkle_root: Option<TapNodeHash>,
    ) -> TweakedKeypair {
        let (pubkey, _parity) = XOnlyPublicKey::from_keypair(&self);
        let tweak = TapTweakHash::from_key_and_tweak(pubkey, merkle_root).to_scalar();
        let tweaked = self
            .add_xonly_tweak(secp, &tweak)
            .expect("Tap tweak failed");
        TweakedKeypair(tweaked)
    }

    fn dangerous_assume_tweaked(self) -> TweakedKeypair {
        TweakedKeypair(self)
    }
}

impl TweakedPublicKey {
    /// Returns the [`TweakedPublicKey`] for `keypair`.
    #[inline]
    pub fn from_keypair(keypair: TweakedKeypair) -> Self {
        let (xonly, _parity) = keypair.0.x_only_public_key();
        TweakedPublicKey(xonly)
    }

    /// Creates a new [`TweakedPublicKey`] from a [`XOnlyPublicKey`]. No tweak is applied, consider
    /// calling `tap_tweak` on an [`UntweakedPublicKey`] instead of using this constructor.
    ///
    /// This method is dangerous and can lead to loss of funds if used incorrectly.
    /// Specifically, in multi-party protocols a peer can provide a value that allows them to steal.
    #[inline]
    pub fn dangerous_assume_tweaked(key: XOnlyPublicKey) -> TweakedPublicKey {
        TweakedPublicKey(key)
    }

    /// Returns the underlying public key.
    pub fn to_inner(self) -> XOnlyPublicKey {
        self.0
    }

    /// Serialize the key as a byte-encoded pair of values. In compressed form
    /// the y-coordinate is represented by only a single bit, as x determines
    /// it up to one bit.
    #[inline]
    pub fn serialize(&self) -> [u8; constants::SCHNORR_PUBLIC_KEY_SIZE] {
        self.0.serialize()
    }
}

impl TweakedKeypair {
    /// Creates a new [`TweakedKeypair`] from a [`Keypair`]. No tweak is applied, consider
    /// calling `tap_tweak` on an [`UntweakedKeypair`] instead of using this constructor.
    ///
    /// This method is dangerous and can lead to loss of funds if used incorrectly.
    /// Specifically, in multi-party protocols a peer can provide a value that allows them to steal.
    #[inline]
    pub fn dangerous_assume_tweaked(pair: Keypair) -> TweakedKeypair {
        TweakedKeypair(pair)
    }

    /// Returns the underlying key pair.
    #[inline]
    pub fn to_inner(self) -> Keypair {
        self.0
    }

    /// Returns the [`TweakedPublicKey`] and its [`Parity`] for this [`TweakedKeypair`].
    #[inline]
    pub fn public_parts(&self) -> (TweakedPublicKey, Parity) {
        let (xonly, parity) = self.0.x_only_public_key();
        (TweakedPublicKey(xonly), parity)
    }
}

impl From<TweakedPublicKey> for XOnlyPublicKey {
    #[inline]
    fn from(pair: TweakedPublicKey) -> Self {
        pair.0
    }
}

impl From<TweakedKeypair> for Keypair {
    #[inline]
    fn from(pair: TweakedKeypair) -> Self {
        pair.0
    }
}

impl From<TweakedKeypair> for TweakedPublicKey {
    #[inline]
    fn from(pair: TweakedKeypair) -> Self {
        TweakedPublicKey::from_keypair(pair)
    }
}

/// Error returned while generating key from slice.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FromSliceError {
    /// Invalid key prefix error.
    InvalidKeyPrefix(u8),
    /// A Secp256k1 error.
    Secp256k1(secp256k1::Error),
    /// Invalid Length of the slice.
    InvalidLength(usize),
}

internals::impl_from_infallible!(FromSliceError);

impl fmt::Display for FromSliceError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use FromSliceError::*;

        match self {
            Secp256k1(e) => write_err!(f, "secp256k1"; e),
            InvalidKeyPrefix(b) => write!(f, "key prefix invalid: {}", b),
            InvalidLength(got) => write!(f, "slice length should be 33 or 65 bytes, got: {}", got),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FromSliceError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use FromSliceError::*;

        match *self {
            Secp256k1(ref e) => Some(e),
            InvalidKeyPrefix(_) | InvalidLength(_) => None,
        }
    }
}

impl From<secp256k1::Error> for FromSliceError {
    fn from(e: secp256k1::Error) -> Self {
        Self::Secp256k1(e)
    }
}

/// Error generated from WIF key format.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum FromWifError {
    /// A base58 decoding error.
    Base58(base58::Error),
    /// Base58 decoded data was an invalid length.
    InvalidBase58PayloadLength(InvalidBase58PayloadLengthError),
    /// Base58 decoded data contained an invalid address version byte.
    InvalidAddressVersion(InvalidAddressVersionError),
    /// A secp256k1 error.
    Secp256k1(secp256k1::Error),
}

internals::impl_from_infallible!(FromWifError);

impl fmt::Display for FromWifError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use FromWifError::*;

        match *self {
            Base58(ref e) => write_err!(f, "invalid base58"; e),
            InvalidBase58PayloadLength(ref e) => {
                write_err!(f, "decoded base58 data was an invalid length"; e)
            }
            InvalidAddressVersion(ref e) => {
                write_err!(f, "decoded base58 data contained an invalid address version btye"; e)
            }
            Secp256k1(ref e) => write_err!(f, "private key validation failed"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for FromWifError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use FromWifError::*;

        match *self {
            Base58(ref e) => Some(e),
            InvalidBase58PayloadLength(ref e) => Some(e),
            InvalidAddressVersion(ref e) => Some(e),
            Secp256k1(ref e) => Some(e),
        }
    }
}

impl From<base58::Error> for FromWifError {
    fn from(e: base58::Error) -> Self {
        Self::Base58(e)
    }
}

impl From<secp256k1::Error> for FromWifError {
    fn from(e: secp256k1::Error) -> Self {
        Self::Secp256k1(e)
    }
}

impl From<InvalidBase58PayloadLengthError> for FromWifError {
    fn from(e: InvalidBase58PayloadLengthError) -> FromWifError {
        Self::InvalidBase58PayloadLength(e)
    }
}

impl From<InvalidAddressVersionError> for FromWifError {
    fn from(e: InvalidAddressVersionError) -> FromWifError {
        Self::InvalidAddressVersion(e)
    }
}

/// Error returned while constructing public key from string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParsePublicKeyError {
    /// Error originated while parsing string.
    Encoding(FromSliceError),
    /// Hex decoding error.
    InvalidChar(u8),
    /// `PublicKey` hex should be 66 or 130 digits long.
    InvalidHexLength(usize),
}

internals::impl_from_infallible!(ParsePublicKeyError);

impl fmt::Display for ParsePublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ParsePublicKeyError::*;
        match self {
            Encoding(e) => write_err!(f, "string error"; e),
            InvalidChar(char) => write!(f, "hex error {}", char),
            InvalidHexLength(got) => write!(
                f,
                "pubkey string should be 66 or 130 digits long, got: {}",
                got
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParsePublicKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ParsePublicKeyError::*;

        match self {
            Encoding(e) => Some(e),
            InvalidChar(_) | InvalidHexLength(_) => None,
        }
    }
}

impl From<FromSliceError> for ParsePublicKeyError {
    fn from(e: FromSliceError) -> Self {
        Self::Encoding(e)
    }
}

/// Error returned when parsing a [`CompressedPublicKey`] from a string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ParseCompressedPublicKeyError {
    /// Secp256k1 Error.
    Secp256k1(secp256k1::Error),
    /// hex to array conversion error.
    Hex(hex::HexToArrayError),
}

internals::impl_from_infallible!(ParseCompressedPublicKeyError);

impl fmt::Display for ParseCompressedPublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use ParseCompressedPublicKeyError::*;
        match self {
            Secp256k1(e) => write_err!(f, "secp256k1 error"; e),
            Hex(e) => write_err!(f, "invalid hex"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for ParseCompressedPublicKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use ParseCompressedPublicKeyError::*;

        match self {
            Secp256k1(e) => Some(e),
            Hex(e) => Some(e),
        }
    }
}

impl From<secp256k1::Error> for ParseCompressedPublicKeyError {
    fn from(e: secp256k1::Error) -> Self {
        Self::Secp256k1(e)
    }
}

impl From<hex::HexToArrayError> for ParseCompressedPublicKeyError {
    fn from(e: hex::HexToArrayError) -> Self {
        Self::Hex(e)
    }
}

/// Segwit public keys must always be compressed.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct UncompressedPublicKeyError;

impl fmt::Display for UncompressedPublicKeyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.write_str("segwit public keys must always be compressed")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for UncompressedPublicKeyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        None
    }
}

/// Decoded base58 data was an invalid length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidBase58PayloadLengthError {
    /// The base58 payload length we got after decoding WIF string.
    pub(crate) length: usize,
}

impl InvalidBase58PayloadLengthError {
    /// Returns the invalid payload length.
    pub fn invalid_base58_payload_length(&self) -> usize {
        self.length
    }
}

impl fmt::Display for InvalidBase58PayloadLengthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "decoded base58 data was an invalid length: {} (expected 33 or 34)",
            self.length
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidBase58PayloadLengthError {}

/// Invalid address version in decoded base58 data.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidAddressVersionError {
    /// The invalid version.
    pub(crate) invalid: u8,
}

impl InvalidAddressVersionError {
    /// Returns the invalid version.
    pub fn invalid_address_version(&self) -> u8 {
        self.invalid
    }
}

impl fmt::Display for InvalidAddressVersionError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "invalid address version in decoded base58 data {}",
            self.invalid
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidAddressVersionError {}
