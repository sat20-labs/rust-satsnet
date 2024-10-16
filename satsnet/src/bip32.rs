// SPDX-License-Identifier: CC0-1.0

//! BIP32 implementation.
//!
//! Implementation of BIP32 hierarchical deterministic wallets, as defined
//! at <https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki>.
//!

use core::ops::Index;
use core::str::FromStr;
use core::{fmt, slice};

use hashes::{hash160, hash_newtype, sha512, Hash, HashEngine, Hmac, HmacEngine};
use internals::{impl_array_newtype, write_err};
use io::Write;
use secp256k1::{Secp256k1, XOnlyPublicKey};

use crate::crypto::key::{CompressedPublicKey, Keypair, PrivateKey};
use crate::internal_macros::impl_bytes_newtype;
use crate::network::NetworkKind;
use crate::prelude::*;

/// Version bytes for extended public keys on the Bitcoin network.
const VERSION_BYTES_MAINNET_PUBLIC: [u8; 4] = [0x04, 0x88, 0xB2, 0x1E];
/// Version bytes for extended private keys on the Bitcoin network.
const VERSION_BYTES_MAINNET_PRIVATE: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4];
/// Version bytes for extended public keys on any of the testnet networks.
const VERSION_BYTES_TESTNETS_PUBLIC: [u8; 4] = [0x04, 0x35, 0x87, 0xCF];
/// Version bytes for extended private keys on any of the testnet networks.
const VERSION_BYTES_TESTNETS_PRIVATE: [u8; 4] = [0x04, 0x35, 0x83, 0x94];

/// The old name for xpub, extended public key.
#[deprecated(since = "0.31.0", note = "use xpub instead")]
pub type ExtendedPubKey = Xpub;

/// The old name for xpub, extended public key (with a released typo in it).
#[deprecated(since = "0.31.0", note = "use xpub instead")]
pub type ExtendendPubKey = Xpub;

/// The old name for xpriv, extended public key.
#[deprecated(since = "0.31.0", note = "use xpriv instead")]
pub type ExtendedPrivKey = Xpriv;

/// The old name for xpriv, extended public key (with a released typo in it).
#[deprecated(since = "0.31.0", note = "use xpriv instead")]
pub type ExtendendPrivKey = Xpriv;

/// A chain code
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ChainCode([u8; 32]);
impl_array_newtype!(ChainCode, u8, 32);
impl_bytes_newtype!(ChainCode, 32);

impl ChainCode {
    fn from_hmac(hmac: Hmac<sha512::Hash>) -> Self {
        hmac[32..].try_into().expect("half of hmac is guaranteed to be 32 bytes")
    }
}

/// A fingerprint
#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Fingerprint([u8; 4]);
impl_array_newtype!(Fingerprint, u8, 4);
impl_bytes_newtype!(Fingerprint, 4);

hash_newtype! {
    /// Extended key identifier as defined in BIP-32.
    pub struct XKeyIdentifier(hash160::Hash);
}

/// Extended private key
#[derive(Copy, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct Xpriv {
    /// The network this key is to be used on
    pub network: NetworkKind,
    /// How many derivations this key is from the master (which is 0)
    pub depth: u8,
    /// Fingerprint of the parent key (0 for master)
    pub parent_fingerprint: Fingerprint,
    /// Child number of the key used to derive from parent (0 for master)
    pub child_number: ChildNumber,
    /// Private key
    pub private_key: secp256k1::SecretKey,
    /// Chain code
    pub chain_code: ChainCode,
}
#[cfg(feature = "serde")]
crate::serde_utils::serde_string_impl!(Xpriv, "a BIP-32 extended private key");

#[cfg(not(feature = "std"))]
impl fmt::Debug for Xpriv {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        f.debug_struct("Xpriv")
            .field("network", &self.network)
            .field("depth", &self.depth)
            .field("parent_fingerprint", &self.parent_fingerprint)
            .field("child_number", &self.child_number)
            .field("chain_code", &self.chain_code)
            .field("private_key", &"[SecretKey]")
            .finish()
    }
}

/// Extended public key
#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub struct Xpub {
    /// The network kind this key is to be used on
    pub network: NetworkKind,
    /// How many derivations this key is from the master (which is 0)
    pub depth: u8,
    /// Fingerprint of the parent key
    pub parent_fingerprint: Fingerprint,
    /// Child number of the key used to derive from parent (0 for master)
    pub child_number: ChildNumber,
    /// Public key
    pub public_key: secp256k1::PublicKey,
    /// Chain code
    pub chain_code: ChainCode,
}
#[cfg(feature = "serde")]
crate::serde_utils::serde_string_impl!(Xpub, "a BIP-32 extended public key");

/// A child number for a derived key
#[derive(Copy, Clone, PartialEq, Eq, Debug, PartialOrd, Ord, Hash)]
pub enum ChildNumber {
    /// Non-hardened key
    Normal {
        /// Key index, within [0, 2^31 - 1]
        index: u32,
    },
    /// Hardened key
    Hardened {
        /// Key index, within [0, 2^31 - 1]
        index: u32,
    },
}

impl ChildNumber {
    /// Create a [`Normal`] from an index, returns an error if the index is not within
    /// [0, 2^31 - 1].
    ///
    /// [`Normal`]: #variant.Normal
    pub fn from_normal_idx(index: u32) -> Result<Self, Error> {
        if index & (1 << 31) == 0 {
            Ok(ChildNumber::Normal { index })
        } else {
            Err(Error::InvalidChildNumber(index))
        }
    }

    /// Create a [`Hardened`] from an index, returns an error if the index is not within
    /// [0, 2^31 - 1].
    ///
    /// [`Hardened`]: #variant.Hardened
    pub fn from_hardened_idx(index: u32) -> Result<Self, Error> {
        if index & (1 << 31) == 0 {
            Ok(ChildNumber::Hardened { index })
        } else {
            Err(Error::InvalidChildNumber(index))
        }
    }

    /// Returns `true` if the child number is a [`Normal`] value.
    ///
    /// [`Normal`]: #variant.Normal
    pub fn is_normal(&self) -> bool { !self.is_hardened() }

    /// Returns `true` if the child number is a [`Hardened`] value.
    ///
    /// [`Hardened`]: #variant.Hardened
    pub fn is_hardened(&self) -> bool {
        match self {
            ChildNumber::Hardened { .. } => true,
            ChildNumber::Normal { .. } => false,
        }
    }

    /// Returns the child number that is a single increment from this one.
    pub fn increment(self) -> Result<ChildNumber, Error> {
        match self {
            ChildNumber::Normal { index: idx } => ChildNumber::from_normal_idx(idx + 1),
            ChildNumber::Hardened { index: idx } => ChildNumber::from_hardened_idx(idx + 1),
        }
    }
}

impl From<u32> for ChildNumber {
    fn from(number: u32) -> Self {
        if number & (1 << 31) != 0 {
            ChildNumber::Hardened { index: number ^ (1 << 31) }
        } else {
            ChildNumber::Normal { index: number }
        }
    }
}

impl From<ChildNumber> for u32 {
    fn from(cnum: ChildNumber) -> Self {
        match cnum {
            ChildNumber::Normal { index } => index,
            ChildNumber::Hardened { index } => index | (1 << 31),
        }
    }
}

impl fmt::Display for ChildNumber {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ChildNumber::Hardened { index } => {
                fmt::Display::fmt(&index, f)?;
                let alt = f.alternate();
                f.write_str(if alt { "h" } else { "'" })
            }
            ChildNumber::Normal { index } => fmt::Display::fmt(&index, f),
        }
    }
}

impl FromStr for ChildNumber {
    type Err = Error;

    fn from_str(inp: &str) -> Result<ChildNumber, Error> {
        let is_hardened = inp.chars().last().map_or(false, |l| l == '\'' || l == 'h');
        Ok(if is_hardened {
            ChildNumber::from_hardened_idx(
                inp[0..inp.len() - 1].parse().map_err(|_| Error::InvalidChildNumberFormat)?,
            )?
        } else {
            ChildNumber::from_normal_idx(inp.parse().map_err(|_| Error::InvalidChildNumberFormat)?)?
        })
    }
}

impl AsRef<[ChildNumber]> for ChildNumber {
    fn as_ref(&self) -> &[ChildNumber] { slice::from_ref(self) }
}

#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for ChildNumber {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        u32::deserialize(deserializer).map(ChildNumber::from)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for ChildNumber {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        u32::from(*self).serialize(serializer)
    }
}

/// Trait that allows possibly failable conversion from a type into a
/// derivation path
pub trait IntoDerivationPath {
    /// Converts a given type into a [`DerivationPath`] with possible error
    fn into_derivation_path(self) -> Result<DerivationPath, Error>;
}

/// A BIP-32 derivation path.
#[derive(Clone, PartialEq, Eq, Ord, PartialOrd, Hash)]
pub struct DerivationPath(Vec<ChildNumber>);

#[cfg(feature = "serde")]
crate::serde_utils::serde_string_impl!(DerivationPath, "a BIP-32 derivation path");

impl<I> Index<I> for DerivationPath
where
    Vec<ChildNumber>: Index<I>,
{
    type Output = <Vec<ChildNumber> as Index<I>>::Output;

    #[inline]
    fn index(&self, index: I) -> &Self::Output { &self.0[index] }
}

impl Default for DerivationPath {
    fn default() -> DerivationPath { DerivationPath::master() }
}

impl<T> IntoDerivationPath for T
where
    T: Into<DerivationPath>,
{
    fn into_derivation_path(self) -> Result<DerivationPath, Error> { Ok(self.into()) }
}

impl IntoDerivationPath for String {
    fn into_derivation_path(self) -> Result<DerivationPath, Error> { self.parse() }
}

impl<'a> IntoDerivationPath for &'a str {
    fn into_derivation_path(self) -> Result<DerivationPath, Error> { self.parse() }
}

impl From<Vec<ChildNumber>> for DerivationPath {
    fn from(numbers: Vec<ChildNumber>) -> Self { DerivationPath(numbers) }
}

impl From<DerivationPath> for Vec<ChildNumber> {
    fn from(path: DerivationPath) -> Self { path.0 }
}

impl<'a> From<&'a [ChildNumber]> for DerivationPath {
    fn from(numbers: &'a [ChildNumber]) -> Self { DerivationPath(numbers.to_vec()) }
}

impl core::iter::FromIterator<ChildNumber> for DerivationPath {
    fn from_iter<T>(iter: T) -> Self
    where
        T: IntoIterator<Item = ChildNumber>,
    {
        DerivationPath(Vec::from_iter(iter))
    }
}

impl<'a> core::iter::IntoIterator for &'a DerivationPath {
    type Item = &'a ChildNumber;
    type IntoIter = slice::Iter<'a, ChildNumber>;
    fn into_iter(self) -> Self::IntoIter { self.0.iter() }
}

impl AsRef<[ChildNumber]> for DerivationPath {
    fn as_ref(&self) -> &[ChildNumber] { &self.0 }
}

impl FromStr for DerivationPath {
    type Err = Error;

    fn from_str(path: &str) -> Result<DerivationPath, Error> {
        if path.is_empty() || path == "m" || path == "m/" {
            return Ok(vec![].into());
        }

        let path = path.strip_prefix("m/").unwrap_or(path);

        let parts = path.split('/');
        let ret: Result<Vec<ChildNumber>, Error> = parts.map(str::parse).collect();
        Ok(DerivationPath(ret?))
    }
}

/// An iterator over children of a [DerivationPath].
///
/// It is returned by the methods [DerivationPath::children_from],
/// [DerivationPath::normal_children] and [DerivationPath::hardened_children].
pub struct DerivationPathIterator<'a> {
    base: &'a DerivationPath,
    next_child: Option<ChildNumber>,
}

impl<'a> DerivationPathIterator<'a> {
    /// Start a new [DerivationPathIterator] at the given child.
    pub fn start_from(path: &'a DerivationPath, start: ChildNumber) -> DerivationPathIterator<'a> {
        DerivationPathIterator { base: path, next_child: Some(start) }
    }
}

impl<'a> Iterator for DerivationPathIterator<'a> {
    type Item = DerivationPath;

    fn next(&mut self) -> Option<Self::Item> {
        let ret = self.next_child?;
        self.next_child = ret.increment().ok();
        Some(self.base.child(ret))
    }
}

impl DerivationPath {
    /// Returns length of the derivation path
    pub fn len(&self) -> usize { self.0.len() }

    /// Returns `true` if the derivation path is empty
    pub fn is_empty(&self) -> bool { self.0.is_empty() }

    /// Returns derivation path for a master key (i.e. empty derivation path)
    pub fn master() -> DerivationPath { DerivationPath(vec![]) }

    /// Returns whether derivation path represents master key (i.e. it's length
    /// is empty). True for `m` path.
    pub fn is_master(&self) -> bool { self.0.is_empty() }

    /// Create a new [DerivationPath] that is a child of this one.
    pub fn child(&self, cn: ChildNumber) -> DerivationPath {
        let mut path = self.0.clone();
        path.push(cn);
        DerivationPath(path)
    }

    /// Convert into a [DerivationPath] that is a child of this one.
    pub fn into_child(self, cn: ChildNumber) -> DerivationPath {
        let mut path = self.0;
        path.push(cn);
        DerivationPath(path)
    }

    /// Get an [Iterator] over the children of this [DerivationPath]
    /// starting with the given [ChildNumber].
    pub fn children_from(&self, cn: ChildNumber) -> DerivationPathIterator {
        DerivationPathIterator::start_from(self, cn)
    }

    /// Get an [Iterator] over the unhardened children of this [DerivationPath].
    pub fn normal_children(&self) -> DerivationPathIterator {
        DerivationPathIterator::start_from(self, ChildNumber::Normal { index: 0 })
    }

    /// Get an [Iterator] over the hardened children of this [DerivationPath].
    pub fn hardened_children(&self) -> DerivationPathIterator {
        DerivationPathIterator::start_from(self, ChildNumber::Hardened { index: 0 })
    }

    /// Concatenate `self` with `path` and return the resulting new path.
    ///
    /// ```
    /// use bitcoin::bip32::{DerivationPath, ChildNumber};
    /// use std::str::FromStr;
    ///
    /// let base = DerivationPath::from_str("m/42").unwrap();
    ///
    /// let deriv_1 = base.extend(DerivationPath::from_str("0/1").unwrap());
    /// let deriv_2 = base.extend(&[
    ///     ChildNumber::from_normal_idx(0).unwrap(),
    ///     ChildNumber::from_normal_idx(1).unwrap()
    /// ]);
    ///
    /// assert_eq!(deriv_1, deriv_2);
    /// ```
    pub fn extend<T: AsRef<[ChildNumber]>>(&self, path: T) -> DerivationPath {
        let mut new_path = self.clone();
        new_path.0.extend_from_slice(path.as_ref());
        new_path
    }

    /// Returns the derivation path as a vector of u32 integers.
    /// Unhardened elements are copied as is.
    /// 0x80000000 is added to the hardened elements.
    ///
    /// ```
    /// use bitcoin::bip32::DerivationPath;
    /// use std::str::FromStr;
    ///
    /// let path = DerivationPath::from_str("m/84'/0'/0'/0/1").unwrap();
    /// const HARDENED: u32 = 0x80000000;
    /// assert_eq!(path.to_u32_vec(), vec![84 + HARDENED, HARDENED, HARDENED, 0, 1]);
    /// ```
    pub fn to_u32_vec(&self) -> Vec<u32> { self.into_iter().map(|&el| el.into()).collect() }
}

impl fmt::Display for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let mut iter = self.0.iter();
        if let Some(first_element) = iter.next() {
            write!(f, "{}", first_element)?;
        }
        for cn in iter {
            f.write_str("/")?;
            write!(f, "{}", cn)?;
        }
        Ok(())
    }
}

impl fmt::Debug for DerivationPath {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result { fmt::Display::fmt(&self, f) }
}

/// Full information on the used extended public key: fingerprint of the
/// master extended public key and a derivation path from it.
pub type KeySource = (Fingerprint, DerivationPath);

/// A BIP32 error
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A pk->pk derivation was attempted on a hardened key
    CannotDeriveFromHardenedKey,
    /// A secp256k1 error occurred
    Secp256k1(secp256k1::Error),
    /// A child number was provided that was out of range
    InvalidChildNumber(u32),
    /// Invalid childnumber format.
    InvalidChildNumberFormat,
    /// Invalid derivation path format.
    InvalidDerivationPathFormat,
    /// Unknown version magic bytes
    UnknownVersion([u8; 4]),
    /// Encoded extended key data has wrong length
    WrongExtendedKeyLength(usize),
    /// Base58 encoding error
    Base58(base58::Error),
    /// Hexadecimal decoding error
    Hex(hex::HexToArrayError),
    /// `PublicKey` hex should be 66 or 130 digits long.
    InvalidPublicKeyHexLength(usize),
    /// Base58 decoded data was an invalid length.
    InvalidBase58PayloadLength(InvalidBase58PayloadLengthError),
}

internals::impl_from_infallible!(Error);

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        use Error::*;

        match *self {
            CannotDeriveFromHardenedKey =>
                f.write_str("cannot derive hardened key from public key"),
            Secp256k1(ref e) => write_err!(f, "secp256k1 error"; e),
            InvalidChildNumber(ref n) =>
                write!(f, "child number {} is invalid (not within [0, 2^31 - 1])", n),
            InvalidChildNumberFormat => f.write_str("invalid child number format"),
            InvalidDerivationPathFormat => f.write_str("invalid derivation path format"),
            UnknownVersion(ref bytes) => write!(f, "unknown version magic bytes: {:?}", bytes),
            WrongExtendedKeyLength(ref len) =>
                write!(f, "encoded extended key data has wrong length {}", len),
            Base58(ref e) => write_err!(f, "base58 encoding error"; e),
            Hex(ref e) => write_err!(f, "Hexadecimal decoding error"; e),
            InvalidPublicKeyHexLength(got) =>
                write!(f, "PublicKey hex should be 66 or 130 digits long, got: {}", got),
            InvalidBase58PayloadLength(ref e) => write_err!(f, "base58 payload"; e),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        use Error::*;

        match *self {
            Secp256k1(ref e) => Some(e),
            Base58(ref e) => Some(e),
            Hex(ref e) => Some(e),
            InvalidBase58PayloadLength(ref e) => Some(e),
            CannotDeriveFromHardenedKey
            | InvalidChildNumber(_)
            | InvalidChildNumberFormat
            | InvalidDerivationPathFormat
            | UnknownVersion(_)
            | WrongExtendedKeyLength(_)
            | InvalidPublicKeyHexLength(_) => None,
        }
    }
}

impl From<secp256k1::Error> for Error {
    fn from(e: secp256k1::Error) -> Error { Error::Secp256k1(e) }
}

impl From<base58::Error> for Error {
    fn from(err: base58::Error) -> Self { Error::Base58(err) }
}

impl From<InvalidBase58PayloadLengthError> for Error {
    fn from(e: InvalidBase58PayloadLengthError) -> Error { Self::InvalidBase58PayloadLength(e) }
}

impl Xpriv {
    /// Construct a new master key from a seed value
    pub fn new_master(network: impl Into<NetworkKind>, seed: &[u8]) -> Result<Xpriv, Error> {
        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(b"Bitcoin seed");
        hmac_engine.input(seed);
        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

        Ok(Xpriv {
            network: network.into(),
            depth: 0,
            parent_fingerprint: Default::default(),
            child_number: ChildNumber::from_normal_idx(0)?,
            private_key: secp256k1::SecretKey::from_slice(&hmac_result[..32])?,
            chain_code: ChainCode::from_hmac(hmac_result),
        })
    }

    /// Constructs ECDSA compressed private key matching internal secret key representation.
    pub fn to_priv(self) -> PrivateKey {
        PrivateKey { compressed: true, network: self.network, inner: self.private_key }
    }

    /// Constructs BIP340 keypair for Schnorr signatures and Taproot use matching the internal
    /// secret key representation.
    pub fn to_keypair<C: secp256k1::Signing>(self, secp: &Secp256k1<C>) -> Keypair {
        Keypair::from_seckey_slice(secp, &self.private_key[..])
            .expect("BIP32 internal private key representation is broken")
    }

    /// Attempts to derive an extended private key from a path.
    ///
    /// The `path` argument can be both of type `DerivationPath` or `Vec<ChildNumber>`.
    pub fn derive_priv<C: secp256k1::Signing, P: AsRef<[ChildNumber]>>(
        &self,
        secp: &Secp256k1<C>,
        path: &P,
    ) -> Result<Xpriv, Error> {
        let mut sk: Xpriv = *self;
        for cnum in path.as_ref() {
            sk = sk.ckd_priv(secp, *cnum)?;
        }
        Ok(sk)
    }

    /// Private->Private child key derivation
    fn ckd_priv<C: secp256k1::Signing>(
        &self,
        secp: &Secp256k1<C>,
        i: ChildNumber,
    ) -> Result<Xpriv, Error> {
        let mut hmac_engine: HmacEngine<sha512::Hash> = HmacEngine::new(&self.chain_code[..]);
        match i {
            ChildNumber::Normal { .. } => {
                // Non-hardened key: compute public data and use that
                hmac_engine.input(
                    &secp256k1::PublicKey::from_secret_key(secp, &self.private_key).serialize()[..],
                );
            }
            ChildNumber::Hardened { .. } => {
                // Hardened key: use only secret data to prevent public derivation
                hmac_engine.input(&[0u8]);
                hmac_engine.input(&self.private_key[..]);
            }
        }

        hmac_engine.input(&u32::from(i).to_be_bytes());
        let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);
        let sk = secp256k1::SecretKey::from_slice(&hmac_result[..32])
            .expect("statistically impossible to hit");
        let tweaked =
            sk.add_tweak(&self.private_key.into()).expect("statistically impossible to hit");

        Ok(Xpriv {
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(secp),
            child_number: i,
            private_key: tweaked,
            chain_code: ChainCode::from_hmac(hmac_result),
        })
    }

    /// Decoding extended private key from binary data according to BIP 32
    pub fn decode(data: &[u8]) -> Result<Xpriv, Error> {
        if data.len() != 78 {
            return Err(Error::WrongExtendedKeyLength(data.len()));
        }

        let network = if data.starts_with(&VERSION_BYTES_MAINNET_PRIVATE) {
            NetworkKind::Main
        } else if data.starts_with(&VERSION_BYTES_TESTNETS_PRIVATE) {
            NetworkKind::Test
        } else {
            let (b0, b1, b2, b3) = (data[0], data[1], data[2], data[3]);
            return Err(Error::UnknownVersion([b0, b1, b2, b3]));
        };

        Ok(Xpriv {
            network,
            depth: data[4],
            parent_fingerprint: data[5..9]
                .try_into()
                .expect("9 - 5 == 4, which is the Fingerprint length"),
            child_number: u32::from_be_bytes(data[9..13].try_into().expect("4 byte slice")).into(),
            chain_code: data[13..45]
                .try_into()
                .expect("45 - 13 == 32, which is the ChainCode length"),
            private_key: secp256k1::SecretKey::from_slice(&data[46..78])?,
        })
    }

    /// Extended private key binary encoding according to BIP 32
    pub fn encode(&self) -> [u8; 78] {
        let mut ret = [0; 78];
        ret[0..4].copy_from_slice(&match self.network {
            NetworkKind::Main => VERSION_BYTES_MAINNET_PRIVATE,
            NetworkKind::Test => VERSION_BYTES_TESTNETS_PRIVATE,
        });
        ret[4] = self.depth;
        ret[5..9].copy_from_slice(&self.parent_fingerprint[..]);
        ret[9..13].copy_from_slice(&u32::from(self.child_number).to_be_bytes());
        ret[13..45].copy_from_slice(&self.chain_code[..]);
        ret[45] = 0;
        ret[46..78].copy_from_slice(&self.private_key[..]);
        ret
    }

    /// Returns the HASH160 of the public key belonging to the xpriv
    pub fn identifier<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>) -> XKeyIdentifier {
        Xpub::from_priv(secp, self).identifier()
    }

    /// Returns the first four bytes of the identifier
    pub fn fingerprint<C: secp256k1::Signing>(&self, secp: &Secp256k1<C>) -> Fingerprint {
        self.identifier(secp)[0..4].try_into().expect("4 is the fingerprint length")
    }
}

impl Xpub {
    /// Derives a public key from a private key
    pub fn from_priv<C: secp256k1::Signing>(secp: &Secp256k1<C>, sk: &Xpriv) -> Xpub {
        Xpub {
            network: sk.network,
            depth: sk.depth,
            parent_fingerprint: sk.parent_fingerprint,
            child_number: sk.child_number,
            public_key: secp256k1::PublicKey::from_secret_key(secp, &sk.private_key),
            chain_code: sk.chain_code,
        }
    }

    /// Constructs ECDSA compressed public key matching internal public key representation.
    pub fn to_pub(self) -> CompressedPublicKey { CompressedPublicKey(self.public_key) }

    /// Constructs BIP340 x-only public key for BIP-340 signatures and Taproot use matching
    /// the internal public key representation.
    pub fn to_x_only_pub(self) -> XOnlyPublicKey { XOnlyPublicKey::from(self.public_key) }

    /// Attempts to derive an extended public key from a path.
    ///
    /// The `path` argument can be any type implementing `AsRef<ChildNumber>`, such as `DerivationPath`, for instance.
    pub fn derive_pub<C: secp256k1::Verification, P: AsRef<[ChildNumber]>>(
        &self,
        secp: &Secp256k1<C>,
        path: &P,
    ) -> Result<Xpub, Error> {
        let mut pk: Xpub = *self;
        for cnum in path.as_ref() {
            pk = pk.ckd_pub(secp, *cnum)?
        }
        Ok(pk)
    }

    /// Compute the scalar tweak added to this key to get a child key
    pub fn ckd_pub_tweak(
        &self,
        i: ChildNumber,
    ) -> Result<(secp256k1::SecretKey, ChainCode), Error> {
        match i {
            ChildNumber::Hardened { .. } => Err(Error::CannotDeriveFromHardenedKey),
            ChildNumber::Normal { index: n } => {
                let mut hmac_engine: HmacEngine<sha512::Hash> =
                    HmacEngine::new(&self.chain_code[..]);
                hmac_engine.input(&self.public_key.serialize()[..]);
                hmac_engine.input(&n.to_be_bytes());

                let hmac_result: Hmac<sha512::Hash> = Hmac::from_engine(hmac_engine);

                let private_key = secp256k1::SecretKey::from_slice(&hmac_result[..32])?;
                let chain_code = ChainCode::from_hmac(hmac_result);
                Ok((private_key, chain_code))
            }
        }
    }

    /// Public->Public child key derivation
    pub fn ckd_pub<C: secp256k1::Verification>(
        &self,
        secp: &Secp256k1<C>,
        i: ChildNumber,
    ) -> Result<Xpub, Error> {
        let (sk, chain_code) = self.ckd_pub_tweak(i)?;
        let tweaked = self.public_key.add_exp_tweak(secp, &sk.into())?;

        Ok(Xpub {
            network: self.network,
            depth: self.depth + 1,
            parent_fingerprint: self.fingerprint(),
            child_number: i,
            public_key: tweaked,
            chain_code,
        })
    }

    /// Decoding extended public key from binary data according to BIP 32
    pub fn decode(data: &[u8]) -> Result<Xpub, Error> {
        if data.len() != 78 {
            return Err(Error::WrongExtendedKeyLength(data.len()));
        }

        let network = if data.starts_with(&VERSION_BYTES_MAINNET_PUBLIC) {
            NetworkKind::Main
        } else if data.starts_with(&VERSION_BYTES_TESTNETS_PUBLIC) {
            NetworkKind::Test
        } else {
            let (b0, b1, b2, b3) = (data[0], data[1], data[2], data[3]);
            return Err(Error::UnknownVersion([b0, b1, b2, b3]));
        };

        Ok(Xpub {
            network,
            depth: data[4],
            parent_fingerprint: data[5..9]
                .try_into()
                .expect("9 - 5 == 4, which is the Fingerprint length"),
            child_number: u32::from_be_bytes(data[9..13].try_into().expect("4 byte slice")).into(),
            chain_code: data[13..45]
                .try_into()
                .expect("45 - 13 == 32, which is the ChainCode length"),
            public_key: secp256k1::PublicKey::from_slice(&data[45..78])?,
        })
    }

    /// Extended public key binary encoding according to BIP 32
    pub fn encode(&self) -> [u8; 78] {
        let mut ret = [0; 78];
        ret[0..4].copy_from_slice(&match self.network {
            NetworkKind::Main => VERSION_BYTES_MAINNET_PUBLIC,
            NetworkKind::Test => VERSION_BYTES_TESTNETS_PUBLIC,
        });
        ret[4] = self.depth;
        ret[5..9].copy_from_slice(&self.parent_fingerprint[..]);
        ret[9..13].copy_from_slice(&u32::from(self.child_number).to_be_bytes());
        ret[13..45].copy_from_slice(&self.chain_code[..]);
        ret[45..78].copy_from_slice(&self.public_key.serialize()[..]);
        ret
    }

    /// Returns the HASH160 of the chaincode
    pub fn identifier(&self) -> XKeyIdentifier {
        let mut engine = XKeyIdentifier::engine();
        engine.write_all(&self.public_key.serialize()).expect("engines don't error");
        XKeyIdentifier::from_engine(engine)
    }

    /// Returns the first four bytes of the identifier
    pub fn fingerprint(&self) -> Fingerprint {
        self.identifier()[0..4].try_into().expect("4 is the fingerprint length")
    }
}

impl fmt::Display for Xpriv {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        base58::encode_check_to_fmt(fmt, &self.encode()[..])
    }
}

impl FromStr for Xpriv {
    type Err = Error;

    fn from_str(inp: &str) -> Result<Xpriv, Error> {
        let data = base58::decode_check(inp)?;

        if data.len() != 78 {
            return Err(InvalidBase58PayloadLengthError { length: data.len() }.into());
        }

        Xpriv::decode(&data)
    }
}

impl fmt::Display for Xpub {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        base58::encode_check_to_fmt(fmt, &self.encode()[..])
    }
}

impl FromStr for Xpub {
    type Err = Error;

    fn from_str(inp: &str) -> Result<Xpub, Error> {
        let data = base58::decode_check(inp)?;

        if data.len() != 78 {
            return Err(InvalidBase58PayloadLengthError { length: data.len() }.into());
        }

        Xpub::decode(&data)
    }
}

impl From<Xpub> for XKeyIdentifier {
    fn from(key: Xpub) -> XKeyIdentifier { key.identifier() }
}

impl From<&Xpub> for XKeyIdentifier {
    fn from(key: &Xpub) -> XKeyIdentifier { key.identifier() }
}

/// Decoded base58 data was an invalid length.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvalidBase58PayloadLengthError {
    /// The base58 payload length we got after decoding xpriv/xpub string.
    pub(crate) length: usize,
}

impl InvalidBase58PayloadLengthError {
    /// Returns the invalid payload length.
    pub fn invalid_base58_payload_length(&self) -> usize { self.length }
}

impl fmt::Display for InvalidBase58PayloadLengthError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "decoded base58 xpriv/xpub data was an invalid length: {} (expected 78)",
            self.length
        )
    }
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidBase58PayloadLengthError {}