// SPDX-License-Identifier: CC0-1.0

//! Signature
//!
//! This module provides signature related functions including secp256k1 signature recovery when
//! library is used with the `secp-recovery` feature.
//!

use hashes::{sha256d, Hash, HashEngine};

use crate::consensus::{encode, Encodable};

#[rustfmt::skip]
#[doc(inline)]
#[cfg(feature = "secp-recovery")]
pub use self::message_signing::{MessageSignature, MessageSignatureError};

/// The prefix for signed messages using Bitcoin's message signing protocol.
pub const BITCOIN_SIGNED_MSG_PREFIX: &[u8] = b"\x18Bitcoin Signed Message:\n";

#[cfg(feature = "secp-recovery")]
mod message_signing {
    use core::fmt;

    use hashes::{sha256d, Hash};
    use internals::write_err;
    use secp256k1::ecdsa::{RecoverableSignature, RecoveryId};

    use crate::address::{Address, AddressType};
    use crate::crypto::key::PublicKey;

    /// An error used for dealing with Bitcoin Signed Messages.
    #[derive(Debug, Clone, PartialEq, Eq)]
    #[non_exhaustive]
    pub enum MessageSignatureError {
        /// Signature is expected to be 65 bytes.
        InvalidLength,
        /// The signature is invalidly constructed.
        InvalidEncoding(secp256k1::Error),
        /// Invalid base64 encoding.
        InvalidBase64,
        /// Unsupported Address Type
        UnsupportedAddressType(AddressType),
    }

    internals::impl_from_infallible!(MessageSignatureError);

    impl fmt::Display for MessageSignatureError {
        fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
            use MessageSignatureError::*;

            match *self {
                InvalidLength => write!(f, "length not 65 bytes"),
                InvalidEncoding(ref e) => write_err!(f, "invalid encoding"; e),
                InvalidBase64 => write!(f, "invalid base64"),
                UnsupportedAddressType(ref address_type) =>
                    write!(f, "unsupported address type: {}", address_type),
            }
        }
    }

    #[cfg(feature = "std")]
    impl std::error::Error for MessageSignatureError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            use MessageSignatureError::*;

            match *self {
                InvalidEncoding(ref e) => Some(e),
                InvalidLength | InvalidBase64 | UnsupportedAddressType(_) => None,
            }
        }
    }

    impl From<secp256k1::Error> for MessageSignatureError {
        fn from(e: secp256k1::Error) -> MessageSignatureError {
            MessageSignatureError::InvalidEncoding(e)
        }
    }

    /// A signature on a Bitcoin Signed Message.
    ///
    /// In order to use the `to_base64` and `from_base64` methods, as well as the
    /// `fmt::Display` and `str::FromStr` implementations, the `base64` feature
    /// must be enabled.
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    pub struct MessageSignature {
        /// The inner recoverable signature.
        pub signature: RecoverableSignature,
        /// Whether or not this signature was created with a compressed key.
        pub compressed: bool,
    }

    impl MessageSignature {
        /// Create a new [MessageSignature].
        pub fn new(signature: RecoverableSignature, compressed: bool) -> MessageSignature {
            MessageSignature { signature, compressed }
        }

        /// Serialize to bytes.
        pub fn serialize(&self) -> [u8; 65] {
            let (recid, raw) = self.signature.serialize_compact();
            let mut serialized = [0u8; 65];
            serialized[0] = 27;
            serialized[0] += recid.to_i32() as u8;
            if self.compressed {
                serialized[0] += 4;
            }
            serialized[1..].copy_from_slice(&raw[..]);
            serialized
        }

        /// Create from a byte slice.
        pub fn from_slice(bytes: &[u8]) -> Result<MessageSignature, MessageSignatureError> {
            if bytes.len() != 65 {
                return Err(MessageSignatureError::InvalidLength);
            }
            // We just check this here so we can safely subtract further.
            if bytes[0] < 27 {
                return Err(MessageSignatureError::InvalidEncoding(
                    secp256k1::Error::InvalidRecoveryId,
                ));
            };
            let recid = RecoveryId::from_i32(((bytes[0] - 27) & 0x03) as i32)?;
            Ok(MessageSignature {
                signature: RecoverableSignature::from_compact(&bytes[1..], recid)?,
                compressed: ((bytes[0] - 27) & 0x04) != 0,
            })
        }

        /// Attempt to recover a public key from the signature and the signed message.
        ///
        /// To get the message hash from a message, use [super::signed_msg_hash].
        pub fn recover_pubkey<C: secp256k1::Verification>(
            &self,
            secp_ctx: &secp256k1::Secp256k1<C>,
            msg_hash: sha256d::Hash,
        ) -> Result<PublicKey, MessageSignatureError> {
            let msg = secp256k1::Message::from_digest(msg_hash.to_byte_array());
            let pubkey = secp_ctx.recover_ecdsa(&msg, &self.signature)?;
            Ok(PublicKey { inner: pubkey, compressed: self.compressed })
        }

        /// Verify that the signature signs the message and was signed by the given address.
        ///
        /// To get the message hash from a message, use [super::signed_msg_hash].
        pub fn is_signed_by_address<C: secp256k1::Verification>(
            &self,
            secp_ctx: &secp256k1::Secp256k1<C>,
            address: &Address,
            msg_hash: sha256d::Hash,
        ) -> Result<bool, MessageSignatureError> {
            match address.address_type() {
                Some(AddressType::P2pkh) => {
                    let pubkey = self.recover_pubkey(secp_ctx, msg_hash)?;
                    Ok(address.pubkey_hash() == Some(pubkey.pubkey_hash()))
                }
                Some(address_type) =>
                    Err(MessageSignatureError::UnsupportedAddressType(address_type)),
                None => Ok(false),
            }
        }
    }

    #[cfg(feature = "base64")]
    mod base64_impls {
        use base64::prelude::{Engine as _, BASE64_STANDARD};

        use super::*;
        use crate::prelude::*;

        impl MessageSignature {
            /// Convert a signature from base64 encoding.
            pub fn from_base64(s: &str) -> Result<MessageSignature, MessageSignatureError> {
                let bytes =
                    BASE64_STANDARD.decode(s).map_err(|_| MessageSignatureError::InvalidBase64)?;
                MessageSignature::from_slice(&bytes)
            }

            /// Convert to base64 encoding.
            pub fn to_base64(self) -> String { BASE64_STANDARD.encode(self.serialize()) }
        }

        impl fmt::Display for MessageSignature {
            fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
                let bytes = self.serialize();
                // This avoids the allocation of a String.
                write!(f, "{}", base64::display::Base64Display::new(&bytes, &BASE64_STANDARD))
            }
        }

        impl core::str::FromStr for MessageSignature {
            type Err = MessageSignatureError;
            fn from_str(s: &str) -> Result<MessageSignature, MessageSignatureError> {
                MessageSignature::from_base64(s)
            }
        }
    }
}

/// Hash message for signature using Bitcoin's message signing format.
pub fn signed_msg_hash(msg: &str) -> sha256d::Hash {
    let mut engine = sha256d::Hash::engine();
    engine.input(BITCOIN_SIGNED_MSG_PREFIX);
    let msg_len = encode::VarInt::from(msg.len());
    msg_len.consensus_encode(&mut engine).expect("engines don't error");
    engine.input(msg.as_bytes());
    sha256d::Hash::from_engine(engine)
}