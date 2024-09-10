// SPDX-License-Identifier: CC0-1.0

//! Bitcoin network addresses.
//!
//! This module defines the structures and functions needed to encode
//! network addresses in Bitcoin messages.

use core::{fmt, iter};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6, ToSocketAddrs};

use io::{BufRead, Read, Write};

use crate::consensus::encode::{self, Decodable, Encodable, ReadExt, VarInt, WriteExt};
use crate::p2p::ServiceFlags;

/// A message which can be sent on the Bitcoin network
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Address {
    /// Services provided by the peer whose address this is
    pub services: ServiceFlags,
    /// Network byte-order ipv6 address, or ipv4-mapped ipv6 address
    pub address: [u16; 8],
    /// Network port
    pub port: u16,
}

const ONION: [u16; 3] = [0xFD87, 0xD87E, 0xEB43];

impl Address {
    /// Create an address message for a socket
    pub fn new(socket: &SocketAddr, services: ServiceFlags) -> Address {
        let (address, port) = match *socket {
            SocketAddr::V4(addr) => (addr.ip().to_ipv6_mapped().segments(), addr.port()),
            SocketAddr::V6(addr) => (addr.ip().segments(), addr.port()),
        };
        Address { address, port, services }
    }

    /// Extract socket address from an [Address] message.
    /// This will return [io::Error] [io::ErrorKind::AddrNotAvailable]
    /// if the message contains a Tor address.
    pub fn socket_addr(&self) -> Result<SocketAddr, io::Error> {
        let addr = &self.address;
        if addr[0..3] == ONION {
            return Err(io::Error::from(io::ErrorKind::AddrNotAvailable));
        }
        let ipv6 =
            Ipv6Addr::new(addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7]);
        if let Some(ipv4) = ipv6.to_ipv4() {
            Ok(SocketAddr::V4(SocketAddrV4::new(ipv4, self.port)))
        } else {
            Ok(SocketAddr::V6(SocketAddrV6::new(ipv6, self.port, 0, 0)))
        }
    }
}

impl Encodable for Address {
    #[inline]
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = self.services.consensus_encode(w)?;

        for word in &self.address {
            w.write_all(&word.to_be_bytes())?;
            len += 2;
        }

        w.write_all(&self.port.to_be_bytes())?;
        len += 2;

        Ok(len)
    }
}

impl Decodable for Address {
    #[inline]
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(Address {
            services: Decodable::consensus_decode(r)?,
            address: read_be_address(r)?,
            port: u16::swap_bytes(Decodable::consensus_decode(r)?),
        })
    }
}

/// Read a big-endian address from reader.
fn read_be_address<R: Read + ?Sized>(r: &mut R) -> Result<[u16; 8], encode::Error> {
    let mut address = [0u16; 8];
    let mut buf = [0u8; 2];

    for word in &mut address {
        Read::read_exact(r, &mut buf)?;
        *word = u16::from_be_bytes(buf)
    }
    Ok(address)
}

impl fmt::Debug for Address {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let ipv6 = Ipv6Addr::from(self.address);

        match ipv6.to_ipv4() {
            Some(addr) => write!(
                f,
                "Address {{services: {}, address: {}, port: {}}}",
                self.services, addr, self.port
            ),
            None => write!(
                f,
                "Address {{services: {}, address: {}, port: {}}}",
                self.services, ipv6, self.port
            ),
        }
    }
}

impl ToSocketAddrs for Address {
    type Iter = iter::Once<SocketAddr>;
    fn to_socket_addrs(&self) -> Result<Self::Iter, std::io::Error> {
        Ok(iter::once(self.socket_addr()?))
    }
}

/// Supported networks for use in BIP155 addrv2 message
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub enum AddrV2 {
    /// IPV4
    Ipv4(Ipv4Addr),
    /// IPV6
    Ipv6(Ipv6Addr),
    /// TORV2
    TorV2([u8; 10]),
    /// TORV3
    TorV3([u8; 32]),
    /// I2P
    I2p([u8; 32]),
    /// CJDNS
    Cjdns(Ipv6Addr),
    /// Unknown
    Unknown(u8, Vec<u8>),
}

impl Encodable for AddrV2 {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        fn encode_addr<W: Write + ?Sized>(
            w: &mut W,
            network: u8,
            bytes: &[u8],
        ) -> Result<usize, io::Error> {
            let len = network.consensus_encode(w)?
                + VarInt::from(bytes.len()).consensus_encode(w)?
                + bytes.len();
            w.emit_slice(bytes)?;
            Ok(len)
        }
        Ok(match *self {
            AddrV2::Ipv4(ref addr) => encode_addr(w, 1, &addr.octets())?,
            AddrV2::Ipv6(ref addr) => encode_addr(w, 2, &addr.octets())?,
            AddrV2::TorV2(ref bytes) => encode_addr(w, 3, bytes)?,
            AddrV2::TorV3(ref bytes) => encode_addr(w, 4, bytes)?,
            AddrV2::I2p(ref bytes) => encode_addr(w, 5, bytes)?,
            AddrV2::Cjdns(ref addr) => encode_addr(w, 6, &addr.octets())?,
            AddrV2::Unknown(network, ref bytes) => encode_addr(w, network, bytes)?,
        })
    }
}

impl Decodable for AddrV2 {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        let network_id = u8::consensus_decode(r)?;
        let len = VarInt::consensus_decode(r)?.0;
        if len > 512 {
            return Err(encode::Error::ParseFailed("IP must be <= 512 bytes"));
        }
        Ok(match network_id {
            1 => {
                if len != 4 {
                    return Err(encode::Error::ParseFailed("invalid IPv4 address"));
                }
                let addr: [u8; 4] = Decodable::consensus_decode(r)?;
                AddrV2::Ipv4(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]))
            }
            2 => {
                if len != 16 {
                    return Err(encode::Error::ParseFailed("invalid IPv6 address"));
                }
                let addr: [u16; 8] = read_be_address(r)?;
                if addr[0..3] == ONION {
                    return Err(encode::Error::ParseFailed(
                        "OnionCat address sent with IPv6 network id",
                    ));
                }
                if addr[0..6] == [0x0000, 0x0000, 0x0000, 0x0000, 0x0000, 0xFFFF] {
                    return Err(encode::Error::ParseFailed(
                        "IPV4 wrapped address sent with IPv6 network id",
                    ));
                }
                AddrV2::Ipv6(Ipv6Addr::new(
                    addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
                ))
            }
            3 => {
                if len != 10 {
                    return Err(encode::Error::ParseFailed("invalid TorV2 address"));
                }
                let id = Decodable::consensus_decode(r)?;
                AddrV2::TorV2(id)
            }
            4 => {
                if len != 32 {
                    return Err(encode::Error::ParseFailed("invalid TorV3 address"));
                }
                let pubkey = Decodable::consensus_decode(r)?;
                AddrV2::TorV3(pubkey)
            }
            5 => {
                if len != 32 {
                    return Err(encode::Error::ParseFailed("invalid I2P address"));
                }
                let hash = Decodable::consensus_decode(r)?;
                AddrV2::I2p(hash)
            }
            6 => {
                if len != 16 {
                    return Err(encode::Error::ParseFailed("invalid CJDNS address"));
                }
                let addr: [u16; 8] = read_be_address(r)?;
                // check the first byte for the CJDNS marker
                if addr[0] >> 8 != 0xFC {
                    return Err(encode::Error::ParseFailed("invalid CJDNS address"));
                }
                AddrV2::Cjdns(Ipv6Addr::new(
                    addr[0], addr[1], addr[2], addr[3], addr[4], addr[5], addr[6], addr[7],
                ))
            }
            _ => {
                // len already checked above to be <= 512
                let mut addr = vec![0u8; len as usize];
                r.read_slice(&mut addr)?;
                AddrV2::Unknown(network_id, addr)
            }
        })
    }
}

/// Address received from BIP155 addrv2 message
#[derive(Clone, PartialEq, Eq, Hash, Debug)]
pub struct AddrV2Message {
    /// Time that this node was last seen as connected to the network
    pub time: u32,
    /// Service bits
    pub services: ServiceFlags,
    /// Network ID + Network Address
    pub addr: AddrV2,
    /// Network port, 0 if not applicable
    pub port: u16,
}

impl AddrV2Message {
    /// Extract socket address from an [AddrV2Message] message.
    /// This will return [io::Error] [io::ErrorKind::AddrNotAvailable]
    /// if the address type can't be converted into a [SocketAddr].
    pub fn socket_addr(&self) -> Result<SocketAddr, io::Error> {
        match self.addr {
            AddrV2::Ipv4(addr) => Ok(SocketAddr::V4(SocketAddrV4::new(addr, self.port))),
            AddrV2::Ipv6(addr) => Ok(SocketAddr::V6(SocketAddrV6::new(addr, self.port, 0, 0))),
            _ => Err(io::Error::from(io::ErrorKind::AddrNotAvailable)),
        }
    }
}

impl Encodable for AddrV2Message {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        let mut len = 0;
        len += self.time.consensus_encode(w)?;
        len += VarInt(self.services.to_u64()).consensus_encode(w)?;
        len += self.addr.consensus_encode(w)?;

        w.write_all(&self.port.to_be_bytes())?;
        len += 2; // port u16 is two bytes.

        Ok(len)
    }
}

impl Decodable for AddrV2Message {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, encode::Error> {
        Ok(AddrV2Message {
            time: Decodable::consensus_decode(r)?,
            services: ServiceFlags::from(VarInt::consensus_decode(r)?.0),
            addr: Decodable::consensus_decode(r)?,
            port: u16::swap_bytes(Decodable::consensus_decode(r)?),
        })
    }
}

impl ToSocketAddrs for AddrV2Message {
    type Iter = iter::Once<SocketAddr>;
    fn to_socket_addrs(&self) -> Result<Self::Iter, std::io::Error> {
        Ok(iter::once(self.socket_addr()?))
    }
}
