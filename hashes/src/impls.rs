// SPDX-License-Identifier: CC0-1.0

//! `std` / `io` Impls.
//!
//! Implementations of traits defined in `std` / `io` and not in `core`.

use satsnet_io::impl_write;

use crate::{hash160, hmac, ripemd160, sha1, sha256, sha256d, sha512, siphash24, HashEngine};

impl_write!(
    hash160::HashEngine,
    |us: &mut hash160::HashEngine, buf| {
        us.input(buf);
        Ok(buf.len())
    },
    |_us| { Ok(()) }
);

impl_write!(
    sha1::HashEngine,
    |us: &mut sha1::HashEngine, buf| {
        us.input(buf);
        Ok(buf.len())
    },
    |_us| { Ok(()) }
);

impl_write!(
    sha256::HashEngine,
    |us: &mut sha256::HashEngine, buf| {
        us.input(buf);
        Ok(buf.len())
    },
    |_us| { Ok(()) }
);

impl_write!(
    sha256d::HashEngine,
    |us: &mut sha256d::HashEngine, buf| {
        us.input(buf);
        Ok(buf.len())
    },
    |_us| { Ok(()) }
);

impl_write!(
    sha512::HashEngine,
    |us: &mut sha512::HashEngine, buf| {
        us.input(buf);
        Ok(buf.len())
    },
    |_us| { Ok(()) }
);

impl_write!(
    ripemd160::HashEngine,
    |us: &mut ripemd160::HashEngine, buf| {
        us.input(buf);
        Ok(buf.len())
    },
    |_us| { Ok(()) }
);

impl_write!(
    siphash24::HashEngine,
    |us: &mut siphash24::HashEngine, buf| {
        us.input(buf);
        Ok(buf.len())
    },
    |_us| { Ok(()) }
);

impl_write!(
    hmac::HmacEngine<T>,
    |us: &mut hmac::HmacEngine<T>, buf| {
        us.input(buf);
        Ok(buf.len())
    },
    |_us| { Ok(()) },
    T: crate::GeneralHash
);
