// SPDX-License-Identifier: CC0-1.0

//! SHA1 implementation.
//!

use core::ops::Index;
use core::slice::SliceIndex;
use core::{cmp, str};

use crate::{FromSliceError, HashEngine as _};

crate::internal_macros::hash_type! {
    160,
    false,
    "Output of the SHA1 hash function."
}

fn from_engine(mut e: HashEngine) -> Hash {
    // pad buffer with a single 1-bit then all 0s, until there are exactly 8 bytes remaining
    let data_len = e.length as u64;

    let zeroes = [0; BLOCK_SIZE - 8];
    e.input(&[0x80]);
    if e.length % BLOCK_SIZE > zeroes.len() {
        e.input(&zeroes);
    }
    let pad_length = zeroes.len() - (e.length % BLOCK_SIZE);
    e.input(&zeroes[..pad_length]);
    debug_assert_eq!(e.length % BLOCK_SIZE, zeroes.len());

    e.input(&(8 * data_len).to_be_bytes());
    debug_assert_eq!(e.length % BLOCK_SIZE, 0);

    Hash(e.midstate())
}

const BLOCK_SIZE: usize = 64;

/// Engine to compute SHA1 hash function.
#[derive(Clone)]
pub struct HashEngine {
    buffer: [u8; BLOCK_SIZE],
    h: [u32; 5],
    length: usize,
}

impl Default for HashEngine {
    fn default() -> Self {
        HashEngine {
            h: [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0],
            length: 0,
            buffer: [0; BLOCK_SIZE],
        }
    }
}

impl crate::HashEngine for HashEngine {
    type MidState = [u8; 20];

    #[cfg(not(hashes_fuzz))]
    fn midstate(&self) -> [u8; 20] {
        let mut ret = [0; 20];
        for (val, ret_bytes) in self.h.iter().zip(ret.chunks_exact_mut(4)) {
            ret_bytes.copy_from_slice(&val.to_be_bytes())
        }
        ret
    }

    #[cfg(hashes_fuzz)]
    fn midstate(&self) -> [u8; 20] {
        let mut ret = [0; 20];
        ret.copy_from_slice(&self.buffer[..20]);
        ret
    }

    const BLOCK_SIZE: usize = 64;

    fn n_bytes_hashed(&self) -> usize {
        self.length
    }

    engine_input_impl!();
}

impl HashEngine {
    // Basic unoptimized algorithm from Wikipedia
    fn process_block(&mut self) {
        debug_assert_eq!(self.buffer.len(), BLOCK_SIZE);

        let mut w = [0u32; 80];
        for (w_val, buff_bytes) in w.iter_mut().zip(self.buffer.chunks_exact(4)) {
            *w_val = u32::from_be_bytes(buff_bytes.try_into().expect("4 bytes slice"))
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }

        let mut a = self.h[0];
        let mut b = self.h[1];
        let mut c = self.h[2];
        let mut d = self.h[3];
        let mut e = self.h[4];

        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5a827999),
                20..=39 => (b ^ c ^ d, 0x6ed9eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1bbcdc),
                60..=79 => (b ^ c ^ d, 0xca62c1d6),
                _ => unreachable!(),
            };

            let new_a = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = new_a;
        }

        self.h[0] = self.h[0].wrapping_add(a);
        self.h[1] = self.h[1].wrapping_add(b);
        self.h[2] = self.h[2].wrapping_add(c);
        self.h[3] = self.h[3].wrapping_add(d);
        self.h[4] = self.h[4].wrapping_add(e);
    }
}
