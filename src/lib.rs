// SPDX-License-Identifier: LGPL-3.0-or-later

//! RIPEMD-160 as a [zkboo] circuit.

#![no_std]
extern crate alloc;

use alloc::vec::Vec;
use zkboo::backend::{Allocator, Backend, WordRef};

/// The RIPEMD-160 block size in bytes.
pub const RIPEMD160_BLOCKSIZE: usize = 64;

/// Message-word selection for the left line.
#[rustfmt::skip]
const R_LEFT: [usize; 80] = [
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
    7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8,
    3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12,
    1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2,
    4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13,
];

/// Message-word selection for the right line.
#[rustfmt::skip]
const R_RIGHT: [usize; 80] = [
    5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12,
    6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2,
    15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13,
    8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14,
    12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11,
];

/// Rotation amounts for the left line.
#[rustfmt::skip]
const S_LEFT: [usize; 80] = [
    11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8,
    7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12,
    11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5,
    11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12,
    9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6,
];

/// Rotation amounts for the right line.
#[rustfmt::skip]
const S_RIGHT: [usize; 80] = [
    8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6,
    9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11,
    9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5,
    15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8,
    8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11,
];

/// Round constants for the left line.
const K_LEFT: [u32; 5] = [0x00000000, 0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xA953FD4E];

/// Round constants for the right line.
const K_RIGHT: [u32; 5] = [0x50A28BE6, 0x5C4DD124, 0x6D703EF3, 0x7A6D76E9, 0x00000000];

const INIT_HASH: [u32; 5] = [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0];

/// The round boolean function for step `j` (the left line uses `j`, the right line `79 - j`), in
/// single-AND form.
fn round_fn<B: Backend>(
    j: usize,
    x: WordRef<B, u32>,
    y: WordRef<B, u32>,
    z: WordRef<B, u32>,
) -> WordRef<B, u32> {
    return match j / 16 {
        // x XOR y XOR z
        0 => x ^ y ^ z,
        // (x AND y) OR (NOT x AND z)
        1 => z.clone() ^ (x & (y ^ z)),
        // (x OR NOT y) XOR z
        2 => !((!x) & y) ^ z,
        // (x AND z) OR (y AND NOT z)
        3 => y.clone() ^ (z & (x ^ y)),
        // x XOR (y OR NOT z)
        4 => x ^ !((!y) & z),
        _ => unreachable!("step index below 80"),
    };
}

/// The MD4-style padding: message, 0x80, zeros, then the 64-bit bit length little-endian, loaded
/// into little-endian u32 words.
fn pad_u32<B: Backend>(
    allocator: Allocator<B>,
    mut msg: Vec<WordRef<B, u8>>,
) -> Vec<WordRef<B, u32>> {
    let bit_len = (msg.len() as u64) * 8;
    msg.push(allocator.alloc(0x80u8));
    while msg.len() % RIPEMD160_BLOCKSIZE != 56 {
        msg.push(allocator.alloc(0x00u8));
    }
    for byte in bit_len.to_le_bytes() {
        msg.push(allocator.alloc(byte));
    }
    let mut words: Vec<WordRef<B, u32>> = Vec::with_capacity(msg.len() / 4);
    let mut chunk: Vec<WordRef<B, u8>> = Vec::with_capacity(4);
    for byte in msg {
        chunk.push(byte);
        if chunk.len() == 4 {
            words.push(
                WordRef::<B, u32>::from_le_bytes(core::mem::take(&mut chunk))
                    .ok()
                    .expect("4 bytes per word"),
            );
        }
    }
    return words;
}

/// One line (left or right) of the RIPEMD-160 compression: 80 steps over a message block.
fn line<B: Backend>(
    block: &[WordRef<B, u32>],
    init: &[WordRef<B, u32>; 5],
    left: bool,
) -> [WordRef<B, u32>; 5] {
    let (r, s, k) = if left {
        (&R_LEFT, &S_LEFT, &K_LEFT)
    } else {
        (&R_RIGHT, &S_RIGHT, &K_RIGHT)
    };
    let [mut a, mut b, mut c, mut d, mut e] = init.clone();
    for j in 0..80 {
        let f_index = if left { j } else { 79 - j };
        let mut t = a + round_fn(f_index, b.clone(), c.clone(), d.clone()) + block[r[j]].clone();
        // Fold in the round constant, skipping the round whose constant is zero (K_LEFT[0] and
        // K_RIGHT[4]) — adding zero is a wasted carry chain.
        let kt = k[j / 16];
        if kt != 0 {
            t = t + kt;
        }
        let t = t.rotate_left(s[j]) + e.clone();
        [a, b, c, d, e] = [e, t, b, c.rotate_left(10), d];
    }
    return [a, b, c, d, e];
}

/// Computes the RIPEMD-160 digest of the given message.
pub fn ripemd160<B: Backend>(
    allocator: Allocator<B>,
    msg: Vec<WordRef<B, u8>>,
) -> [WordRef<B, u8>; 20] {
    const BLOCK_WORDS: usize = RIPEMD160_BLOCKSIZE / 4;
    let words = pad_u32(allocator.clone(), msg);
    let mut h: [WordRef<B, u32>; 5] = core::array::from_fn(|i| allocator.alloc(INIT_HASH[i]));
    for block in words.chunks_exact(BLOCK_WORDS) {
        let [al, bl, cl, dl, el] = line(block, &h, true);
        let [ar, br, cr, dr, er] = line(block, &h, false);
        let [h0, h1, h2, h3, h4] = h;
        h = [
            h1 + cl + dr,
            h2 + dl + er,
            h3 + el + ar,
            h4 + al + br,
            h0 + bl + cr,
        ];
    }
    return h
        .into_iter()
        .flat_map(|word| word.into_le_bytes())
        .collect::<Vec<_>>()
        .try_into()
        .ok()
        .expect("20 output bytes");
}
