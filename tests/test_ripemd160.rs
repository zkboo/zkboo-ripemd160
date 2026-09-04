// SPDX-License-Identifier: LGPL-3.0-or-later

//! Validates RIPEMD-160 against the standard vectors from the RIPEMD-160 paper and against the
//! host-side `ripemd` (RustCrypto) implementation, including padding-boundary lengths.

use ripemd::{Digest, Ripemd160};
use zkboo::{
    backend::{Backend, Frontend},
    circuit::Circuit,
    executor::{OwnedFlexibleWordPool, exec},
};
use zkboo_ripemd160::ripemd160;
use zkboo::executor::ExecOptions;

type WP = OwnedFlexibleWordPool<usize>;

struct Ripemd160Circuit {
    msg: Vec<u8>,
}

impl Circuit for Ripemd160Circuit {
    fn exec<B: Backend>(&self, frontend: &Frontend<B>) {
        let msg = self
            .msg
            .iter()
            .map(|&b| frontend.input(b))
            .collect::<Vec<_>>();
        let digest = ripemd160(frontend.allocator(), msg);
        digest.into_iter().for_each(|w| frontend.output(w));
    }
}

fn to_hex(bytes: &[u8]) -> String {
    return bytes.iter().map(|b| format!("{b:02x}")).collect();
}

fn digest(msg: &[u8]) -> String {
    let out = exec::<_, WP, _>(&Ripemd160Circuit { msg: msg.to_vec() }, ExecOptions::new()).u8;
    assert_eq!(out.len(), 20);
    return to_hex(&out);
}

#[test]
fn test_ripemd160_standard_vectors() {
    let vectors: [(&[u8], &str); 5] = [
        (b"", "9c1185a5c5e9fc54612808977ee8f548b2258d31"),
        (b"a", "0bdc9d2d256b3ee9daae347be6f4dc835a467ffe"),
        (b"abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc"),
        (
            b"message digest",
            "5d0689ef49d2fae572b881b123a85ffa21595f36",
        ),
        (
            b"abcdefghijklmnopqrstuvwxyz",
            "f71c27109c692c1b56bbdceb5b9d2865b3708dbc",
        ),
    ];
    for (msg, expected) in vectors {
        assert_eq!(digest(msg), expected, "message {msg:?}");
    }
}

#[test]
fn test_ripemd160_matches_host_hasher() {
    // Lengths around the padding boundary (56 mod 64) and across multiple blocks.
    for len in [55, 56, 57, 63, 64, 65, 119, 120, 128, 200] {
        let msg = (0..len).map(|i| i as u8).collect::<Vec<u8>>();
        let expected = to_hex(&Ripemd160::digest(&msg));
        assert_eq!(digest(&msg), expected, "message length {len}");
    }
}
