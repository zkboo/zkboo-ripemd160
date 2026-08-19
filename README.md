# ZKBoo-RIPEMD160

![Rust](https://img.shields.io/badge/rust-1.92+-orange.svg)

RIPEMD-160 as a [ZKBoo](https://crates.io/crates/zkboo) circuit.

RIPEMD-160 underlies Bitcoin's `HASH160 = RIPEMD160(SHA256(·))`, used for P2PKH, P2SH, and P2WPKH addresses, so this circuit (composed with [`zkboo-sha2`](https://crates.io/crates/zkboo-sha2)) enables zero-knowledge proofs that a Bitcoin address derives from a secret key or seed.
It is an MD4-family design — little-endian loading and length padding, five 32-bit chaining words, two parallel 80-step lines cross-combined per block — built from u32 adds, rotates, and single-AND boolean functions.
Messages of arbitrary length are supported.

```rust
use zkboo_ripemd160::ripemd160;
// inside a Circuit::exec, given `msg: Vec<WordRef<B, u8>>`:
let digest = ripemd160(frontend.allocator(), msg); // [WordRef<B, u8>; 20]
```

Validated against the standard vectors from the RIPEMD-160 paper and against the host-side `ripemd` (RustCrypto) implementation, including padding-boundary and multi-block lengths.

## 🚧 Warning 🚧

Work in progress, not yet suitable for production. Security has not been audited.

## License

[LGPLv3 © contributors.](LICENSE)
