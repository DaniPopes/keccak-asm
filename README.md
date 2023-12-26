# keccak-asm

Simple wrappers for SHA-3 algorithms written in assembly.

Forked from OpenSSL, [Cryptogams](https://github.com/dot-asm/cryptogams), and [RustCrypto's `sha3`](https://github.com/RustCrypto/hashes/tree/master/sha3).

> [!WARNING]
> Code is somewhat [tested](./tests/test.rs) and [benchmarked](https://github.com/DaniPopes/bench-keccak256).
> Use at your own risk.

## Support

TODO

[1] The MSVC toolchain is not supported, so only `gnu` and `gnullvm` targets will compile
[2] Theoretically supported, but untested in CI

## License

Cryptogams is either licensed under [BSD-3-Clause](https://spdx.org/licenses/BSD-3-Clause.html) (the "new" BSD license, as specified [here](https://www.openssl.org/~appro/cryptogams/)), or the Linux Kernel's license [GPL-2.0-only](https://spdx.org/licenses/GPL-2.0-only.html).
See the [LICENSE](./LICENSE) file for more information.
