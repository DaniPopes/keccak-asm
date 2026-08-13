# keccak-asm

Simple wrappers for SHA-3 algorithms written in assembly.

Forked from OpenSSL, [Cryptogams](https://github.com/dot-asm/cryptogams), and [RustCrypto's `sha3`](https://github.com/RustCrypto/hashes/tree/master/sha3).

These crates have been extensively used in production as the main `keccak256` backend in the [Ethereum client Reth](https://github.com/paradigmxyz/reth) since [v0.1.0-alpha.15 (January 2024)](https://github.com/paradigmxyz/reth/commit/5a623a9c1285d986fc46f1091d58d7a388323457).

## Support

| Architecture | Linux | macOS | Windows |
|:------------:|:-----:|:-----:|:-------:|
|      x86     |   ❌   |   ❌   |    ❌    |
|    x86_64    |   ✅   |   ✅   |    ✅    |
|    aarch64   |   ✅   |   ✅   |    🟨    |
| powerpc{,64} |   ✅   |  N/A  |   N/A   |
| powerpc64le  |   ❌   |  N/A  |   N/A   |
|    riscv32   |   ✅   |  N/A  |   N/A   |
|    riscv64   |   ✅   |  N/A  |   N/A   |
|   mips{,el}  |   ✅   |  N/A  |   N/A   |

- ❌: Currently not supported.
- 🟨: Compiles, but is only built, not tested in CI. Should still work normally.
- ✅: Fully supported, with full CI coverage for the most popular target triples, e.g. `x86_64-unknown-linux-gnu`, `aarch64-apple-darwin`, `x86_64-pc-windows-msvc`.

## License

Cryptogams is either licensed under [BSD-3-Clause](https://spdx.org/licenses/BSD-3-Clause.html) (the "new" BSD license, as specified [here](https://www.openssl.org/~appro/cryptogams/)), or the Linux Kernel's license [GPL-2.0-only](https://spdx.org/licenses/GPL-2.0-only.html).
See the [LICENSE](./LICENSE) file for more information.
