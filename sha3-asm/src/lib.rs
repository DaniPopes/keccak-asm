//! Assembly implementation of the [SHA-3] compression functions.
//!
//! This crate is not intended for direct use, most users should
//! prefer the [`sha3`] crate with enabled `asm` feature instead.
//!
//! Only x86, x86-64, and (partially) AArch64 architectures are
//! currently supported.
//!
//! [SHA-3]: https://en.wikipedia.org/wiki/SHA-3
//! [`sha3`]: https://crates.io/crates/sha3

#![no_std]
#![warn(missing_docs, rust_2018_idioms)]

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
compile_error!("crate can only be used on x86, x86-64 and aarch64 architectures");

/// SHA-3 state buffer.
pub type Buffer = [u64; 25];

// Derived from OpenSSL:
// https://github.com/openssl/openssl/blob/60421893a286bb9eb7fb7c2454b84af9778ffca4/crypto/sha/keccak1600.c#L14-L17
#[link(name = "keccak1600", kind = "static")]
extern "C" {
    /// SHA-3 absorb, defined in assembly.
    ///
    /// `r` is the rate (block size) of the function in bytes.
    ///
    /// C signature:
    ///
    /// ```c
    /// size_t SHA3_absorb(uint64_t A[5][5], const unsigned char *inp, size_t len,
    ///                    size_t r);
    /// ```
    pub fn SHA3_absorb(a: *mut Buffer, inp: *const u8, len: usize, r: usize) -> usize;

    /// SHA-3 squeeze, defined in assembly.
    ///
    /// `r` is the rate (block size) of the function in bytes.
    ///
    /// C signature:
    ///
    /// ```c
    /// void SHA3_squeeze(uint64_t A[5][5], unsigned char *out, size_t len, size_t r);
    /// ```
    pub fn SHA3_squeeze(a: *mut Buffer, out: *mut u8, len: usize, r: usize);
}

/// Safe wrapper for [`SHA3_absorb`]. See its docs for more.
#[inline(always)]
pub fn sha3_absorb(a: &mut Buffer, inp: &[u8], r: usize) -> usize {
    unsafe { SHA3_absorb(a, inp.as_ptr(), inp.len(), r) }
}

/// Safe wrapper for [`SHA3_squeeze`]. See its docs for more.
#[inline(always)]
pub fn sha3_squeeze(a: &mut Buffer, out: &mut [u8], r: usize) {
    unsafe { SHA3_squeeze(a, out.as_mut_ptr(), out.len(), r) }
}
