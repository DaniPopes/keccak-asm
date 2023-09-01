#![no_std]

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
compile_error!("crate can only be used on x86, x86-64 and aarch64 architectures");

use cfg_if::cfg_if;
use core::fmt;

mod state;
use state::Sha3State;

type Buffer = [[u64; 5]; 5];

// https://github.com/openssl/openssl/blob/60421893a286bb9eb7fb7c2454b84af9778ffca4/crypto/sha/keccak1600.c#L14-L17
// size_t SHA3_absorb(uint64_t A[5][5], const unsigned char *inp, size_t len,
//     size_t r);
// void SHA3_squeeze(uint64_t A[5][5], unsigned char *out, size_t len, size_t r);
#[link(name = "keccak1600", kind = "static")]
extern "C" {
    pub fn SHA3_absorb(a: *mut Buffer, inp: *const u8, len: usize, r: usize) -> usize;
    pub fn SHA3_squeeze(a: *mut Buffer, out: *mut u8, len: usize, r: usize);
}

cfg_if! {
    // These do not have a global `KeccakF1600` symbol
    if #[cfg(all(target_arch = "x86_64", any(target_feature = "avx2", target_feature = "avx512f", target_feature = "avx512vl")))] {
        #[link(name = "keccak1600", kind = "static")]
        extern "C" {
            fn __KeccakF1600();
        }

        #[inline(never)]
        #[no_mangle]
        pub unsafe extern "C" fn KeccakF1600(a: *mut Buffer) {
            core::arch::asm!(
                "mov	%rsp,%r11",

                "lea	-240(%rsp),%rsp",
                "and	$-32,%rsp",

                "lea	96(%rdi),%rdi",
                "lea	96(%rsi),%rsi",
                "lea	96(%rsp),%r10",

                "vzeroupper",

                // load A[5][5]
                "vpbroadcastq	-96(%rdi),%ymm0",
                "vmovdqu		8+32*0-96(%rdi),%ymm1",
                "vmovdqu		8+32*1-96(%rdi),%ymm2",
                "vmovdqu		8+32*2-96(%rdi),%ymm3",
                "vmovdqu		8+32*3-96(%rdi),%ymm4",
                "vmovdqu		8+32*4-96(%rdi),%ymm5",
                "vmovdqu		8+32*5-96(%rdi),%ymm6",

                // zero transfer area on stack
                "vpxor		%ymm7,%ymm7,%ymm7",
                "vmovdqa		%ymm7,32*2-96(%r10)",
                "vmovdqa		%ymm7,32*3-96(%r10)",
                "vmovdqa		%ymm7,32*4-96(%r10)",
                "vmovdqa		%ymm7,32*5-96(%r10)",
                "vmovdqa		%ymm7,32*6-96(%r10)",

                "vpbroadcastq	0-96(%rsi),%ymm7",
                "vmovdqu		8-96(%rsi),%ymm8",
                // TODO
                "lea	(%rsi,%rcx),%rsi",
                "vpxor	%ymm7,%ymm0,%ymm0",
                "vpxor	%ymm8,%ymm1,%ymm1",
                "vpxor	32*2-96(%r10),%ymm2,%ymm2",
                "vpxor	32*3-96(%r10),%ymm3,%ymm3",
                "vpxor	32*4-96(%r10),%ymm4,%ymm4",
                "vpxor	32*5-96(%r10),%ymm5,%ymm5",
                "vpxor	32*6-96(%r10),%ymm6,%ymm6",

                "call    __KeccakF1600",

                "vmovq	%xmm0,-96(%rdi)",
                "vmovdqu	%ymm1,8+32*0-96(%rdi)",
                "vmovdqu	%ymm2,8+32*1-96(%rdi)",
                "vmovdqu	%ymm3,8+32*2-96(%rdi)",
                "vmovdqu	%ymm4,8+32*3-96(%rdi)",
                "vmovdqu	%ymm5,8+32*4-96(%rdi)",
                "vmovdqu	%ymm6,8+32*5-96(%rdi)",

                "vzeroupper",

                "lea	(%r11),%rsp",

                in("rdi") a,
                options(att_syntax, preserves_flags)
            );
        }
    } else {
        #[link(name = "keccak1600", kind = "static")]
        extern "C" {
            pub fn KeccakF1600(buf: *mut Buffer);
        }
    }
}

macro_rules! impl_sha3 {
    ($name:ident, $bits:literal, $pad:expr) => {
        #[allow(non_snake_case)]
        pub struct $name {
            inner: Sha3State<$bits, $pad>,
        }

        impl fmt::Debug for $name {
            #[inline]
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), " { ... }"))
            }
        }

        impl $name {
            /// Output length.
            pub const OUT: usize = $bits / 8;
            /// Block size.
            pub const BSZ: usize = (1600 - $bits) / 8;
            /// Padding byte.
            pub const PAD: u8 = $pad;

            #[inline]
            pub fn new() -> Self {
                Self { inner: Sha3State::new() }
            }

            #[inline]
            pub fn reset(&mut self) {
                self.inner.reset();
            }

            // https://github.com/openssl/openssl/blob/60421893a286bb9eb7fb7c2454b84af9778ffca4/crypto/sha/sha3.c#L45
            #[inline]
            pub fn update(&mut self, inp: &[u8]) {
                unsafe { self.inner.update(inp.as_ptr(), inp.len()) }
            }

            #[inline]
            pub fn finalize(self) -> [u8; Self::OUT] {
                let mut out = [0; Self::OUT];
                self.finalize_into(&mut out);
                out
            }

            #[inline]
            pub fn finalize_into(mut self, out: &mut [u8; Self::OUT]) {
                unsafe { self.inner.finalize(out.as_mut_ptr()) };
            }

            #[inline]
            pub fn digest(inp: &[u8]) -> [u8; Self::OUT] {
                let mut out = [0; Self::OUT];
                Self::digest_into(inp, &mut out);
                out
            }

            #[inline]
            pub fn digest_into(inp: &[u8], out: &mut [u8; Self::OUT]) {
                let mut this = Self::new();
                this.update(inp);
                this.finalize_into(out);
            }
        }
    };
}

trait CoreTrait {
    fn new() -> Self;
    fn reset(&mut self);
    unsafe fn update(&mut self, inp: *const u8, len: usize);
    unsafe fn finalize(&mut self, out: *mut u8);
}

// Paddings
// const KECCAK: u8 = 0x01;
const SHA3: u8 = 0x06;
// const SHAKE: u8 = 0x1f;
// const CSHAKE: u8 = 0x4;

// impl_sha3!(Keccak256, 256, KECCAK);
impl_sha3!(Sha3_256, 256, SHA3);

/// Safe [`KeccakF1600`].
#[inline(always)]
pub fn keccak_f1600(buf: &mut Buffer) {
    unsafe { KeccakF1600(buf) }
}

/// See [sha3_sponge].
#[inline(always)]
pub fn sha3_absorb(a: &mut Buffer, inp: &[u8], r: usize) -> usize {
    unsafe { SHA3_absorb(a, inp.as_ptr(), inp.len(), r) }
}

/// See [sha3_sponge].
#[inline(always)]
pub fn sha3_squeeze(a: &mut Buffer, out: &mut [u8], r: usize) {
    unsafe { SHA3_squeeze(a, out.as_mut_ptr(), out.len(), r) }
}

/// Post-padding one-shot implementations would look as following:
///
/// SHA3_224     SHA3_sponge(inp, len, out, 224/8, (1600-448)/8);
/// SHA3_256     SHA3_sponge(inp, len, out, 256/8, (1600-512)/8);
/// SHA3_384     SHA3_sponge(inp, len, out, 384/8, (1600-768)/8);
/// SHA3_512     SHA3_sponge(inp, len, out, 512/8, (1600-1024)/8);
/// SHAKE_128    SHA3_sponge(inp, len, out, d, (1600-256)/8);
/// SHAKE_256    SHA3_sponge(inp, len, out, d, (1600-512)/8);
#[inline(always)]
pub fn sha3_sponge(inp: &[u8], out: &mut [u8], r: usize) {
    let mut a = [[0u64; 5]; 5];
    unsafe {
        SHA3_absorb(&mut a, inp.as_ptr(), inp.len(), r);
        SHA3_squeeze(&mut a, out.as_mut_ptr(), out.len(), r);
    }
}

#[cfg(test)]
mod tests {
    use sha3::Digest;

    #[test]
    #[ignore = "TODO"]
    fn sha3_256() {
        let tests: &[&str] = &["", "a", "ab", "hello world"];
        for &test in tests {
            assert_eq!(
                super::Sha3_256::digest(test.as_bytes())[..],
                // sha3::Keccak256::digest(test.as_bytes())[..],
                sha3::Sha3_256::digest(test.as_bytes())[..],
                "{test:?}"
            )
        }
    }

    #[test]
    // #[ignore = "TODO"]
    fn keccakf1600() {
        let mut buffer = [[1, 2, 3, 4, 5]; 5];
        // unsafe {
        //     super::memset(buffer.as_mut_ptr().cast(), 0x69, core::mem::size_of_val(&buffer));
        // }
        let cpy = buffer;
        super::keccak_f1600(&mut buffer);
        assert_ne!(buffer, cpy);
    }
}
