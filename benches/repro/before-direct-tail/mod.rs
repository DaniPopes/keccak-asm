//! Compile-time backends for one-shot and streaming hashing.

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

cfg_if::cfg_if! {
    if #[cfg(all(target_arch = "x86_64", target_feature = "avx512f", target_feature = "avx512vl"))] {
        mod avx512;
        use avx512 as selected;
    } else if #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))] {
        mod avx2;
        use avx2 as selected;
    } else if #[cfg(all(target_arch = "aarch64", target_feature = "neon", target_endian = "little"))] {
        mod aarch64;
        use aarch64 as selected;
    } else {
        mod asm;
        use asm as selected;
    }
}

use selected::Lanes;

pub(crate) use selected::{absorb, squeeze, IMPL};

#[inline(always)]
pub(crate) unsafe fn digest<const RATE: usize, const PAD: u8>(input: &[u8], output: *mut u8) {
    let rate = RATE;
    // Prepare padding before the lanes become live to avoid spills across a copy call.
    let rem = input.len() % rate;
    let mut block = [0; RATE];
    block[..rem].copy_from_slice(&input[input.len() - rem..]);
    block[rem] = PAD;
    block[rate - 1] |= 0x80;
    let mut lanes = Lanes::new();
    lanes.absorb(input.as_ptr(), input.len() - rem, rate);
    lanes.absorb(block.as_ptr(), rate, rate);
    lanes.squeeze(output, (200 - RATE) / 2);
    #[cfg(feature = "zeroize")]
    {
        lanes.zeroize();
        block.zeroize();
    }
}

#[allow(dead_code)]
const RC: [u64; 24] = [
    0x1,
    0x8082,
    0x800000000000808a,
    0x8000000080008000,
    0x808b,
    0x80000001,
    0x8000000080008081,
    0x8000000000008009,
    0x8a,
    0x88,
    0x80008009,
    0x8000000a,
    0x8000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x80000001,
    0x8000000080008008,
];
