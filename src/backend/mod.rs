//! Compile-time backends for one-shot and streaming hashing.

use core::mem::MaybeUninit;
use digest::{typenum::Unsigned, Output, OutputSizeUser};
use selected::Lanes;

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

pub(crate) use selected::{absorb, squeeze, IMPL};

pub(crate) type Buffer = [u64; 25];

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
    } else if #[cfg(target_arch = "wasm32")] {
        mod scalar;
        use scalar as selected;
    } else {
        mod asm;
        use asm as selected;
    }
}

#[inline(always)]
pub(crate) unsafe fn digest<H: OutputSizeUser, const RATE: usize, const PAD: u8>(
    input: &[u8],
) -> Output<H> {
    // Specialize for common lengths to load input directly into the state registers.
    if const { RATE == 136 && PAD == crate::KECCAK } {
        match input.len() {
            20 => digest_const::<H, RATE, PAD, 20>(input.as_ptr()),
            32 => digest_const::<H, RATE, PAD, 32>(input.as_ptr()),
            64 => digest_const::<H, RATE, PAD, 64>(input.as_ptr()),
            len => digest_dyn::<H, RATE, PAD>(input.as_ptr(), len),
        }
    } else {
        digest_dyn::<H, RATE, PAD>(input.as_ptr(), input.len())
    }
}

#[inline(never)]
unsafe fn digest_const<H: OutputSizeUser, const RATE: usize, const PAD: u8, const LEN: usize>(
    input: *const u8,
) -> Output<H> {
    digest_inline::<H, RATE, PAD>(input, LEN)
}

#[inline(never)]
unsafe fn digest_dyn<H: OutputSizeUser, const RATE: usize, const PAD: u8>(
    input: *const u8,
    len: usize,
) -> Output<H> {
    digest_inline::<H, RATE, PAD>(input, len)
}

#[inline(always)]
unsafe fn digest_inline<H: OutputSizeUser, const RATE: usize, const PAD: u8>(
    input: *const u8,
    len: usize,
) -> Output<H> {
    assert_eq!(H::OutputSize::USIZE, (200 - RATE) / 2);
    let mut output = MaybeUninit::<Output<H>>::uninit();
    let mut lanes = Lanes::new();
    lanes.absorb_message::<RATE, PAD>(input, len);
    lanes.squeeze(output.as_mut_ptr().cast(), (200 - RATE) / 2);
    #[cfg(feature = "zeroize")]
    lanes.zeroize();
    output.assume_init()
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

#[allow(dead_code)]
#[inline(always)]
unsafe fn tail<const PAD: u8>(input: *const u8, len: usize) -> u64 {
    if PAD == 0 {
        return 0;
    }
    let remaining = len % 8;
    let mut input = input.add(len - remaining);
    let mut value = u64::from(PAD) << (remaining * 8);
    // Read only the trailing bytes; a padded block and a copy call are unnecessary.
    if remaining & 4 != 0 {
        value |= u64::from(core::ptr::read_unaligned(input.cast::<u32>()));
        input = input.add(4);
    }
    if remaining & 2 != 0 {
        value |= u64::from(core::ptr::read_unaligned(input.cast::<u16>())) << ((remaining & 4) * 8);
        input = input.add(2);
    }
    if remaining & 1 != 0 {
        value |= u64::from(input.read()) << ((remaining & 6) * 8);
    }
    value
}

#[allow(dead_code)]
#[inline(always)]
unsafe fn word<const PAD: u8>(
    input: *const u8,
    len: usize,
    rate: usize,
    lane: usize,
    tail: u64,
) -> u64 {
    let offset = lane * 8;
    if offset >= rate {
        return 0;
    }
    if PAD == 0 {
        return core::ptr::read_unaligned(input.add(offset).cast());
    }
    let mut value = if offset + 8 <= len {
        core::ptr::read_unaligned(input.add(offset).cast())
    } else if lane == len / 8 {
        tail
    } else {
        0
    };
    if offset == rate - 8 && len < rate {
        value |= 1 << 63;
    }
    value
}
