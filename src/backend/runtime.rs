//! Run-time selection of the AVX-512 backend on x86-64.

use super::{avx512::Lanes, Buffer};
use core::{
    arch::x86_64::{__cpuid, __cpuid_count, _xgetbv},
    mem::MaybeUninit,
    sync::atomic::{AtomicU8, Ordering},
};
use digest::{typenum::Unsigned, Output, OutputSizeUser};

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

const UNKNOWN: u8 = 0;
const ABSENT: u8 = 1;
const PRESENT: u8 = 2;

static AVX512: AtomicU8 = AtomicU8::new(UNKNOWN);

/// Returns whether the CPU and the operating system support the AVX-512 backend.
///
/// The first call runs `cpuid`; later calls read the cached result.
#[inline(always)]
pub(super) fn avx512() -> bool {
    // The compile-time backend is already AVX-512.
    if cfg!(all(target_feature = "avx512f", target_feature = "avx512vl")) {
        return false;
    }
    match AVX512.load(Ordering::Relaxed) {
        UNKNOWN => detect(),
        state => state == PRESENT,
    }
}

#[cold]
#[inline(never)]
fn detect() -> bool {
    let present = unsafe { supported() };
    AVX512.store(if present { PRESENT } else { ABSENT }, Ordering::Relaxed);
    present
}

unsafe fn supported() -> bool {
    const OSXSAVE: u32 = 1 << 27;
    const AVX512F: u32 = 1 << 16;
    const AVX512VL: u32 = 1 << 31;
    // XMM, YMM, opmask, upper ZMM and ZMM16-31 state.
    const XCR0: u64 = 0xe6;

    if __cpuid(0).eax < 7 || __cpuid(1).ecx & OSXSAVE == 0 || xcr0() & XCR0 != XCR0 {
        return false;
    }
    let features = __cpuid_count(7, 0).ebx;
    features & (AVX512F | AVX512VL) == AVX512F | AVX512VL
}

#[target_feature(enable = "xsave")]
unsafe fn xcr0() -> u64 {
    _xgetbv(0)
}

#[target_feature(enable = "avx512f,avx512vl")]
pub(super) unsafe fn absorb(state: &mut Buffer, input: &[u8], rate: usize) -> usize {
    super::avx512::absorb(state, input, rate)
}

#[target_feature(enable = "avx512f,avx512vl")]
pub(super) unsafe fn digest_const<
    H: OutputSizeUser,
    const RATE: usize,
    const PAD: u8,
    const LEN: usize,
>(
    input: *const u8,
) -> Output<H> {
    digest_inline::<H, RATE, PAD>(input, LEN)
}

#[target_feature(enable = "avx512f,avx512vl")]
pub(super) unsafe fn digest_dyn<H: OutputSizeUser, const RATE: usize, const PAD: u8>(
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

#[target_feature(enable = "avx512f,avx512vl")]
pub(super) unsafe fn finalize<const RATE: usize, const PAD: u8>(
    state: &Buffer,
    input: *const u8,
    len: usize,
    out: *mut u8,
) {
    let mut lanes = Lanes::load(state);
    lanes.absorb_message::<RATE, PAD>(input, len);
    lanes.squeeze(out, (200 - RATE) / 2);
    #[cfg(feature = "zeroize")]
    lanes.zeroize();
}

#[cfg(test)]
mod tests {
    extern crate std;

    use super::*;

    #[test]
    fn detection_matches_std() {
        let expected =
            std::is_x86_feature_detected!("avx512f") && std::is_x86_feature_detected!("avx512vl");
        assert_eq!(unsafe { supported() }, expected);
    }
}
