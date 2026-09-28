//! Keccak-f[1600] using one state lane per NEON register.

use super::RC;
use core::{arch::aarch64::*, ptr};
use sha3_asm::Buffer;

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

#[inline(always)]
pub(crate) unsafe fn absorb(
    state: *mut Buffer,
    input: *const u8,
    len: usize,
    rate: usize,
) -> usize {
    let mut lanes = Lanes::load(&*state);
    let rem = lanes.absorb(input, len, rate);
    lanes.store(&mut *state);
    rem
}

pub(super) struct Lanes {
    a0: uint64x2_t,
    a1: uint64x2_t,
    a2: uint64x2_t,
    a3: uint64x2_t,
    a4: uint64x2_t,
    a5: uint64x2_t,
    a6: uint64x2_t,
    a7: uint64x2_t,
    a8: uint64x2_t,
    a9: uint64x2_t,
    a10: uint64x2_t,
    a11: uint64x2_t,
    a12: uint64x2_t,
    a13: uint64x2_t,
    a14: uint64x2_t,
    a15: uint64x2_t,
    a16: uint64x2_t,
    a17: uint64x2_t,
    a18: uint64x2_t,
    a19: uint64x2_t,
    a20: uint64x2_t,
    a21: uint64x2_t,
    a22: uint64x2_t,
    a23: uint64x2_t,
    a24: uint64x2_t,
}

impl Lanes {
    #[inline(always)]
    pub(super) unsafe fn new() -> Self {
        unsafe { core::mem::zeroed() }
    }

    #[inline(always)]
    pub(super) unsafe fn load(state: &Buffer) -> Self {
        Self {
            a0: vdupq_n_u64(state[0]),
            a1: vdupq_n_u64(state[1]),
            a2: vdupq_n_u64(state[2]),
            a3: vdupq_n_u64(state[3]),
            a4: vdupq_n_u64(state[4]),
            a5: vdupq_n_u64(state[5]),
            a6: vdupq_n_u64(state[6]),
            a7: vdupq_n_u64(state[7]),
            a8: vdupq_n_u64(state[8]),
            a9: vdupq_n_u64(state[9]),
            a10: vdupq_n_u64(state[10]),
            a11: vdupq_n_u64(state[11]),
            a12: vdupq_n_u64(state[12]),
            a13: vdupq_n_u64(state[13]),
            a14: vdupq_n_u64(state[14]),
            a15: vdupq_n_u64(state[15]),
            a16: vdupq_n_u64(state[16]),
            a17: vdupq_n_u64(state[17]),
            a18: vdupq_n_u64(state[18]),
            a19: vdupq_n_u64(state[19]),
            a20: vdupq_n_u64(state[20]),
            a21: vdupq_n_u64(state[21]),
            a22: vdupq_n_u64(state[22]),
            a23: vdupq_n_u64(state[23]),
            a24: vdupq_n_u64(state[24]),
        }
    }

    #[inline(always)]
    pub(super) unsafe fn absorb(
        &mut self,
        mut input: *const u8,
        mut len: usize,
        rate: usize,
    ) -> usize {
        while len >= rate {
            self.absorb_block::<0>(input, rate, rate);
            self.permute();
            input = input.add(rate);
            len -= rate;
        }
        len
    }

    #[inline(always)]
    pub(super) unsafe fn absorb_message<const RATE: usize, const PAD: u8>(
        &mut self,
        mut input: *const u8,
        mut len: usize,
    ) {
        while len >= RATE {
            self.absorb_block::<0>(input, RATE, RATE);
            self.permute();
            input = input.add(RATE);
            len -= RATE;
        }
        self.absorb_block::<PAD>(input, len, RATE);
        self.permute();
    }

    #[inline(always)]
    unsafe fn absorb_block<const PAD: u8>(&mut self, input: *const u8, len: usize, rate: usize) {
        let tail = super::tail::<PAD>(input, len);
        if 0 < rate / 8 {
            self.a0 =
                veorq_u64(self.a0, vdupq_n_u64(super::word::<PAD>(input, len, rate, 0, tail)));
        }
        if 1 < rate / 8 {
            self.a1 =
                veorq_u64(self.a1, vdupq_n_u64(super::word::<PAD>(input, len, rate, 1, tail)));
        }
        if 2 < rate / 8 {
            self.a2 =
                veorq_u64(self.a2, vdupq_n_u64(super::word::<PAD>(input, len, rate, 2, tail)));
        }
        if 3 < rate / 8 {
            self.a3 =
                veorq_u64(self.a3, vdupq_n_u64(super::word::<PAD>(input, len, rate, 3, tail)));
        }
        if 4 < rate / 8 {
            self.a4 =
                veorq_u64(self.a4, vdupq_n_u64(super::word::<PAD>(input, len, rate, 4, tail)));
        }
        if 5 < rate / 8 {
            self.a5 =
                veorq_u64(self.a5, vdupq_n_u64(super::word::<PAD>(input, len, rate, 5, tail)));
        }
        if 6 < rate / 8 {
            self.a6 =
                veorq_u64(self.a6, vdupq_n_u64(super::word::<PAD>(input, len, rate, 6, tail)));
        }
        if 7 < rate / 8 {
            self.a7 =
                veorq_u64(self.a7, vdupq_n_u64(super::word::<PAD>(input, len, rate, 7, tail)));
        }
        if 8 < rate / 8 {
            self.a8 =
                veorq_u64(self.a8, vdupq_n_u64(super::word::<PAD>(input, len, rate, 8, tail)));
        }
        if 9 < rate / 8 {
            self.a9 =
                veorq_u64(self.a9, vdupq_n_u64(super::word::<PAD>(input, len, rate, 9, tail)));
        }
        if 10 < rate / 8 {
            self.a10 =
                veorq_u64(self.a10, vdupq_n_u64(super::word::<PAD>(input, len, rate, 10, tail)));
        }
        if 11 < rate / 8 {
            self.a11 =
                veorq_u64(self.a11, vdupq_n_u64(super::word::<PAD>(input, len, rate, 11, tail)));
        }
        if 12 < rate / 8 {
            self.a12 =
                veorq_u64(self.a12, vdupq_n_u64(super::word::<PAD>(input, len, rate, 12, tail)));
        }
        if 13 < rate / 8 {
            self.a13 =
                veorq_u64(self.a13, vdupq_n_u64(super::word::<PAD>(input, len, rate, 13, tail)));
        }
        if 14 < rate / 8 {
            self.a14 =
                veorq_u64(self.a14, vdupq_n_u64(super::word::<PAD>(input, len, rate, 14, tail)));
        }
        if 15 < rate / 8 {
            self.a15 =
                veorq_u64(self.a15, vdupq_n_u64(super::word::<PAD>(input, len, rate, 15, tail)));
        }
        if 16 < rate / 8 {
            self.a16 =
                veorq_u64(self.a16, vdupq_n_u64(super::word::<PAD>(input, len, rate, 16, tail)));
        }
        if 17 < rate / 8 {
            self.a17 =
                veorq_u64(self.a17, vdupq_n_u64(super::word::<PAD>(input, len, rate, 17, tail)));
        }
        if 18 < rate / 8 {
            self.a18 =
                veorq_u64(self.a18, vdupq_n_u64(super::word::<PAD>(input, len, rate, 18, tail)));
        }
        if 19 < rate / 8 {
            self.a19 =
                veorq_u64(self.a19, vdupq_n_u64(super::word::<PAD>(input, len, rate, 19, tail)));
        }
        if 20 < rate / 8 {
            self.a20 =
                veorq_u64(self.a20, vdupq_n_u64(super::word::<PAD>(input, len, rate, 20, tail)));
        }
        if 21 < rate / 8 {
            self.a21 =
                veorq_u64(self.a21, vdupq_n_u64(super::word::<PAD>(input, len, rate, 21, tail)));
        }
        if 22 < rate / 8 {
            self.a22 =
                veorq_u64(self.a22, vdupq_n_u64(super::word::<PAD>(input, len, rate, 22, tail)));
        }
        if 23 < rate / 8 {
            self.a23 =
                veorq_u64(self.a23, vdupq_n_u64(super::word::<PAD>(input, len, rate, 23, tail)));
        }
        if 24 < rate / 8 {
            self.a24 =
                veorq_u64(self.a24, vdupq_n_u64(super::word::<PAD>(input, len, rate, 24, tail)));
        }
    }

    #[inline(always)]
    unsafe fn permute(&mut self) {
        for &rc in &RC {
            let c0 = xor3(xor3(self.a0, self.a5, self.a10), self.a15, self.a20);
            let c1 = xor3(xor3(self.a1, self.a6, self.a11), self.a16, self.a21);
            let c2 = xor3(xor3(self.a2, self.a7, self.a12), self.a17, self.a22);
            let c3 = xor3(xor3(self.a3, self.a8, self.a13), self.a18, self.a23);
            let c4 = xor3(xor3(self.a4, self.a9, self.a14), self.a19, self.a24);
            let d0 = theta(c4, c1);
            let d1 = theta(c0, c2);
            let d2 = theta(c1, c3);
            let d3 = theta(c2, c4);
            let d4 = theta(c3, c0);
            let b0 = veorq_u64(self.a0, d0);
            let b10 = rho::<1, 63>(self.a1, d1);
            let b20 = rho::<62, 2>(self.a2, d2);
            let b5 = rho::<28, 36>(self.a3, d3);
            let b15 = rho::<27, 37>(self.a4, d4);
            let b16 = rho::<36, 28>(self.a5, d0);
            let b1 = rho::<44, 20>(self.a6, d1);
            let b11 = rho::<6, 58>(self.a7, d2);
            let b21 = rho::<55, 9>(self.a8, d3);
            let b6 = rho::<20, 44>(self.a9, d4);
            let b7 = rho::<3, 61>(self.a10, d0);
            let b17 = rho::<10, 54>(self.a11, d1);
            let b2 = rho::<43, 21>(self.a12, d2);
            let b12 = rho::<25, 39>(self.a13, d3);
            let b22 = rho::<39, 25>(self.a14, d4);
            let b23 = rho::<41, 23>(self.a15, d0);
            let b8 = rho::<45, 19>(self.a16, d1);
            let b18 = rho::<15, 49>(self.a17, d2);
            let b3 = rho::<21, 43>(self.a18, d3);
            let b13 = rho::<8, 56>(self.a19, d4);
            let b14 = rho::<18, 46>(self.a20, d0);
            let b24 = rho::<2, 62>(self.a21, d1);
            let b9 = rho::<61, 3>(self.a22, d2);
            let b19 = rho::<56, 8>(self.a23, d3);
            let b4 = rho::<14, 50>(self.a24, d4);
            self.a0 = chi(b0, b1, b2);
            self.a1 = chi(b1, b2, b3);
            self.a2 = chi(b2, b3, b4);
            self.a3 = chi(b3, b4, b0);
            self.a4 = chi(b4, b0, b1);
            self.a5 = chi(b5, b6, b7);
            self.a6 = chi(b6, b7, b8);
            self.a7 = chi(b7, b8, b9);
            self.a8 = chi(b8, b9, b5);
            self.a9 = chi(b9, b5, b6);
            self.a10 = chi(b10, b11, b12);
            self.a11 = chi(b11, b12, b13);
            self.a12 = chi(b12, b13, b14);
            self.a13 = chi(b13, b14, b10);
            self.a14 = chi(b14, b10, b11);
            self.a15 = chi(b15, b16, b17);
            self.a16 = chi(b16, b17, b18);
            self.a17 = chi(b17, b18, b19);
            self.a18 = chi(b18, b19, b15);
            self.a19 = chi(b19, b15, b16);
            self.a20 = chi(b20, b21, b22);
            self.a21 = chi(b21, b22, b23);
            self.a22 = chi(b22, b23, b24);
            self.a23 = chi(b23, b24, b20);
            self.a24 = chi(b24, b20, b21);
            self.a0 = veorq_u64(self.a0, vdupq_n_u64(rc));
        }
    }

    #[inline(always)]
    pub(super) unsafe fn store(&self, state: &mut Buffer) {
        state[0] = vgetq_lane_u64::<0>(self.a0);
        state[1] = vgetq_lane_u64::<0>(self.a1);
        state[2] = vgetq_lane_u64::<0>(self.a2);
        state[3] = vgetq_lane_u64::<0>(self.a3);
        state[4] = vgetq_lane_u64::<0>(self.a4);
        state[5] = vgetq_lane_u64::<0>(self.a5);
        state[6] = vgetq_lane_u64::<0>(self.a6);
        state[7] = vgetq_lane_u64::<0>(self.a7);
        state[8] = vgetq_lane_u64::<0>(self.a8);
        state[9] = vgetq_lane_u64::<0>(self.a9);
        state[10] = vgetq_lane_u64::<0>(self.a10);
        state[11] = vgetq_lane_u64::<0>(self.a11);
        state[12] = vgetq_lane_u64::<0>(self.a12);
        state[13] = vgetq_lane_u64::<0>(self.a13);
        state[14] = vgetq_lane_u64::<0>(self.a14);
        state[15] = vgetq_lane_u64::<0>(self.a15);
        state[16] = vgetq_lane_u64::<0>(self.a16);
        state[17] = vgetq_lane_u64::<0>(self.a17);
        state[18] = vgetq_lane_u64::<0>(self.a18);
        state[19] = vgetq_lane_u64::<0>(self.a19);
        state[20] = vgetq_lane_u64::<0>(self.a20);
        state[21] = vgetq_lane_u64::<0>(self.a21);
        state[22] = vgetq_lane_u64::<0>(self.a22);
        state[23] = vgetq_lane_u64::<0>(self.a23);
        state[24] = vgetq_lane_u64::<0>(self.a24);
    }

    #[inline(always)]
    pub(super) unsafe fn squeeze(&self, output: *mut u8, len: usize) {
        if len > 0 {
            let word = (vgetq_lane_u64::<0>(self.a0)).to_le_bytes();
            ptr::copy_nonoverlapping(word.as_ptr(), output, len.min(8));
        }
        if len > 8 {
            let word = (vgetq_lane_u64::<0>(self.a1)).to_le_bytes();
            ptr::copy_nonoverlapping(word.as_ptr(), output.add(8), (len - 8).min(8));
        }
        if len > 16 {
            let word = (vgetq_lane_u64::<0>(self.a2)).to_le_bytes();
            ptr::copy_nonoverlapping(word.as_ptr(), output.add(16), (len - 16).min(8));
        }
        if len > 24 {
            let word = (vgetq_lane_u64::<0>(self.a3)).to_le_bytes();
            ptr::copy_nonoverlapping(word.as_ptr(), output.add(24), (len - 24).min(8));
        }
        if len > 32 {
            let word = (vgetq_lane_u64::<0>(self.a4)).to_le_bytes();
            ptr::copy_nonoverlapping(word.as_ptr(), output.add(32), (len - 32).min(8));
        }
        if len > 40 {
            let word = (vgetq_lane_u64::<0>(self.a5)).to_le_bytes();
            ptr::copy_nonoverlapping(word.as_ptr(), output.add(40), (len - 40).min(8));
        }
        if len > 48 {
            let word = (vgetq_lane_u64::<0>(self.a6)).to_le_bytes();
            ptr::copy_nonoverlapping(word.as_ptr(), output.add(48), (len - 48).min(8));
        }
        if len > 56 {
            let word = (vgetq_lane_u64::<0>(self.a7)).to_le_bytes();
            ptr::copy_nonoverlapping(word.as_ptr(), output.add(56), (len - 56).min(8));
        }
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for Lanes {
    fn zeroize(&mut self) {
        self.a0.zeroize();
        self.a1.zeroize();
        self.a2.zeroize();
        self.a3.zeroize();
        self.a4.zeroize();
        self.a5.zeroize();
        self.a6.zeroize();
        self.a7.zeroize();
        self.a8.zeroize();
        self.a9.zeroize();
        self.a10.zeroize();
        self.a11.zeroize();
        self.a12.zeroize();
        self.a13.zeroize();
        self.a14.zeroize();
        self.a15.zeroize();
        self.a16.zeroize();
        self.a17.zeroize();
        self.a18.zeroize();
        self.a19.zeroize();
        self.a20.zeroize();
        self.a21.zeroize();
        self.a22.zeroize();
        self.a23.zeroize();
        self.a24.zeroize();
    }
}

#[inline(always)]
pub(crate) unsafe fn squeeze(state: *mut Buffer, output: *mut u8, len: usize, rate: usize) {
    // All supported fixed digests fit in the first rate block.
    debug_assert!(len <= rate);
    ptr::copy_nonoverlapping(state.cast::<u8>(), output, len);
}

pub(crate) const IMPL: &str = "keccak1600-aarch64-rust";

#[inline(always)]
unsafe fn xor3(a: uint64x2_t, b: uint64x2_t, c: uint64x2_t) -> uint64x2_t {
    #[cfg(target_feature = "sha3")]
    {
        veor3q_u64(a, b, c)
    }
    #[cfg(not(target_feature = "sha3"))]
    {
        veorq_u64(veorq_u64(a, b), c)
    }
}

#[inline(always)]
unsafe fn chi(a: uint64x2_t, b: uint64x2_t, c: uint64x2_t) -> uint64x2_t {
    #[cfg(target_feature = "sha3")]
    {
        vbcaxq_u64(a, c, b)
    }
    #[cfg(not(target_feature = "sha3"))]
    {
        veorq_u64(a, vbicq_u64(c, b))
    }
}

#[inline(always)]
unsafe fn theta(a: uint64x2_t, b: uint64x2_t) -> uint64x2_t {
    #[cfg(target_feature = "sha3")]
    {
        vrax1q_u64(a, b)
    }
    #[cfg(not(target_feature = "sha3"))]
    {
        veorq_u64(a, vorrq_u64(vshlq_n_u64::<1>(b), vshrq_n_u64::<63>(b)))
    }
}

#[inline(always)]
unsafe fn rho<const LEFT: i32, const RIGHT: i32>(a: uint64x2_t, d: uint64x2_t) -> uint64x2_t {
    #[cfg(target_feature = "sha3")]
    {
        vxarq_u64::<RIGHT>(a, d)
    }
    #[cfg(not(target_feature = "sha3"))]
    {
        let a = veorq_u64(a, d);
        vorrq_u64(vshlq_n_u64::<LEFT>(a), vshrq_n_u64::<RIGHT>(a))
    }
}
