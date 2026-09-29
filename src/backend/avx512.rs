//! Keccak-f[1600] using one state lane per XMM register.

use super::{Buffer, RC};
use core::{arch::x86_64::*, ptr};

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
    a0: __m128i,
    a1: __m128i,
    a2: __m128i,
    a3: __m128i,
    a4: __m128i,
    a5: __m128i,
    a6: __m128i,
    a7: __m128i,
    a8: __m128i,
    a9: __m128i,
    a10: __m128i,
    a11: __m128i,
    a12: __m128i,
    a13: __m128i,
    a14: __m128i,
    a15: __m128i,
    a16: __m128i,
    a17: __m128i,
    a18: __m128i,
    a19: __m128i,
    a20: __m128i,
    a21: __m128i,
    a22: __m128i,
    a23: __m128i,
    a24: __m128i,
}

impl Lanes {
    #[inline(always)]
    pub(super) unsafe fn new() -> Self {
        unsafe { core::mem::zeroed() }
    }

    #[inline(always)]
    pub(super) unsafe fn load(state: &Buffer) -> Self {
        Self {
            a0: _mm_cvtsi64_si128(state[0] as i64),
            a1: _mm_cvtsi64_si128(state[1] as i64),
            a2: _mm_cvtsi64_si128(state[2] as i64),
            a3: _mm_cvtsi64_si128(state[3] as i64),
            a4: _mm_cvtsi64_si128(state[4] as i64),
            a5: _mm_cvtsi64_si128(state[5] as i64),
            a6: _mm_cvtsi64_si128(state[6] as i64),
            a7: _mm_cvtsi64_si128(state[7] as i64),
            a8: _mm_cvtsi64_si128(state[8] as i64),
            a9: _mm_cvtsi64_si128(state[9] as i64),
            a10: _mm_cvtsi64_si128(state[10] as i64),
            a11: _mm_cvtsi64_si128(state[11] as i64),
            a12: _mm_cvtsi64_si128(state[12] as i64),
            a13: _mm_cvtsi64_si128(state[13] as i64),
            a14: _mm_cvtsi64_si128(state[14] as i64),
            a15: _mm_cvtsi64_si128(state[15] as i64),
            a16: _mm_cvtsi64_si128(state[16] as i64),
            a17: _mm_cvtsi64_si128(state[17] as i64),
            a18: _mm_cvtsi64_si128(state[18] as i64),
            a19: _mm_cvtsi64_si128(state[19] as i64),
            a20: _mm_cvtsi64_si128(state[20] as i64),
            a21: _mm_cvtsi64_si128(state[21] as i64),
            a22: _mm_cvtsi64_si128(state[22] as i64),
            a23: _mm_cvtsi64_si128(state[23] as i64),
            a24: _mm_cvtsi64_si128(state[24] as i64),
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
        loop {
            let last = len < RATE;
            self.absorb_block::<PAD>(input, len.min(RATE), RATE);
            self.permute();
            if last {
                break;
            }
            input = input.add(RATE);
            len -= RATE;
        }
    }

    #[inline(always)]
    unsafe fn absorb_block<const PAD: u8>(&mut self, input: *const u8, len: usize, rate: usize) {
        let tail = super::tail::<PAD>(input, len);
        if 0 < rate / 8 {
            self.a0 = _mm_xor_si128(
                self.a0,
                _mm_cvtsi64_si128(super::word::<PAD>(input, len, rate, 0, tail) as i64),
            );
        }
        if 1 < rate / 8 {
            self.a1 = _mm_xor_si128(
                self.a1,
                _mm_cvtsi64_si128(super::word::<PAD>(input, len, rate, 1, tail) as i64),
            );
        }
        if 2 < rate / 8 {
            self.a2 = _mm_xor_si128(
                self.a2,
                _mm_cvtsi64_si128(super::word::<PAD>(input, len, rate, 2, tail) as i64),
            );
        }
        if 3 < rate / 8 {
            self.a3 = _mm_xor_si128(
                self.a3,
                _mm_cvtsi64_si128(super::word::<PAD>(input, len, rate, 3, tail) as i64),
            );
        }
        if 4 < rate / 8 {
            self.a4 = _mm_xor_si128(
                self.a4,
                _mm_cvtsi64_si128(super::word::<PAD>(input, len, rate, 4, tail) as i64),
            );
        }
        if 5 < rate / 8 {
            self.a5 = _mm_xor_si128(
                self.a5,
                _mm_cvtsi64_si128(super::word::<PAD>(input, len, rate, 5, tail) as i64),
            );
        }
        if 6 < rate / 8 {
            self.a6 = _mm_xor_si128(
                self.a6,
                _mm_cvtsi64_si128(super::word::<PAD>(input, len, rate, 6, tail) as i64),
            );
        }
        if 7 < rate / 8 {
            self.a7 = _mm_xor_si128(
                self.a7,
                _mm_cvtsi64_si128(super::word::<PAD>(input, len, rate, 7, tail) as i64),
            );
        }
        if 8 < rate / 8 {
            self.a8 = _mm_xor_si128(
                self.a8,
                _mm_cvtsi64_si128(super::word::<PAD>(input, len, rate, 8, tail) as i64),
            );
        }
        if 9 < rate / 8 {
            self.a9 = _mm_xor_si128(
                self.a9,
                _mm_cvtsi64_si128(super::word::<PAD>(input, len, rate, 9, tail) as i64),
            );
        }
        if 10 < rate / 8 {
            self.a10 = _mm_xor_si128(
                self.a10,
                _mm_cvtsi64_si128(super::word::<PAD>(input, len, rate, 10, tail) as i64),
            );
        }
        if 11 < rate / 8 {
            self.a11 = _mm_xor_si128(
                self.a11,
                _mm_cvtsi64_si128(super::word::<PAD>(input, len, rate, 11, tail) as i64),
            );
        }
        if 12 < rate / 8 {
            self.a12 = _mm_xor_si128(
                self.a12,
                _mm_cvtsi64_si128(super::word::<PAD>(input, len, rate, 12, tail) as i64),
            );
        }
        if 13 < rate / 8 {
            self.a13 = _mm_xor_si128(
                self.a13,
                _mm_cvtsi64_si128(super::word::<PAD>(input, len, rate, 13, tail) as i64),
            );
        }
        if 14 < rate / 8 {
            self.a14 = _mm_xor_si128(
                self.a14,
                _mm_cvtsi64_si128(super::word::<PAD>(input, len, rate, 14, tail) as i64),
            );
        }
        if 15 < rate / 8 {
            self.a15 = _mm_xor_si128(
                self.a15,
                _mm_cvtsi64_si128(super::word::<PAD>(input, len, rate, 15, tail) as i64),
            );
        }
        if 16 < rate / 8 {
            self.a16 = _mm_xor_si128(
                self.a16,
                _mm_cvtsi64_si128(super::word::<PAD>(input, len, rate, 16, tail) as i64),
            );
        }
        if 17 < rate / 8 {
            self.a17 = _mm_xor_si128(
                self.a17,
                _mm_cvtsi64_si128(super::word::<PAD>(input, len, rate, 17, tail) as i64),
            );
        }
        if 18 < rate / 8 {
            self.a18 = _mm_xor_si128(
                self.a18,
                _mm_cvtsi64_si128(super::word::<PAD>(input, len, rate, 18, tail) as i64),
            );
        }
        if 19 < rate / 8 {
            self.a19 = _mm_xor_si128(
                self.a19,
                _mm_cvtsi64_si128(super::word::<PAD>(input, len, rate, 19, tail) as i64),
            );
        }
        if 20 < rate / 8 {
            self.a20 = _mm_xor_si128(
                self.a20,
                _mm_cvtsi64_si128(super::word::<PAD>(input, len, rate, 20, tail) as i64),
            );
        }
        if 21 < rate / 8 {
            self.a21 = _mm_xor_si128(
                self.a21,
                _mm_cvtsi64_si128(super::word::<PAD>(input, len, rate, 21, tail) as i64),
            );
        }
        if 22 < rate / 8 {
            self.a22 = _mm_xor_si128(
                self.a22,
                _mm_cvtsi64_si128(super::word::<PAD>(input, len, rate, 22, tail) as i64),
            );
        }
        if 23 < rate / 8 {
            self.a23 = _mm_xor_si128(
                self.a23,
                _mm_cvtsi64_si128(super::word::<PAD>(input, len, rate, 23, tail) as i64),
            );
        }
        if 24 < rate / 8 {
            self.a24 = _mm_xor_si128(
                self.a24,
                _mm_cvtsi64_si128(super::word::<PAD>(input, len, rate, 24, tail) as i64),
            );
        }
    }

    #[inline(always)]
    unsafe fn permute(&mut self) {
        for &rc in &RC {
            let c0 = _mm_ternarylogic_epi64::<0x96>(
                _mm_ternarylogic_epi64::<0x96>(self.a0, self.a5, self.a10),
                self.a15,
                self.a20,
            );
            let c1 = _mm_ternarylogic_epi64::<0x96>(
                _mm_ternarylogic_epi64::<0x96>(self.a1, self.a6, self.a11),
                self.a16,
                self.a21,
            );
            let c2 = _mm_ternarylogic_epi64::<0x96>(
                _mm_ternarylogic_epi64::<0x96>(self.a2, self.a7, self.a12),
                self.a17,
                self.a22,
            );
            let c3 = _mm_ternarylogic_epi64::<0x96>(
                _mm_ternarylogic_epi64::<0x96>(self.a3, self.a8, self.a13),
                self.a18,
                self.a23,
            );
            let c4 = _mm_ternarylogic_epi64::<0x96>(
                _mm_ternarylogic_epi64::<0x96>(self.a4, self.a9, self.a14),
                self.a19,
                self.a24,
            );
            let r0 = _mm_rol_epi64::<1>(c1);
            self.a0 = _mm_ternarylogic_epi64::<0x96>(self.a0, c4, r0);
            self.a5 = _mm_ternarylogic_epi64::<0x96>(self.a5, c4, r0);
            self.a10 = _mm_ternarylogic_epi64::<0x96>(self.a10, c4, r0);
            self.a15 = _mm_ternarylogic_epi64::<0x96>(self.a15, c4, r0);
            self.a20 = _mm_ternarylogic_epi64::<0x96>(self.a20, c4, r0);
            let r1 = _mm_rol_epi64::<1>(c2);
            self.a1 = _mm_ternarylogic_epi64::<0x96>(self.a1, c0, r1);
            self.a6 = _mm_ternarylogic_epi64::<0x96>(self.a6, c0, r1);
            self.a11 = _mm_ternarylogic_epi64::<0x96>(self.a11, c0, r1);
            self.a16 = _mm_ternarylogic_epi64::<0x96>(self.a16, c0, r1);
            self.a21 = _mm_ternarylogic_epi64::<0x96>(self.a21, c0, r1);
            let r2 = _mm_rol_epi64::<1>(c3);
            self.a2 = _mm_ternarylogic_epi64::<0x96>(self.a2, c1, r2);
            self.a7 = _mm_ternarylogic_epi64::<0x96>(self.a7, c1, r2);
            self.a12 = _mm_ternarylogic_epi64::<0x96>(self.a12, c1, r2);
            self.a17 = _mm_ternarylogic_epi64::<0x96>(self.a17, c1, r2);
            self.a22 = _mm_ternarylogic_epi64::<0x96>(self.a22, c1, r2);
            let r3 = _mm_rol_epi64::<1>(c4);
            self.a3 = _mm_ternarylogic_epi64::<0x96>(self.a3, c2, r3);
            self.a8 = _mm_ternarylogic_epi64::<0x96>(self.a8, c2, r3);
            self.a13 = _mm_ternarylogic_epi64::<0x96>(self.a13, c2, r3);
            self.a18 = _mm_ternarylogic_epi64::<0x96>(self.a18, c2, r3);
            self.a23 = _mm_ternarylogic_epi64::<0x96>(self.a23, c2, r3);
            let r4 = _mm_rol_epi64::<1>(c0);
            self.a4 = _mm_ternarylogic_epi64::<0x96>(self.a4, c3, r4);
            self.a9 = _mm_ternarylogic_epi64::<0x96>(self.a9, c3, r4);
            self.a14 = _mm_ternarylogic_epi64::<0x96>(self.a14, c3, r4);
            self.a19 = _mm_ternarylogic_epi64::<0x96>(self.a19, c3, r4);
            self.a24 = _mm_ternarylogic_epi64::<0x96>(self.a24, c3, r4);
            let b0 = _mm_rol_epi64::<0>(self.a0);
            let b10 = _mm_rol_epi64::<1>(self.a1);
            let b20 = _mm_rol_epi64::<62>(self.a2);
            let b5 = _mm_rol_epi64::<28>(self.a3);
            let b15 = _mm_rol_epi64::<27>(self.a4);
            let b16 = _mm_rol_epi64::<36>(self.a5);
            let b1 = _mm_rol_epi64::<44>(self.a6);
            let b11 = _mm_rol_epi64::<6>(self.a7);
            let b21 = _mm_rol_epi64::<55>(self.a8);
            let b6 = _mm_rol_epi64::<20>(self.a9);
            let b7 = _mm_rol_epi64::<3>(self.a10);
            let b17 = _mm_rol_epi64::<10>(self.a11);
            let b2 = _mm_rol_epi64::<43>(self.a12);
            let b12 = _mm_rol_epi64::<25>(self.a13);
            let b22 = _mm_rol_epi64::<39>(self.a14);
            let b23 = _mm_rol_epi64::<41>(self.a15);
            let b8 = _mm_rol_epi64::<45>(self.a16);
            let b18 = _mm_rol_epi64::<15>(self.a17);
            let b3 = _mm_rol_epi64::<21>(self.a18);
            let b13 = _mm_rol_epi64::<8>(self.a19);
            let b14 = _mm_rol_epi64::<18>(self.a20);
            let b24 = _mm_rol_epi64::<2>(self.a21);
            let b9 = _mm_rol_epi64::<61>(self.a22);
            let b19 = _mm_rol_epi64::<56>(self.a23);
            let b4 = _mm_rol_epi64::<14>(self.a24);
            self.a0 = _mm_ternarylogic_epi64::<0xd2>(b0, b1, b2);
            self.a1 = _mm_ternarylogic_epi64::<0xd2>(b1, b2, b3);
            self.a2 = _mm_ternarylogic_epi64::<0xd2>(b2, b3, b4);
            self.a3 = _mm_ternarylogic_epi64::<0xd2>(b3, b4, b0);
            self.a4 = _mm_ternarylogic_epi64::<0xd2>(b4, b0, b1);
            self.a5 = _mm_ternarylogic_epi64::<0xd2>(b5, b6, b7);
            self.a6 = _mm_ternarylogic_epi64::<0xd2>(b6, b7, b8);
            self.a7 = _mm_ternarylogic_epi64::<0xd2>(b7, b8, b9);
            self.a8 = _mm_ternarylogic_epi64::<0xd2>(b8, b9, b5);
            self.a9 = _mm_ternarylogic_epi64::<0xd2>(b9, b5, b6);
            self.a10 = _mm_ternarylogic_epi64::<0xd2>(b10, b11, b12);
            self.a11 = _mm_ternarylogic_epi64::<0xd2>(b11, b12, b13);
            self.a12 = _mm_ternarylogic_epi64::<0xd2>(b12, b13, b14);
            self.a13 = _mm_ternarylogic_epi64::<0xd2>(b13, b14, b10);
            self.a14 = _mm_ternarylogic_epi64::<0xd2>(b14, b10, b11);
            self.a15 = _mm_ternarylogic_epi64::<0xd2>(b15, b16, b17);
            self.a16 = _mm_ternarylogic_epi64::<0xd2>(b16, b17, b18);
            self.a17 = _mm_ternarylogic_epi64::<0xd2>(b17, b18, b19);
            self.a18 = _mm_ternarylogic_epi64::<0xd2>(b18, b19, b15);
            self.a19 = _mm_ternarylogic_epi64::<0xd2>(b19, b15, b16);
            self.a20 = _mm_ternarylogic_epi64::<0xd2>(b20, b21, b22);
            self.a21 = _mm_ternarylogic_epi64::<0xd2>(b21, b22, b23);
            self.a22 = _mm_ternarylogic_epi64::<0xd2>(b22, b23, b24);
            self.a23 = _mm_ternarylogic_epi64::<0xd2>(b23, b24, b20);
            self.a24 = _mm_ternarylogic_epi64::<0xd2>(b24, b20, b21);
            self.a0 = _mm_xor_si128(self.a0, _mm_set1_epi64x(rc as i64));
        }
    }

    #[inline(always)]
    pub(super) unsafe fn store(&self, state: &mut Buffer) {
        state[0] = _mm_cvtsi128_si64(self.a0) as u64;
        state[1] = _mm_cvtsi128_si64(self.a1) as u64;
        state[2] = _mm_cvtsi128_si64(self.a2) as u64;
        state[3] = _mm_cvtsi128_si64(self.a3) as u64;
        state[4] = _mm_cvtsi128_si64(self.a4) as u64;
        state[5] = _mm_cvtsi128_si64(self.a5) as u64;
        state[6] = _mm_cvtsi128_si64(self.a6) as u64;
        state[7] = _mm_cvtsi128_si64(self.a7) as u64;
        state[8] = _mm_cvtsi128_si64(self.a8) as u64;
        state[9] = _mm_cvtsi128_si64(self.a9) as u64;
        state[10] = _mm_cvtsi128_si64(self.a10) as u64;
        state[11] = _mm_cvtsi128_si64(self.a11) as u64;
        state[12] = _mm_cvtsi128_si64(self.a12) as u64;
        state[13] = _mm_cvtsi128_si64(self.a13) as u64;
        state[14] = _mm_cvtsi128_si64(self.a14) as u64;
        state[15] = _mm_cvtsi128_si64(self.a15) as u64;
        state[16] = _mm_cvtsi128_si64(self.a16) as u64;
        state[17] = _mm_cvtsi128_si64(self.a17) as u64;
        state[18] = _mm_cvtsi128_si64(self.a18) as u64;
        state[19] = _mm_cvtsi128_si64(self.a19) as u64;
        state[20] = _mm_cvtsi128_si64(self.a20) as u64;
        state[21] = _mm_cvtsi128_si64(self.a21) as u64;
        state[22] = _mm_cvtsi128_si64(self.a22) as u64;
        state[23] = _mm_cvtsi128_si64(self.a23) as u64;
        state[24] = _mm_cvtsi128_si64(self.a24) as u64;
    }

    #[inline(always)]
    pub(super) unsafe fn squeeze(&self, output: *mut u8, len: usize) {
        if len > 0 {
            let word = (_mm_cvtsi128_si64(self.a0) as u64).to_le_bytes();
            ptr::copy_nonoverlapping(word.as_ptr(), output, len.min(8));
        }
        if len > 8 {
            let word = (_mm_cvtsi128_si64(self.a1) as u64).to_le_bytes();
            ptr::copy_nonoverlapping(word.as_ptr(), output.add(8), (len - 8).min(8));
        }
        if len > 16 {
            let word = (_mm_cvtsi128_si64(self.a2) as u64).to_le_bytes();
            ptr::copy_nonoverlapping(word.as_ptr(), output.add(16), (len - 16).min(8));
        }
        if len > 24 {
            let word = (_mm_cvtsi128_si64(self.a3) as u64).to_le_bytes();
            ptr::copy_nonoverlapping(word.as_ptr(), output.add(24), (len - 24).min(8));
        }
        if len > 32 {
            let word = (_mm_cvtsi128_si64(self.a4) as u64).to_le_bytes();
            ptr::copy_nonoverlapping(word.as_ptr(), output.add(32), (len - 32).min(8));
        }
        if len > 40 {
            let word = (_mm_cvtsi128_si64(self.a5) as u64).to_le_bytes();
            ptr::copy_nonoverlapping(word.as_ptr(), output.add(40), (len - 40).min(8));
        }
        if len > 48 {
            let word = (_mm_cvtsi128_si64(self.a6) as u64).to_le_bytes();
            ptr::copy_nonoverlapping(word.as_ptr(), output.add(48), (len - 48).min(8));
        }
        if len > 56 {
            let word = (_mm_cvtsi128_si64(self.a7) as u64).to_le_bytes();
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

pub(crate) const IMPL: &str = "keccak1600-avx512vl-rust";
