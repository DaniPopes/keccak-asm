//! Keccak-f[1600] with seven packed YMM registers.

// Copyright (c) 2017, CRYPTOGAMS by <appro@openssl.org>.
// Adapted from Andy Polyakov's Cryptogams keccak1600-avx2.pl (BSD-3-Clause).

use super::RC;
use core::{arch::x86_64::*, ptr};
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
    a00: __m256i,
    a01: __m256i,
    a20: __m256i,
    a31: __m256i,
    a21: __m256i,
    a41: __m256i,
    a11: __m256i,
}

impl Lanes {
    #[inline(always)]
    pub(super) unsafe fn new() -> Self {
        Self {
            a00: _mm256_setzero_si256(),
            a01: _mm256_setzero_si256(),
            a20: _mm256_setzero_si256(),
            a31: _mm256_setzero_si256(),
            a21: _mm256_setzero_si256(),
            a41: _mm256_setzero_si256(),
            a11: _mm256_setzero_si256(),
        }
    }

    #[inline(always)]
    pub(super) unsafe fn load(state: &Buffer) -> Self {
        Self {
            a00: _mm256_set_epi64x(
                state[0] as i64,
                state[0] as i64,
                state[0] as i64,
                state[0] as i64,
            ),
            a01: _mm256_set_epi64x(
                state[4] as i64,
                state[3] as i64,
                state[2] as i64,
                state[1] as i64,
            ),
            a20: _mm256_set_epi64x(
                state[15] as i64,
                state[5] as i64,
                state[20] as i64,
                state[10] as i64,
            ),
            a31: _mm256_set_epi64x(
                state[14] as i64,
                state[23] as i64,
                state[7] as i64,
                state[16] as i64,
            ),
            a21: _mm256_set_epi64x(
                state[19] as i64,
                state[8] as i64,
                state[22] as i64,
                state[11] as i64,
            ),
            a41: _mm256_set_epi64x(
                state[9] as i64,
                state[13] as i64,
                state[17] as i64,
                state[21] as i64,
            ),
            a11: _mm256_set_epi64x(
                state[24] as i64,
                state[18] as i64,
                state[12] as i64,
                state[6] as i64,
            ),
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
            self.a00 = _mm256_xor_si256(
                self.a00,
                _mm256_set_epi64x(
                    word(input, rate, 0),
                    word(input, rate, 0),
                    word(input, rate, 0),
                    word(input, rate, 0),
                ),
            );
            self.a01 = _mm256_xor_si256(
                self.a01,
                _mm256_set_epi64x(
                    word(input, rate, 4),
                    word(input, rate, 3),
                    word(input, rate, 2),
                    word(input, rate, 1),
                ),
            );
            self.a20 = _mm256_xor_si256(
                self.a20,
                _mm256_set_epi64x(
                    word(input, rate, 15),
                    word(input, rate, 5),
                    word(input, rate, 20),
                    word(input, rate, 10),
                ),
            );
            self.a31 = _mm256_xor_si256(
                self.a31,
                _mm256_set_epi64x(
                    word(input, rate, 14),
                    word(input, rate, 23),
                    word(input, rate, 7),
                    word(input, rate, 16),
                ),
            );
            self.a21 = _mm256_xor_si256(
                self.a21,
                _mm256_set_epi64x(
                    word(input, rate, 19),
                    word(input, rate, 8),
                    word(input, rate, 22),
                    word(input, rate, 11),
                ),
            );
            self.a41 = _mm256_xor_si256(
                self.a41,
                _mm256_set_epi64x(
                    word(input, rate, 9),
                    word(input, rate, 13),
                    word(input, rate, 17),
                    word(input, rate, 21),
                ),
            );
            self.a11 = _mm256_xor_si256(
                self.a11,
                _mm256_set_epi64x(
                    word(input, rate, 24),
                    word(input, rate, 18),
                    word(input, rate, 12),
                    word(input, rate, 6),
                ),
            );
            for &rc in &RC {
                let mut t0;
                let mut t1;
                let mut t2;
                let mut t3;
                let mut t4;
                let mut t5;
                let mut t6;
                let mut t7;
                let mut t8;
                t6 = _mm256_shuffle_epi32::<78>(self.a20);
                t5 = _mm256_xor_si256(self.a41, self.a31);
                t2 = _mm256_xor_si256(self.a21, self.a11);
                t5 = _mm256_xor_si256(t5, self.a01);
                t5 = _mm256_xor_si256(t5, t2);
                t4 = _mm256_permute4x64_epi64::<147>(t5);
                t6 = _mm256_xor_si256(t6, self.a20);
                t0 = _mm256_permute4x64_epi64::<78>(t6);
                t1 = _mm256_srli_epi64::<63>(t5);
                t2 = _mm256_add_epi64(t5, t5);
                t1 = _mm256_or_si256(t1, t2);
                t8 = _mm256_permute4x64_epi64::<57>(t1);
                t7 = _mm256_xor_si256(t1, t4);
                t7 = _mm256_permute4x64_epi64::<0>(t7);
                t6 = _mm256_xor_si256(t6, self.a00);
                t6 = _mm256_xor_si256(t6, t0);
                t0 = _mm256_srli_epi64::<63>(t6);
                t1 = _mm256_add_epi64(t6, t6);
                t1 = _mm256_or_si256(t1, t0);
                self.a20 = _mm256_xor_si256(self.a20, t7);
                self.a00 = _mm256_xor_si256(self.a00, t7);
                t8 = _mm256_blend_epi32::<192>(t8, t1);
                t4 = _mm256_blend_epi32::<3>(t4, t6);
                t8 = _mm256_xor_si256(t8, t4);
                t3 = _mm256_sllv_epi64(self.a20, _mm256_set_epi64x(41, 36, 18, 3));
                self.a20 = _mm256_srlv_epi64(self.a20, _mm256_set_epi64x(23, 28, 46, 61));
                self.a20 = _mm256_or_si256(self.a20, t3);
                self.a31 = _mm256_xor_si256(self.a31, t8);
                t4 = _mm256_sllv_epi64(self.a31, _mm256_set_epi64x(39, 56, 6, 45));
                self.a31 = _mm256_srlv_epi64(self.a31, _mm256_set_epi64x(25, 8, 58, 19));
                self.a31 = _mm256_or_si256(self.a31, t4);
                self.a21 = _mm256_xor_si256(self.a21, t8);
                t5 = _mm256_sllv_epi64(self.a21, _mm256_set_epi64x(8, 55, 61, 10));
                self.a21 = _mm256_srlv_epi64(self.a21, _mm256_set_epi64x(56, 9, 3, 54));
                self.a21 = _mm256_or_si256(self.a21, t5);
                self.a41 = _mm256_xor_si256(self.a41, t8);
                t6 = _mm256_sllv_epi64(self.a41, _mm256_set_epi64x(20, 25, 15, 2));
                self.a41 = _mm256_srlv_epi64(self.a41, _mm256_set_epi64x(44, 39, 49, 62));
                self.a41 = _mm256_or_si256(self.a41, t6);
                self.a11 = _mm256_xor_si256(self.a11, t8);
                t3 = _mm256_permute4x64_epi64::<141>(self.a20);
                t4 = _mm256_permute4x64_epi64::<141>(self.a31);
                t7 = _mm256_sllv_epi64(self.a11, _mm256_set_epi64x(14, 21, 43, 44));
                t1 = _mm256_srlv_epi64(self.a11, _mm256_set_epi64x(50, 43, 21, 20));
                t1 = _mm256_or_si256(t1, t7);
                self.a01 = _mm256_xor_si256(self.a01, t8);
                t5 = _mm256_permute4x64_epi64::<27>(self.a21);
                t6 = _mm256_permute4x64_epi64::<114>(self.a41);
                t8 = _mm256_sllv_epi64(self.a01, _mm256_set_epi64x(27, 28, 62, 1));
                t2 = _mm256_srlv_epi64(self.a01, _mm256_set_epi64x(37, 36, 2, 63));
                t2 = _mm256_or_si256(t2, t8);

                self.a20 = chi(t2, mix(t4, t5, t6, t3), mix(t6, t4, t3, t5));
                self.a31 = _mm256_permute4x64_epi64::<27>(chi(
                    t3,
                    mix(t2, t6, t4, t5),
                    mix(t4, t2, t5, t6),
                ));
                self.a21 = chi(t4, mix(t6, t3, t5, t2), mix(t5, t6, t2, t3));
                self.a41 = _mm256_permute4x64_epi64::<141>(chi(
                    t5,
                    mix(t3, t4, t2, t6),
                    mix(t2, t3, t6, t4),
                ));
                self.a11 = _mm256_permute4x64_epi64::<114>(chi(
                    t6,
                    mix(t5, t2, t3, t4),
                    mix(t3, t5, t4, t2),
                ));
                self.a01 = chi(
                    t1,
                    _mm256_blend_epi32::<192>(_mm256_permute4x64_epi64::<57>(t1), self.a00),
                    _mm256_blend_epi32::<48>(_mm256_permute4x64_epi64::<30>(t1), self.a00),
                );
                self.a00 = _mm256_xor_si256(
                    self.a00,
                    _mm256_permute4x64_epi64::<0>(_mm256_andnot_si256(
                        t1,
                        _mm256_srli_si256::<8>(t1),
                    )),
                );
                self.a00 = _mm256_xor_si256(self.a00, _mm256_set1_epi64x(rc as i64));
            }
            input = input.add(rate);
            len -= rate;
        }
        len
    }

    #[inline(always)]
    pub(super) unsafe fn store(&self, state: &mut Buffer) {
        state[0] = _mm256_extract_epi64::<0>(self.a00) as u64;
        state[1] = _mm256_extract_epi64::<0>(self.a01) as u64;
        state[2] = _mm256_extract_epi64::<1>(self.a01) as u64;
        state[3] = _mm256_extract_epi64::<2>(self.a01) as u64;
        state[4] = _mm256_extract_epi64::<3>(self.a01) as u64;
        state[10] = _mm256_extract_epi64::<0>(self.a20) as u64;
        state[20] = _mm256_extract_epi64::<1>(self.a20) as u64;
        state[5] = _mm256_extract_epi64::<2>(self.a20) as u64;
        state[15] = _mm256_extract_epi64::<3>(self.a20) as u64;
        state[16] = _mm256_extract_epi64::<0>(self.a31) as u64;
        state[7] = _mm256_extract_epi64::<1>(self.a31) as u64;
        state[23] = _mm256_extract_epi64::<2>(self.a31) as u64;
        state[14] = _mm256_extract_epi64::<3>(self.a31) as u64;
        state[11] = _mm256_extract_epi64::<0>(self.a21) as u64;
        state[22] = _mm256_extract_epi64::<1>(self.a21) as u64;
        state[8] = _mm256_extract_epi64::<2>(self.a21) as u64;
        state[19] = _mm256_extract_epi64::<3>(self.a21) as u64;
        state[21] = _mm256_extract_epi64::<0>(self.a41) as u64;
        state[17] = _mm256_extract_epi64::<1>(self.a41) as u64;
        state[13] = _mm256_extract_epi64::<2>(self.a41) as u64;
        state[9] = _mm256_extract_epi64::<3>(self.a41) as u64;
        state[6] = _mm256_extract_epi64::<0>(self.a11) as u64;
        state[12] = _mm256_extract_epi64::<1>(self.a11) as u64;
        state[18] = _mm256_extract_epi64::<2>(self.a11) as u64;
        state[24] = _mm256_extract_epi64::<3>(self.a11) as u64;
    }

    #[inline(always)]
    pub(super) unsafe fn squeeze(&self, output: *mut u8, len: usize) {
        if len > 0 {
            let word = (_mm256_extract_epi64::<0>(self.a00) as u64).to_le_bytes();
            ptr::copy_nonoverlapping(word.as_ptr(), output, len.min(8));
        }
        if len > 8 {
            let word = (_mm256_extract_epi64::<0>(self.a01) as u64).to_le_bytes();
            ptr::copy_nonoverlapping(word.as_ptr(), output.add(8), (len - 8).min(8));
        }
        if len > 16 {
            let word = (_mm256_extract_epi64::<1>(self.a01) as u64).to_le_bytes();
            ptr::copy_nonoverlapping(word.as_ptr(), output.add(16), (len - 16).min(8));
        }
        if len > 24 {
            let word = (_mm256_extract_epi64::<2>(self.a01) as u64).to_le_bytes();
            ptr::copy_nonoverlapping(word.as_ptr(), output.add(24), (len - 24).min(8));
        }
        if len > 32 {
            let word = (_mm256_extract_epi64::<3>(self.a01) as u64).to_le_bytes();
            ptr::copy_nonoverlapping(word.as_ptr(), output.add(32), (len - 32).min(8));
        }
        if len > 40 {
            let word = (_mm256_extract_epi64::<2>(self.a20) as u64).to_le_bytes();
            ptr::copy_nonoverlapping(word.as_ptr(), output.add(40), (len - 40).min(8));
        }
        if len > 48 {
            let word = (_mm256_extract_epi64::<0>(self.a11) as u64).to_le_bytes();
            ptr::copy_nonoverlapping(word.as_ptr(), output.add(48), (len - 48).min(8));
        }
        if len > 56 {
            let word = (_mm256_extract_epi64::<1>(self.a31) as u64).to_le_bytes();
            ptr::copy_nonoverlapping(word.as_ptr(), output.add(56), (len - 56).min(8));
        }
    }
}
#[cfg(feature = "zeroize")]
impl Zeroize for Lanes {
    fn zeroize(&mut self) {
        self.a00.zeroize();
        self.a01.zeroize();
        self.a20.zeroize();
        self.a31.zeroize();
        self.a21.zeroize();
        self.a41.zeroize();
        self.a11.zeroize();
    }
}
#[inline(always)]
pub(crate) unsafe fn squeeze(state: *mut Buffer, output: *mut u8, len: usize, rate: usize) {
    // All supported fixed digests fit in the first rate block.
    debug_assert!(len <= rate);
    ptr::copy_nonoverlapping(state.cast::<u8>(), output, len);
}

pub(crate) const IMPL: &str = "keccak1600-avx2-rust";

#[inline(always)]
unsafe fn word(input: *const u8, rate: usize, lane: usize) -> i64 {
    if lane < rate / 8 {
        ptr::read_unaligned(input.add(lane * 8).cast::<i64>())
    } else {
        0
    }
}

#[inline(always)]
unsafe fn mix(a: __m256i, b: __m256i, c: __m256i, d: __m256i) -> __m256i {
    // Use two blend levels to select [a[0], b[1], c[2], d[3]].
    _mm256_blend_epi32::<60>(_mm256_blend_epi32::<192>(a, d), _mm256_blend_epi32::<48>(b, c))
}

#[inline(always)]
unsafe fn chi(a: __m256i, b: __m256i, c: __m256i) -> __m256i {
    _mm256_xor_si256(a, _mm256_andnot_si256(b, c))
}
