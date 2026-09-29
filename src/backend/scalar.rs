//! Keccak-f[1600] using scalar lanes on WebAssembly.

use super::{Buffer, RC};
use core::ptr;

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

#[inline(never)]
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
    a0: u64,
    a1: u64,
    a2: u64,
    a3: u64,
    a4: u64,
    a5: u64,
    a6: u64,
    a7: u64,
    a8: u64,
    a9: u64,
    a10: u64,
    a11: u64,
    a12: u64,
    a13: u64,
    a14: u64,
    a15: u64,
    a16: u64,
    a17: u64,
    a18: u64,
    a19: u64,
    a20: u64,
    a21: u64,
    a22: u64,
    a23: u64,
    a24: u64,
}

impl Lanes {
    #[inline(always)]
    pub(super) unsafe fn new() -> Self {
        unsafe { core::mem::zeroed() }
    }

    #[inline(always)]
    pub(super) unsafe fn load(state: &Buffer) -> Self {
        Self {
            a0: state[0],
            a1: state[1],
            a2: state[2],
            a3: state[3],
            a4: state[4],
            a5: state[5],
            a6: state[6],
            a7: state[7],
            a8: state[8],
            a9: state[9],
            a10: state[10],
            a11: state[11],
            a12: state[12],
            a13: state[13],
            a14: state[14],
            a15: state[15],
            a16: state[16],
            a17: state[17],
            a18: state[18],
            a19: state[19],
            a20: state[20],
            a21: state[21],
            a22: state[22],
            a23: state[23],
            a24: state[24],
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
            self.a0 ^= super::word::<PAD>(input, len, rate, 0, tail);
        }
        if 1 < rate / 8 {
            self.a1 ^= super::word::<PAD>(input, len, rate, 1, tail);
        }
        if 2 < rate / 8 {
            self.a2 ^= super::word::<PAD>(input, len, rate, 2, tail);
        }
        if 3 < rate / 8 {
            self.a3 ^= super::word::<PAD>(input, len, rate, 3, tail);
        }
        if 4 < rate / 8 {
            self.a4 ^= super::word::<PAD>(input, len, rate, 4, tail);
        }
        if 5 < rate / 8 {
            self.a5 ^= super::word::<PAD>(input, len, rate, 5, tail);
        }
        if 6 < rate / 8 {
            self.a6 ^= super::word::<PAD>(input, len, rate, 6, tail);
        }
        if 7 < rate / 8 {
            self.a7 ^= super::word::<PAD>(input, len, rate, 7, tail);
        }
        if 8 < rate / 8 {
            self.a8 ^= super::word::<PAD>(input, len, rate, 8, tail);
        }
        if 9 < rate / 8 {
            self.a9 ^= super::word::<PAD>(input, len, rate, 9, tail);
        }
        if 10 < rate / 8 {
            self.a10 ^= super::word::<PAD>(input, len, rate, 10, tail);
        }
        if 11 < rate / 8 {
            self.a11 ^= super::word::<PAD>(input, len, rate, 11, tail);
        }
        if 12 < rate / 8 {
            self.a12 ^= super::word::<PAD>(input, len, rate, 12, tail);
        }
        if 13 < rate / 8 {
            self.a13 ^= super::word::<PAD>(input, len, rate, 13, tail);
        }
        if 14 < rate / 8 {
            self.a14 ^= super::word::<PAD>(input, len, rate, 14, tail);
        }
        if 15 < rate / 8 {
            self.a15 ^= super::word::<PAD>(input, len, rate, 15, tail);
        }
        if 16 < rate / 8 {
            self.a16 ^= super::word::<PAD>(input, len, rate, 16, tail);
        }
        if 17 < rate / 8 {
            self.a17 ^= super::word::<PAD>(input, len, rate, 17, tail);
        }
        if 18 < rate / 8 {
            self.a18 ^= super::word::<PAD>(input, len, rate, 18, tail);
        }
        if 19 < rate / 8 {
            self.a19 ^= super::word::<PAD>(input, len, rate, 19, tail);
        }
        if 20 < rate / 8 {
            self.a20 ^= super::word::<PAD>(input, len, rate, 20, tail);
        }
        if 21 < rate / 8 {
            self.a21 ^= super::word::<PAD>(input, len, rate, 21, tail);
        }
        if 22 < rate / 8 {
            self.a22 ^= super::word::<PAD>(input, len, rate, 22, tail);
        }
        if 23 < rate / 8 {
            self.a23 ^= super::word::<PAD>(input, len, rate, 23, tail);
        }
        if 24 < rate / 8 {
            self.a24 ^= super::word::<PAD>(input, len, rate, 24, tail);
        }
    }

    #[inline(always)]
    unsafe fn permute(&mut self) {
        for &rc in &RC {
            let c0 = self.a0 ^ self.a5 ^ self.a10 ^ self.a15 ^ self.a20;
            let c1 = self.a1 ^ self.a6 ^ self.a11 ^ self.a16 ^ self.a21;
            let c2 = self.a2 ^ self.a7 ^ self.a12 ^ self.a17 ^ self.a22;
            let c3 = self.a3 ^ self.a8 ^ self.a13 ^ self.a18 ^ self.a23;
            let c4 = self.a4 ^ self.a9 ^ self.a14 ^ self.a19 ^ self.a24;
            let d0 = c4 ^ c1.rotate_left(1);
            let d1 = c0 ^ c2.rotate_left(1);
            let d2 = c1 ^ c3.rotate_left(1);
            let d3 = c2 ^ c4.rotate_left(1);
            let d4 = c3 ^ c0.rotate_left(1);
            let b0 = self.a0 ^ d0;
            let b10 = (self.a1 ^ d1).rotate_left(1);
            let b20 = (self.a2 ^ d2).rotate_left(62);
            let b5 = (self.a3 ^ d3).rotate_left(28);
            let b15 = (self.a4 ^ d4).rotate_left(27);
            let b16 = (self.a5 ^ d0).rotate_left(36);
            let b1 = (self.a6 ^ d1).rotate_left(44);
            let b11 = (self.a7 ^ d2).rotate_left(6);
            let b21 = (self.a8 ^ d3).rotate_left(55);
            let b6 = (self.a9 ^ d4).rotate_left(20);
            let b7 = (self.a10 ^ d0).rotate_left(3);
            let b17 = (self.a11 ^ d1).rotate_left(10);
            let b2 = (self.a12 ^ d2).rotate_left(43);
            let b12 = (self.a13 ^ d3).rotate_left(25);
            let b22 = (self.a14 ^ d4).rotate_left(39);
            let b23 = (self.a15 ^ d0).rotate_left(41);
            let b8 = (self.a16 ^ d1).rotate_left(45);
            let b18 = (self.a17 ^ d2).rotate_left(15);
            let b3 = (self.a18 ^ d3).rotate_left(21);
            let b13 = (self.a19 ^ d4).rotate_left(8);
            let b14 = (self.a20 ^ d0).rotate_left(18);
            let b24 = (self.a21 ^ d1).rotate_left(2);
            let b9 = (self.a22 ^ d2).rotate_left(61);
            let b19 = (self.a23 ^ d3).rotate_left(56);
            let b4 = (self.a24 ^ d4).rotate_left(14);
            self.a0 = b0 ^ (!b1 & b2);
            self.a1 = b1 ^ (!b2 & b3);
            self.a2 = b2 ^ (!b3 & b4);
            self.a3 = b3 ^ (!b4 & b0);
            self.a4 = b4 ^ (!b0 & b1);
            self.a5 = b5 ^ (!b6 & b7);
            self.a6 = b6 ^ (!b7 & b8);
            self.a7 = b7 ^ (!b8 & b9);
            self.a8 = b8 ^ (!b9 & b5);
            self.a9 = b9 ^ (!b5 & b6);
            self.a10 = b10 ^ (!b11 & b12);
            self.a11 = b11 ^ (!b12 & b13);
            self.a12 = b12 ^ (!b13 & b14);
            self.a13 = b13 ^ (!b14 & b10);
            self.a14 = b14 ^ (!b10 & b11);
            self.a15 = b15 ^ (!b16 & b17);
            self.a16 = b16 ^ (!b17 & b18);
            self.a17 = b17 ^ (!b18 & b19);
            self.a18 = b18 ^ (!b19 & b15);
            self.a19 = b19 ^ (!b15 & b16);
            self.a20 = b20 ^ (!b21 & b22);
            self.a21 = b21 ^ (!b22 & b23);
            self.a22 = b22 ^ (!b23 & b24);
            self.a23 = b23 ^ (!b24 & b20);
            self.a24 = b24 ^ (!b20 & b21);
            self.a0 ^= rc;
        }
    }

    #[inline(always)]
    pub(super) unsafe fn store(&self, state: &mut Buffer) {
        state[0] = self.a0;
        state[1] = self.a1;
        state[2] = self.a2;
        state[3] = self.a3;
        state[4] = self.a4;
        state[5] = self.a5;
        state[6] = self.a6;
        state[7] = self.a7;
        state[8] = self.a8;
        state[9] = self.a9;
        state[10] = self.a10;
        state[11] = self.a11;
        state[12] = self.a12;
        state[13] = self.a13;
        state[14] = self.a14;
        state[15] = self.a15;
        state[16] = self.a16;
        state[17] = self.a17;
        state[18] = self.a18;
        state[19] = self.a19;
        state[20] = self.a20;
        state[21] = self.a21;
        state[22] = self.a22;
        state[23] = self.a23;
        state[24] = self.a24;
    }

    #[inline(always)]
    pub(super) unsafe fn squeeze(&self, output: *mut u8, len: usize) {
        if len > 0 {
            let word = self.a0.to_le_bytes();
            ptr::copy_nonoverlapping(word.as_ptr(), output, len.min(8));
        }
        if len > 8 {
            let word = self.a1.to_le_bytes();
            ptr::copy_nonoverlapping(word.as_ptr(), output.add(8), (len - 8).min(8));
        }
        if len > 16 {
            let word = self.a2.to_le_bytes();
            ptr::copy_nonoverlapping(word.as_ptr(), output.add(16), (len - 16).min(8));
        }
        if len > 24 {
            let word = self.a3.to_le_bytes();
            ptr::copy_nonoverlapping(word.as_ptr(), output.add(24), (len - 24).min(8));
        }
        if len > 32 {
            let word = self.a4.to_le_bytes();
            ptr::copy_nonoverlapping(word.as_ptr(), output.add(32), (len - 32).min(8));
        }
        if len > 40 {
            let word = self.a5.to_le_bytes();
            ptr::copy_nonoverlapping(word.as_ptr(), output.add(40), (len - 40).min(8));
        }
        if len > 48 {
            let word = self.a6.to_le_bytes();
            ptr::copy_nonoverlapping(word.as_ptr(), output.add(48), (len - 48).min(8));
        }
        if len > 56 {
            let word = self.a7.to_le_bytes();
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
    Lanes::load(&*state).squeeze(output, len);
}

pub(crate) const IMPL: &str = "keccak1600-scalar-rust";
