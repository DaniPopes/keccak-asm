//! Adapter for targets using the assembly backend.

use sha3_asm::Buffer;

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

pub(crate) use sha3_asm::{SHA3_absorb as absorb, SHA3_squeeze as squeeze, IMPL};

pub(super) struct Lanes(Buffer);

impl Lanes {
    #[inline(always)]
    pub(super) fn new() -> Self {
        unsafe { core::mem::zeroed() }
    }

    #[inline(always)]
    pub(super) unsafe fn absorb(&mut self, input: *const u8, len: usize, rate: usize) -> usize {
        absorb(&mut self.0, input, len, rate)
    }

    #[inline(always)]
    pub(super) unsafe fn absorb_message<const RATE: usize, const PAD: u8>(
        &mut self,
        input: *const u8,
        len: usize,
    ) {
        let rem = if len >= RATE { self.absorb(input, len, RATE) } else { len };
        let mut block = [0; RATE];
        core::ptr::copy_nonoverlapping(input.add(len - rem), block.as_mut_ptr(), rem);
        block[rem] = PAD;
        block[RATE - 1] |= 0x80;
        self.absorb(block.as_ptr(), RATE, RATE);
        #[cfg(feature = "zeroize")]
        block.zeroize();
    }

    #[inline(always)]
    pub(super) unsafe fn squeeze(&mut self, output: *mut u8, len: usize) {
        squeeze(&mut self.0, output, len, (1600 - len * 16) / 8);
    }
}

#[cfg(feature = "zeroize")]
impl Zeroize for Lanes {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}
