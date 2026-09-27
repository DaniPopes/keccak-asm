//! Adapter for targets using the assembly backend.

use sha3_asm::Buffer;

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

pub(crate) use sha3_asm::{SHA3_absorb as absorb, SHA3_squeeze as squeeze, IMPL};

pub(super) struct Lanes(Buffer);

impl Lanes {
    #[inline(always)]
    pub(super) fn new() -> Self {
        Self([0; 25])
    }

    #[inline(always)]
    pub(super) unsafe fn absorb(&mut self, input: *const u8, len: usize, rate: usize) -> usize {
        absorb(&mut self.0, input, len, rate)
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
