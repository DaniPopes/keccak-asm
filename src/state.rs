use xkcp_rs::KeccakHash;

/// Core SHA-3 state.
// Note: here block_size, md_size (output size), pad are all compile-time constants,
// while the OpenSSL implementation uses runtime variables stored in this struct
pub(crate) struct Sha3State<const BITS: usize, const PAD: u8>(KeccakHash);

impl<const BITS: usize, const PAD: u8> Clone for Sha3State<BITS, PAD> {
    fn clone(&self) -> Self {
        Self::new()
    }
}

impl<const BITS: usize, const PAD: u8> Default for Sha3State<BITS, PAD> {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

impl<const BITS: usize, const PAD: u8> Sha3State<BITS, PAD> {
    const OUT_SIZE: usize = BITS / 8;

    #[inline(always)]
    pub(crate) fn new() -> Self {
        let capacity = BITS as u32 * 2;
        let block_size = 1600 - capacity;
        let bit_length = Self::OUT_SIZE as u32 * 8;
        Self(KeccakHash::new(block_size, capacity, bit_length, PAD).unwrap())
    }

    #[inline(always)]
    pub(crate) fn reset(&mut self) {
        *self = Self::new();
    }

    /// # Safety
    ///
    /// `inp` must point to at least `len` bytes.
    #[inline]
    pub(crate) unsafe fn update(&mut self, inp: *const u8, len: usize) {
        let _ = self.0.update(core::slice::from_raw_parts(inp, len));
    }

    /// # Safety
    ///
    /// `out` must point to at least `BITS / 8` bytes.
    #[inline]
    pub(crate) unsafe fn finalize(&mut self, out: *mut u8) {
        let _ = self.0.finalize(core::slice::from_raw_parts_mut(out, Self::OUT_SIZE));
    }
}
