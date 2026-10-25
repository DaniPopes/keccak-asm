use core::{mem::MaybeUninit, ptr, slice};

use crate::backend::{absorb, finalize, Buffer};

#[cfg(feature = "zeroize")]
use zeroize::{Zeroize, ZeroizeOnDrop};

const MAX_BUFSZ: usize = (1600 / 8) - 32;

/// Core SHA-3 state.
///
/// Implementation from [OpenSSL](https://github.com/openssl/openssl/blob/eaee1765a49c6a8ba728e3e2d18bb67bff8aaa55/include/internal/sha3.h#L34).
// Note: here block_size, md_size (output size), pad are all compile-time constants,
// while the OpenSSL implementation uses runtime variables stored in this struct
#[derive(Clone)]
#[allow(non_snake_case)]
pub(crate) struct Sha3State<const RATE: usize, const PAD: u8> {
    /// Core state buffer.
    A: Buffer,
    /// Used bytes in the temporary buffer.
    bufsz: usize,
    /// Temporary buffer.
    buf: [MaybeUninit<u8>; MAX_BUFSZ],
}

impl<const RATE: usize, const PAD: u8> Default for Sha3State<RATE, PAD> {
    #[inline(always)]
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "zeroize")]
impl<const RATE: usize, const PAD: u8> Drop for Sha3State<RATE, PAD> {
    fn drop(&mut self) {
        self.A.zeroize();
        self.buf.zeroize();
    }
}

#[cfg(feature = "zeroize")]
impl<const RATE: usize, const PAD: u8> ZeroizeOnDrop for Sha3State<RATE, PAD> {}

impl<const RATE: usize, const PAD: u8> Sha3State<RATE, PAD> {
    const BLOCK_SIZE: usize = RATE;

    #[inline(always)]
    pub(crate) fn new() -> Self {
        Self { A: [0; 25], bufsz: 0, buf: unsafe { MaybeUninit::uninit().assume_init() } }
    }

    #[inline(always)]
    pub(crate) fn reset(&mut self) {
        self.A = [0; 25];
        self.bufsz = 0;
    }

    /// Implementation from [OpenSSL](https://github.com/openssl/openssl/blob/9ff816106c2b2ccbffe5c4e3619a840547088674/providers/implementations/digests/sha3_prov.c#L68).
    ///
    /// # Safety
    ///
    /// `inp` must point to at least `len` bytes.
    #[inline]
    pub(crate) unsafe fn update(&mut self, mut inp: *const u8, mut len: usize) {
        let bsz: usize = Self::BLOCK_SIZE;

        if len == 0 {
            return;
        }

        let num = self.bufsz;
        let mut rem;
        // Is there anything in the buffer already?
        if num != 0 {
            // Calculate how much space is left in the buffer
            rem = bsz - num;
            // If the new input does not fill the buffer then just add it
            if len < rem {
                memcpy(self.buf().add(num), inp, len);
                self.bufsz += len;
                return;
            }
            // otherwise fill up the buffer and absorb the buffer
            memcpy(self.buf().add(num), inp, rem);
            // Update the input pointer
            inp = inp.add(rem);
            len -= rem;
            absorb(&mut self.A, slice::from_raw_parts(self.buf.as_ptr().cast(), bsz), bsz);
            self.bufsz = 0;
        }
        // Absorb the input - rem = leftover part of the input < blocksize)
        rem = if len >= bsz {
            absorb(&mut self.A, slice::from_raw_parts(inp, len), bsz)
        } else {
            len
        };
        // Copy the leftover bit of the input into the buffer
        if rem > 0 {
            memcpy(self.buf(), inp.add(len).sub(rem), rem);
            self.bufsz = rem;
        }
    }

    /// Absorbs the buffered tail with padding and writes the digest to `out`.
    ///
    /// Does not update the core state, so the hasher must be dropped or reset afterwards.
    ///
    /// # Safety
    ///
    /// `out` must point to at least `(200 - RATE) / 2` bytes.
    #[inline]
    pub(crate) unsafe fn finalize(&mut self, out: *mut u8) {
        let buf = self.buf();
        finalize::<RATE, PAD>(&self.A, buf, self.bufsz, out);
    }

    #[inline(always)]
    fn buf(&mut self) -> *mut u8 {
        self.buf.as_mut_ptr().cast()
    }
}

#[inline(always)]
unsafe fn memcpy(dst: *mut u8, src: *const u8, count: usize) {
    ptr::copy_nonoverlapping(src, dst, count);
}
