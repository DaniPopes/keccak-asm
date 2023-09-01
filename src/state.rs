#![allow(non_snake_case, non_upper_case_globals)]

use crate::{Buffer, CoreTrait, SHA3_absorb, SHA3_squeeze};
use core::{mem, ptr};

pub(crate) struct Sha3State<const bitlen: usize, const pad: u8> {
    A: Buffer,
    /// Used bytes in below buffer.
    bufsz: usize,
    buf: [u8; (1600 / 8) - 32],
}

impl<const bitlen: usize, const pad: u8> CoreTrait for Sha3State<bitlen, pad> {
    #[inline(always)]
    fn new() -> Self {
        unsafe { mem::MaybeUninit::zeroed().assume_init() }
    }

    #[inline(always)]
    fn reset(&mut self) {
        todo!()
    }

    // https://github.com/openssl/openssl/blob/60421893a286bb9eb7fb7c2454b84af9778ffca4/crypto/sha/sha3.c#L45
    #[inline(always)]
    unsafe fn update(&mut self, mut inp: *const u8, mut len: usize) {
        let bsz: usize = Self::bsz;

        if len == 0 {
            return
        }

        let num = self.bufsz;
        let mut rem;
        if num != 0 {
            /* process intermediate buffer */
            rem = bsz - num;
            if len < rem {
                memcpy(self.buf().add(num), inp, len);
                self.bufsz += len;
                return
            }
            /*
             * We have enough data to fill or overflow the intermediate
             * A. So we append |rem| bytes and process the block,
             * leaving the rest for later processing...
             */
            memcpy(self.buf().add(num), inp, rem);
            inp = inp.add(rem);
            len -= rem;
            SHA3_absorb(&mut self.A, self.buf.as_ptr(), bsz, bsz);
            self.bufsz = 0;
            /* ctx->buf is processed, ctx->num is guaranteed to be zero */
        }

        rem = if len >= bsz { SHA3_absorb(&mut self.A, inp, len, bsz) } else { len };

        if rem > 0 {
            unsafe {
                memcpy(self.buf(), inp.add(len).sub(rem), rem);
            }
            self.bufsz = rem;
        }
    }

    // https://github.com/openssl/openssl/blob/60421893a286bb9eb7fb7c2454b84af9778ffca4/crypto/sha/sha3.c#L87
    #[inline]
    unsafe fn finalize(&mut self, out: *mut u8) {
        let bsz: usize = Self::bsz;

        let num = self.bufsz;

        /*
         * Pad the data with 10*1. Note that |num| can be |bsz - 1|
         * in which case both byte operations below are performed on
         * same byte...
         */
        memset(self.buf().add(num), 0, bsz - num);
        *self.buf().add(num) = pad;
        *self.buf().add(bsz - 1) |= 0x80;

        SHA3_absorb(&mut self.A, self.buf(), bsz, bsz);

        SHA3_squeeze(&mut self.A, out, Self::out, bsz);
    }
}

impl<const bitlen: usize, const pad: u8> Sha3State<bitlen, pad> {
    const out: usize = bitlen / 8;
    const bsz: usize = (1600 - bitlen) / 8;

    #[inline(always)]
    fn buf(&mut self) -> *mut u8 {
        self.buf.as_mut_ptr()
    }
}

#[inline(always)]
unsafe fn memcpy(dst: *mut u8, src: *const u8, count: usize) {
    ptr::copy_nonoverlapping(src, dst, count);
}

#[inline(always)]
unsafe fn memset(dst: *mut u8, val: u8, count: usize) {
    ptr::write_bytes(dst, val, count);
}
