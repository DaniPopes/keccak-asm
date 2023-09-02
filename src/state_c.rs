#![allow(non_snake_case, non_camel_case_types, non_upper_case_globals)]

use core::ffi::c_int;

use crate::CoreTrait;

// typedef struct prov_sha3_meth_st
// {
//     sha3_absorb_fn *absorb;
//     sha3_final_fn *final;
// } PROV_SHA3_METHOD;

#[repr(C)]
struct keccak_st {
    A: [u64; 25],
    block_size: usize,
    md_size: usize,
    bufsz: usize,
    buf: [u8; 1600 / 8 - 32],
    pad: u8,
    // meth: *const EVP_MD,
}
type KECCAK1600_CTX = keccak_st;

#[link(name = "keccak1600", kind = "static")]
extern "C" {
    fn ossl_sha3_reset(ctx: *mut KECCAK1600_CTX);
    fn ossl_sha3_init(ctx: *mut KECCAK1600_CTX, pad: u8, bitlen: usize) -> c_int;
    // fn ossl_keccak_kmac_init(ctx: *mut KECCAK1600_CTX, pad: u8, bitlen: usize) -> c_int;
    fn ossl_sha3_update(ctx: *mut KECCAK1600_CTX, inp: *const u8, len: usize) -> c_int;
    fn ossl_sha3_final(md: *mut u8, ctx: *mut KECCAK1600_CTX) -> c_int;
}

pub(crate) struct Sha3State<const bitlen: usize, const pad: u8> {
    ctx: KECCAK1600_CTX,
}

impl<const bitlen: usize, const pad: u8> CoreTrait for Sha3State<bitlen, pad> {
    #[inline(always)]
    fn new() -> Self {
        let mut ctx: KECCAK1600_CTX = unsafe { core::mem::zeroed() };
        unsafe { ossl_sha3_init(&mut ctx, pad, bitlen) };
        Self { ctx }
    }

    #[inline(always)]
    fn reset(&mut self) {
        unsafe { ossl_sha3_reset(&mut self.ctx) };
    }

    #[inline(always)]
    unsafe fn update(&mut self, inp: *const u8, len: usize) {
        ossl_sha3_update(&mut self.ctx, inp, len);
    }

    #[inline(always)]
    unsafe fn finalize(&mut self, md: *mut u8) {
        ossl_sha3_final(md, &mut self.ctx);
    }
}
