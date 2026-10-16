//! Eight Keccak states, one per 64-bit lane of a ZMM register.

use core::{arch::x86_64::*, mem::transmute};

pub(super) const LANES: usize = 8;

pub(super) type V = __m512i;

#[inline(always)]
pub(super) unsafe fn zero() -> V {
    _mm512_setzero_si512()
}

#[inline(always)]
pub(super) unsafe fn splat(x: u64) -> V {
    _mm512_set1_epi64(x as i64)
}

#[inline(always)]
pub(super) unsafe fn set(words: [u64; LANES]) -> V {
    transmute(words)
}

#[inline(always)]
pub(super) unsafe fn get(v: V) -> [u64; LANES] {
    transmute(v)
}

#[inline(always)]
pub(super) unsafe fn xor(a: V, b: V) -> V {
    _mm512_xor_si512(a, b)
}

#[inline(always)]
pub(super) unsafe fn xor3(a: V, b: V, c: V) -> V {
    _mm512_ternarylogic_epi64::<0x96>(a, b, c)
}

#[inline(always)]
pub(super) unsafe fn chi(a: V, b: V, c: V) -> V {
    _mm512_ternarylogic_epi64::<0xd2>(a, b, c)
}

#[inline(always)]
pub(super) unsafe fn theta(a: V, b: V) -> V {
    _mm512_xor_si512(a, _mm512_rol_epi64::<1>(b))
}

#[inline(always)]
pub(super) unsafe fn rho<const LEFT: i32, const RIGHT: i32>(a: V, d: V) -> V {
    _mm512_rol_epi64::<LEFT>(_mm512_xor_si512(a, d))
}
