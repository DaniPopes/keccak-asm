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

/// Loads eight words from each row and returns them transposed: word `i` of every row in
/// vector `i`.
#[inline(always)]
pub(super) unsafe fn load_transposed(rows: [*const u64; LANES]) -> [V; LANES] {
    let r = rows.map(|row| _mm512_loadu_si512(row.cast()));
    let t0 = _mm512_unpacklo_epi64(r[0], r[1]);
    let t1 = _mm512_unpackhi_epi64(r[0], r[1]);
    let t2 = _mm512_unpacklo_epi64(r[2], r[3]);
    let t3 = _mm512_unpackhi_epi64(r[2], r[3]);
    let t4 = _mm512_unpacklo_epi64(r[4], r[5]);
    let t5 = _mm512_unpackhi_epi64(r[4], r[5]);
    let t6 = _mm512_unpacklo_epi64(r[6], r[7]);
    let t7 = _mm512_unpackhi_epi64(r[6], r[7]);
    let u0 = _mm512_shuffle_i64x2::<0x88>(t0, t2);
    let u1 = _mm512_shuffle_i64x2::<0xdd>(t0, t2);
    let u2 = _mm512_shuffle_i64x2::<0x88>(t1, t3);
    let u3 = _mm512_shuffle_i64x2::<0xdd>(t1, t3);
    let u4 = _mm512_shuffle_i64x2::<0x88>(t4, t6);
    let u5 = _mm512_shuffle_i64x2::<0xdd>(t4, t6);
    let u6 = _mm512_shuffle_i64x2::<0x88>(t5, t7);
    let u7 = _mm512_shuffle_i64x2::<0xdd>(t5, t7);
    [
        _mm512_shuffle_i64x2::<0x88>(u0, u4),
        _mm512_shuffle_i64x2::<0x88>(u2, u6),
        _mm512_shuffle_i64x2::<0x88>(u1, u5),
        _mm512_shuffle_i64x2::<0x88>(u3, u7),
        _mm512_shuffle_i64x2::<0xdd>(u0, u4),
        _mm512_shuffle_i64x2::<0xdd>(u2, u6),
        _mm512_shuffle_i64x2::<0xdd>(u1, u5),
        _mm512_shuffle_i64x2::<0xdd>(u3, u7),
    ]
}
