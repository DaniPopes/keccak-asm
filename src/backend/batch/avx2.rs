//! Four Keccak states, one per 64-bit lane of a YMM register.

use core::{arch::x86_64::*, mem::transmute};

pub(super) const LANES: usize = 4;

pub(super) type V = __m256i;

#[inline(always)]
pub(super) unsafe fn zero() -> V {
    _mm256_setzero_si256()
}

#[inline(always)]
pub(super) unsafe fn splat(x: u64) -> V {
    _mm256_set1_epi64x(x as i64)
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
    _mm256_xor_si256(a, b)
}

#[inline(always)]
pub(super) unsafe fn xor3(a: V, b: V, c: V) -> V {
    _mm256_xor_si256(_mm256_xor_si256(a, b), c)
}

#[inline(always)]
pub(super) unsafe fn chi(a: V, b: V, c: V) -> V {
    _mm256_xor_si256(a, _mm256_andnot_si256(b, c))
}

#[inline(always)]
pub(super) unsafe fn theta(a: V, b: V) -> V {
    _mm256_xor_si256(a, rol::<1, 63>(b))
}

#[inline(always)]
pub(super) unsafe fn rho<const LEFT: i32, const RIGHT: i32>(a: V, d: V) -> V {
    rol::<LEFT, RIGHT>(_mm256_xor_si256(a, d))
}

#[inline(always)]
unsafe fn rol<const LEFT: i32, const RIGHT: i32>(a: V) -> V {
    // Byte rotations take one shuffle instead of two shifts and an OR.
    if LEFT == 8 {
        let indices = _mm256_set_epi64x(
            0x0e0d0c0b0a09080f,
            0x0605040302010007,
            0x0e0d0c0b0a09080f,
            0x0605040302010007,
        );
        _mm256_shuffle_epi8(a, indices)
    } else if LEFT == 56 {
        let indices = _mm256_set_epi64x(
            0x080f0e0d0c0b0a09,
            0x0007060504030201,
            0x080f0e0d0c0b0a09,
            0x0007060504030201,
        );
        _mm256_shuffle_epi8(a, indices)
    } else {
        _mm256_or_si256(_mm256_slli_epi64::<LEFT>(a), _mm256_srli_epi64::<RIGHT>(a))
    }
}

/// Loads four words from each row and returns them transposed: word `i` of every row in
/// vector `i`.
#[inline(always)]
pub(super) unsafe fn load_transposed(rows: [*const u64; LANES]) -> [V; LANES] {
    let r = rows.map(|row| _mm256_loadu_si256(row.cast()));
    let t0 = _mm256_unpacklo_epi64(r[0], r[1]);
    let t1 = _mm256_unpackhi_epi64(r[0], r[1]);
    let t2 = _mm256_unpacklo_epi64(r[2], r[3]);
    let t3 = _mm256_unpackhi_epi64(r[2], r[3]);
    [
        _mm256_permute2x128_si256::<0x20>(t0, t2),
        _mm256_permute2x128_si256::<0x20>(t1, t3),
        _mm256_permute2x128_si256::<0x31>(t0, t2),
        _mm256_permute2x128_si256::<0x31>(t1, t3),
    ]
}
