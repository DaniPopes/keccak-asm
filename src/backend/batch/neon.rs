//! Two Keccak states, one per 64-bit lane of a NEON register.

use core::{arch::aarch64::*, mem::transmute};

pub(super) const LANES: usize = 2;

pub(super) type V = uint64x2_t;

#[inline(always)]
pub(super) unsafe fn zero() -> V {
    vdupq_n_u64(0)
}

#[inline(always)]
pub(super) unsafe fn splat(x: u64) -> V {
    vdupq_n_u64(x)
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
    veorq_u64(a, b)
}

#[inline(always)]
pub(super) unsafe fn xor3(a: V, b: V, c: V) -> V {
    #[cfg(target_feature = "sha3")]
    {
        veor3q_u64(a, b, c)
    }
    #[cfg(not(target_feature = "sha3"))]
    {
        veorq_u64(veorq_u64(a, b), c)
    }
}

#[inline(always)]
pub(super) unsafe fn chi(a: V, b: V, c: V) -> V {
    #[cfg(target_feature = "sha3")]
    {
        vbcaxq_u64(a, c, b)
    }
    #[cfg(not(target_feature = "sha3"))]
    {
        veorq_u64(a, vbicq_u64(c, b))
    }
}

#[inline(always)]
pub(super) unsafe fn theta(a: V, b: V) -> V {
    #[cfg(target_feature = "sha3")]
    {
        vrax1q_u64(a, b)
    }
    #[cfg(not(target_feature = "sha3"))]
    {
        veorq_u64(a, vsriq_n_u64::<63>(vshlq_n_u64::<1>(b), b))
    }
}

#[inline(always)]
pub(super) unsafe fn rho<const LEFT: i32, const RIGHT: i32>(a: V, d: V) -> V {
    #[cfg(target_feature = "sha3")]
    {
        vxarq_u64::<RIGHT>(a, d)
    }
    #[cfg(not(target_feature = "sha3"))]
    {
        let a = veorq_u64(a, d);
        vsriq_n_u64::<RIGHT>(vshlq_n_u64::<LEFT>(a), a)
    }
}
