//! One Keccak state per batch, for targets without a multi-lane backend.
//!
//! [`super::digest_batch`] hashes each input with the one-message backend when `LANES` is 1, so
//! these helpers only need to compile.

pub(super) const LANES: usize = 1;

pub(super) type V = u64;

#[inline(always)]
pub(super) unsafe fn zero() -> V {
    0
}

#[inline(always)]
pub(super) unsafe fn splat(x: u64) -> V {
    x
}

#[inline(always)]
pub(super) unsafe fn set(words: [u64; LANES]) -> V {
    words[0]
}

#[inline(always)]
pub(super) unsafe fn get(v: V) -> [u64; LANES] {
    [v]
}

#[inline(always)]
pub(super) unsafe fn xor(a: V, b: V) -> V {
    a ^ b
}

#[inline(always)]
pub(super) unsafe fn xor3(a: V, b: V, c: V) -> V {
    a ^ b ^ c
}

#[inline(always)]
pub(super) unsafe fn chi(a: V, b: V, c: V) -> V {
    a ^ (!b & c)
}

#[inline(always)]
pub(super) unsafe fn theta(a: V, b: V) -> V {
    a ^ b.rotate_left(1)
}

#[inline(always)]
pub(super) unsafe fn rho<const LEFT: i32, const RIGHT: i32>(a: V, d: V) -> V {
    (a ^ d).rotate_left(LEFT as u32)
}
