//! Keccak-f[1600] on [`commonware_simd`] vectors, using one state lane per vector.
//!
//! Each vector holds the same value in every lane; only lane zero is read back.

use super::{Buffer, DYN, RC};
use commonware_simd::{dispatch, Operation, Simd};
use core::ptr;

pub(crate) const IMPL: &str = "keccak1600-simd-rust";

/// Expands `$body` once per state lane with `$i` bound to the lane index. Loops over the state are
/// not reliably unrolled, which leaves it in memory instead of registers.
macro_rules! unroll {
    ($i:ident => $body:expr) => {
        unroll!(@ $i => $body; 0 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24)
    };
    (@ $i:ident => $body:expr; $($n:literal)*) => {
        $({
            let $i: usize = $n;
            $body;
        })*
    };
}

#[inline(always)]
pub(crate) unsafe fn absorb(state: &mut Buffer, input: &[u8], rate: usize) -> usize {
    match rate {
        72 => absorb_rate::<72>(state, input),
        104 => absorb_rate::<104>(state, input),
        136 => absorb_rate::<136>(state, input),
        144 => absorb_rate::<144>(state, input),
        _ => unreachable!(),
    }
}

// Streaming state lives in memory between calls. Inlining this into `update`/`finalize` keeps the
// lanes in registers across their `memcpy`/`bzero` calls, which forces spills and reloads.
#[inline(never)]
fn absorb_rate<const RATE: usize>(state: &mut Buffer, input: &[u8]) -> usize {
    dispatch(Absorb::<RATE> { state, input })
}

#[inline(always)]
pub(crate) unsafe fn squeeze(state: *mut Buffer, output: *mut u8, len: usize, rate: usize) {
    // All supported fixed digests fit in the first rate block.
    debug_assert!(len <= rate);
    ptr::copy_nonoverlapping(state.cast::<u8>(), output, len);
}

/// # Safety
///
/// `input` must point to `len` readable bytes, `len` must equal `LEN` unless `LEN` is [`DYN`],
/// and `output` must point to `(200 - RATE) / 2` writable bytes.
#[inline(always)]
pub(super) unsafe fn digest<const RATE: usize, const PAD: u8, const LEN: usize>(
    input: *const u8,
    len: usize,
    output: *mut u8,
) {
    dispatch(Digest::<RATE, PAD, LEN> { input, len, output })
}

struct Absorb<'a, const RATE: usize> {
    state: &'a mut Buffer,
    input: &'a [u8],
}

impl<S: Simd, const RATE: usize> Operation<S> for Absorb<'_, RATE> {
    type Output = usize;

    #[inline(always)]
    fn portable(self, simd: S) -> usize {
        let mut a = [simd.u64_splat(0); 25];
        unroll!(i => a[i] = simd.u64_splat(self.state[i]));
        let (blocks, rem) = self.input.as_chunks::<RATE>();
        for block in blocks {
            unsafe { absorb_block::<S, RATE, 0>(simd, &mut a, block.as_ptr(), RATE) };
            permute(simd, &mut a);
        }
        unroll!(i => self.state[i] = simd.u64_extract::<0>(a[i]));
        rem.len()
    }
}

/// One-shot hash; `LEN` specializes the input length when it is known at compile time.
struct Digest<const RATE: usize, const PAD: u8, const LEN: usize> {
    input: *const u8,
    len: usize,
    output: *mut u8,
}

impl<S: Simd, const RATE: usize, const PAD: u8, const LEN: usize> Operation<S>
    for Digest<RATE, PAD, LEN>
{
    type Output = ();

    #[inline(always)]
    fn portable(self, simd: S) {
        let mut input = self.input;
        let mut len = if LEN == DYN { self.len } else { LEN };
        let mut a = [simd.u64_splat(0); 25];
        unsafe {
            while len >= RATE {
                absorb_block::<S, RATE, 0>(simd, &mut a, input, RATE);
                permute(simd, &mut a);
                input = input.add(RATE);
                len -= RATE;
            }
            absorb_block::<S, RATE, PAD>(simd, &mut a, input, len);
            permute(simd, &mut a);

            let out_len = (200 - RATE) / 2;
            unroll!(i => if i * 8 < out_len {
                let word = simd.u64_extract::<0>(a[i]).to_le_bytes();
                let n = (out_len - i * 8).min(8);
                ptr::copy_nonoverlapping(word.as_ptr(), self.output.add(i * 8), n);
            });
        }
        #[cfg(feature = "zeroize")]
        unsafe {
            ptr::write_volatile(&mut a, [simd.u64_splat(0); 25]);
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }
    }
}

/// XORs one block into the state, padding it when `PAD` is nonzero and `len < RATE`.
#[inline(always)]
unsafe fn absorb_block<S: Simd, const RATE: usize, const PAD: u8>(
    simd: S,
    a: &mut [S::U64; 25],
    input: *const u8,
    len: usize,
) {
    let tail = super::tail::<PAD>(input, len);
    unroll!(i => if i < RATE / 8 {
        a[i] = simd.u64_xor(a[i], simd.u64_splat(super::word::<PAD>(input, len, RATE, i, tail)));
    });
}

#[inline(always)]
fn permute<S: Simd>(simd: S, a: &mut [S::U64; 25]) {
    let ones = simd.u64_splat(u64::MAX);
    let xor = |x, y| simd.u64_xor(x, y);
    let chi = |x, y, z| simd.u64_xor(x, simd.u64_and(simd.u64_xor(y, ones), z));
    for &rc in &RC {
        let c: [S::U64; 5] = core::array::from_fn(|x| {
            xor(xor(xor(a[x], a[x + 5]), xor(a[x + 10], a[x + 15])), a[x + 20])
        });
        let d: [S::U64; 5] =
            core::array::from_fn(|x| xor(c[(x + 4) % 5], rotl::<S, 1, 63>(simd, c[(x + 1) % 5])));
        let mut b = [ones; 25];
        b[0] = xor(a[0], d[0]);
        b[10] = rotl::<S, 1, 63>(simd, xor(a[1], d[1]));
        b[20] = rotl::<S, 62, 2>(simd, xor(a[2], d[2]));
        b[5] = rotl::<S, 28, 36>(simd, xor(a[3], d[3]));
        b[15] = rotl::<S, 27, 37>(simd, xor(a[4], d[4]));
        b[16] = rotl::<S, 36, 28>(simd, xor(a[5], d[0]));
        b[1] = rotl::<S, 44, 20>(simd, xor(a[6], d[1]));
        b[11] = rotl::<S, 6, 58>(simd, xor(a[7], d[2]));
        b[21] = rotl::<S, 55, 9>(simd, xor(a[8], d[3]));
        b[6] = rotl::<S, 20, 44>(simd, xor(a[9], d[4]));
        b[7] = rotl::<S, 3, 61>(simd, xor(a[10], d[0]));
        b[17] = rotl::<S, 10, 54>(simd, xor(a[11], d[1]));
        b[2] = rotl::<S, 43, 21>(simd, xor(a[12], d[2]));
        b[12] = rotl::<S, 25, 39>(simd, xor(a[13], d[3]));
        b[22] = rotl::<S, 39, 25>(simd, xor(a[14], d[4]));
        b[23] = rotl::<S, 41, 23>(simd, xor(a[15], d[0]));
        b[8] = rotl::<S, 45, 19>(simd, xor(a[16], d[1]));
        b[18] = rotl::<S, 15, 49>(simd, xor(a[17], d[2]));
        b[3] = rotl::<S, 21, 43>(simd, xor(a[18], d[3]));
        b[13] = rotl::<S, 8, 56>(simd, xor(a[19], d[4]));
        b[14] = rotl::<S, 18, 46>(simd, xor(a[20], d[0]));
        b[24] = rotl::<S, 2, 62>(simd, xor(a[21], d[1]));
        b[9] = rotl::<S, 61, 3>(simd, xor(a[22], d[2]));
        b[19] = rotl::<S, 56, 8>(simd, xor(a[23], d[3]));
        b[4] = rotl::<S, 14, 50>(simd, xor(a[24], d[4]));
        for y in (0..25).step_by(5) {
            for x in 0..5 {
                a[y + x] = chi(b[y + x], b[y + (x + 1) % 5], b[y + (x + 2) % 5]);
            }
        }
        a[0] = xor(a[0], simd.u64_splat(rc));
    }
}

/// Rotates left by `L`; `R` must be `64 - L`.
#[inline(always)]
fn rotl<S: Simd, const L: u32, const R: u32>(simd: S, x: S::U64) -> S::U64 {
    simd.u64_or(simd.u64_shl::<L>(x), simd.u64_shr::<R>(x))
}
