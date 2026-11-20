//! Hashing several messages at once, with one Keccak state per vector lane.
//!
//! Each of the 25 state words is a vector that holds that word for every message in the batch,
//! so one Keccak-f[1600] pass on the vectors permutes all states together.

use super::{tail, word, RC};
use core::{array, mem::MaybeUninit, ptr};
use digest::{typenum::Unsigned, Output, OutputSizeUser};
use simd::*;

#[cfg(feature = "zeroize")]
use zeroize::Zeroize;

cfg_if::cfg_if! {
    if #[cfg(all(target_arch = "x86_64", target_feature = "avx512f"))] {
        mod avx512;
        use avx512 as simd;
    } else if #[cfg(all(target_arch = "x86_64", target_feature = "avx2"))] {
        mod avx2;
        use avx2 as simd;
    } else if #[cfg(all(target_arch = "aarch64", target_feature = "neon", target_endian = "little"))] {
        mod neon;
        use neon as simd;
    } else {
        mod scalar;
        use scalar as simd;
    }
}

pub(crate) const BATCH_LANES: usize = LANES;

/// The largest rate in 64-bit words, used by Keccak-224.
const MAX_RATE_WORDS: usize = 18;

static ZERO_BLOCK: [u64; MAX_RATE_WORDS] = [0; MAX_RATE_WORDS];

#[inline]
pub(crate) fn digest_batch<H: OutputSizeUser, const RATE: usize, const PAD: u8, T: AsRef<[u8]>>(
    inputs: impl IntoIterator<Item = T>,
    mut f: impl FnMut(T, Output<H>),
) {
    let mut inputs = inputs.into_iter();
    if LANES == 1 {
        for input in inputs {
            let digest = unsafe { super::digest::<H, RATE, PAD>(input.as_ref()) };
            f(input, digest);
        }
        return;
    }

    loop {
        let mut items: [Option<T>; LANES] = [const { None }; LANES];
        let mut count = 0;
        for (slot, input) in items.iter_mut().zip(&mut inputs) {
            *slot = Some(input);
            count += 1;
        }

        if count <= 1 {
            // A vector pass costs a little more than hashing one message alone.
            if let Some(item) = items.into_iter().next().flatten() {
                let digest = unsafe { super::digest::<H, RATE, PAD>(item.as_ref()) };
                f(item, digest);
            }
            return;
        }

        let mut outputs = [const { MaybeUninit::<Output<H>>::uninit() }; LANES];
        {
            let first = unsafe { items[0].as_ref().unwrap_unchecked().as_ref() };
            // Unused lanes repeat the first input so that equal lengths keep the fixed-length path.
            let slices = array::from_fn(|i| items[i].as_ref().map_or(first, AsRef::as_ref));
            unsafe { digest_lanes::<H, RATE, PAD>(&slices, &mut outputs) };
        }
        for (item, output) in items.into_iter().zip(outputs).take(count) {
            unsafe { f(item.unwrap_unchecked(), output.assume_init()) };
        }

        if count < LANES {
            return;
        }
    }
}

#[inline(never)]
unsafe fn digest_lanes<H: OutputSizeUser, const RATE: usize, const PAD: u8>(
    inputs: &[&[u8]; LANES],
    outputs: &mut [MaybeUninit<Output<H>>; LANES],
) {
    // Specialize for common lengths to load input words directly into the state, as `digest`
    // does for one message.
    if const { RATE == 136 && PAD == crate::KECCAK } {
        let len = inputs[0].len();
        if inputs.iter().all(|input| input.len() == len) {
            match len {
                20 => return digest_lanes_const::<H, RATE, PAD, 20>(inputs, outputs),
                32 => return digest_lanes_const::<H, RATE, PAD, 32>(inputs, outputs),
                64 => return digest_lanes_const::<H, RATE, PAD, 64>(inputs, outputs),
                _ => {}
            }
        }
    }
    digest_lanes_dyn::<H, RATE, PAD>(inputs, outputs)
}

#[inline(always)]
unsafe fn digest_lanes_const<
    H: OutputSizeUser,
    const RATE: usize,
    const PAD: u8,
    const LEN: usize,
>(
    inputs: &[&[u8]; LANES],
    outputs: &mut [MaybeUninit<Output<H>>; LANES],
) {
    const { assert!(LEN < RATE) };
    let ptrs = inputs.map(<[u8]>::as_ptr);
    let tails = ptrs.map(|ptr| tail::<PAD>(ptr, LEN));
    let mut state = [zero(); 25];
    seq!(i in 0..25 => {
        if i < RATE / 8 {
            state[i] = set(array::from_fn(|lane| word::<PAD>(ptrs[lane], LEN, RATE, i, tails[lane])));
        }
    });
    permute(&mut state);
    squeeze::<H, RATE>(&state, outputs, |_| true);
    #[cfg(feature = "zeroize")]
    state.zeroize();
}

#[inline(always)]
unsafe fn digest_lanes_dyn<H: OutputSizeUser, const RATE: usize, const PAD: u8>(
    inputs: &[&[u8]; LANES],
    outputs: &mut [MaybeUninit<Output<H>>; LANES],
) {
    // The padded last block of each message, so that every block loads the same way.
    let mut last = [[0u64; MAX_RATE_WORDS]; LANES];
    let mut blocks = [0; LANES];
    for lane in 0..LANES {
        let input = inputs[lane];
        let full = input.len() / RATE;
        let rem = input.len() % RATE;
        let block = last[lane].as_mut_ptr().cast::<u8>();
        ptr::copy_nonoverlapping(input.as_ptr().add(full * RATE), block, rem);
        *block.add(rem) = PAD;
        *block.add(RATE - 1) |= 0x80;
        blocks[lane] = full + 1;
    }

    let mut state = [zero(); 25];
    let steps = blocks.iter().copied().max().unwrap_or(0);
    for step in 0..steps {
        let rows = array::from_fn(|lane| {
            if step + 1 < blocks[lane] {
                inputs[lane].as_ptr().add(step * RATE).cast()
            } else if step + 1 == blocks[lane] {
                last[lane].as_ptr()
            } else {
                // Messages that already finished absorb zeros; their digests are taken.
                ZERO_BLOCK.as_ptr()
            }
        });
        absorb::<RATE>(&mut state, rows);
        permute(&mut state);
        if blocks.iter().any(|&b| b == step + 1) {
            squeeze::<H, RATE>(&state, outputs, |lane| blocks[lane] == step + 1);
        }
    }
    #[cfg(feature = "zeroize")]
    {
        state.zeroize();
        last.zeroize();
    }
}

/// XORs one rate block from each row into the state.
#[inline(always)]
unsafe fn absorb<const RATE: usize>(state: &mut [V; 25], rows: [*const u64; LANES]) {
    // Whole groups of `LANES` words load as rows and transpose into state words; the rest load
    // one word per row.
    let grouped = RATE / 8 / LANES * LANES;
    seq!(i in 0..25 => {
        if i < grouped && i.is_multiple_of(LANES) {
            let words = load_transposed(rows.map(|row| row.add(i)));
            for (k, word) in words.into_iter().enumerate() {
                state[i + k] = xor(state[i + k], word);
            }
        } else if i >= grouped && i < RATE / 8 {
            state[i] = xor(state[i], set(rows.map(|row| row.add(i).read_unaligned())));
        }
    });
}

#[inline(always)]
unsafe fn squeeze<H: OutputSizeUser, const RATE: usize>(
    state: &[V; 25],
    outputs: &mut [MaybeUninit<Output<H>>; LANES],
    mut take: impl FnMut(usize) -> bool,
) {
    let len = H::OutputSize::USIZE;
    debug_assert_eq!(len, (200 - RATE) / 2);
    let mut words = [[0; LANES]; 8];
    seq!(i in 0..8 => {
        if i * 8 < len {
            words[i] = get(state[i]);
        }
    });
    for (lane, output) in outputs.iter_mut().enumerate() {
        if !take(lane) {
            continue;
        }
        let output = output.as_mut_ptr().cast::<u8>();
        seq!(i in 0..8 => {
            if i * 8 < len {
                let word = words[i][lane].to_le_bytes();
                ptr::copy_nonoverlapping(word.as_ptr(), output.add(i * 8), (len - i * 8).min(8));
            }
        });
    }
}

#[inline(always)]
unsafe fn permute(a: &mut [V; 25]) {
    for &rc in &RC {
        let c0 = xor3(xor3(a[0], a[5], a[10]), a[15], a[20]);
        let c1 = xor3(xor3(a[1], a[6], a[11]), a[16], a[21]);
        let c2 = xor3(xor3(a[2], a[7], a[12]), a[17], a[22]);
        let c3 = xor3(xor3(a[3], a[8], a[13]), a[18], a[23]);
        let c4 = xor3(xor3(a[4], a[9], a[14]), a[19], a[24]);
        let d0 = theta(c4, c1);
        let d1 = theta(c0, c2);
        let d2 = theta(c1, c3);
        let d3 = theta(c2, c4);
        let d4 = theta(c3, c0);
        let b0 = xor(a[0], d0);
        let b10 = rho::<1, 63>(a[1], d1);
        let b20 = rho::<62, 2>(a[2], d2);
        let b5 = rho::<28, 36>(a[3], d3);
        let b15 = rho::<27, 37>(a[4], d4);
        let b16 = rho::<36, 28>(a[5], d0);
        let b1 = rho::<44, 20>(a[6], d1);
        let b11 = rho::<6, 58>(a[7], d2);
        let b21 = rho::<55, 9>(a[8], d3);
        let b6 = rho::<20, 44>(a[9], d4);
        let b7 = rho::<3, 61>(a[10], d0);
        let b17 = rho::<10, 54>(a[11], d1);
        let b2 = rho::<43, 21>(a[12], d2);
        let b12 = rho::<25, 39>(a[13], d3);
        let b22 = rho::<39, 25>(a[14], d4);
        let b23 = rho::<41, 23>(a[15], d0);
        let b8 = rho::<45, 19>(a[16], d1);
        let b18 = rho::<15, 49>(a[17], d2);
        let b3 = rho::<21, 43>(a[18], d3);
        let b13 = rho::<8, 56>(a[19], d4);
        let b14 = rho::<18, 46>(a[20], d0);
        let b24 = rho::<2, 62>(a[21], d1);
        let b9 = rho::<61, 3>(a[22], d2);
        let b19 = rho::<56, 8>(a[23], d3);
        let b4 = rho::<14, 50>(a[24], d4);
        a[0] = xor(chi(b0, b1, b2), splat(rc));
        a[1] = chi(b1, b2, b3);
        a[2] = chi(b2, b3, b4);
        a[3] = chi(b3, b4, b0);
        a[4] = chi(b4, b0, b1);
        a[5] = chi(b5, b6, b7);
        a[6] = chi(b6, b7, b8);
        a[7] = chi(b7, b8, b9);
        a[8] = chi(b8, b9, b5);
        a[9] = chi(b9, b5, b6);
        a[10] = chi(b10, b11, b12);
        a[11] = chi(b11, b12, b13);
        a[12] = chi(b12, b13, b14);
        a[13] = chi(b13, b14, b10);
        a[14] = chi(b14, b10, b11);
        a[15] = chi(b15, b16, b17);
        a[16] = chi(b16, b17, b18);
        a[17] = chi(b17, b18, b19);
        a[18] = chi(b18, b19, b15);
        a[19] = chi(b19, b15, b16);
        a[20] = chi(b20, b21, b22);
        a[21] = chi(b21, b22, b23);
        a[22] = chi(b22, b23, b24);
        a[23] = chi(b23, b24, b20);
        a[24] = chi(b24, b20, b21);
    }
}
