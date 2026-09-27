//! Experimental fixed-size Keccak wrappers and AVX-512 implementations.

use keccak_asm::Keccak256;
use std::arch::x86_64::*;

#[inline(never)]
pub fn digest<const N: usize>(input: &[u8; N]) -> [u8; 32] {
    Keccak256::digest(input).into()
}

#[inline(never)]
pub fn wrapper<const N: usize, const COPY: bool>(input: &[u8; N]) -> [u8; 32] {
    assert!(N < 136);
    let mut state = [0; 25];
    let mut block = [0; 136];
    block[..N].copy_from_slice(input);
    block[N] = 1;
    block[135] |= 0x80;
    sha3_asm::sha3_absorb(&mut state, &block, 136);
    let mut out = [0; 32];
    if COPY {
        let indices = match sha3_asm::IMPL {
            "keccak1600-avx512vl" => [0, 1, 2, 3],
            "keccak1600-x86_64" => [0, 1, 2, 3],
            _ => panic!("unverified state layout"),
        };
        for (i, lane) in indices.into_iter().enumerate() {
            out[i * 8..i * 8 + 8].copy_from_slice(&state[lane].to_le_bytes());
        }
    } else {
        sha3_asm::sha3_squeeze(&mut state, &mut out, 136);
    }
    out
}

#[inline(never)]
pub fn scalar_permutation<const N: usize>(input: &[u8; N]) -> [u8; 32] {
    assert_eq!(sha3_asm::IMPL, "keccak1600-x86_64");
    assert!(N < 136);
    extern "C" {
        fn KeccakF1600(state: *mut [u64; 25]);
    }
    let mut bytes = [0; 200];
    bytes[..N].copy_from_slice(input);
    bytes[N] = 1;
    bytes[135] |= 0x80;
    let mut state =
        std::array::from_fn(|i| u64::from_le_bytes(bytes[i * 8..i * 8 + 8].try_into().unwrap()));
    unsafe { KeccakF1600(&mut state) };
    let mut out = [0; 32];
    for (bytes, word) in out.as_chunks_mut::<8>().0.iter_mut().zip(state) {
        bytes.copy_from_slice(&word.to_le_bytes());
    }
    out
}

const RC: [u64; 24] = [
    0x1,
    0x8082,
    0x800000000000808a,
    0x8000000080008000,
    0x808b,
    0x80000001,
    0x8000000080008081,
    0x8000000000008009,
    0x8a,
    0x88,
    0x80008009,
    0x8000000a,
    0x8000808b,
    0x800000000000008b,
    0x8000000000008089,
    0x8000000000008003,
    0x8000000000008002,
    0x8000000000000080,
    0x800a,
    0x800000008000000a,
    0x8000000080008081,
    0x8000000000008080,
    0x80000001,
    0x8000000080008008,
];

/// Hashes independent inputs using one vector register per state lane.
///
/// # Safety
/// Requires AVX-512F and AVX-512VL.
#[target_feature(enable = "avx512f,avx512vl")]
#[inline(never)]
pub unsafe fn lanes1<const N: usize>(inputs: &[[u8; N]; 1]) -> [[u8; 32]; 1] {
    let mut blocks = [[0u8; 544]; 1];
    assert!(N < 544);
    let padded = (N / 136 + 1) * 136;
    for (block, input) in blocks.iter_mut().zip(inputs) {
        block[..N].copy_from_slice(input);
        block[N] = 1;
        block[padded - 1] |= 0x80;
    }
    let mut a0 = _mm_setzero_si128();
    let mut a1 = _mm_setzero_si128();
    let mut a2 = _mm_setzero_si128();
    let mut a3 = _mm_setzero_si128();
    let mut a4 = _mm_setzero_si128();
    let mut a5 = _mm_setzero_si128();
    let mut a6 = _mm_setzero_si128();
    let mut a7 = _mm_setzero_si128();
    let mut a8 = _mm_setzero_si128();
    let mut a9 = _mm_setzero_si128();
    let mut a10 = _mm_setzero_si128();
    let mut a11 = _mm_setzero_si128();
    let mut a12 = _mm_setzero_si128();
    let mut a13 = _mm_setzero_si128();
    let mut a14 = _mm_setzero_si128();
    let mut a15 = _mm_setzero_si128();
    let mut a16 = _mm_setzero_si128();
    let mut a17 = _mm_setzero_si128();
    let mut a18 = _mm_setzero_si128();
    let mut a19 = _mm_setzero_si128();
    let mut a20 = _mm_setzero_si128();
    let mut a21 = _mm_setzero_si128();
    let mut a22 = _mm_setzero_si128();
    let mut a23 = _mm_setzero_si128();
    let mut a24 = _mm_setzero_si128();
    for offset in (0..padded).step_by(136) {
        let words = std::array::from_fn::<_, 1, _>(|j| {
            u64::from_le_bytes(blocks[j][offset..offset + 8].try_into().unwrap())
        });
        a0 = _mm_xor_si128(a0, _mm_cvtsi64_si128(words[0] as i64));
        let words = std::array::from_fn::<_, 1, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 8..offset + 16].try_into().unwrap())
        });
        a1 = _mm_xor_si128(a1, _mm_cvtsi64_si128(words[0] as i64));
        let words = std::array::from_fn::<_, 1, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 16..offset + 24].try_into().unwrap())
        });
        a2 = _mm_xor_si128(a2, _mm_cvtsi64_si128(words[0] as i64));
        let words = std::array::from_fn::<_, 1, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 24..offset + 32].try_into().unwrap())
        });
        a3 = _mm_xor_si128(a3, _mm_cvtsi64_si128(words[0] as i64));
        let words = std::array::from_fn::<_, 1, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 32..offset + 40].try_into().unwrap())
        });
        a4 = _mm_xor_si128(a4, _mm_cvtsi64_si128(words[0] as i64));
        let words = std::array::from_fn::<_, 1, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 40..offset + 48].try_into().unwrap())
        });
        a5 = _mm_xor_si128(a5, _mm_cvtsi64_si128(words[0] as i64));
        let words = std::array::from_fn::<_, 1, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 48..offset + 56].try_into().unwrap())
        });
        a6 = _mm_xor_si128(a6, _mm_cvtsi64_si128(words[0] as i64));
        let words = std::array::from_fn::<_, 1, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 56..offset + 64].try_into().unwrap())
        });
        a7 = _mm_xor_si128(a7, _mm_cvtsi64_si128(words[0] as i64));
        let words = std::array::from_fn::<_, 1, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 64..offset + 72].try_into().unwrap())
        });
        a8 = _mm_xor_si128(a8, _mm_cvtsi64_si128(words[0] as i64));
        let words = std::array::from_fn::<_, 1, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 72..offset + 80].try_into().unwrap())
        });
        a9 = _mm_xor_si128(a9, _mm_cvtsi64_si128(words[0] as i64));
        let words = std::array::from_fn::<_, 1, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 80..offset + 88].try_into().unwrap())
        });
        a10 = _mm_xor_si128(a10, _mm_cvtsi64_si128(words[0] as i64));
        let words = std::array::from_fn::<_, 1, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 88..offset + 96].try_into().unwrap())
        });
        a11 = _mm_xor_si128(a11, _mm_cvtsi64_si128(words[0] as i64));
        let words =
            blocks.map(|b| u64::from_le_bytes(b[offset + 96..offset + 104].try_into().unwrap()));
        a12 = _mm_xor_si128(a12, _mm_cvtsi64_si128(words[0] as i64));
        let words =
            blocks.map(|b| u64::from_le_bytes(b[offset + 104..offset + 112].try_into().unwrap()));
        a13 = _mm_xor_si128(a13, _mm_cvtsi64_si128(words[0] as i64));
        let words =
            blocks.map(|b| u64::from_le_bytes(b[offset + 112..offset + 120].try_into().unwrap()));
        a14 = _mm_xor_si128(a14, _mm_cvtsi64_si128(words[0] as i64));
        let words =
            blocks.map(|b| u64::from_le_bytes(b[offset + 120..offset + 128].try_into().unwrap()));
        a15 = _mm_xor_si128(a15, _mm_cvtsi64_si128(words[0] as i64));
        let words =
            blocks.map(|b| u64::from_le_bytes(b[offset + 128..offset + 136].try_into().unwrap()));
        a16 = _mm_xor_si128(a16, _mm_cvtsi64_si128(words[0] as i64));
        for &rc in &RC {
            let c0 = _mm_ternarylogic_epi64::<0x96>(
                _mm_ternarylogic_epi64::<0x96>(a0, a5, a10),
                a15,
                a20,
            );
            let c1 = _mm_ternarylogic_epi64::<0x96>(
                _mm_ternarylogic_epi64::<0x96>(a1, a6, a11),
                a16,
                a21,
            );
            let c2 = _mm_ternarylogic_epi64::<0x96>(
                _mm_ternarylogic_epi64::<0x96>(a2, a7, a12),
                a17,
                a22,
            );
            let c3 = _mm_ternarylogic_epi64::<0x96>(
                _mm_ternarylogic_epi64::<0x96>(a3, a8, a13),
                a18,
                a23,
            );
            let c4 = _mm_ternarylogic_epi64::<0x96>(
                _mm_ternarylogic_epi64::<0x96>(a4, a9, a14),
                a19,
                a24,
            );
            let r0 = _mm_rol_epi64::<1>(c1);
            a0 = _mm_ternarylogic_epi64::<0x96>(a0, c4, r0);
            a5 = _mm_ternarylogic_epi64::<0x96>(a5, c4, r0);
            a10 = _mm_ternarylogic_epi64::<0x96>(a10, c4, r0);
            a15 = _mm_ternarylogic_epi64::<0x96>(a15, c4, r0);
            a20 = _mm_ternarylogic_epi64::<0x96>(a20, c4, r0);
            let r1 = _mm_rol_epi64::<1>(c2);
            a1 = _mm_ternarylogic_epi64::<0x96>(a1, c0, r1);
            a6 = _mm_ternarylogic_epi64::<0x96>(a6, c0, r1);
            a11 = _mm_ternarylogic_epi64::<0x96>(a11, c0, r1);
            a16 = _mm_ternarylogic_epi64::<0x96>(a16, c0, r1);
            a21 = _mm_ternarylogic_epi64::<0x96>(a21, c0, r1);
            let r2 = _mm_rol_epi64::<1>(c3);
            a2 = _mm_ternarylogic_epi64::<0x96>(a2, c1, r2);
            a7 = _mm_ternarylogic_epi64::<0x96>(a7, c1, r2);
            a12 = _mm_ternarylogic_epi64::<0x96>(a12, c1, r2);
            a17 = _mm_ternarylogic_epi64::<0x96>(a17, c1, r2);
            a22 = _mm_ternarylogic_epi64::<0x96>(a22, c1, r2);
            let r3 = _mm_rol_epi64::<1>(c4);
            a3 = _mm_ternarylogic_epi64::<0x96>(a3, c2, r3);
            a8 = _mm_ternarylogic_epi64::<0x96>(a8, c2, r3);
            a13 = _mm_ternarylogic_epi64::<0x96>(a13, c2, r3);
            a18 = _mm_ternarylogic_epi64::<0x96>(a18, c2, r3);
            a23 = _mm_ternarylogic_epi64::<0x96>(a23, c2, r3);
            let r4 = _mm_rol_epi64::<1>(c0);
            a4 = _mm_ternarylogic_epi64::<0x96>(a4, c3, r4);
            a9 = _mm_ternarylogic_epi64::<0x96>(a9, c3, r4);
            a14 = _mm_ternarylogic_epi64::<0x96>(a14, c3, r4);
            a19 = _mm_ternarylogic_epi64::<0x96>(a19, c3, r4);
            a24 = _mm_ternarylogic_epi64::<0x96>(a24, c3, r4);
            let b0 = _mm_rol_epi64::<0>(a0);
            let b10 = _mm_rol_epi64::<1>(a1);
            let b20 = _mm_rol_epi64::<62>(a2);
            let b5 = _mm_rol_epi64::<28>(a3);
            let b15 = _mm_rol_epi64::<27>(a4);
            let b16 = _mm_rol_epi64::<36>(a5);
            let b1 = _mm_rol_epi64::<44>(a6);
            let b11 = _mm_rol_epi64::<6>(a7);
            let b21 = _mm_rol_epi64::<55>(a8);
            let b6 = _mm_rol_epi64::<20>(a9);
            let b7 = _mm_rol_epi64::<3>(a10);
            let b17 = _mm_rol_epi64::<10>(a11);
            let b2 = _mm_rol_epi64::<43>(a12);
            let b12 = _mm_rol_epi64::<25>(a13);
            let b22 = _mm_rol_epi64::<39>(a14);
            let b23 = _mm_rol_epi64::<41>(a15);
            let b8 = _mm_rol_epi64::<45>(a16);
            let b18 = _mm_rol_epi64::<15>(a17);
            let b3 = _mm_rol_epi64::<21>(a18);
            let b13 = _mm_rol_epi64::<8>(a19);
            let b14 = _mm_rol_epi64::<18>(a20);
            let b24 = _mm_rol_epi64::<2>(a21);
            let b9 = _mm_rol_epi64::<61>(a22);
            let b19 = _mm_rol_epi64::<56>(a23);
            let b4 = _mm_rol_epi64::<14>(a24);
            a0 = _mm_ternarylogic_epi64::<0xd2>(b0, b1, b2);
            a1 = _mm_ternarylogic_epi64::<0xd2>(b1, b2, b3);
            a2 = _mm_ternarylogic_epi64::<0xd2>(b2, b3, b4);
            a3 = _mm_ternarylogic_epi64::<0xd2>(b3, b4, b0);
            a4 = _mm_ternarylogic_epi64::<0xd2>(b4, b0, b1);
            a5 = _mm_ternarylogic_epi64::<0xd2>(b5, b6, b7);
            a6 = _mm_ternarylogic_epi64::<0xd2>(b6, b7, b8);
            a7 = _mm_ternarylogic_epi64::<0xd2>(b7, b8, b9);
            a8 = _mm_ternarylogic_epi64::<0xd2>(b8, b9, b5);
            a9 = _mm_ternarylogic_epi64::<0xd2>(b9, b5, b6);
            a10 = _mm_ternarylogic_epi64::<0xd2>(b10, b11, b12);
            a11 = _mm_ternarylogic_epi64::<0xd2>(b11, b12, b13);
            a12 = _mm_ternarylogic_epi64::<0xd2>(b12, b13, b14);
            a13 = _mm_ternarylogic_epi64::<0xd2>(b13, b14, b10);
            a14 = _mm_ternarylogic_epi64::<0xd2>(b14, b10, b11);
            a15 = _mm_ternarylogic_epi64::<0xd2>(b15, b16, b17);
            a16 = _mm_ternarylogic_epi64::<0xd2>(b16, b17, b18);
            a17 = _mm_ternarylogic_epi64::<0xd2>(b17, b18, b19);
            a18 = _mm_ternarylogic_epi64::<0xd2>(b18, b19, b15);
            a19 = _mm_ternarylogic_epi64::<0xd2>(b19, b15, b16);
            a20 = _mm_ternarylogic_epi64::<0xd2>(b20, b21, b22);
            a21 = _mm_ternarylogic_epi64::<0xd2>(b21, b22, b23);
            a22 = _mm_ternarylogic_epi64::<0xd2>(b22, b23, b24);
            a23 = _mm_ternarylogic_epi64::<0xd2>(b23, b24, b20);
            a24 = _mm_ternarylogic_epi64::<0xd2>(b24, b20, b21);
            a0 = _mm_xor_si128(a0, _mm_set1_epi64x(rc as i64));
        }
    }
    let mut out = [[0; 32]; 1];
    let words = [_mm_cvtsi128_si64(a0) as u64];
    for (output, word) in out.iter_mut().zip(words) {
        output[0..8].copy_from_slice(&word.to_le_bytes());
    }
    let words = [_mm_cvtsi128_si64(a1) as u64];
    for (output, word) in out.iter_mut().zip(words) {
        output[8..16].copy_from_slice(&word.to_le_bytes());
    }
    let words = [_mm_cvtsi128_si64(a2) as u64];
    for (output, word) in out.iter_mut().zip(words) {
        output[16..24].copy_from_slice(&word.to_le_bytes());
    }
    let words = [_mm_cvtsi128_si64(a3) as u64];
    for (output, word) in out.iter_mut().zip(words) {
        output[24..32].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// Hashes independent inputs using one vector register per state lane.
///
/// # Safety
/// Requires AVX-512F and AVX-512VL.
#[target_feature(enable = "avx512f,avx512vl")]
#[inline(never)]
pub unsafe fn lanes2<const N: usize>(inputs: &[[u8; N]; 2]) -> [[u8; 32]; 2] {
    let mut blocks = [[0u8; 544]; 2];
    assert!(N < 544);
    let padded = (N / 136 + 1) * 136;
    for (block, input) in blocks.iter_mut().zip(inputs) {
        block[..N].copy_from_slice(input);
        block[N] = 1;
        block[padded - 1] |= 0x80;
    }
    let mut a0 = _mm_setzero_si128();
    let mut a1 = _mm_setzero_si128();
    let mut a2 = _mm_setzero_si128();
    let mut a3 = _mm_setzero_si128();
    let mut a4 = _mm_setzero_si128();
    let mut a5 = _mm_setzero_si128();
    let mut a6 = _mm_setzero_si128();
    let mut a7 = _mm_setzero_si128();
    let mut a8 = _mm_setzero_si128();
    let mut a9 = _mm_setzero_si128();
    let mut a10 = _mm_setzero_si128();
    let mut a11 = _mm_setzero_si128();
    let mut a12 = _mm_setzero_si128();
    let mut a13 = _mm_setzero_si128();
    let mut a14 = _mm_setzero_si128();
    let mut a15 = _mm_setzero_si128();
    let mut a16 = _mm_setzero_si128();
    let mut a17 = _mm_setzero_si128();
    let mut a18 = _mm_setzero_si128();
    let mut a19 = _mm_setzero_si128();
    let mut a20 = _mm_setzero_si128();
    let mut a21 = _mm_setzero_si128();
    let mut a22 = _mm_setzero_si128();
    let mut a23 = _mm_setzero_si128();
    let mut a24 = _mm_setzero_si128();
    for offset in (0..padded).step_by(136) {
        let words = std::array::from_fn::<_, 2, _>(|j| {
            u64::from_le_bytes(blocks[j][offset..offset + 8].try_into().unwrap())
        });
        a0 = _mm_xor_si128(a0, std::mem::transmute::<[u64; 2], __m128i>(words));
        let words = std::array::from_fn::<_, 2, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 8..offset + 16].try_into().unwrap())
        });
        a1 = _mm_xor_si128(a1, std::mem::transmute::<[u64; 2], __m128i>(words));
        let words = std::array::from_fn::<_, 2, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 16..offset + 24].try_into().unwrap())
        });
        a2 = _mm_xor_si128(a2, std::mem::transmute::<[u64; 2], __m128i>(words));
        let words = std::array::from_fn::<_, 2, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 24..offset + 32].try_into().unwrap())
        });
        a3 = _mm_xor_si128(a3, std::mem::transmute::<[u64; 2], __m128i>(words));
        let words = std::array::from_fn::<_, 2, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 32..offset + 40].try_into().unwrap())
        });
        a4 = _mm_xor_si128(a4, std::mem::transmute::<[u64; 2], __m128i>(words));
        let words = std::array::from_fn::<_, 2, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 40..offset + 48].try_into().unwrap())
        });
        a5 = _mm_xor_si128(a5, std::mem::transmute::<[u64; 2], __m128i>(words));
        let words = std::array::from_fn::<_, 2, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 48..offset + 56].try_into().unwrap())
        });
        a6 = _mm_xor_si128(a6, std::mem::transmute::<[u64; 2], __m128i>(words));
        let words = std::array::from_fn::<_, 2, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 56..offset + 64].try_into().unwrap())
        });
        a7 = _mm_xor_si128(a7, std::mem::transmute::<[u64; 2], __m128i>(words));
        let words = std::array::from_fn::<_, 2, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 64..offset + 72].try_into().unwrap())
        });
        a8 = _mm_xor_si128(a8, std::mem::transmute::<[u64; 2], __m128i>(words));
        let words = std::array::from_fn::<_, 2, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 72..offset + 80].try_into().unwrap())
        });
        a9 = _mm_xor_si128(a9, std::mem::transmute::<[u64; 2], __m128i>(words));
        let words = std::array::from_fn::<_, 2, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 80..offset + 88].try_into().unwrap())
        });
        a10 = _mm_xor_si128(a10, std::mem::transmute::<[u64; 2], __m128i>(words));
        let words = std::array::from_fn::<_, 2, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 88..offset + 96].try_into().unwrap())
        });
        a11 = _mm_xor_si128(a11, std::mem::transmute::<[u64; 2], __m128i>(words));
        let words =
            blocks.map(|b| u64::from_le_bytes(b[offset + 96..offset + 104].try_into().unwrap()));
        a12 = _mm_xor_si128(a12, std::mem::transmute::<[u64; 2], __m128i>(words));
        let words =
            blocks.map(|b| u64::from_le_bytes(b[offset + 104..offset + 112].try_into().unwrap()));
        a13 = _mm_xor_si128(a13, std::mem::transmute::<[u64; 2], __m128i>(words));
        let words =
            blocks.map(|b| u64::from_le_bytes(b[offset + 112..offset + 120].try_into().unwrap()));
        a14 = _mm_xor_si128(a14, std::mem::transmute::<[u64; 2], __m128i>(words));
        let words =
            blocks.map(|b| u64::from_le_bytes(b[offset + 120..offset + 128].try_into().unwrap()));
        a15 = _mm_xor_si128(a15, std::mem::transmute::<[u64; 2], __m128i>(words));
        let words =
            blocks.map(|b| u64::from_le_bytes(b[offset + 128..offset + 136].try_into().unwrap()));
        a16 = _mm_xor_si128(a16, std::mem::transmute::<[u64; 2], __m128i>(words));
        for &rc in &RC {
            let c0 = _mm_ternarylogic_epi64::<0x96>(
                _mm_ternarylogic_epi64::<0x96>(a0, a5, a10),
                a15,
                a20,
            );
            let c1 = _mm_ternarylogic_epi64::<0x96>(
                _mm_ternarylogic_epi64::<0x96>(a1, a6, a11),
                a16,
                a21,
            );
            let c2 = _mm_ternarylogic_epi64::<0x96>(
                _mm_ternarylogic_epi64::<0x96>(a2, a7, a12),
                a17,
                a22,
            );
            let c3 = _mm_ternarylogic_epi64::<0x96>(
                _mm_ternarylogic_epi64::<0x96>(a3, a8, a13),
                a18,
                a23,
            );
            let c4 = _mm_ternarylogic_epi64::<0x96>(
                _mm_ternarylogic_epi64::<0x96>(a4, a9, a14),
                a19,
                a24,
            );
            let r0 = _mm_rol_epi64::<1>(c1);
            a0 = _mm_ternarylogic_epi64::<0x96>(a0, c4, r0);
            a5 = _mm_ternarylogic_epi64::<0x96>(a5, c4, r0);
            a10 = _mm_ternarylogic_epi64::<0x96>(a10, c4, r0);
            a15 = _mm_ternarylogic_epi64::<0x96>(a15, c4, r0);
            a20 = _mm_ternarylogic_epi64::<0x96>(a20, c4, r0);
            let r1 = _mm_rol_epi64::<1>(c2);
            a1 = _mm_ternarylogic_epi64::<0x96>(a1, c0, r1);
            a6 = _mm_ternarylogic_epi64::<0x96>(a6, c0, r1);
            a11 = _mm_ternarylogic_epi64::<0x96>(a11, c0, r1);
            a16 = _mm_ternarylogic_epi64::<0x96>(a16, c0, r1);
            a21 = _mm_ternarylogic_epi64::<0x96>(a21, c0, r1);
            let r2 = _mm_rol_epi64::<1>(c3);
            a2 = _mm_ternarylogic_epi64::<0x96>(a2, c1, r2);
            a7 = _mm_ternarylogic_epi64::<0x96>(a7, c1, r2);
            a12 = _mm_ternarylogic_epi64::<0x96>(a12, c1, r2);
            a17 = _mm_ternarylogic_epi64::<0x96>(a17, c1, r2);
            a22 = _mm_ternarylogic_epi64::<0x96>(a22, c1, r2);
            let r3 = _mm_rol_epi64::<1>(c4);
            a3 = _mm_ternarylogic_epi64::<0x96>(a3, c2, r3);
            a8 = _mm_ternarylogic_epi64::<0x96>(a8, c2, r3);
            a13 = _mm_ternarylogic_epi64::<0x96>(a13, c2, r3);
            a18 = _mm_ternarylogic_epi64::<0x96>(a18, c2, r3);
            a23 = _mm_ternarylogic_epi64::<0x96>(a23, c2, r3);
            let r4 = _mm_rol_epi64::<1>(c0);
            a4 = _mm_ternarylogic_epi64::<0x96>(a4, c3, r4);
            a9 = _mm_ternarylogic_epi64::<0x96>(a9, c3, r4);
            a14 = _mm_ternarylogic_epi64::<0x96>(a14, c3, r4);
            a19 = _mm_ternarylogic_epi64::<0x96>(a19, c3, r4);
            a24 = _mm_ternarylogic_epi64::<0x96>(a24, c3, r4);
            let b0 = _mm_rol_epi64::<0>(a0);
            let b10 = _mm_rol_epi64::<1>(a1);
            let b20 = _mm_rol_epi64::<62>(a2);
            let b5 = _mm_rol_epi64::<28>(a3);
            let b15 = _mm_rol_epi64::<27>(a4);
            let b16 = _mm_rol_epi64::<36>(a5);
            let b1 = _mm_rol_epi64::<44>(a6);
            let b11 = _mm_rol_epi64::<6>(a7);
            let b21 = _mm_rol_epi64::<55>(a8);
            let b6 = _mm_rol_epi64::<20>(a9);
            let b7 = _mm_rol_epi64::<3>(a10);
            let b17 = _mm_rol_epi64::<10>(a11);
            let b2 = _mm_rol_epi64::<43>(a12);
            let b12 = _mm_rol_epi64::<25>(a13);
            let b22 = _mm_rol_epi64::<39>(a14);
            let b23 = _mm_rol_epi64::<41>(a15);
            let b8 = _mm_rol_epi64::<45>(a16);
            let b18 = _mm_rol_epi64::<15>(a17);
            let b3 = _mm_rol_epi64::<21>(a18);
            let b13 = _mm_rol_epi64::<8>(a19);
            let b14 = _mm_rol_epi64::<18>(a20);
            let b24 = _mm_rol_epi64::<2>(a21);
            let b9 = _mm_rol_epi64::<61>(a22);
            let b19 = _mm_rol_epi64::<56>(a23);
            let b4 = _mm_rol_epi64::<14>(a24);
            a0 = _mm_ternarylogic_epi64::<0xd2>(b0, b1, b2);
            a1 = _mm_ternarylogic_epi64::<0xd2>(b1, b2, b3);
            a2 = _mm_ternarylogic_epi64::<0xd2>(b2, b3, b4);
            a3 = _mm_ternarylogic_epi64::<0xd2>(b3, b4, b0);
            a4 = _mm_ternarylogic_epi64::<0xd2>(b4, b0, b1);
            a5 = _mm_ternarylogic_epi64::<0xd2>(b5, b6, b7);
            a6 = _mm_ternarylogic_epi64::<0xd2>(b6, b7, b8);
            a7 = _mm_ternarylogic_epi64::<0xd2>(b7, b8, b9);
            a8 = _mm_ternarylogic_epi64::<0xd2>(b8, b9, b5);
            a9 = _mm_ternarylogic_epi64::<0xd2>(b9, b5, b6);
            a10 = _mm_ternarylogic_epi64::<0xd2>(b10, b11, b12);
            a11 = _mm_ternarylogic_epi64::<0xd2>(b11, b12, b13);
            a12 = _mm_ternarylogic_epi64::<0xd2>(b12, b13, b14);
            a13 = _mm_ternarylogic_epi64::<0xd2>(b13, b14, b10);
            a14 = _mm_ternarylogic_epi64::<0xd2>(b14, b10, b11);
            a15 = _mm_ternarylogic_epi64::<0xd2>(b15, b16, b17);
            a16 = _mm_ternarylogic_epi64::<0xd2>(b16, b17, b18);
            a17 = _mm_ternarylogic_epi64::<0xd2>(b17, b18, b19);
            a18 = _mm_ternarylogic_epi64::<0xd2>(b18, b19, b15);
            a19 = _mm_ternarylogic_epi64::<0xd2>(b19, b15, b16);
            a20 = _mm_ternarylogic_epi64::<0xd2>(b20, b21, b22);
            a21 = _mm_ternarylogic_epi64::<0xd2>(b21, b22, b23);
            a22 = _mm_ternarylogic_epi64::<0xd2>(b22, b23, b24);
            a23 = _mm_ternarylogic_epi64::<0xd2>(b23, b24, b20);
            a24 = _mm_ternarylogic_epi64::<0xd2>(b24, b20, b21);
            a0 = _mm_xor_si128(a0, _mm_set1_epi64x(rc as i64));
        }
    }
    let mut out = [[0; 32]; 2];
    let words: [u64; 2] = std::mem::transmute(a0);
    for (output, word) in out.iter_mut().zip(words) {
        output[0..8].copy_from_slice(&word.to_le_bytes());
    }
    let words: [u64; 2] = std::mem::transmute(a1);
    for (output, word) in out.iter_mut().zip(words) {
        output[8..16].copy_from_slice(&word.to_le_bytes());
    }
    let words: [u64; 2] = std::mem::transmute(a2);
    for (output, word) in out.iter_mut().zip(words) {
        output[16..24].copy_from_slice(&word.to_le_bytes());
    }
    let words: [u64; 2] = std::mem::transmute(a3);
    for (output, word) in out.iter_mut().zip(words) {
        output[24..32].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// Hashes independent inputs using one vector register per state lane.
///
/// # Safety
/// Requires AVX-512F.
#[target_feature(enable = "avx512f")]
#[inline(never)]
pub unsafe fn lanes8<const N: usize>(inputs: &[[u8; N]; 8]) -> [[u8; 32]; 8] {
    let mut blocks = [[0u8; 544]; 8];
    assert!(N < 544);
    let padded = (N / 136 + 1) * 136;
    for (block, input) in blocks.iter_mut().zip(inputs) {
        block[..N].copy_from_slice(input);
        block[N] = 1;
        block[padded - 1] |= 0x80;
    }
    let mut a0 = _mm512_setzero_si512();
    let mut a1 = _mm512_setzero_si512();
    let mut a2 = _mm512_setzero_si512();
    let mut a3 = _mm512_setzero_si512();
    let mut a4 = _mm512_setzero_si512();
    let mut a5 = _mm512_setzero_si512();
    let mut a6 = _mm512_setzero_si512();
    let mut a7 = _mm512_setzero_si512();
    let mut a8 = _mm512_setzero_si512();
    let mut a9 = _mm512_setzero_si512();
    let mut a10 = _mm512_setzero_si512();
    let mut a11 = _mm512_setzero_si512();
    let mut a12 = _mm512_setzero_si512();
    let mut a13 = _mm512_setzero_si512();
    let mut a14 = _mm512_setzero_si512();
    let mut a15 = _mm512_setzero_si512();
    let mut a16 = _mm512_setzero_si512();
    let mut a17 = _mm512_setzero_si512();
    let mut a18 = _mm512_setzero_si512();
    let mut a19 = _mm512_setzero_si512();
    let mut a20 = _mm512_setzero_si512();
    let mut a21 = _mm512_setzero_si512();
    let mut a22 = _mm512_setzero_si512();
    let mut a23 = _mm512_setzero_si512();
    let mut a24 = _mm512_setzero_si512();
    for offset in (0..padded).step_by(136) {
        let words = std::array::from_fn::<_, 8, _>(|j| {
            u64::from_le_bytes(blocks[j][offset..offset + 8].try_into().unwrap())
        });
        a0 = _mm512_xor_si512(a0, std::mem::transmute::<[u64; 8], __m512i>(words));
        let words = std::array::from_fn::<_, 8, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 8..offset + 16].try_into().unwrap())
        });
        a1 = _mm512_xor_si512(a1, std::mem::transmute::<[u64; 8], __m512i>(words));
        let words = std::array::from_fn::<_, 8, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 16..offset + 24].try_into().unwrap())
        });
        a2 = _mm512_xor_si512(a2, std::mem::transmute::<[u64; 8], __m512i>(words));
        let words = std::array::from_fn::<_, 8, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 24..offset + 32].try_into().unwrap())
        });
        a3 = _mm512_xor_si512(a3, std::mem::transmute::<[u64; 8], __m512i>(words));
        let words = std::array::from_fn::<_, 8, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 32..offset + 40].try_into().unwrap())
        });
        a4 = _mm512_xor_si512(a4, std::mem::transmute::<[u64; 8], __m512i>(words));
        let words = std::array::from_fn::<_, 8, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 40..offset + 48].try_into().unwrap())
        });
        a5 = _mm512_xor_si512(a5, std::mem::transmute::<[u64; 8], __m512i>(words));
        let words = std::array::from_fn::<_, 8, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 48..offset + 56].try_into().unwrap())
        });
        a6 = _mm512_xor_si512(a6, std::mem::transmute::<[u64; 8], __m512i>(words));
        let words = std::array::from_fn::<_, 8, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 56..offset + 64].try_into().unwrap())
        });
        a7 = _mm512_xor_si512(a7, std::mem::transmute::<[u64; 8], __m512i>(words));
        let words = std::array::from_fn::<_, 8, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 64..offset + 72].try_into().unwrap())
        });
        a8 = _mm512_xor_si512(a8, std::mem::transmute::<[u64; 8], __m512i>(words));
        let words = std::array::from_fn::<_, 8, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 72..offset + 80].try_into().unwrap())
        });
        a9 = _mm512_xor_si512(a9, std::mem::transmute::<[u64; 8], __m512i>(words));
        let words = std::array::from_fn::<_, 8, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 80..offset + 88].try_into().unwrap())
        });
        a10 = _mm512_xor_si512(a10, std::mem::transmute::<[u64; 8], __m512i>(words));
        let words = std::array::from_fn::<_, 8, _>(|j| {
            u64::from_le_bytes(blocks[j][offset + 88..offset + 96].try_into().unwrap())
        });
        a11 = _mm512_xor_si512(a11, std::mem::transmute::<[u64; 8], __m512i>(words));
        let words =
            blocks.map(|b| u64::from_le_bytes(b[offset + 96..offset + 104].try_into().unwrap()));
        a12 = _mm512_xor_si512(a12, std::mem::transmute::<[u64; 8], __m512i>(words));
        let words =
            blocks.map(|b| u64::from_le_bytes(b[offset + 104..offset + 112].try_into().unwrap()));
        a13 = _mm512_xor_si512(a13, std::mem::transmute::<[u64; 8], __m512i>(words));
        let words =
            blocks.map(|b| u64::from_le_bytes(b[offset + 112..offset + 120].try_into().unwrap()));
        a14 = _mm512_xor_si512(a14, std::mem::transmute::<[u64; 8], __m512i>(words));
        let words =
            blocks.map(|b| u64::from_le_bytes(b[offset + 120..offset + 128].try_into().unwrap()));
        a15 = _mm512_xor_si512(a15, std::mem::transmute::<[u64; 8], __m512i>(words));
        let words =
            blocks.map(|b| u64::from_le_bytes(b[offset + 128..offset + 136].try_into().unwrap()));
        a16 = _mm512_xor_si512(a16, std::mem::transmute::<[u64; 8], __m512i>(words));
        for &rc in &RC {
            let c0 = _mm512_ternarylogic_epi64::<0x96>(
                _mm512_ternarylogic_epi64::<0x96>(a0, a5, a10),
                a15,
                a20,
            );
            let c1 = _mm512_ternarylogic_epi64::<0x96>(
                _mm512_ternarylogic_epi64::<0x96>(a1, a6, a11),
                a16,
                a21,
            );
            let c2 = _mm512_ternarylogic_epi64::<0x96>(
                _mm512_ternarylogic_epi64::<0x96>(a2, a7, a12),
                a17,
                a22,
            );
            let c3 = _mm512_ternarylogic_epi64::<0x96>(
                _mm512_ternarylogic_epi64::<0x96>(a3, a8, a13),
                a18,
                a23,
            );
            let c4 = _mm512_ternarylogic_epi64::<0x96>(
                _mm512_ternarylogic_epi64::<0x96>(a4, a9, a14),
                a19,
                a24,
            );
            let r0 = _mm512_rol_epi64::<1>(c1);
            a0 = _mm512_ternarylogic_epi64::<0x96>(a0, c4, r0);
            a5 = _mm512_ternarylogic_epi64::<0x96>(a5, c4, r0);
            a10 = _mm512_ternarylogic_epi64::<0x96>(a10, c4, r0);
            a15 = _mm512_ternarylogic_epi64::<0x96>(a15, c4, r0);
            a20 = _mm512_ternarylogic_epi64::<0x96>(a20, c4, r0);
            let r1 = _mm512_rol_epi64::<1>(c2);
            a1 = _mm512_ternarylogic_epi64::<0x96>(a1, c0, r1);
            a6 = _mm512_ternarylogic_epi64::<0x96>(a6, c0, r1);
            a11 = _mm512_ternarylogic_epi64::<0x96>(a11, c0, r1);
            a16 = _mm512_ternarylogic_epi64::<0x96>(a16, c0, r1);
            a21 = _mm512_ternarylogic_epi64::<0x96>(a21, c0, r1);
            let r2 = _mm512_rol_epi64::<1>(c3);
            a2 = _mm512_ternarylogic_epi64::<0x96>(a2, c1, r2);
            a7 = _mm512_ternarylogic_epi64::<0x96>(a7, c1, r2);
            a12 = _mm512_ternarylogic_epi64::<0x96>(a12, c1, r2);
            a17 = _mm512_ternarylogic_epi64::<0x96>(a17, c1, r2);
            a22 = _mm512_ternarylogic_epi64::<0x96>(a22, c1, r2);
            let r3 = _mm512_rol_epi64::<1>(c4);
            a3 = _mm512_ternarylogic_epi64::<0x96>(a3, c2, r3);
            a8 = _mm512_ternarylogic_epi64::<0x96>(a8, c2, r3);
            a13 = _mm512_ternarylogic_epi64::<0x96>(a13, c2, r3);
            a18 = _mm512_ternarylogic_epi64::<0x96>(a18, c2, r3);
            a23 = _mm512_ternarylogic_epi64::<0x96>(a23, c2, r3);
            let r4 = _mm512_rol_epi64::<1>(c0);
            a4 = _mm512_ternarylogic_epi64::<0x96>(a4, c3, r4);
            a9 = _mm512_ternarylogic_epi64::<0x96>(a9, c3, r4);
            a14 = _mm512_ternarylogic_epi64::<0x96>(a14, c3, r4);
            a19 = _mm512_ternarylogic_epi64::<0x96>(a19, c3, r4);
            a24 = _mm512_ternarylogic_epi64::<0x96>(a24, c3, r4);
            let b0 = _mm512_rol_epi64::<0>(a0);
            let b10 = _mm512_rol_epi64::<1>(a1);
            let b20 = _mm512_rol_epi64::<62>(a2);
            let b5 = _mm512_rol_epi64::<28>(a3);
            let b15 = _mm512_rol_epi64::<27>(a4);
            let b16 = _mm512_rol_epi64::<36>(a5);
            let b1 = _mm512_rol_epi64::<44>(a6);
            let b11 = _mm512_rol_epi64::<6>(a7);
            let b21 = _mm512_rol_epi64::<55>(a8);
            let b6 = _mm512_rol_epi64::<20>(a9);
            let b7 = _mm512_rol_epi64::<3>(a10);
            let b17 = _mm512_rol_epi64::<10>(a11);
            let b2 = _mm512_rol_epi64::<43>(a12);
            let b12 = _mm512_rol_epi64::<25>(a13);
            let b22 = _mm512_rol_epi64::<39>(a14);
            let b23 = _mm512_rol_epi64::<41>(a15);
            let b8 = _mm512_rol_epi64::<45>(a16);
            let b18 = _mm512_rol_epi64::<15>(a17);
            let b3 = _mm512_rol_epi64::<21>(a18);
            let b13 = _mm512_rol_epi64::<8>(a19);
            let b14 = _mm512_rol_epi64::<18>(a20);
            let b24 = _mm512_rol_epi64::<2>(a21);
            let b9 = _mm512_rol_epi64::<61>(a22);
            let b19 = _mm512_rol_epi64::<56>(a23);
            let b4 = _mm512_rol_epi64::<14>(a24);
            a0 = _mm512_ternarylogic_epi64::<0xd2>(b0, b1, b2);
            a1 = _mm512_ternarylogic_epi64::<0xd2>(b1, b2, b3);
            a2 = _mm512_ternarylogic_epi64::<0xd2>(b2, b3, b4);
            a3 = _mm512_ternarylogic_epi64::<0xd2>(b3, b4, b0);
            a4 = _mm512_ternarylogic_epi64::<0xd2>(b4, b0, b1);
            a5 = _mm512_ternarylogic_epi64::<0xd2>(b5, b6, b7);
            a6 = _mm512_ternarylogic_epi64::<0xd2>(b6, b7, b8);
            a7 = _mm512_ternarylogic_epi64::<0xd2>(b7, b8, b9);
            a8 = _mm512_ternarylogic_epi64::<0xd2>(b8, b9, b5);
            a9 = _mm512_ternarylogic_epi64::<0xd2>(b9, b5, b6);
            a10 = _mm512_ternarylogic_epi64::<0xd2>(b10, b11, b12);
            a11 = _mm512_ternarylogic_epi64::<0xd2>(b11, b12, b13);
            a12 = _mm512_ternarylogic_epi64::<0xd2>(b12, b13, b14);
            a13 = _mm512_ternarylogic_epi64::<0xd2>(b13, b14, b10);
            a14 = _mm512_ternarylogic_epi64::<0xd2>(b14, b10, b11);
            a15 = _mm512_ternarylogic_epi64::<0xd2>(b15, b16, b17);
            a16 = _mm512_ternarylogic_epi64::<0xd2>(b16, b17, b18);
            a17 = _mm512_ternarylogic_epi64::<0xd2>(b17, b18, b19);
            a18 = _mm512_ternarylogic_epi64::<0xd2>(b18, b19, b15);
            a19 = _mm512_ternarylogic_epi64::<0xd2>(b19, b15, b16);
            a20 = _mm512_ternarylogic_epi64::<0xd2>(b20, b21, b22);
            a21 = _mm512_ternarylogic_epi64::<0xd2>(b21, b22, b23);
            a22 = _mm512_ternarylogic_epi64::<0xd2>(b22, b23, b24);
            a23 = _mm512_ternarylogic_epi64::<0xd2>(b23, b24, b20);
            a24 = _mm512_ternarylogic_epi64::<0xd2>(b24, b20, b21);
            a0 = _mm512_xor_si512(a0, _mm512_set1_epi64(rc as i64));
        }
    }
    let mut out = [[0; 32]; 8];
    let words: [u64; 8] = std::mem::transmute(a0);
    for (output, word) in out.iter_mut().zip(words) {
        output[0..8].copy_from_slice(&word.to_le_bytes());
    }
    let words: [u64; 8] = std::mem::transmute(a1);
    for (output, word) in out.iter_mut().zip(words) {
        output[8..16].copy_from_slice(&word.to_le_bytes());
    }
    let words: [u64; 8] = std::mem::transmute(a2);
    for (output, word) in out.iter_mut().zip(words) {
        output[16..24].copy_from_slice(&word.to_le_bytes());
    }
    let words: [u64; 8] = std::mem::transmute(a3);
    for (output, word) in out.iter_mut().zip(words) {
        output[24..32].copy_from_slice(&word.to_le_bytes());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check<const N: usize>() {
        for seed in 0..16u64 {
            let mut rng = seed + 1;
            let inputs = std::array::from_fn::<_, 8, _>(|_| {
                std::array::from_fn(|_| {
                    rng ^= rng << 13;
                    rng ^= rng >> 7;
                    rng ^= rng << 17;
                    rng as u8
                })
            });
            let expected = inputs.map(|input| {
                let mut out = [0; 32];
                crate::tiny_keccak(&input, &mut out);
                out
            });
            for i in 0..8 {
                assert_eq!(digest(&inputs[i]), expected[i]);
                #[cfg(feature = "tail-sharing")]
                assert_eq!(tail_fixed(&inputs[i]), expected[i]);
                if N < 136 {
                    assert_eq!(wrapper::<N, false>(&inputs[i]), expected[i]);
                    assert_eq!(wrapper::<N, true>(&inputs[i]), expected[i]);
                    if sha3_asm::IMPL == "keccak1600-x86_64" {
                        assert_eq!(scalar_permutation(&inputs[i]), expected[i]);
                    }
                }
            }
            if is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512vl") {
                assert_eq!(unsafe { lanes2(&[inputs[0], inputs[1]]) }, [expected[0], expected[1]]);
                assert_eq!(unsafe { lanes1(&[inputs[0]]) }, [expected[0]]);
                assert_eq!(unsafe { lanes8(&inputs) }, expected);
            }
        }
    }

    #[test]
    fn differential() {
        check::<0>();
        check::<1>();
        check::<20>();
        check::<32>();
        check::<64>();
        check::<135>();
        check::<136>();
        check::<137>();
        check::<272>();
        check::<532>();
        check::<543>();
        #[cfg(feature = "tail-sharing")]
        for len in [20, 32, 64] {
            for offset in 0..32 {
                let bytes = (0..len + offset).map(|i| (i * 137) as u8).collect::<Vec<_>>();
                let mut expected = [0; 32];
                crate::tiny_keccak(&bytes[offset..], &mut expected);
                assert_eq!(tail_runtime(&bytes[offset..]), expected);
            }
        }
    }
}

#[inline(never)]
pub fn assembly<const N: usize>(input: &[u8; N]) -> [u8; 32] {
    let rem = N % 136;
    let mut block = [0; 136];
    block[..rem].copy_from_slice(&input[N - rem..]);
    block[rem] = 1;
    block[135] |= 0x80;
    let mut state = [0; 25];
    if N >= 136 {
        sha3_asm::sha3_absorb(&mut state, &input[..N - rem], 136);
    }
    sha3_asm::sha3_absorb(&mut state, &block, 136);
    let mut out = [0; 32];
    sha3_asm::sha3_squeeze(&mut state, &mut out, 136);
    out
}

#[inline(never)]
pub fn digest_runtime(input: &[u8]) -> [u8; 32] {
    Keccak256::digest(input).into()
}

#[inline(never)]
pub fn assembly_runtime(input: &[u8]) -> [u8; 32] {
    let rem = input.len() % 136;
    let mut block = [0; 136];
    block[..rem].copy_from_slice(&input[input.len() - rem..]);
    block[rem] = 1;
    block[135] |= 0x80;
    let mut state = [0; 25];
    if input.len() >= 136 {
        sha3_asm::sha3_absorb(&mut state, &input[..input.len() - rem], 136);
    }
    sha3_asm::sha3_absorb(&mut state, &block, 136);
    let mut out = [0; 32];
    sha3_asm::sha3_squeeze(&mut state, &mut out, 136);
    out
}

#[inline(never)]
pub fn digest224(input: &[u8]) -> [u8; 28] {
    keccak_asm::Keccak224::digest(input).into()
}

#[inline(never)]
pub fn digest384(input: &[u8]) -> [u8; 48] {
    keccak_asm::Keccak384::digest(input).into()
}

#[inline(never)]
pub fn digest512(input: &[u8]) -> [u8; 64] {
    keccak_asm::Keccak512::digest(input).into()
}

#[inline(never)]
pub fn assembly_variant<const RATE: usize, const OUT: usize>(input: &[u8]) -> [u8; OUT] {
    let mut state = [0; 25];
    let rem = sha3_asm::sha3_absorb(&mut state, input, RATE);
    let mut block = [0; RATE];
    block[..rem].copy_from_slice(&input[input.len() - rem..]);
    block[rem] = 1;
    block[RATE - 1] |= 0x80;
    sha3_asm::sha3_absorb(&mut state, &block, RATE);
    let mut out = [0; OUT];
    sha3_asm::sha3_squeeze(&mut state, &mut out, RATE);
    out
}

#[allow(dead_code, unused_imports, unexpected_cfgs)]
#[path = "../before-direct-tail/mod.rs"]
mod stack_backend;

#[inline(never)]
pub fn stack_runtime(input: &[u8]) -> [u8; 32] {
    let mut output = [0; 32];
    unsafe { stack_backend::digest::<136, 1>(input, output.as_mut_ptr()) };
    output
}

#[inline(never)]
pub fn stack_fixed<const N: usize>(input: &[u8; N]) -> [u8; 32] {
    let mut output = [0; 32];
    unsafe { stack_backend::digest::<136, 1>(input, output.as_mut_ptr()) };
    output
}

// AVX2 tail-sharing experiment. The shared assembly uses a private register convention.
// Copyright (c) 2017, CRYPTOGAMS by <appro@openssl.org>.
// Adapted from the existing AVX2 backend (BSD-3-Clause).
#[cfg(feature = "tail-sharing")]
core::arch::global_asm!(
    r#".text
.p2align 4
.hidden __keccak_avx2_tail
.globl __keccak_avx2_tail
.type __keccak_avx2_tail,@function
__keccak_avx2_tail:
xor ecx, ecx
lea rax, [rip + .Lkt_rc]
vmovdqa ymm10, ymmword ptr [rip + .Lkt_12]
vmovdqa ymm11, ymmword ptr [rip + .Lkt_13]
.p2align 5
.Lkt_round:
	vpshufd ymm3, ymm13, 78
	vpxor ymm4, ymm2, ymm1
	vpxor ymm5, ymm15, ymm0
	vpxor ymm4, ymm4, ymm5
	vpxor ymm4, ymm12, ymm4
	vpermq ymm5, ymm4, 147
	vpxor ymm3, ymm13, ymm3
	vpermq ymm6, ymm3, 78
	vpsrlq ymm7, ymm4, 63
	vpaddq ymm4, ymm4, ymm4
	vpor ymm4, ymm4, ymm7
	vpxor xmm7, xmm5, xmm4
	vpbroadcastq ymm7, xmm7
	vpxor ymm3, ymm14, ymm3
	vpxor ymm3, ymm3, ymm6
	vpsrlq ymm6, ymm3, 63
	vpaddq ymm8, ymm3, ymm3
	vpor ymm6, ymm8, ymm6
	vpxor ymm8, ymm13, ymm7
	vpxor ymm14, ymm14, ymm7
	vpermq ymm4, ymm4, 249
	vpblendd ymm4, ymm4, ymm6, 192
	vpblendd ymm3, ymm5, ymm3, 3
	vpxor ymm4, ymm3, ymm4
	vpsrlvq ymm3, ymm8, ymmword ptr [rip + .Lkt_2]
	vpsllvq ymm5, ymm8, ymmword ptr [rip + .Lkt_3]
	vpor ymm3, ymm5, ymm3
	vpxor ymm0, ymm0, ymm4
	vpsrlvq ymm5, ymm0, ymmword ptr [rip + .Lkt_4]
	vpsllvq ymm0, ymm0, ymmword ptr [rip + .Lkt_5]
	vpor ymm13, ymm0, ymm5
	vpxor ymm0, ymm15, ymm4
	vpsrlvq ymm5, ymm0, ymmword ptr [rip + .Lkt_6]
	vpsllvq ymm0, ymm0, ymmword ptr [rip + .Lkt_7]
	vpor ymm5, ymm0, ymm5
	vpxor ymm0, ymm2, ymm4
	vpsrlvq ymm2, ymm0, ymmword ptr [rip + .Lkt_8]
	vpsllvq ymm0, ymm0, ymmword ptr [rip + .Lkt_9]
	vpor ymm6, ymm0, ymm2
	vpxor ymm0, ymm1, ymm4
	vpermq ymm15, ymm3, 141
	vpermq ymm2, ymm13, 141
	vpsrlvq ymm1, ymm0, ymmword ptr [rip + .Lkt_10]
	vpsllvq ymm0, ymm0, ymmword ptr [rip + .Lkt_11]
	vpor ymm0, ymm0, ymm1
	vpxor ymm4, ymm12, ymm4
	vpermq ymm12, ymm5, 27
	vpermq ymm1, ymm6, 114
	vpsrlvq ymm5, ymm4, ymm10
	vpsllvq ymm4, ymm4, ymm11
	vpor ymm5, ymm4, ymm5
	vpblendd ymm4, ymm2, ymm15, 240
	vpunpckhqdq ymm7, ymm6, ymm12
	vpblendd ymm7, ymm4, ymm7, 60
	vperm2i128 ymm8, ymm6, ymm12, 49
	vpblendd ymm4, ymm8, ymm4, 60
	vpandn ymm7, ymm7, ymm4
	vpunpcklqdq ymm4, ymm2, ymm6
	vpblendd ymm6, ymm5, ymm12, 240
	vpblendd ymm4, ymm6, ymm4, 60
	vpunpckhqdq ymm8, ymm13, ymm1
	vpblendd ymm6, ymm8, ymm6, 60
	vpandn ymm4, ymm4, ymm6
	vpblendd ymm6, ymm1, ymm5, 240
	vperm2i128 ymm8, ymm3, ymm12, 49
	vpblendd ymm8, ymm6, ymm8, 60
	vpunpcklqdq ymm9, ymm12, ymm3
	vpblendd ymm6, ymm9, ymm6, 60
	vpxor ymm4, ymm15, ymm4
	vpandn ymm6, ymm8, ymm6
	vpblendd ymm8, ymm15, ymm1, 240
	vperm2i128 ymm9, ymm13, ymm5, 49
	vpblendd ymm9, ymm8, ymm9, 60
	vpunpcklqdq ymm13, ymm5, ymm13
	vpblendd ymm8, ymm13, ymm8, 60
	vpandn ymm8, ymm9, ymm8
	vpxor ymm13, ymm7, ymm5
	vpxor ymm15, ymm6, ymm2
	vpxor ymm6, ymm8, ymm12
	vpblendd ymm2, ymm12, ymm2, 240
	vinserti128 ymm7, ymm5, xmm3, 1
	vpunpckhqdq ymm3, ymm3, ymm5
	vpblendd ymm5, ymm2, ymm7, 60
	vpblendd ymm2, ymm3, ymm2, 60
	vpandn ymm2, ymm5, ymm2
	vpxor ymm1, ymm2, ymm1
	vpermq ymm2, ymm0, 249
	vpblendd ymm2, ymm2, ymm14, 192
	vpermq ymm3, ymm0, 46
	vpblendd ymm3, ymm3, ymm14, 48
	vpandn ymm2, ymm2, ymm3
	vpxor ymm12, ymm2, ymm0
	vpshufd xmm2, xmm0, 238
	vpandn ymm0, ymm0, ymm2
	vmovq xmm2, qword ptr [rcx + rax]
	vpxor xmm0, xmm2, xmm0
	vpbroadcastq ymm0, xmm0
	vpxor ymm14, ymm14, ymm0
	add rcx, 8
	vpermq ymm0, ymm4, 27
	vpermq ymm2, ymm6, 141
	vpermq ymm1, ymm1, 114
	cmp rcx, 192
	jne .Lkt_round
	vpermq ymm0, ymm12, 144
	vpblendd ymm0, ymm0, ymm14, 3
	vmovdqu ymmword ptr [rdi], ymm0
	vzeroupper
	ret
.size __keccak_avx2_tail, .-__keccak_avx2_tail
.section .rodata
.p2align 5
.Lkt_0:
	.quad	1

.p2align 5
.Lkt_14:
	.quad	-9223372036854775808

.p2align 5
.Lkt_2:
	.quad	61
	.quad	46
	.quad	28
	.quad	23

.p2align 5
.Lkt_3:
	.quad	3
	.quad	18
	.quad	36
	.quad	41

.p2align 5
.Lkt_4:
	.quad	19
	.quad	58
	.quad	8
	.quad	25

.p2align 5
.Lkt_5:
	.quad	45
	.quad	6
	.quad	56
	.quad	39

.p2align 5
.Lkt_6:
	.quad	54
	.quad	3
	.quad	9
	.quad	56

.p2align 5
.Lkt_7:
	.quad	10
	.quad	61
	.quad	55
	.quad	8

.p2align 5
.Lkt_8:
	.quad	62
	.quad	49
	.quad	39
	.quad	44

.p2align 5
.Lkt_9:
	.quad	2
	.quad	15
	.quad	25
	.quad	20

.p2align 5
.Lkt_10:
	.quad	20
	.quad	21
	.quad	43
	.quad	50

.p2align 5
.Lkt_11:
	.quad	44
	.quad	43
	.quad	21
	.quad	14

.p2align 5
.Lkt_12:
	.quad	63
	.quad	2
	.quad	36
	.quad	37

.p2align 5
.Lkt_13:
	.quad	1
	.quad	62
	.quad	28
	.quad	27

.p2align 5
.Lkt_rc:
	.ascii	"\001\000\000\000\000\000\000\000\202\200\000\000\000\000\000\000\212\200\000\000\000\000\000\200\000\200\000\200\000\000\000\200\213\200\000\000\000\000\000\000\001\000\000\200\000\000\000\000\201\200\000\200\000\000\000\200\t\200\000\000\000\000\000\200\212\000\000\000\000\000\000\000\210\000\000\000\000\000\000\000\t\200\000\200\000\000\000\000\n\000\000\200\000\000\000\000\213\200\000\200\000\000\000\000\213\000\000\000\000\000\000\200\211\200\000\000\000\000\000\200\003\200\000\000\000\000\000\200\002\200\000\000\000\000\000\200\200\000\000\000\000\000\000\200\n\200\000\000\000\000\000\000\n\000\000\200\000\000\000\200\201\200\000\200\000\000\000\200\200\200\000\000\000\000\000\200\001\000\000\200\000\000\000\000\b\200\000\200\000\000\000\200"
"#
);

#[cfg(feature = "tail-sharing")]
#[unsafe(naked)]
unsafe extern "sysv64" fn tail_loader<const N: usize>(output: *mut u8, input: *const u8) {
    core::arch::naked_asm!(
        "vpbroadcastq ymm14, qword ptr [rsi]",
        "vpxor xmm13, xmm13, xmm13",
        "vmovq xmm0, qword ptr [rip + .Lkt_14]",
        "vpxor xmm15, xmm15, xmm15",
        "vpxor xmm2, xmm2, xmm2",
        "vpxor xmm1, xmm1, xmm1",
        ".if {n} == 20",
        "vmovq xmm12, qword ptr [rsi + 8]",
        "mov eax, dword ptr [rsi + 16]",
        "bts rax, 32",
        "vpinsrq xmm12, xmm12, rax, 1",
        ".elseif {n} == 32",
        "vmovdqu xmm12, xmmword ptr [rsi + 8]",
        "vmovq xmm3, qword ptr [rsi + 24]",
        "vpinsrq xmm3, xmm3, qword ptr [rip + .Lkt_0], 1",
        "vinserti128 ymm12, ymm12, xmm3, 1",
        ".elseif {n} == 64",
        "vmovdqu ymm12, ymmword ptr [rsi + 8]",
        "vmovq xmm3, qword ptr [rsi + 40]",
        "vinserti128 ymm13, ymm13, xmm3, 1",
        "vpinsrq xmm0, xmm0, qword ptr [rsi + 56], 1",
        "vmovq xmm3, qword ptr [rip + .Lkt_0]",
        "vinserti128 ymm15, ymm15, xmm3, 1",
        "vmovq xmm1, qword ptr [rsi + 48]",
        ".else",
        ".error \"unsupported input length\"",
        ".endif",
        "jmp __keccak_avx2_tail",
        n = const N,
    );
}

#[cfg(feature = "tail-sharing")]
#[inline(never)]
pub fn tail_fixed<const N: usize>(input: &[u8; N]) -> [u8; 32] {
    tail_runtime(input)
}

#[cfg(feature = "tail-sharing")]
#[inline]
pub fn tail_runtime(input: &[u8]) -> [u8; 32] {
    assert!(is_x86_feature_detected!("avx2"));
    let mut output = std::mem::MaybeUninit::<[u8; 32]>::uninit();
    unsafe {
        match input.len() {
            20 => tail_loader::<20>(output.as_mut_ptr().cast(), input.as_ptr()),
            32 => tail_loader::<32>(output.as_mut_ptr().cast(), input.as_ptr()),
            64 => tail_loader::<64>(output.as_mut_ptr().cast(), input.as_ptr()),
            _ => return digest_runtime(input),
        }
        output.assume_init()
    }
}
