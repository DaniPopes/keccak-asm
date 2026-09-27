#![no_std]

extern crate std;

use digest::{dev::fixed_reset_test, new_test, Digest, FixedOutputReset};

new_test!(keccak_224, "keccak_224", keccak_asm::Keccak224, fixed_reset_test);
new_test!(keccak_256, "keccak_256", keccak_asm::Keccak256, fixed_reset_test);
new_test!(keccak_384, "keccak_384", keccak_asm::Keccak384, fixed_reset_test);
new_test!(keccak_512, "keccak_512", keccak_asm::Keccak512, fixed_reset_test);
// tests are from https://github.com/kazcw/yellowsun/blob/test-keccak/src/lib.rs#L171
// new_test!(keccak_256_full, "keccak_256_full", keccak_asm::Keccak256Full, fixed_reset_test);

new_test!(sha3_224, "sha3_224", keccak_asm::Sha3_224, fixed_reset_test);
new_test!(sha3_256, "sha3_256", keccak_asm::Sha3_256, fixed_reset_test);
new_test!(sha3_384, "sha3_384", keccak_asm::Sha3_384, fixed_reset_test);
new_test!(sha3_512, "sha3_512", keccak_asm::Sha3_512, fixed_reset_test);

#[test]
fn sanity() {
    type D = keccak_asm::Keccak256;

    fn test_hasher(input: &str, expected: &str) {
        let mut hasher = D::new();
        hasher.update(input.as_bytes());
        let result = hasher.finalize();
        assert_eq!(hex::encode(result), expected);

        assert_eq!(hex::encode(D::digest(input)), expected);
    }
    test_hasher("testFoo()", "79adbd5094e60c1bc2b963678ff44695d1430b8ccff0b1cd57c03a7f63567822");
    test_hasher("test_Foo()", "45c48c2bd4afc6adc7884fe296b9af10e234ddbc44f2f99f40cfb8b6391e9798");
}

#[test]
fn digest_matches_references() {
    let mut input = [0; 65568];
    for pattern in 0..6 {
        let mut rng = pattern + 1u64;
        for (i, byte) in input.iter_mut().enumerate() {
            rng ^= rng << 13;
            rng ^= rng >> 7;
            rng ^= rng << 17;
            *byte = match pattern {
                0 => 0,
                1 => 0xff,
                2 => i as u8,
                _ => rng as u8,
            };
        }
        for len in (0..=433).chain([532, 544, 1023, 1024, 1025, 4095, 4096, 4097, 65536]) {
            let offset = len % 32;
            check_all(&input[offset..offset + len]);
        }
        for offset in 0..32 {
            for rate in [72, 104, 136, 144] {
                for len in [rate - 1, rate, rate + 1, 2 * rate - 1, 2 * rate, 2 * rate + 1] {
                    check_all(&input[offset..offset + len]);
                }
            }
        }
    }
}

fn check_all(input: &[u8]) {
    check::<keccak_asm::Keccak224, sha3::Keccak224>(
        input,
        &keccak_asm::Keccak224::digest(input),
        144,
        1,
    );
    let digest = inspect_keccak256(input);
    assert_eq!(inspect_keccak256_output(input).as_slice(), digest);
    check::<keccak_asm::Keccak256, sha3::Keccak256>(input, &digest, 136, 1);
    if let Ok(input) = input.try_into() {
        assert_eq!(inspect_keccak256_64(input), digest);
    }
    if let Ok(input) = input.try_into() {
        assert_eq!(inspect_keccak256_20(input), digest);
    }
    if let Ok(input) = input.try_into() {
        assert_eq!(inspect_keccak256_32(input), digest);
    }
    check::<keccak_asm::Keccak384, sha3::Keccak384>(
        input,
        &keccak_asm::Keccak384::digest(input),
        104,
        1,
    );
    check::<keccak_asm::Keccak512, sha3::Keccak512>(
        input,
        &keccak_asm::Keccak512::digest(input),
        72,
        1,
    );
    check::<keccak_asm::Sha3_224, sha3::Sha3_224>(
        input,
        &keccak_asm::Sha3_224::digest(input),
        144,
        6,
    );
    check::<keccak_asm::Sha3_256, sha3::Sha3_256>(
        input,
        &keccak_asm::Sha3_256::digest(input),
        136,
        6,
    );
    check::<keccak_asm::Sha3_384, sha3::Sha3_384>(
        input,
        &keccak_asm::Sha3_384::digest(input),
        104,
        6,
    );
    check::<keccak_asm::Sha3_512, sha3::Sha3_512>(
        input,
        &keccak_asm::Sha3_512::digest(input),
        72,
        6,
    );
}

fn check<D: Digest, R: Digest>(input: &[u8], digest: &[u8], rate: usize, pad: u8) {
    let expected = R::digest(input);
    assert_eq!(
        digest,
        expected.as_slice(),
        "{} length {}",
        core::any::type_name::<D>(),
        input.len()
    );

    let mut state = [0; 25];
    let rem = sha3_asm::sha3_absorb(&mut state, input, rate);
    let mut block = [0; 144];
    block[..rem].copy_from_slice(&input[input.len() - rem..]);
    block[rem] = pad;
    block[rate - 1] |= 0x80;
    sha3_asm::sha3_absorb(&mut state, &block[..rate], rate);
    let mut assembly = [0; 64];
    let assembly = &mut assembly[..digest.len()];
    sha3_asm::sha3_squeeze(&mut state, assembly, rate);
    assert_eq!(assembly, expected.as_slice());

    assert_eq!(D::digest(input).as_slice(), expected.as_slice());
}

#[test]
fn streaming_boundaries_clone_and_reset() {
    check_streaming::<keccak_asm::Keccak224, sha3::Keccak224>(144);
    check_streaming::<keccak_asm::Keccak256, sha3::Keccak256>(136);
    check_streaming::<keccak_asm::Keccak384, sha3::Keccak384>(104);
    check_streaming::<keccak_asm::Keccak512, sha3::Keccak512>(72);
    check_streaming::<keccak_asm::Sha3_224, sha3::Sha3_224>(144);
    check_streaming::<keccak_asm::Sha3_256, sha3::Sha3_256>(136);
    check_streaming::<keccak_asm::Sha3_384, sha3::Sha3_384>(104);
    check_streaming::<keccak_asm::Sha3_512, sha3::Sha3_512>(72);
}

fn check_streaming<D: Digest + FixedOutputReset + Clone, R: Digest>(rate: usize) {
    let input = core::array::from_fn::<_, 4097, _>(|i| i.wrapping_mul(131) as u8);
    for len in [0, 1, rate - 1, rate, rate + 1, 2 * rate - 1, 2 * rate, 2 * rate + 1, 4096] {
        let input = &input[1..1 + len];
        let expected = R::digest(input);
        for chunk_size in [1, 7, 13, rate - 1, rate, rate + 1, 2 * rate + 1, 4096] {
            let mut state = D::new();
            for chunk in input.chunks(chunk_size) {
                Digest::update(&mut state, []);
                Digest::update(&mut state, chunk);
            }
            assert_eq!(state.finalize_reset().as_slice(), expected.as_slice());
            assert_eq!(state.finalize_reset().as_slice(), R::digest([]).as_slice());
            Digest::update(&mut state, input);
            assert_eq!(state.finalize().as_slice(), expected.as_slice());
        }
        for split in [0, len / 2, len] {
            let mut state = D::new();
            Digest::update(&mut state, &input[..split]);
            let mut cloned = state.clone();
            Digest::update(&mut cloned, &input[split..]);
            assert_eq!(cloned.finalize().as_slice(), expected.as_slice());
            assert_eq!(state.clone().finalize().as_slice(), R::digest(&input[..split]).as_slice());
            Digest::reset(&mut state);
            Digest::update(&mut state, input);
            assert_eq!(state.finalize().as_slice(), expected.as_slice());
        }
    }
}

#[test]
fn selected_backend() {
    if let Some(expected) = option_env!("KECCAK_TEST_BACKEND") {
        assert_eq!(keccak_asm::IMPL, expected);
    }
}

#[test]
fn digest_exact_allocations() {
    for len in (0..=433).chain([4095, 4096, 4097]) {
        let input = (0..len).map(|i| i as u8).collect::<std::vec::Vec<_>>().into_boxed_slice();
        check_all(&input);
    }
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn inspect_keccak256(input: &[u8]) -> [u8; 32] {
    keccak_asm::Keccak256::digest(input).into()
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn inspect_keccak256_64(input: &[u8; 64]) -> [u8; 32] {
    keccak_asm::Keccak256::digest(input).into()
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn inspect_keccak256_20(input: &[u8; 20]) -> [u8; 32] {
    keccak_asm::Keccak256::digest(input).into()
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn inspect_keccak256_32(input: &[u8; 32]) -> [u8; 32] {
    keccak_asm::Keccak256::digest(input).into()
}

#[unsafe(no_mangle)]
#[inline(never)]
pub fn inspect_keccak256_output(input: &[u8]) -> digest::Output<keccak_asm::Keccak256> {
    keccak_asm::Keccak256::digest(input)
}
