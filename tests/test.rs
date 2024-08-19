#![no_std]

use digest::{dev::fixed_reset_test, new_test};

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

#[track_caller]
fn test_hasher<D: digest::Digest>(input: &str, expected: &str) {
    let mut hasher = D::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    assert_eq!(hex::encode(result), expected);
}

#[test]
fn sanity() {
    test_hasher::<keccak_asm::Keccak256>(
        "testFoo()",
        "79adbd5094e60c1bc2b963678ff44695d1430b8ccff0b1cd57c03a7f63567822",
    );
    test_hasher::<keccak_asm::Keccak256>(
        "test_Foo()",
        "45c48c2bd4afc6adc7884fe296b9af10e234ddbc44f2f99f40cfb8b6391e9798",
    );
}
