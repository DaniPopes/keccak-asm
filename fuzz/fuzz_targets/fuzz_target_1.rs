#![no_main]

use keccak_asm::{Digest, Keccak256};
use libfuzzer_sys::fuzz_target;
use tiny_keccak::{Hasher, Keccak};

fuzz_target!(|data: &[u8]| {
    // init
    let mut keccak = Keccak256::new();
    let mut keccak2 = Keccak::v256();

    // update
    keccak.update(data);
    keccak2.update(data);

    // output
    let mut tiny_output = [0u8; 32];
    keccak2.finalize(&mut tiny_output);

    let asm_output = &keccak.finalize()[..];

    // compare
    assert_eq!(asm_output, &tiny_output, "Keccak mismatch! Input: {data:x?}\ntiny_keccak output: {tiny_output:x?}, keccak_asm output: {asm_output:x?}");
});
