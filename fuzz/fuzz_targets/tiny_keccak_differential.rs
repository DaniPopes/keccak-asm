#![no_main]

use keccak_asm::{Digest, Keccak256};
use libfuzzer_sys::fuzz_target;
use tiny_keccak::{Hasher, Keccak};

fn tiny_keccak(data: &[u8]) -> [u8; 32] {
    let mut keccak = Keccak::v256();
    keccak.update(data);
    let mut output = [0u8; 32];
    keccak.finalize(&mut output);
    output
}

fuzz_target!(|data: &[u8]| {
    // init
    let mut keccak = Keccak256::new();

    // update
    keccak.update(data);

    // output
    let tiny_output = tiny_keccak(data);

    let asm_output = &keccak.finalize()[..];

    // compare
    assert_eq!(asm_output, &tiny_output, "Keccak mismatch! Input: {data:x?}\ntiny_keccak output: {tiny_output:x?}, keccak_asm output: {asm_output:x?}");

    // Split the rest of the input into messages whose lengths come from the first byte, and
    // hash them as a batch.
    let Some((&split, rest)) = data.split_first() else { return };
    let inputs = rest.chunks(usize::from(split) + 1).collect::<Vec<_>>();
    let mut count = 0;
    Keccak256::digest_batch(&inputs, |input, digest| {
        assert_eq!(digest[..], tiny_keccak(input), "Batch mismatch! Input: {input:x?}");
        count += 1;
    });
    assert_eq!(count, inputs.len());
});
