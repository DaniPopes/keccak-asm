//! TODO

#![no_std]
#![warn(missing_docs, rust_2018_idioms)]

pub use digest::{self, Digest};

use core::fmt;
use digest::block_buffer::Eager;
#[cfg(feature = "oid")]
use digest::const_oid::{AssociatedOid, ObjectIdentifier};
use digest::consts::{U104, U136, U144, U28, U32, U48, U64, U72};
use digest::core_api::{AlgorithmName, BlockSizeUser, BufferKindUser};
use digest::typenum::Unsigned;
use digest::{FixedOutput, FixedOutputReset, HashMarker, Output, OutputSizeUser, Reset, Update};

#[macro_use]
mod macros;
mod state;
use state::Sha3State;

// Paddings
const KECCAK: u8 = 0x01;
const SHA3: u8 = 0x06;
// const SHAKE: u8 = 0x1f;
// const CSHAKE: u8 = 0x4;

impl_sha3!(Keccak224, U28, U144, KECCAK, "Keccak-224");
impl_sha3!(Keccak256, U32, U136, KECCAK, "Keccak-256");
impl_sha3!(Keccak384, U48, U104, KECCAK, "Keccak-384");
impl_sha3!(Keccak512, U64, U72, KECCAK, "Keccak-512");

// TODO: Block size is not derived from bits
// impl_sha3!(Keccak256Full, U200, U136, KECCAK, "SHA-3 CryptoNight variant");

impl_sha3!(Sha3_224, U28, U144, SHA3, "SHA-3-224", "2.16.840.1.101.3.4.2.7");
impl_sha3!(Sha3_256, U32, U136, SHA3, "SHA-3-256", "2.16.840.1.101.3.4.2.8");
impl_sha3!(Sha3_384, U48, U104, SHA3, "SHA-3-384", "2.16.840.1.101.3.4.2.9");
impl_sha3!(Sha3_512, U64, U72, SHA3, "SHA-3-512", "2.16.840.1.101.3.4.2.10");

#[cfg(test)]
#[cfg(TODO)]
mod tests {
    #[test]
    fn keccakf1600() {
        let mut buffer = [69; 200];
        let cpy = buffer;
        super::keccak_f1600(&mut buffer);
        assert_ne!(buffer, cpy);
    }
}
