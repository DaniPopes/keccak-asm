#![no_std]

#[cfg(not(any(target_arch = "x86_64", target_arch = "x86", target_arch = "aarch64")))]
compile_error!("crate can only be used on x86, x86-64 and aarch64 architectures");

#[link(name = "keccak1600", kind = "static")]
extern "C" {
    fn SHA3_squeeze();
    fn SHA3_absorb();
}
