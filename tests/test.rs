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
    let digest = keccak_asm::Keccak256::digest(input);
    check::<keccak_asm::Keccak256, sha3::Keccak256>(input, &digest, 136, 1);
    if let Ok(input) = <&[u8; 64]>::try_from(input) {
        assert_eq!(keccak_asm::Keccak256::digest(input), digest);
    }
    if let Ok(input) = <&[u8; 20]>::try_from(input) {
        assert_eq!(keccak_asm::Keccak256::digest(input), digest);
    }
    if let Ok(input) = <&[u8; 32]>::try_from(input) {
        assert_eq!(keccak_asm::Keccak256::digest(input), digest);
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

    #[cfg(not(target_arch = "wasm32"))]
    {
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
    }
    #[cfg(target_arch = "wasm32")]
    let _ = (rate, pad);

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

#[test]
fn digest_batch_matches_references() {
    let data = core::array::from_fn::<_, 4096, _>(|i| (i.wrapping_mul(167) ^ (i >> 8)) as u8);
    let inputs = |lens: &[usize]| {
        lens.iter()
            .enumerate()
            .map(|(i, &len)| &data[i * 13 % 512..][..len])
            .collect::<std::vec::Vec<_>>()
    };
    // Equal lengths, across every block boundary up to four Keccak-256 blocks.
    for len in 0..=600 {
        for count in [1, 2, 3, 4, 5, 8, 9, 17] {
            check_batch(&inputs(&[len; 17][..count]));
        }
    }
    // Mixed lengths, for every count up to two passes of eight lanes plus one.
    for count in 0..=17 {
        let lens = (0..count).map(|i| i * 37 % 600).collect::<std::vec::Vec<_>>();
        check_batch(&inputs(&lens));
        let lens = (0..count).map(|i| [20, 32][i % 2]).collect::<std::vec::Vec<_>>();
        check_batch(&inputs(&lens));
        let lens =
            (0..count).map(|i| if i == count / 2 { 31 } else { 32 }).collect::<std::vec::Vec<_>>();
        check_batch(&inputs(&lens));
    }
    for lens in [
        &[0, 136, 1000, 5, 272, 135, 137, 3000, 64][..],
        &[3000, 0, 0, 0, 0, 0, 0, 0],
        &[71, 72, 73, 103, 104, 105, 143, 144, 145],
    ] {
        check_batch(&inputs(lens));
    }

    // Items are passed back by value, in input order.
    let owned = (0..11).map(|i| data[..i * 29].to_vec()).collect::<std::vec::Vec<_>>();
    let mut i = 0;
    keccak_asm::Keccak256::digest_batch(owned.clone(), |input, digest| {
        assert_eq!(input, owned[i]);
        assert_eq!(digest, sha3::Keccak256::digest(&input));
        i += 1;
    });
    assert_eq!(i, owned.len());
}

fn check_batch(inputs: &[&[u8]]) {
    macro_rules! check {
        ($($asm:ident => $reference:ident),* $(,)?) => {$({
            let mut i = 0;
            keccak_asm::$asm::digest_batch(inputs, |input, digest| {
                assert!(core::ptr::eq(*input, inputs[i]));
                assert_eq!(
                    digest.as_slice(),
                    sha3::$reference::digest(input).as_slice(),
                    "{} batch of {} at {i}, lengths {:?}",
                    stringify!($asm),
                    inputs.len(),
                    inputs.iter().map(|input| input.len()).collect::<std::vec::Vec<_>>(),
                );
                i += 1;
            });
            assert_eq!(i, inputs.len());
        })*};
    }
    check!(
        Keccak224 => Keccak224,
        Keccak256 => Keccak256,
        Keccak384 => Keccak384,
        Keccak512 => Keccak512,
        Sha3_224 => Sha3_224,
        Sha3_256 => Sha3_256,
        Sha3_384 => Sha3_384,
        Sha3_512 => Sha3_512,
    );
}

#[cfg(feature = "std")]
mod measurements {
    use super::*;
    use std::{hint::black_box, time::Instant};

    #[cfg(target_os = "linux")]
    mod counters {
        use std::{
            io::{self, Result},
            mem::size_of,
        };

        #[repr(C)]
        struct Attr {
            kind: u32,
            size: u32,
            config: u64,
            period: u64,
            sample_type: u64,
            read_format: u64,
            flags: u64,
            wakeup: u32,
            bp_type: u32,
            config1: u64,
        }

        pub(super) struct Counters {
            cycles: i32,
            instructions: i32,
        }

        impl Counters {
            fn open_event(config: u64, group: i32) -> Result<i32> {
                let attr = Attr {
                    kind: 0,
                    size: size_of::<Attr>() as u32,
                    config,
                    period: 0,
                    sample_type: 0,
                    read_format: 1 | 2 | 8,
                    flags: 1 | (1 << 5) | (1 << 6),
                    wakeup: 0,
                    bp_type: 0,
                    config1: 0,
                };
                let fd =
                    unsafe { libc::syscall(libc::SYS_perf_event_open, &attr, 0, -1, group, 8) };
                if fd < 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(fd as i32)
            }

            pub(super) fn new() -> Result<Self> {
                let cycles = Self::open_event(0, -1)?;
                let instructions = match Self::open_event(1, cycles) {
                    Ok(fd) => fd,
                    Err(err) => {
                        unsafe {
                            libc::close(cycles);
                        }
                        return Err(err);
                    }
                };
                Ok(Self { cycles, instructions })
            }

            fn control(&self, request: libc::c_ulong) -> Result<()> {
                let result = unsafe { libc::ioctl(self.cycles, request, 1) };
                if result != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(())
            }

            pub(super) fn start(&self) -> Result<()> {
                self.control(0x2403)?;
                self.control(0x2400)
            }

            pub(super) fn stop(&self) -> Result<[u64; 5]> {
                self.control(0x2401)?;
                let mut values = [0; 5];
                let len = unsafe {
                    libc::read(self.cycles, values.as_mut_ptr().cast(), size_of::<[u64; 5]>())
                };
                assert!(len == 40 && values[0] == 2, "bad perf group read: {len}, {values:?}");
                assert!(
                    values[2] > 0 && values[2] as f64 / values[1] as f64 > 0.995,
                    "counter multiplexing: {values:?}"
                );
                Ok(values)
            }
        }

        impl Drop for Counters {
            fn drop(&mut self) {
                unsafe {
                    libc::close(self.instructions);
                    libc::close(self.cycles);
                }
            }
        }
    }

    #[inline(never)]
    fn dynamic(input: &[u8]) -> [u8; 32] {
        keccak_asm::Keccak256::digest(input).into()
    }

    #[inline(never)]
    fn fixed<const N: usize>(input: &[u8; N]) -> [u8; 32] {
        keccak_asm::Keccak256::digest(input).into()
    }

    #[inline(never)]
    fn reference(input: &[u8]) -> [u8; 32] {
        sha3::Keccak256::digest(input).into()
    }

    #[inline(never)]
    fn reference_fixed<const N: usize>(input: &[u8; N]) -> [u8; 32] {
        sha3::Keccak256::digest(input).into()
    }

    #[inline(never)]
    fn streaming(input: &[u8]) -> [u8; 32] {
        let mut state = keccak_asm::Keccak256::new();
        state.update(input);
        state.finalize().into()
    }

    #[inline(never)]
    fn kernel<const N: usize, F: Fn(&[u8; N]) -> [u8; 32]>(
        input: &mut [u8; N],
        count: u64,
        latency: bool,
        hash: F,
    ) {
        for _ in 0..count {
            let output = black_box(hash(black_box(input)));
            if latency {
                input[..N.min(32)].copy_from_slice(&output[..N.min(32)]);
            }
        }
        black_box(input);
    }

    fn sample<const N: usize, F: Fn(&[u8; N]) -> [u8; 32] + Copy>(
        shape: &str,
        implementation: &str,
        repeat: usize,
        hash: F,
    ) {
        for latency in [false, true].into_iter().filter(|&latency| !latency || N != 0) {
            let mode = if latency { "latency" } else { "throughput" };
            if std::env::var("KECCAK_BENCH_FILTER")
                .is_ok_and(|filter| filter != std::format!("{shape}/{implementation}/{N}/{mode}"))
            {
                continue;
            }
            let duration = std::env::var("KECCAK_BENCH_NS")
                .map(|value| value.parse::<u128>().expect("invalid KECCAK_BENCH_NS"))
                .unwrap_or(10_000_000);
            let mut input = core::array::from_fn::<_, N, _>(|i| i.wrapping_mul(131) as u8);
            assert_eq!(hash(&input), reference(&input));
            kernel(&mut input, 64, latency, hash);
            let start = Instant::now();
            kernel(&mut input, 128, latency, hash);
            let count = (duration.saturating_mul(128) / start.elapsed().as_nanos().max(1))
                .clamp(16, 200_000_000) as u64;
            #[cfg(target_os = "linux")]
            let counters = counters::Counters::new().unwrap();
            #[cfg(target_os = "linux")]
            counters.start().unwrap();
            let start = Instant::now();
            kernel(&mut input, count, latency, hash);
            let ns = start.elapsed().as_nanos();
            #[cfg(target_os = "linux")]
            let values = counters.stop().unwrap();
            #[cfg(not(target_os = "linux"))]
            let values = [0; 5];
            std::println!("MEASURE\t{}\t{shape}\t{implementation}\t{N}\t{mode}\t{repeat}\t{count}\t{ns}\t{}\t{}\t{}\t{}", keccak_asm::IMPL, values[3], values[4], values[1], values[2]);
        }
    }

    fn size<const N: usize>(repeat: usize) {
        for step in 0..3 {
            match (step + repeat) % 3 {
                0 => {
                    sample("fixed", "rust", repeat, fixed::<N>);
                    sample("dynamic", "rust", repeat, |a: &[u8; N]| {
                        dynamic(black_box(a.as_slice()))
                    });
                }
                1 => {
                    sample("fixed", "reference", repeat, reference_fixed::<N>);
                    sample("dynamic", "reference", repeat, |a: &[u8; N]| {
                        reference(black_box(a.as_slice()))
                    });
                }
                _ => sample("dynamic", "streaming", repeat, |a: &[u8; N]| {
                    streaming(black_box(a.as_slice()))
                }),
            }
        }
    }

    #[test]
    #[ignore = "performance measurements; run in release with --ignored --nocapture"]
    fn benchmark() {
        std::println!("MEASURE\tbackend\tshape\timplementation\tbytes\tmode\trepeat\titerations\tns\tcycles\tinstructions\tenabled\trunning");
        for repeat in 0..7 {
            macro_rules! sizes { ($($n:literal),*) => { $(size::<$n>(repeat);)* }; }
            sizes!(0, 20, 32, 64, 135, 136, 137, 272, 532, 1024, 4096, 16384, 131072);
        }
    }

    /// Returns the fastest of seven samples, in nanoseconds per call.
    fn time(mut f: impl FnMut()) -> f64 {
        let duration = std::env::var("KECCAK_BENCH_NS")
            .map(|value| value.parse::<u128>().expect("invalid KECCAK_BENCH_NS"))
            .unwrap_or(10_000_000);
        let start = Instant::now();
        for _ in 0..16 {
            f();
        }
        let count = (duration.saturating_mul(16) / start.elapsed().as_nanos().max(1)).max(16);
        (0..7)
            .map(|_| {
                let start = Instant::now();
                for _ in 0..count {
                    f();
                }
                start.elapsed().as_nanos() as f64 / count as f64
            })
            .fold(f64::INFINITY, f64::min)
    }

    #[test]
    #[ignore = "performance measurements; run in release with --ignored --nocapture"]
    fn benchmark_batch() {
        type D = keccak_asm::Keccak256;
        std::println!("BATCH\tbackend\tlanes\tbytes\tcount\tscalar_ns\tbatch_ns");
        let data = (0..64 * 300).map(|i| (i * 131) as u8).collect::<std::vec::Vec<_>>();
        for len in [20, 32, 64, 110, 300] {
            for count in [1, 2, 3, 4, 8, 16, 64] {
                let inputs =
                    (0..count).map(|i| &data[i * len..][..len]).collect::<std::vec::Vec<_>>();
                let scalar = time(|| {
                    for input in black_box(&inputs) {
                        black_box(D::digest(input));
                    }
                });
                let batch = time(|| {
                    D::digest_batch(black_box(&inputs), |_, digest| {
                        black_box(digest);
                    })
                });
                std::println!(
                    "BATCH\t{}\t{}\t{len}\t{count}\t{scalar:.1}\t{batch:.1}",
                    keccak_asm::IMPL,
                    D::BATCH_LANES,
                );
            }
        }
    }
}
