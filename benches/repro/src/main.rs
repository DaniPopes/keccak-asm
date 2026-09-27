use anyhow::{bail, Result};
use bench_keccak256::{HashFn, ALL};
use rand::prelude::*;
use std::{env::current_exe, hint::black_box, process::exit};

macro_rules! usage {
    ($($t:tt)*) => {
        bail!("{}", usage(format_args!($($t)*)))
    };
}

fn main() {
    match _main() {
        Ok(()) => {}
        Err(e) => {
            eprintln!("{e}");
            exit(1);
        }
    }
}

fn _main() -> Result<()> {
    let args = std::env::args().skip(1).collect::<Vec<_>>();
    if args.first().is_some_and(|arg| arg == "matrix") {
        return metrics::run();
    }
    let [backend, mode, args @ ..] = &args[..] else {
        usage!("<backend> <mode> [args]...");
    };

    let Some(&(_, hash_fn)) = ALL.iter().find(|&&(f, _)| f == backend) else {
        bail!("Unknown backend: {backend}");
    };

    match mode.as_str() {
        "count" => count(hash_fn, args)?,
        "info" => match backend.as_str() {
            "keccak-asm" => {
                eprintln!("keccak-asm impl: {}", keccak_asm::IMPL);
            }
            "xkcp" => {
                eprintln!(
                    "xkcp impl:       {}",
                    xkcp_rs::ffi::KeccakP1600_implementation.to_str().unwrap(),
                );
            }
            _ => {}
        },
        mode => bail!("Unknown mode: {mode}"),
    }

    Ok(())
}

fn count(hash_fn: HashFn, args: &[String]) -> Result<()> {
    let [n, args @ ..] = args else {
        usage!("count <count> [size]");
    };
    let count = n.parse::<usize>()?;
    let size = match args {
        [] => 32,
        [size] => size.parse()?,
        _ => usage!("count {count} [size]"),
    };

    let mut input = vec![0u8; size];
    rand::rng().fill_bytes(&mut input);
    let input = &input[..];
    let output = &mut [0u8; 32];
    for _ in 0..black_box(count) {
        hash_fn(black_box(input), black_box(output));
    }
    black_box(output);

    Ok(())
}

fn usage(rest: std::fmt::Arguments<'_>) -> String {
    let exe = current_exe().unwrap();
    let mut exe = exe.as_path();
    if let Ok(curr_dir) = std::env::current_dir() {
        exe = exe.strip_prefix(curr_dir).unwrap_or(exe);
    }
    format!("Usage: {} {rest}", exe.display())
}

#[cfg(target_arch = "x86_64")]
mod metrics {
    use anyhow::{ensure, Result};
    use bench_keccak256::experiment::{
        assembly, assembly_runtime, digest, digest_runtime, stack_fixed, stack_runtime,
    };
    use std::{arch::x86_64::*, hint::black_box, io, mem::size_of, time::Instant};

    #[cfg(feature = "tail-sharing")]
    use bench_keccak256::experiment::{tail_fixed, tail_runtime};

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

    struct Counters {
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
            let fd = unsafe { libc::syscall(libc::SYS_perf_event_open, &attr, 0, -1, group, 8) };
            ensure!(fd >= 0, "perf_event_open: {}", io::Error::last_os_error());
            Ok(fd as i32)
        }
        fn new() -> Result<Self> {
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
            ensure!(result == 0, "perf ioctl: {}", io::Error::last_os_error());
            Ok(())
        }
        fn start(&self) -> Result<()> {
            self.control(0x2403)?;
            self.control(0x2400)
        }
        fn stop(&self) -> Result<[u64; 5]> {
            self.control(0x2401)?;
            let mut values = [0; 5];
            let len = unsafe {
                libc::read(self.cycles, values.as_mut_ptr().cast(), size_of::<[u64; 5]>())
            };
            ensure!(len == 40 && values[0] == 2, "bad perf group read: {len}, {values:?}");
            ensure!(
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

    #[inline(never)]
    fn kernel<const N: usize, F: Fn(&[u8; N]) -> [u8; 32]>(
        input: &mut [u8; N],
        count: u64,
        latency: bool,
        hash: F,
    ) {
        if latency {
            for _ in 0..count {
                let out = black_box(hash(black_box(input)));
                if N == 0 {
                    unsafe {
                        _mm_lfence();
                    }
                } else {
                    input[..N.min(32)].copy_from_slice(&out[..N.min(32)]);
                }
            }
        } else {
            for _ in 0..count {
                black_box(hash(black_box(input)));
            }
        }
        black_box(input);
    }

    #[inline(never)]
    fn empty<const N: usize>(input: &[u8; N]) -> [u8; 32] {
        black_box(input);
        [0; 32]
    }

    fn sample<const N: usize, F: Fn(&[u8; N]) -> [u8; 32] + Copy>(
        counters: &Counters,
        shape: &str,
        implementation: &str,
        repeat: usize,
        hash: F,
    ) -> Result<()> {
        for latency in [false, true] {
            let mut input = std::array::from_fn::<_, N, _>(|i| (i.wrapping_mul(131) + 17) as u8);
            kernel(&mut input, 16, latency, hash);
            let start = Instant::now();
            kernel(&mut input, 64, latency, hash);
            let elapsed = start.elapsed().as_nanos().max(1);
            let count = ((30_000_000u128 * 64 / elapsed) as u64).clamp(16, 2_000_000);
            counters.start()?;
            let start = Instant::now();
            kernel(&mut input, count, latency, hash);
            let ns = start.elapsed().as_nanos();
            let values = counters.stop()?;
            let mode = if latency { "latency" } else { "throughput" };
            println!("{}\t{}\t{shape}\t{implementation}\t{N}\t{mode}\t{repeat}\t{count}\t{ns}\t{}\t{}\t{}\t{}",
                keccak_asm::IMPL, sha3_asm::IMPL, values[3], values[4], values[1], values[2]);
        }
        Ok(())
    }

    fn size<const N: usize>(counters: &Counters) -> Result<()> {
        let input = std::array::from_fn::<_, N, _>(|i| (i.wrapping_mul(131) + 17) as u8);
        let expected = assembly_runtime(&input);
        ensure!(digest_runtime(&input) == expected && stack_runtime(&input) == expected);
        ensure!(
            digest(&input) == expected
                && stack_fixed(&input) == expected
                && assembly(&input) == expected
        );
        #[cfg(feature = "tail-sharing")]
        ensure!(tail_runtime(&input) == expected && tail_fixed(&input) == expected);
        for repeat in 0..5 {
            for step in 0..if cfg!(feature = "tail-sharing") { 4 } else { 3 } {
                match (repeat + step) % if cfg!(feature = "tail-sharing") { 4 } else { 3 } {
                    0 => {
                        sample(counters, "runtime", "shared", repeat, |a: &[u8; N]| {
                            digest_runtime(black_box(a.as_slice()))
                        })?;
                        sample(counters, "fixed", "shared", repeat, digest::<N>)?;
                    }
                    1 => {
                        sample(counters, "runtime", "stack", repeat, |a: &[u8; N]| {
                            stack_runtime(black_box(a.as_slice()))
                        })?;
                        sample(counters, "fixed", "stack", repeat, stack_fixed::<N>)?;
                    }
                    2 => {
                        sample(counters, "runtime", "asm", repeat, |a: &[u8; N]| {
                            assembly_runtime(black_box(a.as_slice()))
                        })?;
                        sample(counters, "fixed", "asm", repeat, assembly::<N>)?;
                    }
                    #[cfg(feature = "tail-sharing")]
                    3 => {
                        sample(counters, "runtime", "tail", repeat, |a: &[u8; N]| {
                            tail_runtime(black_box(a.as_slice()))
                        })?;
                        sample(counters, "fixed", "tail", repeat, tail_fixed::<N>)?;
                    }
                    _ => unreachable!(),
                }
            }
        }
        sample(counters, "control", "empty", 0, empty::<N>)?;
        Ok(())
    }

    pub fn run() -> Result<()> {
        let counters = Counters::new()?;
        println!("backend\tasm_backend\tshape\timplementation\tbytes\tmode\trepeat\titerations\tns\tcycles\tinstructions\tenabled\trunning");
        macro_rules! sizes { ($($n:literal),*) => { $(size::<$n>(&counters)?;)* }; }
        sizes!(0, 20, 32, 64, 135, 136, 137, 272, 532, 1024, 4096, 16384, 131072);
        Ok(())
    }
}
