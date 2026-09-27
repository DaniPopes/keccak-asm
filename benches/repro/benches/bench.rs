use criterion::{criterion_group, criterion_main, BenchmarkId, Criterion};
use rand::prelude::*;
use std::{hint::black_box, time::Duration};

#[cfg(target_arch = "x86_64")]
use bench_keccak256::experiment::*;

fn bench_all(c: &mut Criterion) {
    let counts: &[usize] = &[32, 128, 1024, 16384, 131072, 1048576, 16777216];
    let max_sz = *counts.iter().max().unwrap();
    let mut buffer = vec![0u8; max_sz];
    let output = &mut [0u8; 32];

    let rng = &mut rand::rng();
    for &(name, hash_fn) in bench_keccak256::ALL {
        let mut g = c.benchmark_group(name);
        g.sample_size(50);
        g.warm_up_time(Duration::from_secs(3));
        g.measurement_time(Duration::from_secs(10));
        g.noise_threshold(0.02);

        for &count in counts {
            assert!(count <= max_sz);
            let input = &mut buffer[..count];
            rng.fill_bytes(input);

            // g.throughput(criterion::Throughput::Bytes(count as u64));
            g.bench_function(BenchmarkId::from_parameter(count), |b| {
                b.iter(|| hash_fn(black_box(input), black_box(output)));
            });
        }
    }
}

#[cfg(target_arch = "x86_64")]
fn investigate_size<const N: usize>(c: &mut Criterion) {
    let mut g = c.benchmark_group(format!("investigate/{N}"));
    g.sample_size(30);
    g.warm_up_time(Duration::from_millis(300));
    g.measurement_time(Duration::from_secs(1));
    let inputs =
        std::array::from_fn::<_, 8, _>(|i| std::array::from_fn::<_, N, _>(|j| (i * 13 + j) as u8));
    assert_eq!(digest_runtime(&inputs[0]), assembly_runtime(&inputs[0]));
    let single = [inputs[0]];
    let pair = [inputs[0], inputs[1]];
    g.bench_function("digest_runtime", |b| {
        b.iter(|| digest_runtime(black_box(inputs[0].as_slice())))
    });
    g.bench_function("assembly_runtime", |b| {
        b.iter(|| assembly_runtime(black_box(inputs[0].as_slice())))
    });
    g.bench_function("assembly", |b| b.iter(|| assembly(black_box(&inputs[0]))));
    g.bench_function("digest", |b| b.iter(|| digest(black_box(&inputs[0]))));
    if N < 136 && sha3_asm::IMPL == "keccak1600-x86_64" {
        g.bench_function("scalar_permutation", |b| {
            b.iter(|| scalar_permutation(black_box(&inputs[0])))
        });
    }
    if N < 136 {
        g.bench_function("wrapper", |b| b.iter(|| wrapper::<N, false>(black_box(&inputs[0]))));
        g.bench_function("copy", |b| b.iter(|| wrapper::<N, true>(black_box(&inputs[0]))));
    }
    if is_x86_feature_detected!("avx512f") && is_x86_feature_detected!("avx512vl") {
        g.bench_function("xmm_single", |b| b.iter(|| unsafe { lanes1(black_box(&single))[0] }));
        g.bench_function("xmm_pair", |b| b.iter(|| unsafe { lanes2(black_box(&pair)) }));
        g.bench_function("zmm_eight", |b| b.iter(|| unsafe { lanes8(black_box(&inputs)) }));
    }
    g.bench_function("serial_pair", |b| {
        b.iter(|| [digest(black_box(&inputs[0])), digest(black_box(&inputs[1]))])
    });
    g.bench_function("serial_eight", |b| {
        b.iter(|| std::array::from_fn::<_, 8, _>(|i| digest(black_box(&inputs[i]))))
    });
    g.finish();
}

fn investigate(c: &mut Criterion) {
    #[cfg(target_arch = "x86_64")]
    {
        investigate_size::<20>(c);
        investigate_size::<32>(c);
        investigate_size::<64>(c);
        investigate_size::<532>(c);
    }
    #[cfg(not(target_arch = "x86_64"))]
    let _ = c;
}

fn runtime_sizes(c: &mut Criterion) {
    let input = (0..131072).map(|i| i as u8).collect::<Vec<_>>();
    let mut g = c.benchmark_group("runtime");
    g.sample_size(30);
    g.warm_up_time(Duration::from_millis(200));
    g.measurement_time(Duration::from_millis(600));
    for len in [0, 20, 32, 64, 135, 136, 137, 272, 532, 1024, 4096, 16384, 131072] {
        let input = &input[..len];
        assert_eq!(digest_runtime(input), assembly_runtime(input));
        g.bench_function(BenchmarkId::new("digest", len), |b| {
            b.iter(|| digest_runtime(black_box(input)))
        });
        g.bench_function(BenchmarkId::new("assembly", len), |b| {
            b.iter(|| assembly_runtime(black_box(input)))
        });
    }
    g.finish();
}
fn variants(c: &mut Criterion) {
    let input = (0..4096).map(|i| i as u8).collect::<Vec<_>>();
    macro_rules! variant {
        ($name:literal, $digest:ident, $rate:literal, $out:literal) => {{
            let mut g = c.benchmark_group(concat!("variants/", $name));
            g.sample_size(30);
            g.warm_up_time(Duration::from_millis(200));
            g.measurement_time(Duration::from_millis(600));
            for len in [64, 532, 4096] {
                let input = &input[..len];
                assert_eq!($digest(input), assembly_variant::<$rate, $out>(input));
                g.bench_function(BenchmarkId::new("digest", len), |b| {
                    b.iter(|| $digest(black_box(input)))
                });
                g.bench_function(BenchmarkId::new("assembly", len), |b| {
                    b.iter(|| assembly_variant::<$rate, $out>(black_box(input)))
                });
            }
            g.finish();
        }};
    }
    variant!("224", digest224, 144, 28);
    variant!("384", digest384, 104, 48);
    variant!("512", digest512, 72, 64);
}
fn three_way(c: &mut Criterion) {
    let input = (0..131072).map(|i| (i * 131) as u8).collect::<Vec<_>>();
    let mut g = c.benchmark_group("three_way");
    g.sample_size(50);
    g.warm_up_time(Duration::from_millis(400));
    g.measurement_time(Duration::from_secs(1));
    for len in [20, 64, 135, 136, 137, 532, 4096, 131072] {
        let input = &input[..len];
        let expected = assembly_runtime(input);
        assert_eq!(digest_runtime(input), expected);
        assert_eq!(stack_runtime(input), expected);
        g.bench_function(BenchmarkId::new("shared", len), |b| {
            b.iter(|| digest_runtime(black_box(input)))
        });
        g.bench_function(BenchmarkId::new("stack", len), |b| {
            b.iter(|| stack_runtime(black_box(input)))
        });
        g.bench_function(BenchmarkId::new("asm", len), |b| {
            b.iter(|| assembly_runtime(black_box(input)))
        });
    }
    let fixed: &[u8; 64] = input[..64].try_into().unwrap();
    assert_eq!(digest(fixed), stack_fixed(fixed));
    assert_eq!(digest(fixed), assembly(fixed));
    g.bench_function("fixed64/shared", |b| b.iter(|| digest(black_box(fixed))));
    g.bench_function("fixed64/stack", |b| b.iter(|| stack_fixed(black_box(fixed))));
    g.bench_function("fixed64/asm", |b| b.iter(|| assembly(black_box(fixed))));
    g.finish();
}

criterion_group!(benches, bench_all, investigate, runtime_sizes, variants, three_way);
criterion_main!(benches);
