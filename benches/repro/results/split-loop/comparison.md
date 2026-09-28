# x86 split-loop comparison

Ryzen 9 7950X, CPU 12, Rust 1.100.0-nightly (feaadeeac), release LTO. Same tracked benches/repro matrix and default features. Before is ab421ae; after applies the same full-block/tail split to AVX2 and AVX-512. Values are medians of five samples in cycles/hash. Negative change is better.

## avx2

| Bytes | Runtime before | Runtime after | Change | Fixed change | Latency change (runtime) |
|---:|---:|---:|---:|---:|---:|
| 0 | 1007.4 | 1004.7 | -0.27% | -0.70% | -0.35% |
| 20 | 983.6 | 987.5 | +0.40% | -0.01% | +0.08% |
| 32 | 988.3 | 987.2 | -0.12% | -0.20% | +0.27% |
| 64 | 982.2 | 988.0 | +0.59% | -0.15% | -0.10% |
| 135 | 994.3 | 995.4 | +0.11% | -0.09% | -0.31% |
| 136 | 1990.2 | 1990.5 | +0.01% | -0.17% | +0.05% |
| 137 | 1993.8 | 1989.5 | -0.21% | -0.11% | +0.17% |
| 272 | 2982.5 | 2980.1 | -0.08% | -0.36% | -0.08% |
| 532 | 3975.5 | 3964.5 | -0.28% | -0.27% | -0.14% |
| 1024 | 7946.9 | 7920.5 | -0.33% | -0.32% | -0.30% |
| 4096 | 30779.0 | 30657.1 | -0.40% | -0.42% | -0.40% |
| 16384 | 120097.2 | 119568.5 | -0.44% | -0.52% | -0.44% |
| 131072 | 956768.5 | 952614.8 | -0.43% | -0.44% | -0.44% |

## native

| Bytes | Runtime before | Runtime after | Change | Fixed change | Latency change (runtime) |
|---:|---:|---:|---:|---:|---:|
| 0 | 874.4 | 899.7 | +2.90% | +2.14% | +2.88% |
| 20 | 888.7 | 884.4 | -0.48% | -0.54% | -0.16% |
| 32 | 878.3 | 878.8 | +0.05% | +0.11% | -0.20% |
| 64 | 887.1 | 891.3 | +0.47% | +0.05% | -0.12% |
| 135 | 857.2 | 876.8 | +2.29% | +3.72% | +2.82% |
| 136 | 1713.4 | 1749.8 | +2.13% | +2.06% | +1.83% |
| 137 | 1719.3 | 1745.7 | +1.54% | +1.72% | +1.65% |
| 272 | 2582.6 | 2603.3 | +0.80% | +1.32% | +1.39% |
| 532 | 3418.1 | 3417.0 | -0.03% | +1.06% | +1.00% |
| 1024 | 6857.2 | 6853.5 | -0.06% | +0.66% | +0.69% |
| 4096 | 26379.0 | 26517.7 | +0.53% | +0.40% | +0.43% |
| 16384 | 102969.9 | 103387.4 | +0.41% | +0.35% | +0.38% |
| 131072 | 820958.1 | 823552.0 | +0.32% | +0.34% | +0.33% |


## Decision and code size

Keep the fused loop on x86. AVX2 saves about 0.4% on large runtime inputs,
which does not justify the larger kernel here. AVX-512 regresses on short
dynamic inputs and shows no consistent multiblock improvement. The ARM fix
remains independent. The assembly fallback already separates full blocks and
padding, so this change does not apply to it.

The Keccak-256 `digest_dyn` symbol grows from 1,954 to 2,549 bytes on AVX2
(+30.5%), and from 2,059 to 3,009 bytes on AVX-512 (+46.1%). These are machine
code sizes from the benchmark binaries, excluding constants and wrappers.
The AVX2 split eliminates the dynamic kernel's stack spill, but measured cycles
do not fall much. The AVX-512 split still spills vector registers.

Both split backends passed the existing release tests with all features,
Clippy, and formatting. The raw TSVs include instructions, wall time, controls,
and all five samples per combination; all samples had equal enabled/running
counter time. Throughput and latency are defined in BENCHMARKS.md. This is one
before/after pass per backend on one 7950X, not a result for all x86 CPUs.

## Reproduction

Run from the repository root in an isolated checkout of `ab421ae` with the
tracked `benches/repro` workspace. The patch and this result directory can be
copied from a newer checkout; all required files are tracked. If using a newer
revision directly, check that its x86 source still matches the baseline before
comparing against these numbers. Use the compiler/profile and prerequisites
from BENCHMARKS.md. This experiment did not enable `tail-sharing`.

Build both baselines before applying `split.patch`:

```bash
unset SHA3_ASM_SCRIPT CARGO_ENCODED_RUSTFLAGS
RUSTFLAGS='-Ctarget-cpu=x86-64-v3' CARGO_TARGET_DIR=target/split-before-avx2 \
cargo build --release --locked --manifest-path benches/repro/Cargo.toml
RUSTFLAGS='-Ctarget-cpu=native' CARGO_TARGET_DIR=target/split-before-native \
cargo build --release --locked --manifest-path benches/repro/Cargo.toml

git apply benches/repro/results/split-loop/split.patch
RUSTFLAGS='-Ctarget-cpu=x86-64-v3' CARGO_TARGET_DIR=target/split-after-avx2 \
cargo build --release --locked --manifest-path benches/repro/Cargo.toml
RUSTFLAGS='-Ctarget-cpu=native' CARGO_TARGET_DIR=target/split-after-native \
cargo build --release --locked --manifest-path benches/repro/Cargo.toml

mkdir -p target/split-loop-results
for config in before-avx2 after-avx2 before-native after-native; do
  taskset -c 12 "target/split-$config/release/bench-keccak256" matrix \
    > "target/split-loop-results/$config.tsv" \
    2> "target/split-loop-results/$config.log" || break
done
cp benches/repro/results/split-loop/summarize.py target/split-loop-results/
uv run --no-project python target/split-loop-results/summarize.py
```

Use an available idle core instead of 12 on another machine. Each TSV must
have 807 lines. The summary script checks row counts and rejects multiplexing.
All runs are sequential; do not compile or run other benchmarks during timing.
The trial patch is retained here for reproduction, not applied to the library.
