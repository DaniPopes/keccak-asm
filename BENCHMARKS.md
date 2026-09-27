# Reproducing the Keccak-256 measurements

This guide reproduces the runtime-length comparison from September 27, 2026,
and explains how to collect the full matrix of cycles, retired instructions,
throughput, and dependent-call latency. Run commands from the repository root
unless stated otherwise. Shell examples use Bash.

## Source and artifacts

The latest comparison used commit
`424a72e1ded758819e23928d2acb94d69670edc9`. It includes the return-value backend
helpers and the 20/32/64-byte Keccak-256 specializations.

The earlier five-configuration matrix used
`12ff65fcd6577205e4690fbabfafdea5b523a146`. It predates the explicit length
dispatch and return-value helpers. Do not attribute its numbers to the latest
implementation.

The complete harness is checked in at `benches/repro`, including its Cargo.lock,
archived stack backend, analysis scripts, and raw measurements. No local archive,
ignored source, or files from the author's machine are required.

Start from a fresh clone of this branch:

```bash
git clone --recurse-submodules --branch simd-digest-backends https://github.com/DaniPopes/keccak-asm.git
cd keccak-asm
mkdir -p target/repro-results
```

Use this branch's harness with its current production code to repeat the latest
comparison. The historical revisions above identify the code measured originally;
they do not themselves contain this reproduction package. To repeat an older
revision, keep the checked-in `benches/repro` directory and change only its two
path dependencies to an isolated checkout of that revision. Do not overwrite
local source changes.

The measured Cryptogams submodule revision was
`680f98c1765a7cb89c193db169ed048599f92186`.

## Machine and compiler

The recorded measurements used:

| Item | Value |
|---|---|
| CPU | AMD Ryzen 9 7950X, Zen 4, 16 cores / 32 threads |
| OS target | Linux x86-64 |
| Logical CPU | 12, selected with `taskset` |
| Rust | `rustc 1.100.0-nightly (feaadeeac 2026-09-19)` |
| Rust's LLVM | 23.1.1 |
| CPU boost | Enabled |
| Features | Default crate features; no `zeroize` |
| Release profile | opt-level 3, LTO enabled, one codegen unit, panic abort |
| Debug info | Level 2; no stripping |

Use the configured toolchain; do not add `+nightly` to commands. For close
codegen comparisons, match the compiler above. A different compiler is a new
experiment, even if the source is unchanged. The standalone `llvm-mca` used
for the earlier static estimates was version 22.1.8, separate from Rust's LLVM.

Required tools include Cargo/Rust, a C build toolchain, Perl, Clang/libclang for
the harness's bindings, `taskset`, Linux performance-counter access, and `uv`
for the Python summaries. On Ubuntu, install the native build dependencies with:

```bash
sudo apt-get update
sudo apt-get install build-essential pkg-config clang libclang-dev perl git util-linux linux-tools-generic
```

Install Rust and `uv` through your normal toolchain setup before building. `perf` is useful for checking counter access.
Use the checked-in Cargo.lock; the build commands below pass `--locked`.

Record the environment alongside each new run:

```bash
mkdir -p target/repro-results
git rev-parse HEAD > target/repro-results/revision.txt
git diff > target/repro-results/source.diff
git submodule status > target/repro-results/submodules.txt
rustc -Vv > target/repro-results/rustc.txt
cargo -V > target/repro-results/cargo.txt
uname -a > target/repro-results/kernel.txt
lscpu > target/repro-results/cpu.txt
cat /proc/sys/kernel/perf_event_paranoid > target/repro-results/perf-policy.txt
perf stat -e cycles:u,instructions:u -- true
```

A permission error means the host must grant performance-counter access before
the harness can run. Do not substitute elapsed time or TSC ticks for hardware
cycles. The recorded host had `perf_event_paranoid=1`.

Use an idle core, avoid work on its SMT sibling, and run benchmark processes
sequentially. CPU 12 is the recorded choice, not a universally idle CPU. Boost,
other workloads, thermals, OS scheduling, and compiler changes can move the
results. The original run did not fix the CPU frequency or isolate the core
from all OS work. Expect variation rather than exact decimal matches.

## What the three implementations mean

The wrappers live in `benches/repro/src/experiment.rs`:

| TSV name | Implementation |
|---|---|
| `shared` | Current `Keccak256::digest(input).into()`, returning `[u8; 32]`. The name is historical. |
| `stack` | Archived SIMD implementation in `before-direct-tail/`, which builds a padded rate-sized stack block. |
| `asm` | One-shot Rust wrapper over `sha3_asm::sha3_absorb` and `sha3_squeeze`. It handles full blocks, then the padded tail, and skips the empty full-block absorb. |
| `empty` | Control function that returns zero bytes; it measures some loop/call overhead. |

The assembly baseline is this explicit wrapper, not an untouched release of
keccak-asm's streaming API. The stack baseline is the checked-in source snapshot,
not the current backend checked out under another name. Preserve it exactly;
changing it changes the comparison.

The `shared` wrappers include conversion from `Output<Keccak256>` to an array.
In this revision, runtime array conversion creates a temporary and copy even
though returning `Output<Keccak256>` directly does not. These measurements
include that cost. Do not describe them as direct-`Output` measurements.

`fixed` passes `&[u8; N]` to an out-of-line wrapper, so LLVM knows the length.
`runtime` passes an opaque slice, preventing the wrapper from learning the
length at compile time. Runtime 20/32/64-byte inputs still select the explicit
specializations; other sizes exercise the generic dynamic path.

## Build the latest two-configuration comparison

Use separate target directories to keep backend builds apart. Clear any
inherited assembly override and encoded Rust flags first:

```bash
unset SHA3_ASM_SCRIPT CARGO_ENCODED_RUSTFLAGS

RUSTFLAGS='-Ctarget-cpu=native' \
CARGO_TARGET_DIR=target/metrics-native \
cargo build --release --locked --manifest-path benches/repro/Cargo.toml \
  > target/repro-results/build-native.log 2>&1

RUSTFLAGS='-Ctarget-cpu=x86-64-v3' \
CARGO_TARGET_DIR=target/metrics-avx2 \
cargo build --release --locked --manifest-path benches/repro/Cargo.toml \
  > target/repro-results/build-avx2.log 2>&1
```

On the measured 7950X, these select:

| Configuration | Current Rust backend | sha3-asm baseline |
|---|---|---|
| `native` | AVX-512F/VL, one XMM per state lane | Packed AVX-512VL |
| `avx2` | AVX2 | Scalar x86-64 |

AVX2 in the Rust backend does **not** imply AVX2 in sha3-asm's default selection.
`native` means the build host's capabilities; verify the selected backend on
another CPU rather than assuming it means AVX-512.

## Run the measurements

Run sequentially, preserving stdout and stderr separately. Do not run under
`cargo run`, another profiler, or a second `perf stat` instance.

```bash
taskset -c 12 target/metrics-native/release/bench-keccak256 matrix \
  > target/repro-results/native.tsv \
  2> target/repro-results/native.log

taskset -c 12 target/metrics-avx2/release/bench-keccak256 matrix \
  > target/repro-results/avx2.tsv \
  2> target/repro-results/avx2.log

wc -l target/repro-results/native.tsv target/repro-results/avx2.tsv
head -n 2 target/repro-results/native.tsv
head -n 2 target/repro-results/avx2.tsv
```

Check that both commands exit successfully. Each complete file has **807
lines**: a header, 780 measurement rows, and 26 controls. An empty error log is
normal. The first two TSV fields record the current and assembly backends;
inspect them before comparing runs.

The matrix covers these input sizes in bytes:

```text
0, 20, 32, 64, 135, 136, 137, 272, 532, 1024, 4096, 16384, 131072
```

For each size, the harness checks equality of all six fixed/runtime wrappers
before timing. It then measures three implementations, two length forms, two
modes, and five repeats, rotating implementation order between repeats.

Each sample performs 16 warm-up hashes, times 64 hashes to choose an iteration
count, then targets about 30 ms of measured work. The count is clamped to
16–2,000,000. Input starts with byte `i` equal to `(i * 131 + 17) mod 256`.
Inputs are cache-hot; this is not a cold-memory benchmark.

## Counters and metrics

The `metrics` module in the existing harness main.rs opens a Linux
`perf_event_open` group for hardware cycles and retired instructions on the
current thread. It excludes kernel and hypervisor execution. The group resets
and enables just before the measured loop, then disables and reads afterward.
Wall time comes from `Instant` around the loop.

The output columns are:

```text
backend asm_backend shape implementation bytes mode repeat iterations ns cycles instructions enabled running
```

They are tab-separated. `ns`, `cycles`, and `instructions` are totals for that
sample, not per-hash values. Counts include loop/call overhead and a small
amount of userspace timing/counter-control overhead. No empty-control
subtraction was applied to the reported numbers.

`enabled` and `running` are cumulative perf scheduling times, not per-sample
wall durations. Resetting the event counts does not reset these times. The
harness rejects a cumulative running/enabled ratio at or below 0.995; the
summary below requires exact equality, as in the recorded runs. For runs with
unequal values, also inspect adjacent-row time deltas; cumulative ratios can
hide a short multiplexed interval. Do not silently rescale and combine those
samples with the original data.

The two modes are distinct:

- `throughput`: sequential independent calls on one core, with input and output
  passed through `black_box`. This is not an eight-message batch implementation.
- `latency`: copy the first `min(N, 32)` digest bytes into the next input, forming
  a dependency chain. It includes that copy. Empty input cannot depend on the
  previous digest, so the empty case uses `LFENCE` after each hash instead.

Compute each sample's values before taking the median of five samples:

```text
cycles/hash     = cycles / iterations
instructions/hash = instructions / iterations
ns/hash         = ns / iterations
IPC             = instructions / cycles
Mhash/s         = 1000 / (ns/hash)
GiB/s           = bytes * 1e9 / (ns/hash) / 2^30
cycles/byte     = (cycles/hash) / bytes       # Undefined for empty input.
change (%)      = 100 * (current / baseline - 1)
```

Negative cycle change is better. Retired instructions are dynamic hardware
counts, not a count of lines in the assembly file. Hardware cycles are not
reference-clock ticks. Nanoseconds can change with CPU frequency even when
cycles/hash stays similar.

## Recreate the reported table

The checked-in script checks counter scheduling and requires five samples per
runtime-throughput group. Copy it next to the new TSVs so it reads the new
results rather than the archived originals:

```bash
cp benches/repro/results/current-dyn/summarize.py target/repro-results/
uv run --no-project python target/repro-results/summarize.py
```

This writes `target/repro-results/comparison.md`. The latest recorded medians,
rounded to whole cycles/hash, were:

| Bytes | Current AVX-512 | sha3-asm AVX-512VL | Current AVX2 | sha3-asm scalar |
|---:|---:|---:|---:|---:|
| 135 | 864 | 1,036 | 1,000 | 1,049 |
| 136 | 1,713 | 1,977 | 1,994 | 2,009 |
| 532 | 3,419 | 3,851 | 3,996 | 3,968 |
| 4,096 | 26,374 | 29,053 | 30,774 | 30,537 |
| 131,072 | 821,125 | 901,656 | 956,566 | 948,526 |

The original raw samples remain in
`benches/repro/results/current-dyn/`. Differences near 1% need repeat
runs and sample-spread checks before treating them as a stable gain or loss.

To export all shapes, modes, and metrics from the new runs, use:

```bash
uv run --no-project python - <<'PY'
import csv
import statistics
from pathlib import Path

root = Path('target/repro-results')
summary = []
for path in sorted(root.glob('*.tsv')):
    groups = {}
    for row in csv.DictReader(path.open(), delimiter='\t'):
        assert row['enabled'] == row['running'], (path, row)
        key = (row['shape'], row['implementation'], int(row['bytes']), row['mode'])
        groups.setdefault(key, []).append(row)
    for (shape, implementation, size, mode), samples in groups.items():
        assert len(samples) == (1 if shape == 'control' else 5)
        result = dict(config=path.stem, shape=shape, implementation=implementation,
                      bytes=size, mode=mode, samples=len(samples),
                      permutations=size // 136 + 1)
        for metric in ('cycles', 'instructions', 'ns'):
            values = [int(r[metric]) / int(r['iterations']) for r in samples]
            result[metric + '_per_hash'] = statistics.median(values)
            result[metric + '_min'] = min(values)
            result[metric + '_max'] = max(values)
        result['ipc'] = statistics.median(
            int(r['instructions']) / int(r['cycles']) for r in samples)
        result['mhash_s'] = 1000 / result['ns_per_hash']
        result['gib_s'] = size * 1e9 / result['ns_per_hash'] / 2**30
        result['cycles_per_byte'] = result['cycles_per_hash'] / size if size else ''
        summary.append(result)
assert summary
with (root / 'summary.csv').open('w', newline='') as output:
    writer = csv.DictWriter(output, fieldnames=summary[0].keys())
    writer.writeheader()
    writer.writerows(summary)
PY
```

Use throughput rows for independent-call rates and latency rows for the
feedback-chain cost. The CSV includes minima and maxima to make noise visible.

## Additional x86 assembly baselines

The earlier matrix also forced the handwritten AVX2 and ZMM AVX-512 kernels.
To repeat those choices at the current revision, build these three additional
configurations, then run their binaries with the same `matrix` command:

```bash
RUSTFLAGS='-Ctarget-cpu=x86-64' \
CARGO_TARGET_DIR=target/metrics-scalar \
cargo build --release --locked --manifest-path benches/repro/Cargo.toml

SHA3_ASM_SCRIPT=cryptogams/x86_64/keccak1600-avx2.pl \
RUSTFLAGS='-Ctarget-cpu=x86-64-v3' \
CARGO_TARGET_DIR=target/metrics-avx2-asm \
cargo build --release --locked --manifest-path benches/repro/Cargo.toml

SHA3_ASM_SCRIPT=cryptogams/x86_64/keccak1600-avx512.pl \
RUSTFLAGS='-Ctarget-cpu=native' \
CARGO_TARGET_DIR=target/metrics-avx512-asm \
cargo build --release --locked --manifest-path benches/repro/Cargo.toml

for config in scalar avx2-asm avx512-asm; do
  taskset -c 12 "target/metrics-$config/release/bench-keccak256" matrix \
    > "target/repro-results/$config.tsv" \
    2> "target/repro-results/$config.log" || break
done
```

The forced AVX2 configuration compares Rust AVX2 against assembly AVX2. The
forced ZMM configuration compares Rust AVX-512 against assembly ZMM AVX-512.
These overrides change the assembly baseline; they do not replace the current
Rust backend. Only run binaries on CPUs that support their build flags.

For the historical five-configuration numbers, point the harness dependencies
at an isolated worktree at `12ff65fcd6577205e4690fbabfafdea5b523a146`. Raw
measurements and round-model inputs from that revision are checked in under
`benches/repro/results/hardware-matrix/`. The latest two-configuration run did not remeasure all four handwritten
assembly kernels or native ARM.

## Inspect the matching assembly

Use cargo-show-asm (`cargo asm`) and the existing top-level inspection functions
in `tests/test.rs`. At the latest measured revision these include runtime,
20/32/64-byte array returns, and `inspect_keccak256_output`, which returns the
library's output type directly.

```bash
RUSTFLAGS='-Ctarget-cpu=native' \
cargo asm -p keccak-asm --test test --no-color inspect_keccak256_output

RUSTFLAGS='-Ctarget-cpu=x86-64-v3' \
CARGO_TARGET_DIR=target/specialized-avx2 \
cargo asm -p keccak-asm --test test --no-color inspect_keccak256_output
```

cargo-show-asm 0.2.62 sometimes reports that it cannot locate the assembly after
a successful build with this Cargo version. Locate the emitted file and use
`--file` instead:

```bash
rg --files target/release target/specialized-avx2/release | rg '/test[^/]*\.s$'
cargo asm --file /path/from/the/list.s --no-color --include-constants inspect_keccak256_output
cargo asm --file /path/from/the/list.s --no-color --include-constants inspect_keccak256_32
cargo asm --file /path/from/the/list.s --no-color digest_const
cargo asm --file /path/from/the/list.s --no-color digest_dyn
```

When several symbols match, cargo-asm prints names and indices; select the
wanted symbol from that list. Do not hard-code an old build hash or reuse an
assembly file from the temporary `&mut u8` experiment. Rebuild the source being
measured first.

These root test builds are useful for inspection, but the benchmark workspace
has its own LTO/profile settings. For exact benchmark codegen, emit assembly
from that workspace and select `experiment::digest_runtime`, `digest`,
`assembly_runtime`, or `stack_runtime`:

```bash
RUSTFLAGS='-Ctarget-cpu=native' \
CARGO_TARGET_DIR=target/metrics-native \
cargo asm --manifest-path benches/repro/Cargo.toml \
  -p bench-keccak256 --bin bench-keccak256 --no-color experiment::digest_runtime
```

Use the same `--file` workaround if needed. The standalone inspection wrapper
and the LTO benchmark are not interchangeable evidence about every spill or
call boundary.

## Expected work and static models

Keccak-256 absorbs 136 bytes per block. The expected permutation count is
`floor(bytes / 136) + 1`, with 24 rounds per permutation. Exact block multiples
need a separate padding block. Compare cycles per permutation when explaining
jumps at 136 or 272 bytes; do not expect cycles/hash to be flat there.

The earlier LLVM-MCA models cover permutation loops only. The checked-in
`results/hardware-matrix/round-*.s` files are the exact model inputs. The commands below regenerate model outputs. For example:

```bash
llvm-mca --version
llvm-mca -mtriple=x86_64-unknown-linux-gnu -mcpu=znver4 -iterations=24 \
  benches/repro/results/hardware-matrix/round-rust-native.s
llvm-mca -mtriple=x86_64-unknown-linux-gnu -mcpu=znver4 -iterations=12 \
  benches/repro/results/hardware-matrix/round-asm-avx512.s
```

The ZMM assembly loop performs two rounds per iteration, hence 12 iterations;
the other saved loops use 24. For fresh source, extract its round loop again.
Do not present the saved model as a model of changed code.

`Total Cycles` is the model's simulated loop cost. `Block RThroughput` times
the iteration count is a resource bound. Neither includes whole-hash setup,
absorption, padding, output, dispatch, or benchmark overhead. Scheduling and
memory-alias assumptions can also miss real costs. These are predictions,
not hardware measurements or promised attainable latencies.

## ARM and interpretation limits

No native AArch64 cycles, latency, or throughput were measured. QEMU correctness
tests do not supply native ARM performance numbers. This counter harness uses
Linux x86-64 code, including an empty-input fence; ARM measurements need a native
host and an adapted harness. Use stable Rust when cross-compiling for a
non-default target.

All measurements here are Keccak-256 on one host, with cache-hot inputs and
single-core execution. They do not establish gains for other hash variants,
CPUs, batched workloads, cold inputs, or builds with different features.

## Reproduce the shared-tail experiment

The same checked-in harness includes the Linux x86-64 AVX2 tail-sharing prototype,
behind the benchmark-only `tail-sharing` feature. It does not alter the library.
The original sample data is in `benches/repro/results/tail-sharing/avx2.tsv`.

```bash
RUSTFLAGS='-Ctarget-cpu=x86-64-v3' \
CARGO_TARGET_DIR=target/metrics-tail \
cargo test --release --locked --manifest-path benches/repro/Cargo.toml \
  --features tail-sharing --lib experiment::tests::differential

RUSTFLAGS='-Ctarget-cpu=x86-64-v3' \
CARGO_TARGET_DIR=target/metrics-tail \
cargo build --release --locked --manifest-path benches/repro/Cargo.toml \
  --features tail-sharing

taskset -c 12 target/metrics-tail/release/bench-keccak256 matrix \
  > target/repro-results/tail.tsv 2> target/repro-results/tail.log
```

This adds a fourth implementation named `tail`: the file has 1,067 lines rather
than 807. Compare `tail` with `shared` at 20, 32, and 64 bytes; other sizes fall
back to the current dynamic backend. The all-metrics summary above also handles
this file. Run on an AVX2-capable Linux x86-64 machine. The original results
showed 2,010 to 802 bytes of kernel machine code, with cycle differences within
0.5%. This prototype has not been ported to ARM or AVX-512.
