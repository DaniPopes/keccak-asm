#![allow(dead_code)]

use std::path::Path;
use std::process::Command;
use std::{env, fs};

// (script, outfile)
const CRYPTOGAMS_FILES: &[(&str, &str)] = &[
    // arm
    ("cryptogams/arm/keccak1600-armv4.pl", "src/SHA3/armv4.s"),
    ("cryptogams/arm/keccak1600-armv8.pl", "src/SHA3/armv8.s"),
    // x86
    ("cryptogams/x86/keccak1600-mmx.pl", "src/SHA3/x86.s"),
    // x86_64
    ("cryptogams/x86_64/keccak1600-avx2.pl", "src/SHA3/x86_64-avx2.s"),
    ("cryptogams/x86_64/keccak1600-avx512.pl", "src/SHA3/x86_64-avx512f.s"),
    ("cryptogams/x86_64/keccak1600-avx512vl.pl", "src/SHA3/x86_64-avx512vl.s"),
    ("cryptogams/x86_64/keccak1600-x86_64.pl", "src/SHA3/x86_64.s"),
];

const CRYPTOGAMS_HEADERS: &[&str] = &["cryptogams/arm/arm_arch.h"];

// (asm, outfile)
const XKCP_FILES: &[(&str, &str)] = &[
    ("XKCP/lib/low/KeccakP-1600/AVX2/KeccakP-1600-AVX2.s", "src/KeccakP-1600/x86_64-avx2.s"),
    ("XKCP/lib/low/KeccakP-1600/AVX512/KeccakP-1600-AVX512.s", "src/KeccakP-1600/x86_64-avx512.s"),
];

const XKCP_HEADERS: &[&str] = &[
    // optimized
    "XKCP/lib/common/brg_endian.h",
    // // avx2
    // "XKCP/lib/low/KeccakP-1600/AVX2/KeccakP-1600-SnP.h",
    // // avx512
    // "XKCP/lib/low/KeccakP-1600/AVX512/KeccakP-1600-SnP.h",
];

fn main() {
    if Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/cryptogams")).exists() {
        // run Perl scripts
        for &(script, output) in CRYPTOGAMS_FILES {
            rerun_if_changed(script);
            perl(script, output);
        }

        // update headers
        CRYPTOGAMS_HEADERS.iter().copied().for_each(include);
    }

    if Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/XKCP")).exists() {
        // copy assembly files
        for &(path, output) in XKCP_FILES {
            rerun_if_changed(path);
            fs::copy(path, output).unwrap();
        }

        // update headers
        XKCP_HEADERS.iter().copied().for_each(include);
    }

    let target_arch = env("CARGO_CFG_TARGET_ARCH");
    let target_features = env("CARGO_CFG_TARGET_FEATURE");
    let target_features = target_features.split(',').collect::<Vec<_>>();
    let feature = |s: &str| target_features.iter().any(|&f| f == s);

    let mut cc = cc::Build::new();
    cc.include("include");

    let sha3 = match target_arch.as_str() {
        "x86" => "src/SHA3/x86.s",
        "x86_64" => {
            if feature("avx512vl") {
                "src/SHA3/x86_64-avx512vl.s"
            } else if feature("avx512f") {
                "src/SHA3/x86_64-avx512f.s"
            } else if feature("avx2") {
                "src/SHA3/x86_64-avx2.s"
            } else {
                "src/SHA3/x86_64.s"
            }
        }
        // TODO
        "aarch64" => {
            if target_features.iter().any(|&f| f.contains("v8")) {
                "src/SHA3/armv8.s"
            } else {
                "src/SHA3/armv4.s"
            }
        }
        s => panic!("Unsupported target arch: {s}"),
    };

    let keccak1600p = match target_arch.as_str() {
        "x86_64" => {
            if feature("avx512vl") && feature("avx512f") {
                Some("src/KeccakP-1600/x86_64-avx512.s")
            } else if feature("avx2") {
                Some("src/KeccakP-1600/x86_64-avx2.s")
            } else {
                // Note: plain x86_64 impl is obsolete
                None
            }
        }
        // TODO: arm
        _ => None,
    };
    if let Some(keccak1600p) = keccak1600p {
        println!("cargo:rustc-cfg=keccakp1600");
        cc.file(keccak1600p);
    }

    cc.file(sha3).compile("keccak");
}

fn perl(path: &str, to: &str) {
    let mut cmd = Command::new("perl");
    cmd.arg(path);
    cmd.args(["elf", to]);
    let out = cmd.output().unwrap();
    if !out.status.success() {
        panic!("perl for {path} failed:\n{}", String::from_utf8_lossy(&out.stderr));
    }
    let stdout = String::from_utf8(out.stdout).unwrap();
    if !stdout.trim().is_empty() {
        fs::write(to, stdout).unwrap();
    }
}

fn include(path: &str) {
    rerun_if_changed(path);
    let f = Path::new(path).file_name().unwrap().to_str().unwrap();
    fs::copy(path, format!("include/{f}")).unwrap();
}

fn rerun_if_changed(path: &str) {
    println!("cargo:rerun-if-changed={path}");
}

fn env(s: &str) -> String {
    println!("cargo:rerun-if-env-changed={s}");
    env::var(s).unwrap()
}
