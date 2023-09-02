#![allow(dead_code)]

use std::path::Path;
use std::process::Command;
use std::{env, fs};

// (script, outfile)
const FILES: &[(&str, &str)] = &[
    // arm
    ("cryptogams/arm/keccak1600-armv4.pl", "src/keccak1600-armv4.s"),
    ("cryptogams/arm/keccak1600-armv8.pl", "src/keccak1600-armv8.s"),
    // x86
    ("cryptogams/x86/keccak1600-mmx.pl", "src/keccak1600-x86.s"),
    // x86_64
    ("cryptogams/x86_64/keccak1600-avx2.pl", "src/keccak1600-x86_64-avx2.s"),
    ("cryptogams/x86_64/keccak1600-avx512.pl", "src/keccak1600-x86_64-avx512f.s"),
    ("cryptogams/x86_64/keccak1600-avx512vl.pl", "src/keccak1600-x86_64-avx512vl.s"),
    ("cryptogams/x86_64/keccak1600-x86_64.pl", "src/keccak1600-x86_64.s"),
];

const HEADERS: &[&str] = &["cryptogams/arm/arm_arch.h"];

fn main() {
    if Path::new(concat!(env!("CARGO_MANIFEST_DIR"), "/cryptogams")).exists() {
        // run Perl scripts
        for &(script, output) in FILES {
            rerun_if_changed(script);
            perl(script, output);
        }

        // update headers
        for &path in HEADERS {
            rerun_if_changed(path);
            let f = Path::new(path).file_name().unwrap().to_str().unwrap();
            fs::copy(path, format!("include/{f}")).unwrap();
        }
    }

    let target_arch = env("CARGO_CFG_TARGET_ARCH");
    let target_features = env("CARGO_CFG_TARGET_FEATURE");
    let target_features = target_features.split(',').collect::<Vec<_>>();
    let feature = |s: &str| target_features.iter().any(|&f| f == s);

    let mut cc = cc::Build::new();
    cc.include("include");
    let output = match target_arch.as_str() {
        "x86" => "src/keccak1600-x86.s",
        "x86_64" => {
            if feature("avx512vl") {
                cc.flag("-mavx512vl");
                "src/keccak1600-x86_64-avx512vl.s"
            } else if feature("avx512f") {
                cc.flag("-mavx512f");
                "src/keccak1600-x86_64-avx512f.s"
            } else if feature("avx2") {
                cc.flag("-mavx2");
                "src/keccak1600-x86_64-avx2.s"
            } else {
                "src/keccak1600-x86_64.s"
            }
        }
        // TODO
        "aarch64" => {
            if target_features.iter().any(|&f| f.contains("v8")) {
                "src/keccak1600-armv8.s"
            } else {
                "src/keccak1600-armv4.s"
            }
        }
        s => panic!("Unsupported target arch: {s}"),
    };

    // println!("cargo:warning={output}");
    cc.file(output).compile("keccak1600");
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

fn rerun_if_changed(path: &str) {
    println!("cargo:rerun-if-changed={path}");
}

fn env(s: &str) -> String {
    println!("cargo:rerun-if-env-changed={s}");
    env::var(s).unwrap()
}
