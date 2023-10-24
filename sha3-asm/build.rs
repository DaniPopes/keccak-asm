use std::path::Path;
use std::process::Command;
use std::{env, fs};

const INCLUDES: &[&str] = &["cryptogams/arm"];

fn main() {
    let target_features = maybe_env("CARGO_CFG_TARGET_FEATURE").unwrap_or_default();
    let target_features = target_features.split(',').collect::<Vec<_>>();
    let feature = |s: &str| target_features.iter().any(|&f| f == s);

    let script = cryptogams_script(feature);
    let src = Path::new(script).file_stem().unwrap().to_str().unwrap();
    let sha3 = Path::new(&env("OUT_DIR")).join(format!("{src}.s"));
    println!("cargo:rustc-env=SHA3_ASM_SRC={src}");

    let flavor = cryptogams_script_flavor(feature);
    perl(script, flavor.as_deref(), sha3.to_str().unwrap());

    cc::Build::new().includes(INCLUDES).file(sha3).compile("keccak");
}

fn cryptogams_script(feature: impl Fn(&str) -> bool) -> &'static str {
    if let Ok(script) = maybe_env("SHA3_ASM_SCRIPT") {
        eprintln!("cryptogams script overridden by environment variable");
        // TODO(MSRV-1.72): use `String::leak` instead
        return Box::leak(script.into_boxed_str())
    }

    let target_arch = env("CARGO_CFG_TARGET_ARCH");
    match target_arch.as_str() {
        // "arm" => "cryptogams/arm/keccak1600-armv4.pl",
        "arm" | "aarch64" => "cryptogams/arm/keccak1600-armv8.pl",
        "x86" => {
            if feature("mmx") {
                "cryptogams/x86/keccak1600-mmx.pl"
            } else {
                panic!("x86 targets require MMX support")
            }
        }
        "x86_64" => {
            if feature("avx512vl") {
                "cryptogams/x86_64/keccak1600-avx512vl.pl"
            } else if feature("avx512f") {
                "cryptogams/x86_64/keccak1600-avx512.pl"
            } else if feature("avx2") {
                "cryptogams/x86_64/keccak1600-avx2.pl"
            } else {
                "cryptogams/x86_64/keccak1600-x86_64.pl"
            }
        }
        // TODO: cil (?)
        // TODO: ia64 (?)
        s if s.starts_with("mips") => "cryptogams/mips/keccak1600-mips.pl",
        s if s.starts_with("powerpc") => "cryptogams/ppc/keccak1600-ppc.pl",
        s if s.starts_with("riscv") => "cryptogams/riscv/keccak1600-riscv.pl",
        "s390x" => "cryptogams/s390x/keccak1600-s390x.pl",
        s => panic!("Unsupported target arch: {s}"),
    }
}

fn cryptogams_script_flavor(feature: impl Fn(&str) -> bool) -> Option<String> {
    let target_arch = env("CARGO_CFG_TARGET_ARCH");
    let os = env("CARGO_CFG_TARGET_OS");
    let environ = env("CARGO_CFG_TARGET_ENV");
    let family = env("CARGO_CFG_TARGET_FAMILY");
    let mut flavor = match target_arch.as_str() {
        "arm" | "aarch64" => match os.as_str() {
            "ios" | "macos" => Some("ios64"),
            "windows" => Some("win64"),
            "linux" => Some("linux64"),
            _ => None,
        },
        "x86" => match os.as_str() {
            "windows" => Some("win32n"),
            _ => Some("elf"),
        },
        "x86_64" => match os.as_str() {
            "macos" => Some("macosx"),
            "windows" if environ == "gnu" => Some("mingw64"),
            _ if family == "unix" => Some("elf"),
            _ => None,
        },
        s if s.starts_with("mips") && s.contains("64") => Some("64"),
        s if s.starts_with("powerpc") && s.contains("64") => Some("64"),
        s if s.starts_with("riscv") && s.contains("32") => Some("32"),
        s if s.starts_with("riscv") && s.contains("64") => Some("64"),
        _ => None,
    }
    .map(String::from);

    if let Some(s) = &mut flavor {
        if target_arch == "aarch64" && feature("sha3") {
            s.push_str("+sha3");
        }
    }

    flavor
}

fn perl(path: &str, flavor: Option<&str>, to: &str) {
    let mut cmd = Command::new("perl");
    cmd.arg(path);
    if let Some(flavor) = flavor {
        cmd.arg(flavor);
    }
    cmd.arg(to);
    let out = cmd.output().unwrap();
    if !out.status.success() {
        panic!("perl for {path} failed:\n{}", String::from_utf8_lossy(&out.stderr));
    }
    let stdout = String::from_utf8(out.stdout).unwrap();
    if !stdout.trim().is_empty() {
        fs::write(to, stdout).unwrap();
    }
}

#[track_caller]
fn env(s: &str) -> String {
    maybe_env(s).unwrap()
}

fn maybe_env(s: &str) -> Result<String, env::VarError> {
    println!("cargo:rerun-if-env-changed={s}");
    env::var(s)
}
