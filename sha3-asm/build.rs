use std::{env, fs, path::Path, process::Command};

const INCLUDES: &[&str] = &["cryptogams/arm"];

fn main() {
    let target_features = maybe_env("CARGO_CFG_TARGET_FEATURE").unwrap_or_default();
    let target_features = target_features.split(',').collect::<Vec<_>>();
    eprintln!("target features: {target_features:?}");
    let feature = |s: &str| target_features.iter().any(|&f| f == s);

    let script = cryptogams_script(feature);
    eprintln!("selected cryptogams script: {script}");
    let src = Path::new(script).file_stem().unwrap().to_str().unwrap();
    let sha3 = Path::new(&env("OUT_DIR")).join(format!("{src}.s"));
    println!("cargo:rustc-env=SHA3_ASM_SRC={src}");

    let target_arch = env("CARGO_CFG_TARGET_ARCH");
    let flavor = cryptogams_script_flavor(&target_arch, feature);
    eprintln!("selected cryptogams script flavor: {flavor:?}");
    perl(script, flavor.as_deref(), &target_arch, sha3.to_str().unwrap());

    cc::Build::new().includes(INCLUDES).file(sha3).compile("keccak");
}

fn cryptogams_script(feature: impl Fn(&str) -> bool) -> &'static str {
    // Allow overriding the script path via an environment variable.
    if let Ok(script) = maybe_env("SHA3_ASM_SCRIPT") {
        eprintln!("cryptogams script overridden by environment variable");
        let p = Path::new(&script);
        assert!(p.is_relative(), "SHA3_ASM_SCRIPT={script:?} is not relative");

        let p = p.strip_prefix("cryptogams").unwrap_or(p);
        let p = Path::new("cryptogams").join(p);
        let meta = p.metadata().unwrap_or_else(|e| panic!("SHA3_ASM_SCRIPT={p:?}: {e}"));

        assert!(meta.is_file(), "SHA3_ASM_SCRIPT={p:?} is not a file");
        assert!(
            p.components().all(|c| c != std::path::Component::ParentDir),
            "SHA3_ASM_SCRIPT={p:?} contains a parent directory component"
        );

        let p = p.to_str().unwrap().to_string();
        // TODO(MSRV-1.72): use `String::leak` instead
        return Box::leak(p.into_boxed_str());
    }

    let target_arch = env("CARGO_CFG_TARGET_ARCH");
    match target_arch.as_str() {
        // TODO: arm (?)
        // "arm" => "cryptogams/arm/keccak1600-armv4.pl",
        "aarch64" => "cryptogams/arm/keccak1600-armv8.pl",
        "x86" => {
            if in_ci() || feature("mmx") {
                "cryptogams/x86/keccak1600-mmx.pl"
            } else {
                panic!("x86 targets require MMX support")
            }
        }
        "x86_64" => {
            if feature("avx512vl") {
                "cryptogams/x86_64/keccak1600-avx512vl.pl"
            // These are obsolete, plain x86_64 implementation is faster:
            // https://github.com/DaniPopes/bench-keccak256

            // } else if feature("avx512f") {
            //     "cryptogams/x86_64/keccak1600-avx512.pl"
            // } else if feature("avx2") {
            //     "cryptogams/x86_64/keccak1600-avx2.pl"
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
        s => panic!("unsupported target arch: {s}"),
    }
}

fn cryptogams_script_flavor(target_arch: &str, feature: impl Fn(&str) -> bool) -> Option<String> {
    let os = env("CARGO_CFG_TARGET_OS");
    let environ = env("CARGO_CFG_TARGET_ENV");
    let family = env("CARGO_CFG_TARGET_FAMILY");
    let mut flavor = match target_arch {
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

fn perl(path: &str, flavor: Option<&str>, target_arch: &str, to: &str) {
    let mut cmd = Command::new("perl");
    cmd.arg(path);

    // let to_is_second = target_arch == "arm" || target_arch == "aarch64";
    let _ = target_arch;
    if let Some(flavor) = flavor {
        cmd.arg(flavor);
    }
    cmd.arg(to);

    eprintln!("running script: {cmd:?}");
    let out = cmd.output().unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stderr = stderr.trim();

    assert!(out.status.success(), "perl for {path} failed:\n{stderr}");
    assert!(stderr.is_empty(), "non-empty stderr for {path}:\n{stderr}");

    if stdout.trim().is_empty() {
        assert!(Path::new(to).exists(), "assembly file was not created at {to}");
        eprintln!("stdout for {path} is empty: file {to} was written by perl script");
    } else {
        eprintln!("writing stdout manually to {to}");
        fs::write(to, stdout.as_bytes()).unwrap();
    }
}

#[track_caller]
fn env(s: &str) -> String {
    maybe_env(s).unwrap()
}

fn in_ci() -> bool {
    maybe_env("CI").is_ok()
}

fn maybe_env(s: &str) -> Result<String, env::VarError> {
    println!("cargo:rerun-if-env-changed={s}");
    env::var(s)
}
