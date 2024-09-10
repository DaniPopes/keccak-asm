use std::{env, fs, path::Path, process::Command};

fn main() {
    let target = Target::from_env();

    let script = cryptogams_script(&target);
    eprintln!("selected cryptogams script: {script}");
    let src = Path::new(script).file_stem().unwrap().to_str().unwrap();
    let ext = if target.is_msvc() { "asm" } else { "S" };
    let sha3 = Path::new(&env("OUT_DIR")).join(format!("{src}.{ext}"));
    println!("cargo:rustc-env=SHA3_ASM_SRC={src}");

    let flavor = cryptogams_script_flavor(&target);
    eprintln!("selected cryptogams script flavor: {flavor:?}");
    run_perlasm(script, flavor.as_deref(), &sha3);

    let mut cc = cc::Build::new();
    if target.is_any_arm() {
        cc.include("cryptogams/arm");
    }
    cc.file(sha3)
        .flag("-D")
        .flag("_SHA3_squeeze=_KECCAK_ASM_SHA3_squeeze")
        .flag("-D")
        .flag("_SHA3_absorb=_KECCAK_ASM_SHA3_absorb")
        .flag("-D")
        .flag("_SHA3_squeeze_cext=_KECCAK_ASM_SHA3_squeeze_cext")
        .flag("-D")
        .flag("_SHA3_absorb_cext=_KECCAK_ASM_SHA3_absorb_cext")
        .flag("-D")
        .flag("SHA3_squeeze=KECCAK_ASM_SHA3_squeeze")
        .flag("-D")
        .flag("SHA3_absorb=KECCAK_ASM_SHA3_absorb")
        .flag("-D")
        .flag("SHA3_squeeze_cext=KECCAK_ASM_SHA3_squeeze_cext")
        .flag("-D")
        .flag("SHA3_absorb_cext=KECCAK_ASM_SHA3_absorb_cext")
        .compile("keccak");
}

fn cryptogams_script(target: &Target) -> &'static str {
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

    match target.arch.as_str() {
        "arm" => "cryptogams/arm/keccak1600-armv4.pl",
        "aarch64" => "cryptogams/arm/keccak1600-armv8.pl",
        "x86" => {
            if in_ci() || target.has_feature("mmx") {
                "cryptogams/x86/keccak1600-mmx.pl"
            } else {
                panic!("x86 targets require MMX support")
            }
        }
        "x86_64" => {
            if target.has_feature("avx512vl") {
                "cryptogams/x86_64/keccak1600-avx512vl.pl"
            // These are obsolete, plain x86_64 implementation is faster:
            // https://github.com/DaniPopes/bench-keccak256

            // } else if target.has_feature("avx512f") {
            //     "cryptogams/x86_64/keccak1600-avx512.pl"
            // } else if target.has_feature("avx2") {
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

fn cryptogams_script_flavor(target: &Target) -> Option<String> {
    let mut flavor = match target.arch.as_str() {
        "arm" => match target.os.as_str() {
            "ios" | "macos" => Some("ios32"),
            "windows" => Some(if target.is_msvc() { "win32" } else { "coff32" }),
            "linux" => Some("linux32"),
            _ => None,
        },
        "aarch64" => match target.os.as_str() {
            "ios" | "macos" => Some("ios64"),
            "windows" => Some(if target.is_msvc() { "win64" } else { "coff64" }),
            "linux" => Some("linux64"),
            _ => None,
        },
        "x86" => match target.os.as_str() {
            "windows" => Some("win32n"),
            _ => Some("elf"),
        },
        "x86_64" => match target.os.as_str() {
            "macos" => Some("macosx"),
            "windows" => Some(if target.is_msvc() { "masm" } else { "mingw64" }),
            _ if target.family == "unix" => Some("elf"),
            _ => None,
        },
        "powerpc" => Some("linux32"),
        "powerpc64" => Some("linux64"),
        "powerpc64le" => Some("linux64le"),
        s if s.starts_with("mips") && s.contains("64") => Some("64"),
        s if s.starts_with("riscv") && s.contains("32") => Some("32"),
        s if s.starts_with("riscv") && s.contains("64") => Some("64"),
        _ => None,
    }
    .map(String::from);

    if let Some(s) = &mut flavor {
        if target.arch == "aarch64" && target.has_feature("sha3") {
            s.push_str("+sha3");
        }
    }

    flavor
}

fn run_perlasm(path: &str, flavor: Option<&str>, to: &Path) {
    let mut cmd = Command::new("perl");

    cmd.arg(path);
    cmd.arg(flavor.unwrap_or("void"));
    let to_relative = to.strip_prefix(env::current_dir().unwrap()).unwrap_or(to);
    let to_relative = to_relative.to_str().unwrap().replace('\\', "/");
    cmd.arg(to_relative);

    eprintln!("running script: {cmd:?}");
    let out = cmd.output().unwrap_or_else(|e| panic!("could not execute perl ({cmd:?}): {e}"));
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let stderr = stderr.trim();

    assert!(out.status.success(), "perl for {path} failed ({cmd:?}):\n{stderr}");

    if stdout.trim().is_empty() {
        assert!(to.exists(), "assembly file was not created at {to:?}");
        eprintln!("stdout for {path} is empty: file {to:?} was written by perl script");
    } else {
        eprintln!("writing stdout manually to {to:?}");
        fs::write(to, stdout.as_bytes()).unwrap();
    }
}

struct Target {
    arch: String,
    os: String,
    env: String,
    family: String,
    features: Vec<String>,
}

impl Target {
    fn from_env() -> Self {
        Self {
            arch: env("CARGO_CFG_TARGET_ARCH"),
            os: env("CARGO_CFG_TARGET_OS"),
            env: env("CARGO_CFG_TARGET_ENV"),
            family: env("CARGO_CFG_TARGET_FAMILY"),
            features: if let Ok(features) = maybe_env("CARGO_CFG_TARGET_FEATURE") {
                features.split(',').map(Into::into).collect()
            } else {
                vec![]
            },
        }
    }

    fn is_any_arm(&self) -> bool {
        self.arch.starts_with("arm") || self.arch.starts_with("aarch64")
    }

    fn is_msvc(&self) -> bool {
        self.env == "msvc"
    }

    fn has_feature(&self, feature: &str) -> bool {
        self.features.iter().any(|f| f == feature)
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
