use std::{borrow::Cow, env, fs, path::Path, process::Command};

fn main() {
    let target = Target::from_env();

    let script = cryptogams_script(&target);
    eprintln!("selected cryptogams script: {script}");
    let script = maybe_patch_script(script);
    let src = Path::new(script.as_ref()).file_stem().unwrap().to_str().unwrap();
    let ext = if target.is_msvc() { "asm" } else { "S" };
    let sha3 = Path::new(&env("OUT_DIR")).join(format!("{src}.{ext}"));
    println!("cargo:rustc-env=SHA3_ASM_SRC={src}");

    let symbol_prefix = "KECCAK_ASM";
    println!(
        "cargo:rustc-env=SHA3_ASM_ABSORB={}",
        link_name(&target, symbol_prefix, "SHA3_absorb")
    );
    println!(
        "cargo:rustc-env=SHA3_ASM_SQUEEZE={}",
        link_name(&target, symbol_prefix, "SHA3_squeeze")
    );

    let flavor = cryptogams_script_flavor(&target);
    eprintln!("selected cryptogams script flavor: {flavor:?}");
    run_perlasm(&script, flavor.as_deref(), &sha3);

    let mut cc = cc::Build::new();
    if target.is_any_arm() {
        cc.include("cryptogams/arm");
    }

    // We need to rename symbols, because if a dependency brings in openssl, the linker may detect
    // `libcrypto.a`, which ships the same symbol names as cryptogams. This is not ideal, because
    // while openssl-sys does not expose these functions, and some of these symbols are private and
    // not meant for bindings, they are still shipped in `libcrypto.a`. If imports are in the wrong
    // order, the linker would detect these and link to our interface. This can lead to incorrect
    // hash results.
    //
    // Instead, we rename the symbols with a prefix, so that the symbols do not conflict.
    let preprocessor_renames = ["SHA3_squeeze", "SHA3_absorb"];

    cc.file(&sha3);

    // MSVC's provided arm assembler does not support -D, only allowing PreDefine to be used.
    // Unfortunately these are subtly different from -D, making them difficult to use when there
    // might be symbol conflicts.
    //
    // Instead, we will do a find/replace on the assembly here.
    if target.is_msvc() && target.is_any_arm() {
        let mut assembly = fs::read_to_string(&sha3).unwrap();
        for symbol in preprocessor_renames {
            assembly = assembly.replace(symbol, &format!("{symbol_prefix}_{symbol}"));
        }

        fs::write(&sha3, &assembly).unwrap()
    } else {
        // we do not want to define anything for msvc + arm
        for symbol in preprocessor_renames {
            for suffix in ["", "_cext", "_neon", "_kimd"] {
                let symbol = format!("{symbol}{suffix}");
                // sometimes the symbols have underscores
                cc.define(&format!("_{symbol}"), format!("_{symbol_prefix}_{symbol}").as_str());
                // and sometimes they do not
                cc.define(&symbol, format!("{symbol_prefix}_{symbol}").as_str());
            }
        }
    }

    cc.compile("keccak");
}

fn link_name(target: &Target, prefix: &str, symbol: &str) -> String {
    // OpenSSL only wires the ARM SHA3 cext absorb symbol because its squeeze
    // path uses a newer five-argument ABI. These cryptogams sources expose the
    // old four-argument ABI, so both cext symbols match our direct bindings.
    let suffix = if target.use_arm_sha3_cext() { "_cext" } else { "" };
    format!("{prefix}_{symbol}{suffix}")
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
        // See https://github.com/DaniPopes/bench-keccak256 for why this order is chosen.
        "x86_64" => {
            // TODO: OpenSSL has not enabled this yet.
            // if target.has_feature("apxf") {
            //     "cryptogams/x86_64/keccak1600-apx.pl"
            // } else
            if target.is_zen5_target() {
                "cryptogams/x86_64/keccak1600-avx512.pl"
            } else if target.has_feature("avx512vl") {
                "cryptogams/x86_64/keccak1600-avx512vl.pl"
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
        if target.use_arm_sha3_cext() {
            s.push_str("+sha3");
        }
    }

    flavor
}

fn maybe_patch_script<'a>(script: &'a str) -> Cow<'a, str> {
    let script_path = Path::new(script);
    let script_name = script_path.file_name().unwrap().to_str().unwrap();

    let patches_dir = Path::new("patches");
    if !patches_dir.is_dir() {
        return Cow::Borrowed(script);
    }

    let mut patches: Vec<_> = fs::read_dir(patches_dir)
        .unwrap()
        .filter_map(|e| {
            let e = e.unwrap();
            let name = e.file_name();
            let name = name.to_str().unwrap();
            // Patches are named `<script-stem>-<suffix>.patch`; match the stem exactly
            // (split at the last '-') rather than as a substring, otherwise e.g.
            // `keccak1600-avx512vl-cfi.patch` also matches `keccak1600-avx512.pl`,
            // whose stem is a prefix of the VL one.
            let stem = script_path.file_stem().unwrap().to_str().unwrap();
            if name.ends_with(".patch")
                && matches!(
                    name.trim_end_matches(".patch").rsplit_once('-'),
                    Some((patch_stem, _)) if patch_stem == stem
                )
            {
                Some(e.path())
            } else {
                None
            }
        })
        .collect();

    if patches.is_empty() {
        return Cow::Borrowed(script);
    }

    patches.sort();
    for patch in &patches {
        println!("cargo:rerun-if-changed={}", patch.display());
    }

    let out_dir = env("OUT_DIR");
    let patched = Path::new(&out_dir).join(script_name);
    // The sibling-symlink loop below may have planted `OUT_DIR/<script_name>` as a
    // symlink back to the source on a previous run that selected a different script
    // (the build script re-runs in the same OUT_DIR when e.g. `SHA3_ASM_SCRIPT`
    // changes). `fs::copy` follows the symlink and opens the destination with
    // truncate, which would zero out the checked-in source before reading it.
    // Remove whatever is at the destination so the copy creates a fresh file.
    let _ = fs::remove_file(&patched);
    fs::copy(script, &patched).unwrap();

    // Symlink sibling files (e.g. x86_64-xlate.pl) so patched scripts can find them.
    if let Some(script_dir) = script_path.parent() {
        let script_dir = env::current_dir().unwrap().join(script_dir);
        for entry in fs::read_dir(&script_dir).unwrap() {
            let entry = entry.unwrap();
            let name = entry.file_name();
            if name == script_name {
                continue;
            }
            let dest = Path::new(&out_dir).join(&name);
            if !dest.exists() {
                #[cfg(unix)]
                std::os::unix::fs::symlink(entry.path(), &dest).ok();
                #[cfg(windows)]
                fs::copy(entry.path(), &dest).ok();
            }
        }
    }

    for patch in &patches {
        eprintln!("applying patch: {}", patch.display());
        let out = Command::new("patch")
            .arg("--no-backup-if-mismatch")
            .arg(patched.to_str().unwrap())
            .arg(patch.to_str().unwrap())
            .output()
            .expect("could not execute `patch`");
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert!(out.status.success(), "patch {} failed:\n{stderr}", patch.display());
    }

    Cow::Owned(patched.to_str().unwrap().to_string())
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
    vendor: String,
    os: String,
    env: String,
    family: String,
    features: Vec<String>,
}

impl Target {
    fn from_env() -> Self {
        Self {
            arch: env("CARGO_CFG_TARGET_ARCH"),
            vendor: env("CARGO_CFG_TARGET_VENDOR"),
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

    fn use_arm_sha3_cext(&self) -> bool {
        // The ARM SHA3 crypto extension path has only been tested to perform better on Apple.
        self.arch == "aarch64" && self.vendor == "apple" && self.has_feature("sha3")
    }

    fn is_zen5_target(&self) -> bool {
        // Cargo/rustc do not expose an x86 CPU family/model cfg. This is a
        // target-feature heuristic, not exact CPU identification: native Zen 5
        // expands to both features below, while Zen 4 lacks both. The checked
        // Intel target CPUs do not set both: Tiger Lake has avx512vp2intersect
        // without avxvnni, and newer Intel server CPUs have avxvnni without
        // avx512vp2intersect. Explicit feature flags can still fool this.
        rustflags_codegen_option_is("target-cpu", "znver5")
            || self.is_native_zen5_target()
            || self.has_zen5_target_features()
    }

    fn is_native_zen5_target(&self) -> bool {
        rustflags_codegen_option_is("target-cpu", "native") && self.has_zen5_target_features()
    }

    fn has_zen5_target_features(&self) -> bool {
        self.has_feature("avx512vp2intersect") && self.has_feature("avxvnni")
    }
}

fn rustflags_codegen_option_is(key: &str, value: &str) -> bool {
    match maybe_env("CARGO_ENCODED_RUSTFLAGS") {
        Ok(flags) => {
            let mut codegen = false;
            for flag in flags.split('\x1f') {
                if flag == "-C" || flag == "--codegen" {
                    codegen = true;
                } else if let Some(option) = flag.strip_prefix("-C") {
                    if codegen_option_is(option, key, value) {
                        return true;
                    }
                } else if let Some(option) = flag.strip_prefix("--codegen=") {
                    if codegen_option_is(option, key, value) {
                        return true;
                    }
                } else if codegen {
                    if codegen_option_is(flag, key, value) {
                        return true;
                    }
                    codegen = false;
                }
            }

            false
        }
        Err(_) => false,
    }
}

fn codegen_option_is(option: &str, key: &str, value: &str) -> bool {
    option.strip_prefix(key).and_then(|option| option.strip_prefix('=')) == Some(value)
}

#[track_caller]
fn env(s: &str) -> String {
    maybe_env(s).expect(s)
}

fn in_ci() -> bool {
    maybe_env("CI").is_ok()
}

fn maybe_env(s: &str) -> Result<String, env::VarError> {
    println!("cargo:rerun-if-env-changed={s}");
    env::var(s)
}
