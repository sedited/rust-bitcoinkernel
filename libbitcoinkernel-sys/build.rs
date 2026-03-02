use bindgen::RustEdition;
use std::env;
use std::path::Path;
use std::path::PathBuf;
use std::process::Command;

fn main() {
    let bitcoin_dir = Path::new("bitcoin");
    let out_dir = env::var("OUT_DIR").unwrap();
    let build_dir = Path::new(&out_dir).join("bitcoin");
    let install_dir = Path::new(&out_dir).join("install");

    println!("{} {}", bitcoin_dir.display(), build_dir.display());

    // Iterate through all files in the Bitcoin Core submodule directory
    println!("cargo:rerun-if-changed={}", bitcoin_dir.display());

    let build_config = "RelWithDebInfo";

    let mut cmake_configure = Command::new("cmake");
    cmake_configure
        .arg("-B")
        .arg(&build_dir)
        .arg("-S")
        .arg(bitcoin_dir)
        .arg(format!("-DCMAKE_BUILD_TYPE={build_config}"))
        .arg("-DBUILD_KERNEL_LIB=ON")
        .arg("-DBUILD_TESTS=OFF")
        .arg("-DBUILD_BENCH=OFF")
        .arg("-DBUILD_KERNEL_TEST=OFF")
        .arg("-DBUILD_TX=OFF")
        .arg("-DBUILD_WALLET_TOOL=OFF")
        .arg("-DENABLE_WALLET=OFF")
        .arg("-DENABLE_EXTERNAL_SIGNER=OFF")
        .arg("-DBUILD_UTIL=OFF")
        .arg("-DBUILD_BITCOIN_BIN=OFF")
        .arg("-DBUILD_DAEMON=OFF")
        .arg("-DBUILD_UTIL_CHAINSTATE=OFF")
        .arg("-DBUILD_CLI=OFF")
        .arg("-DBUILD_FUZZ_BINARY=OFF")
        .arg("-DBUILD_SHARED_LIBS=OFF")
        .arg("-DCMAKE_INSTALL_LIBDIR=lib")
        .arg("-DENABLE_IPC=OFF")
        .arg(format!("-DCMAKE_INSTALL_PREFIX={}", install_dir.display()));

    if env::var("CARGO_FEATURE_SCRIPT_DEBUG").is_ok() {
        cmake_configure.arg("-DENABLE_SCRIPT_DEBUG=ON");
    }

    cmake_configure.status().unwrap();

    let num_jobs = env::var("NUM_JOBS")
        .ok()
        .and_then(|v| v.parse::<u32>().ok())
        .unwrap_or(1); // Default to 1 if not set

    Command::new("cmake")
        .arg("--build")
        .arg(&build_dir)
        .arg("--config")
        .arg(build_config)
        .arg(format!("--parallel={num_jobs}"))
        .status()
        .unwrap();

    Command::new("cmake")
        .arg("--install")
        .arg(&build_dir)
        .arg("--config")
        .arg(build_config)
        .status()
        .unwrap();

    // Check if the build system used a multi-config generator
    let lib_dir = if install_dir.join("lib").join(build_config).exists() {
        install_dir.join("lib").join(build_config)
    } else {
        install_dir.join("lib")
    };
    println!("cargo:rustc-link-search=native={}", lib_dir.display());

    println!("cargo:rustc-link-lib=static=bitcoinkernel");

    // Header path for bindgen
    let include_path = install_dir.join("include");
    let header = include_path.join("bitcoinkernel.h");

    #[allow(deprecated)]
    let bindings = bindgen::Builder::default()
        .header(header.to_str().unwrap())
        .clang_arg("-DBITCOINKERNEL_STATIC")
        .rust_target(bindgen::RustTarget::Stable_1_71)
        .rust_edition(RustEdition::Edition2021)
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(
        env::var("OUT_DIR").expect("OUT_DIR was not defined by the cargo environment!"),
    );
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");

    let compiler = cc::Build::new().get_compiler();
    let target_os = std::env::var("CARGO_CFG_TARGET_OS").unwrap();

    if target_os == "windows" {
        println!("cargo:rustc-link-lib=bcrypt");
        println!("cargo:rustc-link-lib=shell32");
    }

    if compiler.is_like_clang() {
        if target_os == "macos" {
            println!("cargo:rustc-link-lib=dylib=c++");
        } else {
            println!("cargo:rustc-link-lib=dylib=stdc++");
        }
    } else if compiler.is_like_gnu() {
        println!("cargo:rustc-link-lib=dylib=stdc++");
    }
}
