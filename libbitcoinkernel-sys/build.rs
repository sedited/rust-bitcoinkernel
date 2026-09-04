use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

const BUILD_CONFIG: &str = "RelWithDebInfo";
const MIN_ANDROID_API: u32 = 24;
const BITCOIN_SRC_DIR: &str = "bitcoin";

const BASE_CMAKE_FLAGS: &[&str] = &[
    "-DBUILD_KERNEL_LIB=ON",
    "-DBUILD_TESTS=OFF",
    "-DBUILD_BENCH=OFF",
    "-DBUILD_KERNEL_TEST=OFF",
    "-DBUILD_TX=OFF",
    "-DBUILD_WALLET_TOOL=OFF",
    "-DENABLE_WALLET=OFF",
    "-DENABLE_EXTERNAL_SIGNER=OFF",
    "-DBUILD_UTIL=OFF",
    "-DBUILD_BITCOIN_BIN=OFF",
    "-DBUILD_DAEMON=OFF",
    "-DBUILD_UTIL_CHAINSTATE=OFF",
    "-DBUILD_CLI=OFF",
    "-DBUILD_FUZZ_BINARY=OFF",
    "-DBUILD_SHARED_LIBS=OFF",
    "-DCMAKE_INSTALL_LIBDIR=lib",
    "-DCMAKE_POSITION_INDEPENDENT_CODE=ON",
    "-DENABLE_IPC=OFF",
];

fn main() {
    let target = target_config();

    for var in target.rerun_env {
        println!("cargo:rerun-if-env-changed={var}");
    }

    let lib_dir = build_kernel(&target.cmake_args);

    println!("cargo:rustc-link-search=native={}", lib_dir.display());
    println!("cargo:rustc-link-lib=static=bitcoinkernel");

    for directive in &target.link_directives {
        println!("cargo:{directive}");
    }
}

fn build_kernel(extra_cmake_args: &[String]) -> PathBuf {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());
    let cmake = Cmake::new(BITCOIN_SRC_DIR, &out_dir);

    // Rebuild whenever anything in the Bitcoin Core submodule changes.
    println!("cargo:rerun-if-changed={BITCOIN_SRC_DIR}");

    cmake.configure(extra_cmake_args);
    cmake.build();
    cmake.install();

    cmake.lib_dir()
}

// Everything that varies by platform, resolved once up front.
#[derive(Default)]
struct TargetConfig {
    // Extra cmake flags needed to cross-compile for this target.
    cmake_args: Vec<String>,
    // Emitted verbatim as `cargo:{directive}`.
    link_directives: Vec<String>,
    // Variables that should force a rebuild when they change.
    rerun_env: &'static [&'static str],
}

fn target_config() -> TargetConfig {
    match &*env::var("CARGO_CFG_TARGET_OS").unwrap() {
        "windows" => TargetConfig {
            link_directives: vec![
                "rustc-link-lib=bcrypt".into(),
                "rustc-link-lib=shell32".into(),
            ],
            ..Default::default()
        },

        "macos" | "ios" | "tvos" | "watchos" | "visionos" => TargetConfig {
            link_directives: cxx_runtime("c++"),
            ..Default::default()
        },

        "android" => Android::from_env().config(),

        "linux" | "freebsd" | "openbsd" | "netbsd" | "dragonfly" | "illumos" | "solaris" => {
            TargetConfig {
                link_directives: cxx_runtime("stdc++"),
                ..Default::default()
            }
        }

        other => panic!(
            "unsupported target OS: {other}. If the generic libstdc++ handling \
            works there, add it to the linux/BSD arm in build.rs."
        ),
    }
}

fn cxx_runtime(clang_lib: &str) -> Vec<String> {
    let compiler = cc::Build::new().get_compiler();

    let lib = if compiler.is_like_clang() {
        clang_lib
    } else if compiler.is_like_gnu() {
        "stdc++"
    } else {
        return Vec::new();
    };

    vec![format!("rustc-link-lib=dylib={lib}")]
}

#[derive(PartialEq, Eq, Clone, Copy)]
enum Abi {
    Arm64,
    ArmV7,
    X86_64,
}

impl Abi {
    fn from_env() -> Self {
        match &*env::var("CARGO_CFG_TARGET_ARCH").unwrap() {
            "aarch64" => Self::Arm64,
            "arm" => Self::ArmV7,
            "x86_64" => Self::X86_64,
            arch => panic!("Unsupported Android ABI: {arch}"),
        }
    }

    // Value for `-DANDROID_ABI`.
    fn cmake_name(self) -> &'static str {
        match self {
            Self::Arm64 => "arm64-v8a",
            Self::ArmV7 => "armeabi-v7a",
            Self::X86_64 => "x86_64",
        }
    }

    // NDK sysroot lib directory triple. Differs from the Rust triple for
    // armv7: Rust says `armv7-linux-androideabi`, the NDK says
    // `arm-linux-androideabi`.
    fn ndk_triple(self) -> &'static str {
        match self {
            Self::Arm64 => "aarch64-linux-android",
            Self::ArmV7 => "arm-linux-androideabi",
            Self::X86_64 => "x86_64-linux-android",
        }
    }
}

struct Android {
    ndk: PathBuf,
    abi: Abi,
    api_level: u32,
}

impl Android {
    fn from_env() -> Self {
        let ndk = env::var("ANDROID_NDK_HOME")
            .map(PathBuf::from)
            .expect("Android target detected but ANDROID_NDK_HOME is not set");

        // API level 24+ is required because Bitcoin Core uses getifaddrs,
        // which was introduced in Android API 24 (Nougat).
        let api_level = match env::var("ANDROID_API_LEVEL") {
            Ok(level) => {
                let n: u32 = level.parse().expect("ANDROID_API_LEVEL must be a number");
                assert!(
                    n >= MIN_ANDROID_API,
                    "ANDROID_API_LEVEL must be {MIN_ANDROID_API}+"
                );
                n
            }
            Err(_) => MIN_ANDROID_API,
        };

        Self {
            ndk,
            abi: Abi::from_env(),
            api_level,
        }
    }

    fn toolchain_file(&self) -> PathBuf {
        self.ndk
            .join("build")
            .join("cmake")
            .join("android.toolchain.cmake")
    }

    fn sysroot_lib_dir(&self) -> PathBuf {
        let host_tag = match env::consts::OS {
            "macos" => "darwin-x86_64",
            "linux" => "linux-x86_64",
            os => panic!("unsupported build host for Android cross-compilation: {os}"),
        };

        self.ndk
            .join("toolchains/llvm/prebuilt")
            .join(host_tag)
            .join("sysroot/usr/lib")
            .join(self.abi.ndk_triple())
    }

    fn config(&self) -> TargetConfig {
        let cmake_args = vec![
            format!("-DCMAKE_TOOLCHAIN_FILE={}", self.toolchain_file().display()),
            format!("-DANDROID_ABI={}", self.abi.cmake_name()),
            format!("-DANDROID_PLATFORM=android-{}", self.api_level),
            "-DCMAKE_SYSTEM_NAME=Android".into(),
            format!("-DCMAKE_ANDROID_NDK={}", self.ndk.display()),
            // The NDK toolchain sets CMAKE_FIND_ROOT_PATH_MODE_PACKAGE to ONLY,
            // which prevents cmake from finding host packages via
            // CMAKE_PREFIX_PATH. Relax it for headers so Boost can be located.
            "-DCMAKE_FIND_ROOT_PATH_MODE_PACKAGE=BOTH".into(),
        ];

        // The NDK ships libc++_static.a and libc++abi.a in the per-architecture
        // sysroot directory, not the API-level subdirectory.
        let mut link_directives = vec![
            format!(
                "rustc-link-search=native={}",
                self.sysroot_lib_dir().display()
            ),
            "rustc-link-lib=static=c++_static".into(),
            "rustc-link-lib=static=c++abi".into(),
        ];

        // The pre-compiled libcompiler_builtins for armv7-linux-androideabi ships
        // ARM EABI helper symbols tagged with @@LIBC_N (e.g. __aeabi_memcpy@@LIBC_N).
        // lld errors when linking a shared library or executable because the LIBC_N
        // version node is not defined in any version script. --exclude-libs,ALL
        // marks every symbol pulled from static archives as local, suppressing it.
        if self.abi == Abi::ArmV7 {
            link_directives.push("rustc-link-arg=-Wl,--exclude-libs,ALL".into());
        }

        TargetConfig {
            cmake_args,
            link_directives,
            rerun_env: &["ANDROID_NDK_HOME", "ANDROID_API_LEVEL"],
        }
    }
}

struct Cmake {
    source_dir: PathBuf,
    build_dir: PathBuf,
    install_dir: PathBuf,
}

impl Cmake {
    fn new(source_dir: impl Into<PathBuf>, out_dir: &Path) -> Self {
        Self {
            source_dir: source_dir.into(),
            build_dir: out_dir.join("bitcoin"),
            install_dir: out_dir.join("install"),
        }
    }

    fn configure(&self, extra_args: &[String]) {
        let mut flags = vec![format!("-DCMAKE_BUILD_TYPE={BUILD_CONFIG}")];
        flags.extend(BASE_CMAKE_FLAGS.iter().map(|s| s.to_string()));
        flags.extend_from_slice(extra_args);
        flags.push(format!(
            "-DCMAKE_INSTALL_PREFIX={}",
            self.install_dir.display()
        ));
        run(
            Command::new("cmake")
                .arg("-B")
                .arg(&self.build_dir)
                .arg("-S")
                .arg(&self.source_dir)
                .args(flags),
            "cmake configure",
        );
    }

    fn build(&self) {
        let num_jobs = env::var("NUM_JOBS")
            .ok()
            .and_then(|v| v.parse::<u32>().ok())
            .unwrap_or_else(|| {
                std::thread::available_parallelism()
                    .map(|n| n.get() as u32)
                    .unwrap_or(1) // Default to 1 if not set
            });

        run(
            Command::new("cmake")
                .arg("--build")
                .arg(&self.build_dir)
                .arg("--config")
                .arg(BUILD_CONFIG)
                .arg(format!("--parallel={num_jobs}")),
            "cmake build",
        );
    }

    fn install(&self) {
        run(
            Command::new("cmake")
                .arg("--install")
                .arg(&self.build_dir)
                .arg("--config")
                .arg(BUILD_CONFIG),
            "cmake install",
        );
    }

    // Multi-config generators (MSVC, Xcode) nest the config name under `lib/`.
    fn lib_dir(&self) -> PathBuf {
        let multi_config = self.install_dir.join("lib").join(BUILD_CONFIG);

        if multi_config.exists() {
            multi_config
        } else {
            self.install_dir.join("lib")
        }
    }
}

fn run(cmd: &mut Command, what: &str) {
    let status = cmd
        .status()
        .unwrap_or_else(|e| panic!("failed to spawn {what}: {e}"));

    assert!(status.success(), "{what} failed with {status}");
}
