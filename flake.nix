{
  description = "rust-bitcoinkernel";

  inputs = {
    nixpkgs.url = "nixpkgs/nixos-26.05";
    flake-utils.url = "github:numtide/flake-utils";
    fenix = {
      url = "github:nix-community/fenix";
      inputs.nixpkgs.follows = "nixpkgs";
    };
  };

  outputs =
    {
      self,
      nixpkgs,
      flake-utils,
      fenix,
    }:
    flake-utils.lib.eachDefaultSystem (
      system:
      let
        pkgs = import nixpkgs {
          inherit system;
        };

        rustVersion = "1.71.0";
        rustToolchainSha256 = "sha256-ks0nMEGGXKrHnfv4Fku+vhQ7gx76ruv6Ij4fKZR3l78=";
        rustToolchain = fenix.packages.${system}.fromToolchainName {
          name = rustVersion;
          sha256 = rustToolchainSha256;
        };
        rustBuildToolchain = fenix.packages.${system}.combine [
          rustToolchain.rustc
          rustToolchain.cargo
          rustToolchain.rust-src
          rustToolchain.rust-std
        ];

        rustBuildToolchainNightly = fenix.packages.${system}.latest.toolchain;

        rustPlatformNightly = pkgs.makeRustPlatform {
          cargo = rustBuildToolchainNightly;
          rustc = rustBuildToolchainNightly;
        };
        rustfilt = rustPlatformNightly.buildRustPackage rec {
          pname = "rustfilt";
          version = "0.2.1";
          src = pkgs.fetchFromGitHub {
            owner = "luser";
            repo = "rustfilt";
            rev = version;
            hash = "sha256-zb1tkeWmeMq7aM8hWssS/UpvGzGbfsaVYCOKBnAKwiQ=";
          };
          cargoLock.lockFile = "${src}/Cargo.lock";
        };
      in
      {
        devShells.default = pkgs.mkShell {
          packages = [
            rustBuildToolchain

            pkgs.cmake
            pkgs.boost.dev
            pkgs.cargo-fuzz
          ];

          LIBCLANG_PATH = "${pkgs.llvmPackages.clang-unwrapped.lib}/lib/";
        };

        devShells.nightly = pkgs.mkShell {
          packages = [
            rustBuildToolchainNightly

            pkgs.cmake
            pkgs.boost.dev
            pkgs.cargo-fuzz

            pkgs.libllvm
            pkgs.cargo-llvm-cov
            rustfilt
          ];

          LIBCLANG_PATH = "${pkgs.llvmPackages.clang-unwrapped.lib}/lib/";
          LD_LIBRARY_PATH = pkgs.lib.makeLibraryPath [
            pkgs.gcc.cc.lib
          ];
        };

        packages =
          # Android build infrastructure (unfree NDK + SDK).
          let
            ndkVersion = "28.2.13676358"; # which NDK release to download
            lockfile = ./Cargo-minimal.lock;
            ANDROID_API_LEVEL = "24";
            crateVersion =
              (builtins.fromTOML (builtins.readFile ./libbitcoinkernel-sys/Cargo.toml)).package.version;

            androidPkgs = import nixpkgs {
              inherit system;
              config.android_sdk.accept_license = true;
              config.allowUnfree = true;
            };
            androidComposition = androidPkgs.androidenv.composeAndroidPackages {
              # platformVersions is the SDK tooling version, not the minimum API level.
              # The NDK target floor is set via ANDROID_API_LEVEL in build.rs (default 24).
              platformVersions = [ "34" ];
              ndkVersions = [ ndkVersion ];
              includeNDK = true;
            };
            androidSdk = androidComposition.androidsdk;
            androidNdk = "${androidSdk}/libexec/android-sdk/ndk/${ndkVersion}";

            runTests = system == "x86_64-linux";

            # x86_64-linux-android is excluded from tests: Rust 1.71's
            # compiler_builtins lacks the f128 routines (__eqtf2, __multf3, …)
            # that bionic's static libc.a requires on x86_64.
            #
            # See #198
            testableTargets = [
              "aarch64-linux-android"
              "armv7-linux-androideabi"
            ];

            mkAndroidPackage =
              rustTarget:
              let
                canTest = runTests && builtins.elem rustTarget testableTargets;
                rustTargetToolchain = fenix.packages.${system}.combine [
                  rustToolchain.rustc
                  rustToolchain.cargo
                  rustToolchain.rust-src
                  rustToolchain.rust-std
                  (fenix.packages.${system}.targets.${rustTarget}.fromToolchainName {
                    name = rustVersion;
                    sha256 = rustToolchainSha256;
                  }).rust-std
                ];
                rustPlatform = androidPkgs.makeRustPlatform {
                  cargo = rustTargetToolchain;
                  rustc = rustTargetToolchain;
                };
                qemuBin =
                  if builtins.match "aarch64.*" rustTarget != null then
                    "qemu-aarch64"
                  else if builtins.match "armv7.*" rustTarget != null then
                    "qemu-arm"
                  else
                    throw "Unsupported Android target: ${rustTarget}";
                # NDK clang wrapper triple: armv7 uses "armv7a-linux-androideabi",
                # all others match the Rust target triple.
                ndkClangTriple =
                  if builtins.match "armv7.*" rustTarget != null then "armv7a-linux-androideabi" else rustTarget;
                ndkLinker = "${androidNdk}/toolchains/llvm/prebuilt/linux-x86_64/bin/${ndkClangTriple}${ANDROID_API_LEVEL}-clang";
                cargoTargetPrefix = "CARGO_TARGET_${
                  builtins.replaceStrings [ "-" ] [ "_" ] (pkgs.lib.toUpper rustTarget)
                }";
                cargoRunnerEnvVar = "${cargoTargetPrefix}_RUNNER";
                cargoLinkerEnvVar = "${cargoTargetPrefix}_LINKER";
              in
              rustPlatform.buildRustPackage {
                pname = "libbitcoinkernel-${rustTarget}";
                version = crateVersion;
                src = ./.;
                cargoLock.lockFile = lockfile;
                postPatch = ''
                  cp ${lockfile} Cargo.lock
                '';
                nativeBuildInputs = [
                  androidPkgs.cmake
                  androidPkgs.boost.dev
                  androidSdk
                ]
                ++ pkgs.lib.optionals canTest [
                  pkgs.qemu
                ];

                ANDROID_HOME = "${androidSdk}/libexec/android-sdk";
                ANDROID_NDK_HOME = androidNdk;
                CMAKE_PREFIX_PATH = "${androidPkgs.boost.dev}";

                # cargoBuildHook hardcodes the host --target at
                # derivation time, so we bypass it for cross builds.
                dontCargoBuild = true;
                doCheck = canTest;
                buildPhase = ''
                  cargo build -p libbitcoinkernel-sys --target ${rustTarget} --offline --release
                '';
                checkPhase = pkgs.lib.optionalString canTest ''
                  export ${cargoLinkerEnvVar}=${ndkLinker}
                  export ${cargoRunnerEnvVar}=${pkgs.qemu}/bin/${qemuBin}
                  export QEMU_LD_PREFIX=${androidNdk}/toolchains/llvm/prebuilt/linux-x86_64/sysroot
                  export RUSTFLAGS="-C target-feature=+crt-static"
                  cargo test --target ${rustTarget} --offline --release --verbose
                '';
                installPhase = ''
                  mkdir -p $out/lib $out/include
                  find target/${rustTarget}/release -path "*/out/install/lib/*.a" \
                    -exec cp {} $out/lib/ \;
                  find target/${rustTarget}/release -path "*/out/install/include/*" \
                    -exec cp {} $out/include/ \;
                '';
              };
          in
          {
            libbitcoinkernel-android-aarch64 = mkAndroidPackage "aarch64-linux-android";
            libbitcoinkernel-android-armv7 = mkAndroidPackage "armv7-linux-androideabi";
            libbitcoinkernel-android-x86_64 = mkAndroidPackage "x86_64-linux-android";
            # i686 omitted: not a current target
          };
      }
    );
}
