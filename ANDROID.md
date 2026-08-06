# Android Cross-Compilation (manual)

This document describes how to cross-compile `rust-bitcoinkernel` for Android
without Nix. If you can use Nix, prefer the `nix build` outputs described in
the [README](README.md#android-cross-compilation) — they pin the NDK, Rust
toolchains, Boost, and cmake for you.

## Prerequisites

Android NDK (r27+ recommended), cmake, and Boost headers installed on the
host.

Install the Rust target for the architecture you want:

```bash
rustup target add aarch64-linux-android    # 64-bit ARM
rustup target add armv7-linux-androideabi  # 32-bit ARM
rustup target add x86_64-linux-android     # x86_64 emulator
```

## Environment

The NDK toolchain must be on `PATH` so cmake can find the compilers and
`llvm-ar`. Boost headers must be discoverable by cmake — either set
`CMAKE_PREFIX_PATH` or symlink them into the NDK sysroot:

```bash
export ANDROID_NDK_HOME=/path/to/android-ndk

# Detect host platform
NDK_HOST="linux-x86_64"   # or "darwin-x86_64" on macOS

# Put NDK clang and llvm-ar on PATH
export PATH="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST/bin:$PATH"

# Option A: point cmake at your Boost installation
export CMAKE_PREFIX_PATH=/usr/lib/x86_64-linux-gnu/cmake

# Option B: symlink Boost headers into the NDK sysroot
ln -sf /usr/include/boost \
  "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST/sysroot/usr/include/boost"
```

## Building

Build the `-sys` crate (the static `libbitcoinkernel.a`). The NDK cmake
toolchain file handles cross-compiler selection, so no extra `CC` or linker
variables are needed for this step:

```bash
cargo build -p libbitcoinkernel-sys --target aarch64-linux-android --release
```

To build the higher-level `bitcoinkernel` crate or run tests, Cargo needs the
NDK clang as the linker. Set the appropriate `CARGO_TARGET_*_LINKER` variable:

```bash
export CARGO_TARGET_AARCH64_LINUX_ANDROID_LINKER=aarch64-linux-android24-clang
cargo build --target aarch64-linux-android
```

The linker binary names for each target are:

| Target                    | Linker                             |
| ------------------------- | ---------------------------------- |
| `aarch64-linux-android`   | `aarch64-linux-android24-clang`    |
| `armv7-linux-androideabi` | `armv7a-linux-androideabi24-clang` |
| `x86_64-linux-android`    | `x86_64-linux-android24-clang`     |

## API level

Replace `24` in the linker name with a higher API level if needed.
`ANDROID_API_LEVEL` defaults to 24 (Nougat) and can be overridden:

```bash
export ANDROID_API_LEVEL=28
```
