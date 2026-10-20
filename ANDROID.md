# Android Cross-Compilation (manual)

This document describes how to cross-compile `rust-bitcoinkernel` for Android
without Nix. If you can use Nix, prefer the `nix build` outputs described in
the [README](README.md#android-cross-compilation) — they pin the NDK, Rust
toolchains, Boost, and cmake for you.

## Prerequisites

Android NDK (tested with r27.3), cmake, and Boost headers installed on the
host.

Install the Rust target for the architecture you want:

```bash
rustup target add aarch64-linux-android    # 64-bit ARM
rustup target add armv7-linux-androideabi  # 32-bit ARM
rustup target add x86_64-linux-android     # x86_64 emulator
```

## Environment

`ANDROID_NDK_HOME` selects the NDK that the build uses. If you have more than
one NDK installed — Android Studio keeps several — make sure the `PATH` entry
below points at the same one, or cmake and the linker will silently use
different toolchains.

```bash
export ANDROID_NDK_HOME=/path/to/android-ndk

# Detect host platform
NDK_HOST="linux-x86_64"   # or "darwin-x86_64" on macOS

# Put NDK clang and llvm-ar on PATH
export PATH="$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST/bin:$PATH"
```

### Boost

cmake has to find the Boost package, and the NDK compiler has to find the
headers. For a distro-installed Boost, with headers in `/usr/include/boost`,
that takes two steps:

```bash
export CMAKE_PREFIX_PATH=/usr/lib/x86_64-linux-gnu/cmake   # Debian/Ubuntu

ln -sfn /usr/include/boost \
  "$ANDROID_NDK_HOME/toolchains/llvm/prebuilt/$NDK_HOST/sysroot/usr/include/boost"
```

Without `CMAKE_PREFIX_PATH`, cmake fails at configure. Without the symlink,
configure succeeds and the build fails later with
`'boost/multi_index/hashed_index.hpp' file not found`.

If Boost is installed under its own prefix (a source build, or Homebrew on
macOS), pointing `CMAKE_PREFIX_PATH` at that prefix may be enough on its own,
since the headers are then outside the system include directories. If the
build still reports a missing Boost header, add the symlink as well.

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
cargo build --target aarch64-linux-android --release
```

Keep the same cargo profile as the step above — the kernel is built inside
`OUT_DIR`, so switching profiles rebuilds all of Bitcoin Core from scratch.

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
