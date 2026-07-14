# rust-bitcoinkernel

`rust-bitcoinkernel` is a wrapper around
[libbitcoinkernel](https://github.com/bitcoin/bitcoin/issues/27587), an experimental C++
library exposing Bitcoin Core's validation engine. It supports both validation
of blocks and transaction outputs as well as reading block data.

## Building

The library statically compiles the Bitcoin Core libbitcoinkernel library as
part of its build system.

Bitcoin Core is vendored as a `git subtree` in this project. The subtree can
be updated, or made to point at a different commit or branch in Bitcoin Core's
history with:

```
git subtree pull --prefix libbitcoinkernel-sys/bitcoin https://github.com/bitcoin/bitcoin master --squash
```

After updating the subtree, you can check for kernel-related commits in the
update using the provided script:

```
./contrib/check_subtree_kernel_commits.sh
```

To build this library, the usual Bitcoin Core build requirements, such as
`cmake` and a working C and C++ compiler are required. An installation of boost
is required as well. Consult the Bitcoin Core documentation for the required
dependencies. Once setup, run:

```bash
cargo b
```

## MSRV (Minimum Supported Rust Version)

The minimum supported Rust version is 1.71. Users on rustc older than
1.77 should build with `--locked` to ensure a compatible dependency
resolution:

```bash
cargo build --locked
```

## Lock files

`Cargo-minimal.lock` and `Cargo-recent.lock` pin dependencies to their minimum
and most recent compatible versions.

To regenerate them run:

```bash
./contrib/update_lock_files.sh
```

## Documentation

You can find detailed information about the library on its
[crates.io](https://crates.io/crates/bitcoinkernel), or access its
documentation directly via
[doc.rs](https://docs.rs/bitcoinkernel/latest/bitcoinkernel/).

## Examples

Examples for the usage of the library can be found in the `examples/` directory
and the `tests`. The `silentpaymentscanner` binary implements a bare-bones
silent payments scanner, and the `scripttrace` binary demonstrates the
`script_trace` feature by printing a per-opcode execution trace while
verifying a transaction.

## Fuzzing

Fuzzing is done with [cargo fuzz](https://github.com/rust-fuzz/cargo-fuzz).

There are currently three supported fuzzing targets: `block_roundtrip`,
`chainman_process_block` and `script_verify`. The `chainman` target touches
the filesystem in `/tmp`. If `/tmp` is not already a tmpfs, the user should
create a tmpfs in `/tmp/rust_kernel_fuzz`.

To get fuzzing run (in this case the `verify` target):

```bash
cargo fuzz run script_verify
```

Sanitizers can be turned on with e.g.

```bash
RUSTFLAGS="-Zsanitizer=address" cargo fuzz run block_roundtrip
```

To get the sanitizer flags working in the libbitcoinkernel Bitcoin Core
library, the easiest way for now is to edit the `libbitcoinkernel-sys/build.rs`
flags.

New fuzzing results may be submitted to the following corpus repository:
https://github.com/alexanderwiederin/qa-assets

### Coverage

Once fuzzed, a coverage report can be generated with (picking the `verify`
target as an example):

```
RUSTFLAGS="-C instrument-coverage" cargo fuzz coverage script_verify
llvm-cov show \
  -format=html \
  -instr-profile=fuzz/coverage/script_verify/coverage.profdata \
  target/x86_64-unknown-linux-gnu/coverage/x86_64-unknown-linux-gnu/release/script_verify \
  -show-line-counts-or-regions \
  -Xdemangler=rustfilt \
  -output-dir=coverage_report \
  -ignore-filename-regex="/rustc"
```

You may have to install the following tooling:

```
rustup component add llvm-tools-preview
cargo install rustfilt
```
