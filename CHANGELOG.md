# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Added `Block::check` to perform context-free validation of a block (size, weight, coinbase, transactions, sigops), with optional proof-of-work and merkle-root checks toggled via the `BLOCK_CHECK_BASE` / `_POW` / `_MERKLE` / `_ALL` flags. Returns a `BlockCheckResult` enum carrying the validation state on failure.
- Implemented `Debug` for `BlockValidationResult`, `BlockValidationStateRef`, `ProcessBlockHeaderresult` and `BlockCheckResult`, enabling inspection via `{:?}` in logs and test output.
- Added `#[must_use]` to `BlockCheckResult` and `ProcessBlockHeaderResult` to warn when validation results are silently ignored.
- Added `ScriptPubkeyExt::as_bytes` to return a zero-copy slice into kernel-managed memory. Unlike `to_bytes`, this does not allocate.
- Added `Transaction::check` for context-free consensus validation of a transaction. Returns `TxCheckResult::Valid` on success or `TxCheckResult::Invalid(TxValidationResult)` on failure.
- Added `TxValidationResult` enum with all transaction validation result variants.
- Added `ChainParams::new_signet` and `ContextBuilder::signet` to configure a custom signet from a user-provided challenge.
- Added a `script_trace` module with `set_script_trace_callback`/`unset_script_trace_callback` for registering a global `ScriptTracer` (or closure) that receives per-opcode `ScriptTraceFrame`s during script execution. Gated behind the `script-trace` feature.
- Added `ScriptTraceFrame`, `ScriptTraceFrameKind`, and `SigVersion` types.
- Added `KernelError::ScriptTraceUnavailable`, returned by `set_script_trace_callback` if the kernel wasn't built with `ENABLE_SCRIPT_TRACE`.

### Changed
- The `verify` function's `flags` parameter now uses `ScriptVerificationFlags` instead of `u32`, making the type explicit in the public API.
- `BlockHeader::new` now returns `Err(KernelError::InvalidLength)` when passed a buffer that is not exactly 80 bytes, rather than delegating the check to the underlying library.
- `ChainstateManager::process_block_header` now returns `Result<ProcessBlockHeaderResult, KernelError>` instead of `ProcessBlockHeaderResult` directly. `Err` indicates an internal failure; `Ok(ProcessBlockHeaderResult::Invalid(state)` indicates the header failed validation.
- `ProcessBlockHeaderResult::Success` and `ProcessBlockHeaderResult::Failed` renamed to `ProcessBlockHeaderResult::Valid` and `ProcessBlockHeaderResult::Invalid` respectively. `Valid` no longer carries a `BlockValidationState`.

### Fixed
- `verify` now uses an infallible conversion for the internal `ScriptVerifyStatus`, since an unrecognized status can only indicate a build-time mismatch between the bindings and the vendored `libbitcoinkernel` subtree rather than a runtime condition.

## [0.2.1] 2026-05-20

### Added
- Added `BlockTreeEntry::ancestor` to look up an ancestor block at a given height. Returns `None` if the height is out of range. This operation is O(log N).
- Added `Transaction::locktime()` to retrieve a transaction's `nLockTime` value as a `u32`.
- Added `TxIn::sequence()` to retrieve an input's `nSequence` value as a `u32`.
- Added `TryFrom<&[u8]>` for `BlockHeader` to align with the exisitng `TryFrom<&[u8]>` implementation for `Block`.
- Added `BlockHeaderExt::consensus_encode` to serialize a block header to its Bitcoin wire format, returning a fixed `[u8; 80]` array.
- Added `From<BlockHeader>` and `From<&BlockHeader>` for `[u8; 80]` to align with existing block conversions.

### Dependencies

- The sys crate no longer uses auto-generated bindings from bindgen. This removes some build-time dependencies for this crate.

## [0.2.0] 2026-01-26

### Added
- Added a `PrecomputedTransactionData` struct for holding transaction hashes required for script verification. It may be initialized with and without an array of outputs spent by the transaction. If no outputs are passed, no taproot verification is possible.
- Added a `BlockHeader` struct for holding block header data. This may be used to retrieve block header struct internals, and to process block headers for the purpose of "headers-first" synchronization. Also add a `ChainstateManager` method to process block headers, i.e. validate and add them to its internal block tree data structure.

### Changed
- Updated to latest libbitcoinkernel-sys with btck_PrecomputedTransactionData` changes.
- The `verify` function now takes a `PrecomputedTransactionData` instead of an array of outputs spent by the transaction. The user is now always required to pass this struct to the function. This is done to encourage its use and protect against quadratic hashing costs.

## [0.1.1] - 2025-24-11

### Fixed
- Updated to latest libbitcoinkernel-sys with cmake packaging include fix.
