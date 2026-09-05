# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.3.0] 2026-08-26

### Added
- Added Nix package outputs for Android with bundled NDK r24, Rust toolchains, Boost, and cmake.
- Added `Block::check` to perform context-free validation of a block (size, weight, coinbase, transactions, sigops), with optional proof-of-work and merkle-root checks toggled via the `BLOCK_CHECK_BASE` / `_POW` / `_MERKLE` / `_ALL` flags. Returns a `BlockCheckResult` enum carrying the validation state on failure.
- Implemented `Debug` for `BlockValidationResult`, `BlockValidationStateRef`, `ProcessBlockHeaderResult` and `BlockCheckResult`, enabling inspection via `{:?}` in logs and test output.
- Added `#[must_use]` to `BlockCheckResult` and `ProcessBlockHeaderResult` to warn when validation results are silently ignored.
- Added `ScriptPubkeyExt::as_bytes` to return a zero-copy slice into kernel-managed memory. Unlike `to_bytes`, this does not allocate.
- Added `Transaction::check` for context-free consensus validation of a transaction. Returns `TxCheckResult::Valid` on success or `TxCheckResult::Invalid(TxValidationResult)` on failure.
- Added `TxValidationResult` enum with all transaction validation result variants.
- Added `ChainParams::new_signet` and `ContextBuilder::signet` to configure a custom signet from a user-provided challenge.
- Added `TxIn::witness_stack()` (via `TxInExt`) to retrieve a transaction input's witness stack. Returns a `WitnessStackRef` borrowing from the input.
- Added `WitnessStack` and `WitnessStackRef` types for holding a transaction input's witness stack, along with the shared `WitnessStackExt` trait exposing `len()`, `is_empty()` and `item(index)`. `item` returns the raw bytes of the item at the given index, or `Err(KernelError::OutOfBounds)` if the index is invalid.
- Added `WitnessStackExt::items()` returning a `WitnessStackIter` that yields each witness stack item as an owned `Vec<u8>` in order. Implements `Iterator` and `ExactSizeIterator`.
- Added `TxIn::script_sig()` (via `TxInExt`) to retrieve an input's scriptSig as a serialized `Vec<u8>`. Returns `Err(KernelError::SerializationFailed)` if serialization fails
- Added `TransactionExt::is_coinbase` to check whether a transaction is a coinbase transaction.
- Added `Coin::new` to construct a coin from a transaction output, confirmation height, and coinbase flag, for use with `ChainstateManager::validate_block` when validating a block without the full UTXO set present.
- Added `TxOutPoint::new` to construct a new outpoint from a transaction ID and output index.

### Changed
- The `verify` function's `flags` parameter now uses `ScriptVerificationFlags` instead of `u32`, making the type explicit in the public API.
- `BlockHeader::new` now returns `Err(KernelError::InvalidLength)` when passed a buffer that is not exactly 80 bytes, rather than delegating the check to the underlying library.
- `ChainstateManager::process_block_header` now returns `Result<ProcessBlockHeaderResult, KernelError>` instead of `ProcessBlockHeaderResult` directly. `Err` indicates an internal failure; `Ok(ProcessBlockHeaderResult::Invalid(state))` indicates the header failed validation.
- `ProcessBlockHeaderResult::Success` and `ProcessBlockHeaderResult::Failed` renamed to `ProcessBlockHeaderResult::Valid` and `ProcessBlockHeaderResult::Invalid` respectively. `Valid` no longer carries a `BlockValidationState`.

### Fixed
- `verify` now uses an infallible conversion for the internal `ScriptVerifyStatus`, since an unrecognized status can only indicate a build-time mismatch between the bindings and the vendored `libbitcoinkernel` subtree rather than a runtime condition.
- `ChainstateManager::get_block_tree_entry` now resolves the requested block instead of returning `None` for every input. It passed the address of the `BlockHash` wrapper to the kernel rather than the block hash handle the wrapper owns, so no lookup ever matched an entry in the block tree.
- `TxOutIter::size_hint` returned the transaction's input count instead of its output count, giving an incorrect hint (and an incorrect `ExactSizeIterator::len`).

### Dependencies
- Bumped libbitcoinkernel-sys dependency to 0.4.0

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

## [0.1.1] - 2025-11-24

### Fixed
- Updated to latest libbitcoinkernel-sys with cmake packaging include fix.
