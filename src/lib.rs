//! # rust-bitcoinkernel
//!
//! Rust bindings for the `libbitcoinkernel` library, providing safe and idiomatic
//! access to Bitcoin's consensus engine and validation logic.
//!
//! ## Overview
//!
//! This crate enables Rust applications to leverage Bitcoin Core's consensus implementation.
//! It provides type-safe wrappers around the C API exposed by `libbitcoinkernel`.
//!
//! ## Key Features
//!
//! - **Block Processing**: Process and validate blocks and block headers against consensus rules
//! - **Script Verification**: Validate transaction scripts
//! - **Chain Queries**: Traverse the chain and read block data
//! - **Event Notifications**: Subscribe to block validation, tip updates, and error events
//! - **Memory Safety**: FFI interactions are wrapped in safe Rust abstractions
//!
//! ## Architecture
//!
//! The crate is organized into several modules:
//!
//! - [`core`]: Core Bitcoin primitives (blocks, transactions, scripts)
//! - [`state`]: Chain state management (chainstate, context, chain parameters)
//! - [`notifications`]: Event callbacks for validation and synchronization events
//! - [`log`]: Logging integration with Bitcoin Core's logging system
//! - [`prelude`]: Commonly used extension traits for ergonomic API access
//!
//! ## Quick Start
//!
//! ### Basic Block Validation
//!
//! ```no_run
//! use bitcoinkernel::{
//!     Block, ContextBuilder, ChainType, ChainstateManager,
//!     KernelError, ProcessBlockResult
//! };
//!
//! // Create a context for mainnet
//! let context = ContextBuilder::new()
//!     .chain_type(ChainType::Mainnet)
//!     .build()?;
//!
//! // Initialize chainstate manager
//! let chainman = ChainstateManager::new(&context, "/path/to/data", "path/to/blocks/")?;
//!
//! // Process a block
//! let block_data = vec![0u8; 100]; // placeholder
//! let block = Block::new(&block_data)?;
//!
//! match chainman.process_block(&block) {
//!     ProcessBlockResult::NewBlock => println!("Block validated and written to disk"),
//!     ProcessBlockResult::Duplicate => println!("Block already known (valid)"),
//!     ProcessBlockResult::Rejected => println!("Block validation failed"),
//! }
//!
//! # Ok::<(), KernelError>(())
//! ```
//!
//! ### Script Verification
//!
//! ```no_run
//! use bitcoinkernel::{prelude::*, PrecomputedTransactionData, Transaction, verify, VERIFY_ALL};
//! let spending_tx_bytes = vec![]; // placeholder
//! let prev_tx_bytes = vec![]; // placeholder
//! let spending_tx = Transaction::new(&spending_tx_bytes).unwrap();
//! let prev_tx = Transaction::new(&prev_tx_bytes).unwrap();
//! let prev_output = prev_tx.output(0).unwrap();
//! let tx_data = PrecomputedTransactionData::new(&spending_tx, &[prev_output]).unwrap();
//!
//! let result = verify(
//!     &prev_output.script_pubkey(),
//!     Some(prev_output.value()),
//!     &spending_tx,
//!     0,
//!     Some(VERIFY_ALL),
//!     &tx_data,
//! );
//!
//! match result {
//!     Ok(()) => println!("Script verification passed"),
//!     Err(e) => println!("Script verification failed: {}", e),
//! }
//! ```
//!
//! ### Event Notifications
//!
//! ```no_run
//! use bitcoinkernel::{
//!     Block, BlockValidationStateRef, ChainType, ContextBuilder, KernelError,
//!     ValidationCallbackRegistry,
//! };
//!
//! let context = ContextBuilder::new()
//!     .chain_type(ChainType::Mainnet)
//!     .notifications(|registry| {
//!         registry.register_progress(|title, percent, _resume| {
//!             println!("{}: {}%", title, percent);
//!         });
//!         registry.register_warning_set(|warning, message| {
//!             eprintln!("Warning: {} - {}", warning, message);
//!         });
//!         registry.register_flush_error(|message| {
//!             eprintln!("Flush error: {}", message);
//!             // Consider tearing down context and terminating operations
//!         });
//!         registry.register_fatal_error(|message| {
//!             eprintln!("FATAL: {}", message);
//!             // Tear down context and terminate all operations
//!             std::process::exit(1);
//!         });
//!     })
//!     .validation(|registry| {
//!         registry.register_block_checked(|block: Block, _state: BlockValidationStateRef<'_>| {
//!             println!("Checked block: {}", block.hash());
//!         });
//!     })
//!     .build()?;
//! # Ok::<(), KernelError>(())
//! ```
//!
//! **Note**: System-level errors are surfaced through [`FatalErrorCallback`] and
//! [`FlushErrorCallback`]. When encountering either error type, it is recommended to
//! tear down the [`Context`] and terminate any running tasks using the [`ChainstateManager`].
//!
//! ### Chain Traversal
//!
//! ```no_run
//! use bitcoinkernel::{ContextBuilder, ChainType, ChainstateManager, KernelError};
//!
//! // Create a context for mainnet
//! let context = ContextBuilder::new()
//!     .chain_type(ChainType::Mainnet)
//!     .build()?;
//!
//! // Initialize chainstate manager
//! let chainman = ChainstateManager::new(&context, "path/to/data", "path/to/blocks")?;
//!
//! chainman.import_blocks()?;
//!
//! // Get the active chain
//! let chain = chainman.active_chain();
//!
//! // Traverse the chain
//! for entry in chain.iter() {
//!     println!("Block hash {} at height {}", entry.block_hash(), entry.height());
//! }
//! # Ok::<(), KernelError>(())
//! ```
//!
//! ## Type System
//!
//! The crate uses owned and borrowed types extensively:
//!
//! - **Owned types** (e.g., `Block`, `Transaction`): Manage C memory lifecycle
//! - **Borrowed types** (e.g., `BlockRef`, `TransactionRef`): Zero-copy views into data
//! - **Extension traits**: Provide ergonomic methods (use `prelude::*` to import)
//!
//! ## Error Handling
//!
//! The crate provides multiple layers of error handling:
//!
//! - **Operation Errors**: Standard [`KernelError`] results for validation failures,
//!   serialization errors, and internal library errors
//! - **System Errors**: Critical failures are reported through notification callbacks:
//!   - [`FatalErrorCallback`]: Unrecoverable system errors requiring immediate shutdown
//!   - [`FlushErrorCallback`]: Disk I/O errors during state persistence
//!
//! When encountering fatal or flush errors through these callbacks, applications should
//! tear down the [`Context`] and terminate any operations using the [`ChainstateManager`].
//!
//! ## Minimum Supported Rust Version (MSRV)
//!
//! This crate requires Rust 1.71.0 or later.
//!
//! ## Examples
//!
//! See the `examples/` directory for complete working examples including:
//!
//! - Silent Payment Scanning

#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]

use std::ffi::NulError;
use std::{fmt, panic};

use crate::core::{ScriptPubkeyExt, TransactionExt, TxOutExt};
use ffi::{
    c_helpers, BTCK_BLOCK_VALIDATION_RESULT_CACHED_INVALID, BTCK_BLOCK_VALIDATION_RESULT_CONSENSUS,
    BTCK_BLOCK_VALIDATION_RESULT_HEADER_LOW_WORK, BTCK_BLOCK_VALIDATION_RESULT_INVALID_HEADER,
    BTCK_BLOCK_VALIDATION_RESULT_INVALID_PREV, BTCK_BLOCK_VALIDATION_RESULT_MISSING_PREV,
    BTCK_BLOCK_VALIDATION_RESULT_MUTATED, BTCK_BLOCK_VALIDATION_RESULT_TIME_FUTURE,
    BTCK_BLOCK_VALIDATION_RESULT_UNSET, BTCK_CHAIN_TYPE_MAINNET, BTCK_CHAIN_TYPE_REGTEST,
    BTCK_CHAIN_TYPE_SIGNET, BTCK_CHAIN_TYPE_TESTNET, BTCK_CHAIN_TYPE_TESTNET_4,
    BTCK_SYNCHRONIZATION_STATE_INIT_DOWNLOAD, BTCK_SYNCHRONIZATION_STATE_INIT_REINDEX,
    BTCK_SYNCHRONIZATION_STATE_POST_INIT, BTCK_VALIDATION_MODE_INTERNAL_ERROR,
    BTCK_VALIDATION_MODE_INVALID, BTCK_VALIDATION_MODE_VALID,
    BTCK_WARNING_LARGE_WORK_INVALID_CHAIN, BTCK_WARNING_UNKNOWN_NEW_RULES_ACTIVATED,
};
use libbitcoinkernel_sys::*;

pub mod core;
pub mod ffi;
pub mod log;
pub mod notifications;
pub mod state;

/// Serializes data using a C callback function pattern.
///
/// Takes a C function that writes data via a callback and returns the
/// serialized bytes as a `Vec<u8>`.
fn c_serialize<F>(c_function: F) -> Result<Vec<u8>, KernelError>
where
    F: FnOnce(
        unsafe extern "C" fn(*const std::ffi::c_void, usize, *mut std::ffi::c_void) -> i32,
        *mut std::ffi::c_void,
    ) -> i32,
{
    let mut buffer = Vec::new();

    unsafe extern "C" fn write_callback(
        data: *const std::ffi::c_void,
        len: usize,
        user_data: *mut std::ffi::c_void,
    ) -> i32 {
        panic::catch_unwind(|| {
            let buffer = &mut *(user_data as *mut Vec<u8>);
            let slice = std::slice::from_raw_parts(data as *const u8, len);
            buffer.extend_from_slice(slice);
            c_helpers::to_c_result(true)
        })
        .unwrap_or_else(|_| c_helpers::to_c_result(false))
    }

    let result = c_function(
        write_callback,
        &mut buffer as *mut Vec<u8> as *mut std::ffi::c_void,
    );

    if c_helpers::success(result) {
        Ok(buffer)
    } else {
        Err(KernelError::SerializationFailed)
    }
}

/// A collection of errors emitted by this library
#[derive(Debug)]
pub enum KernelError {
    Internal(String),
    CStringCreationFailed(String),
    InvalidOptions(String),
    OutOfBounds,
    ScriptVerify(ScriptVerifyError),
    SerializationFailed,
    MismatchedOutputsSize,
    InvalidLength { expected: usize, actual: usize },
}

impl From<NulError> for KernelError {
    fn from(err: NulError) -> Self {
        KernelError::CStringCreationFailed(err.to_string())
    }
}

impl fmt::Display for KernelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            KernelError::Internal(msg) => write!(f, "Internal error: {}", msg),
            KernelError::CStringCreationFailed(msg) => {
                write!(f, "C string creation failed: {}", msg)
            }
            KernelError::InvalidOptions(msg) => write!(f, "Invalid options: {}", msg),
            KernelError::OutOfBounds => write!(f, "Out of bounds"),
            KernelError::ScriptVerify(err) => write!(f, "Script verification error: {}", err),
            KernelError::SerializationFailed => write!(f, "Serialization failed"),
            KernelError::MismatchedOutputsSize => write!(f, "Number of outputs size does not correspond to the number of inputs of the transaction."),
            KernelError::InvalidLength { expected, actual } => {
                write!(f, "Invalid length: expected {}, got {}", expected, actual)
            }
        }
    }
}

impl std::error::Error for KernelError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            KernelError::ScriptVerify(err) => Some(err),
            _ => None,
        }
    }
}

pub use crate::core::{
    verify, Block, BlockHash, BlockHeader, BlockSpentOutputs, BlockSpentOutputsRef, BlockTreeEntry,
    Coin, CoinRef, PrecomputedTransactionData, ScriptPubkey, ScriptPubkeyRef, ScriptVerifyError,
    Transaction, TransactionRef, TransactionSpentOutputs, TransactionSpentOutputsRef, TxIn,
    TxInRef, TxOut, TxOutPoint, TxOutPointRef, TxOutRef, Txid, TxidRef,
};

pub use crate::log::{disable_logging, Log, LogCategory, LogLevel, Logger};

pub use crate::notifications::{
    BlockCheckedCallback, BlockTipCallback, BlockValidationResult, BlockValidationStateRef,
    FatalErrorCallback, FlushErrorCallback, HeaderTipCallback, NotificationCallbackRegistry,
    ProgressCallback, SynchronizationState, ValidationCallbackRegistry, ValidationMode, Warning,
    WarningSetCallback, WarningUnsetCallback,
};

pub use crate::state::{
    Chain, ChainParams, ChainType, ChainstateManager, ChainstateManagerBuilder, Context,
    ContextBuilder, ProcessBlockHeaderResult, ProcessBlockResult,
};

#[cfg(feature = "script_debug")]
pub use crate::core::script_debug::{ScriptDebugFrame, ScriptDebugger};

pub use crate::core::verify_flags::{
    VERIFY_ALL, VERIFY_ALL_PRE_TAPROOT, VERIFY_CHECKLOCKTIMEVERIFY, VERIFY_CHECKSEQUENCEVERIFY,
    VERIFY_DERSIG, VERIFY_NONE, VERIFY_NULLDUMMY, VERIFY_P2SH, VERIFY_TAPROOT, VERIFY_WITNESS,
};

pub mod prelude {
    pub use crate::core::{
        BlockHashExt, BlockHeaderExt, BlockSpentOutputsExt, CoinExt, ScriptPubkeyExt,
        TransactionExt, TransactionSpentOutputsExt, TxInExt, TxOutExt, TxOutPointExt, TxidExt,
    };
    pub use crate::notifications::BlockValidationStateExt;
}
