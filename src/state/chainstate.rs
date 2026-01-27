//! Chainstate manager for validation and chain state management.
//!
//! The [`ChainstateManager`] is the central component for:
//! - Processing and validating blocks
//! - Reading block data from disk
//! - Querying the active chain and block tree
//! - Managing chainstate databases
//!
//! # Example
//! ```no_run
//! # use bitcoinkernel::{Context, ChainType, ChainstateManager, KernelError};
//! #
//! # fn main() -> Result<(), KernelError> {
//!     let context = Context::builder().chain_type(ChainType::Regtest).build()?;
//!
//!     let chainman = ChainstateManager::builder(&context, "./data", "./blocks")?
//!         .chainstate_db_in_memory(true)
//!         .build()?;
//!
//!     chainman.import_blocks()?;
//!
//!     # let block = unimplemented!();
//!     chainman.process_block(&block);
//!
//! #     Ok(())
//! # }

use std::ffi::CString;

use libbitcoinkernel_sys::{
    btck_BlockHash, btck_BlockValidationState, btck_ChainstateManager,
    btck_ChainstateManagerOptions, btck_block_read, btck_block_spent_outputs_read,
    btck_chainstate_manager_create, btck_chainstate_manager_destroy,
    btck_chainstate_manager_get_active_chain, btck_chainstate_manager_get_best_entry,
    btck_chainstate_manager_get_block_tree_entry_by_hash, btck_chainstate_manager_import_blocks,
    btck_chainstate_manager_options_create, btck_chainstate_manager_options_destroy,
    btck_chainstate_manager_options_set_wipe_dbs,
    btck_chainstate_manager_options_set_worker_threads_num,
    btck_chainstate_manager_options_update_block_tree_db_in_memory,
    btck_chainstate_manager_options_update_chainstate_db_in_memory,
    btck_chainstate_manager_process_block, btck_chainstate_manager_process_block_header,
    btck_chainstate_manager_validate_block,
};

use crate::{
    core::block::BlockHeader,
    ffi::{
        c_helpers,
        sealed::{AsPtr, FromMutPtr, FromPtr},
    },
    notifications::types::BlockValidationState,
    Block, BlockHash, BlockSpentOutputs, BlockTreeEntry, KernelError,
};

use super::{Chain, Context};

/// Result of processing a block with the [`ChainstateManager`].
///
/// Indicates whether a block was accepted (but not necessarily valid), rejected,
/// or was already known to the chainstate manager.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessBlockResult {
    /// Block was accepted and is new to the chainstate manager
    NewBlock,
    /// Block was accepted but was already known
    Duplicate,
    /// Block failed validation.
    ///
    /// The block violated one or more consensus rules. See
    /// [`crate::ContextBuilder::with_block_checked_validation`] for retrieving
    /// detailed error information.
    Rejected,
}

/// Result of proceesing a header with the [`ChainstateManager`]
///
/// Indicates whether a block header was processed, or rejected, and whether it is valid.
#[derive(Clone)]
pub enum ProcessBlockHeaderResult {
    /// Header was succssfully processed and added to the block tree
    Success(BlockValidationState),
    /// Header processing failed
    Failed(BlockValidationState),
}

impl ProcessBlockResult {
    /// Returns true if the block was accepted and is new
    pub fn is_new_block(&self) -> bool {
        matches!(self, Self::NewBlock)
    }

    /// Returns true if the block was accepted but was already known
    pub fn is_duplicate(&self) -> bool {
        matches!(self, Self::Duplicate)
    }

    /// Returns true if the block was rejected
    pub fn is_rejected(&self) -> bool {
        matches!(self, Self::Rejected)
    }
}

/// The chainstate manager handles block validation and chain state.
///
/// This is the primary interface for interacting with the chain,
/// providing functionality to process and validate blocks, read block data from
/// disk, and query chain state.
///
/// # Lifetime
/// The chainstate manager holds a reference to the [`Context`] used to create it.
/// It is recommended to keep the context in scope for the lifetime of the
/// chainstate manager.
///
/// # Thread Safety
/// The chainstate manager is `Send` and `Sync`, allowing it to be shared
/// across threads safely.
///
/// # Examples
/// See module-level documentation for usage examples.
pub struct ChainstateManager {
    inner: *mut btck_ChainstateManager,
}

unsafe impl Send for ChainstateManager {}
unsafe impl Sync for ChainstateManager {}

impl ChainstateManager {
    /// Creates a new chainstate manager builder for configuring and constructing a chainstate manager.
    ///
    /// This is the recommended way to create a [`ChainstateManager`], as it provides a fluent
    /// interface for configuring all available options before construction.
    ///
    /// # Arguments
    /// * `context` - The [`Context`] that this chainstate manager will use. It is recommended
    ///   to keep the context in scope for the lifetime of the chainstate manager.
    /// * `data_dir` - The directory path where the chainstate manager will write its data files.
    ///   This directory will be created if it doesn't exist.
    /// * `blocks_dir` - The directory path where block files will be stored.
    ///   This directory will be created if it doesn't exist.
    ///
    /// # Errors
    /// Returns [`KernelError`] if:
    /// - The directory paths contain null bytes
    /// - The underlying C++ library fails to create the builder options
    ///
    /// # Examples
    /// ```no_run
    /// use bitcoinkernel::{Context, ChainType, ChainstateManager};
    ///
    /// # fn main() -> Result<(), bitcoinkernel::KernelError> {
    /// let context = Context::builder().chain_type(ChainType::Regtest).build()?;
    ///
    /// let chainman = ChainstateManager::builder(&context, "./data", "./blocks")?
    ///     .chainstate_db_in_memory(true)
    ///     .worker_threads(4)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    /// - [`ChainstateManagerBuilder`] for available configuration options
    /// - [`new`](Self::new) for a simpler constructor with default options
    pub fn builder(
        context: &Context,
        data_dir: &str,
        blocks_dir: &str,
    ) -> Result<ChainstateManagerBuilder, KernelError> {
        ChainstateManagerBuilder::new(context, data_dir, blocks_dir)
    }

    /// Creates a new chainstate manager with default configuration.
    ///
    /// This is a convenience constructor that creates a chainstate manager with default settings.
    /// For more control over configuration options (such as in-memory databases, worker threads,
    /// or database wiping), use [`builder`](Self::builder) instead.
    ///
    /// # Arguments
    /// * `context` - The [`Context`] that this chainstate manager will use. It is recommended
    ///   to keep the context in scope for the lifetime of the chainstate manager.
    /// * `data_dir` - The directory path where the chainstate manager will write its data files.
    ///   This directory will be created if it doesn't exist.
    /// * `blocks_dir` - The directory path where block files will be stored.
    ///   This directory will be created if it doesn't exist.
    ///
    /// # Errors
    /// Returns [`KernelError`] if:
    /// - The directory paths contain null bytes
    /// - The underlying C++ library fails to create the chainstate manager
    /// - Invalid data directory paths
    /// - Insufficient permissions
    /// - Corrupted database files
    ///
    /// # Examples
    /// ```no_run
    /// use bitcoinkernel::{Context, ChainType, ChainstateManager};
    ///
    /// # fn main() -> Result<(), bitcoinkernel::KernelError> {
    /// let context = Context::builder().chain_type(ChainType::Regtest).build()?;
    /// let chainman = ChainstateManager::new(&context, "./data", "./blocks")?;
    /// # Ok(())
    /// # }
    /// ```
    ///
    /// # See Also
    /// - [`builder`](Self::builder) for configurable construction with additional options
    pub fn new(
        context: &Context,
        data_dir: &str,
        blocks_dir: &str,
    ) -> Result<ChainstateManager, KernelError> {
        ChainstateManagerBuilder::new(context, data_dir, blocks_dir)?.build()
    }

    /// Process and validate a block.
    ///
    /// Attempts to validate and add the block to the block tree. The block goes
    /// through full consensus validation including proof-of-work, transaction
    /// validity, and script verification.
    ///
    /// # Arguments
    /// * `block` - The [`Block`] to process
    ///
    /// # Returns
    /// A [`ProcessBlockResult`] indicating whether the block was:
    /// - Accepted and committed to the block tree ([`ProcessBlockResult::NewBlock`])
    /// - Accepted but already present in the block tree ([`ProcessBlockResult::Duplicate`])
    /// - Rejected due to validation failure ([`ProcessBlockResult::Rejected`])
    ///
    /// # Important Notes
    /// - [`ProcessBlockResult::NewBlock`] indicates the block was newly written to disk,
    ///   **not** that it was added to the active chain. The block may be valid but not
    ///   extend the current best chain.
    /// - To determine full validity and chain status, you **must** register a validation
    ///   interface callback. Use [`ContextBuilder::with_block_checked_validation`](crate::ContextBuilder::with_block_checked_validation)
    ///   or [`ContextBuilder::validation`](crate::ContextBuilder::validation) to receive detailed
    ///   validation state through the block checked callback.
    ///
    /// # Validation Details
    /// The block checked callback receives a [`BlockValidationStateRef`](crate::BlockValidationStateRef)
    /// containing validation results for the block. This callback fires for all validated blocks.
    /// To detect when a block extends the active chain, use [`ContextBuilder::with_block_connected_validation`](crate::ContextBuilder::with_block_connected_validation)
    /// or [`ContextBuilder::validation`](crate::ContextBuilder::validation).
    ///
    /// # Example
    /// ```no_run
    /// # use bitcoinkernel::{Block, ChainstateManager, ProcessBlockResult};
    /// # let chainman: ChainstateManager = unimplemented!();
    /// # let block: Block = unimplemented!();
    /// match chainman.process_block(&block) {
    ///     ProcessBlockResult::NewBlock => println!("Block validated and written to disk"),
    ///     ProcessBlockResult::Duplicate => println!("Block already known (valid)"),
    ///     ProcessBlockResult::Rejected => println!("Block validation failed"),
    /// }
    /// ```
    pub fn process_block(&self, block: &Block) -> ProcessBlockResult {
        let mut new_block: i32 = 0;
        let accepted = unsafe {
            btck_chainstate_manager_process_block(self.inner, block.as_ptr(), &mut new_block)
        };

        let is_accepted = c_helpers::success(accepted);
        let is_new = c_helpers::enabled(new_block);

        match (is_accepted, is_new) {
            (true, true) => ProcessBlockResult::NewBlock,
            (true, false) => ProcessBlockResult::Duplicate,
            (false, _) => ProcessBlockResult::Rejected,
        }
    }

    /// Process and validate a block header.
    ///
    /// Attempts to validate the block header and add it to the block tree. This
    /// verifies its proof of work and connection to another existing header, or
    /// block. `process_block_header` can be used by developers to implement
    /// "headers first sync", where a complete header chain is synchronized first
    /// before synchronizing blocks.
    ///
    /// # Arguments
    /// * `header` - The [`BlockHeader`] to process
    ///
    /// # Returns
    /// A [`ProcessBlockHeaderResult`] indicating whether it was processed successfully and
    /// the header was valid.
    ///
    /// # Important Notes
    /// - Calling this function will allocate internal resources and will eventually
    ///   write to the file system on success. It is up to the implementing developer
    ///   to ensure that headers processed here do indeed build towards a most proof
    ///   of work chain to avoid attackers feeding many low-work header chains in
    ///   order to exhaust system resources. This can be achieved by pre-syncing a
    ///   portion of the header chain outside of the kernel's responsibility up to a
    ///   certain minimum proof of work threshold.
    ///
    /// To detect when a header extends the most proof of work header chain, use
    /// [`ContextBuilder::with_header_tip_notification`](crate::ContextBuilder::with_header_tip_notification),
    /// or [`ContextBuilder::notifications`](crate::ContextBuilder::notifications)
    /// # Example
    /// ```no_run
    /// # use bitcoinkernel::{BlockHeader, ChainstateManager, ProcessBlockHeaderResult};
    /// # let chainman: ChainstateManager = unimplemented!();
    /// # let header: BlockHeader = unimplemented!();
    /// match chainman.process_block_header(&header) {
    ///     ProcessBlockHeaderResult::Success(_) => println!("Block header validated and written to disk"),
    ///     _ => println!("Failed to process header")
    /// }
    /// ```
    pub fn process_block_header(&self, header: &BlockHeader) -> ProcessBlockHeaderResult {
        let state = BlockValidationState::new();
        let processed = unsafe {
            btck_chainstate_manager_process_block_header(
                self.inner,
                header.as_ptr(),
                state.as_ptr() as *mut btck_BlockValidationState,
            )
        };
        if c_helpers::success(processed) {
            ProcessBlockHeaderResult::Success(state)
        } else {
            ProcessBlockHeaderResult::Failed(state)
        }
    }

    /// Returns a pair indicating wether the block was accepted, and whether it is valid.
    /// # Example
    /// ```no_run
    /// # use bitcoinkernel::{BlockSpentOutputs, Block, ChainstateManager};
    /// # let chainman: ChainstateManager = unimplemented!();
    /// # let block: Block = unimplemented!();
    /// # let spent_outputs: BlockSpentOutputs= unimplemented!();
    /// let res = chainman.validate_block(&block, &spent_outputs);
    /// ```
    pub fn validate_block(
        &self,
        block: &Block,
        block_spent_outputs: &BlockSpentOutputs,
    ) -> (bool, BlockValidationState) {
        let state = BlockValidationState::new();
        let accepted = unsafe {
            btck_chainstate_manager_validate_block(
                self.inner,
                block.as_ptr(),
                block_spent_outputs.as_ptr(),
                state.as_ptr() as *mut btck_BlockValidationState,
            )
        };
        (c_helpers::success(accepted), state)
    }

    /// Initialize the chainstate manager and optionally trigger a reindex.
    ///
    /// This should be called after creating the chainstate manager to complete
    /// initialization. If the `wipe_db` option was set, this will trigger a
    /// blockchain reindex.
    ///
    /// # Errors
    /// Returns [`KernelError::Internal`] if initialization fails.

    pub fn import_blocks(&self) -> Result<(), KernelError> {
        let result = unsafe {
            btck_chainstate_manager_import_blocks(
                self.inner,
                std::ptr::null_mut(),
                std::ptr::null_mut(),
                0,
            )
        };
        match c_helpers::success(result) {
            true => Ok(()),
            false => Err(KernelError::Internal(
                "Failed to import blocks.".to_string(),
            )),
        }
    }

    /// Read a block's full data from disk.
    ///
    /// # Arguments
    /// * `entry` - The [`BlockTreeEntry`] identifying which block to read
    ///
    /// # Returns
    /// The complete [`Block`] including all transactions.
    ///
    /// # Errors
    /// Returns [`KernelError::Internal`] if:
    /// - The block file cannot be read
    /// - The block data is corrupted
    /// - The block has been pruned
    pub fn read_block_data(&self, entry: &BlockTreeEntry) -> Result<Block, KernelError> {
        let inner = unsafe { btck_block_read(self.inner, entry.as_ptr()) };
        if inner.is_null() {
            return Err(KernelError::Internal("Failed to read block.".to_string()));
        }
        Ok(unsafe { Block::from_ptr(inner) })
    }

    /// Read a block's spent outputs (undo data) from disk.
    ///
    /// Retrieves the spent outputs associated with a specific block. Spent outputs
    /// contain information about the transaction outputs that were consumed when the
    /// block's transactions were applied to the UTXO set. This data is essential for
    /// rolling back blocks during chain reorganizations.
    ///
    /// # Arguments
    /// * `entry` - The [`BlockTreeEntry`] identifying which block's spent outputs to read
    ///
    /// # Returns
    /// The [`BlockSpentOutputs`] for the specified block, containing the transaction
    /// outputs that were consumed by the block's transactions.
    ///
    /// # Errors
    /// Returns [`KernelError::Internal`] if:
    /// - The undo data file cannot be read
    /// - The undo data is corrupted
    /// - The block has been pruned
    pub fn read_spent_outputs(
        &self,
        entry: &BlockTreeEntry,
    ) -> Result<BlockSpentOutputs, KernelError> {
        let inner = unsafe { btck_block_spent_outputs_read(self.inner, entry.as_ptr()) };
        if inner.is_null() {
            return Err(KernelError::Internal(
                "Failed to read undo data.".to_string(),
            ));
        }
        Ok(unsafe { BlockSpentOutputs::from_ptr(inner) })
    }

    /// Get a reference to the currently active blockchain.
    ///
    /// Returns the active chain, which represents the chain with the most
    /// accumulated proof-of-work. This is the canonical chain used for validation.
    ///
    /// # Returns
    /// A [`Chain`] reference representing the active chain.
    ///
    /// # Lifetime
    /// The returned [`Chain`] reference is tied to the lifetime of the
    /// [`ChainstateManager`] and becomes invalid when the manager is dropped.
    pub fn active_chain(&self) -> Chain<'_> {
        let ptr = unsafe { btck_chainstate_manager_get_active_chain(self.inner) };
        unsafe { Chain::from_ptr(ptr) }
    }

    /// Get the block tree entry with the most known cumulative proof of work.
    ///
    /// This is tracked internally by the ChainstateManager.
    ///
    /// # Returns
    /// * `Some(`[`BlockTreeEntry`]`)` - The entry with the most known cumulative proof of work.
    /// * `None` - No best entry exists. This should never occur outside, but is left as a defensive measure.
    ///
    /// # Lifetime
    /// The returned [`BlockTreeEntry`] reference is tied to the lifetime of the
    /// [`ChainstateManager`] and becomes invalid when the manager is dropped.
    pub fn best_entry(&self) -> Option<BlockTreeEntry<'_>> {
        let ptr = unsafe { btck_chainstate_manager_get_best_entry(self.inner) };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { BlockTreeEntry::from_ptr(ptr) })
        }
    }

    /// Get a block tree entry by its block hash.
    ///
    /// Looks up a block in the block tree using its hash. The block tree contains
    /// metadata about all known blocks, including those not on the active chain.
    ///
    /// # Arguments
    /// * `block_hash` - The [`BlockHash`] of the block to look up
    ///
    /// # Returns
    /// * `Some(`[`BlockTreeEntry`]`)` - If a block with the given hash exists in the block tree
    /// * `None` - If no block with the given hash is found
    ///
    /// # Lifetime
    /// The returned [`BlockTreeEntry`] reference is tied to the lifetime of the
    /// [`ChainstateManager`] and becomes invalid when the manager is dropped.
    pub fn get_block_tree_entry(&self, block_hash: &BlockHash) -> Option<BlockTreeEntry<'_>> {
        let ptr = unsafe {
            btck_chainstate_manager_get_block_tree_entry_by_hash(
                self.inner,
                block_hash as *const _ as *const btck_BlockHash,
            )
        };
        if ptr.is_null() {
            None
        } else {
            Some(unsafe { BlockTreeEntry::from_ptr(ptr) })
        }
    }
}

impl Drop for ChainstateManager {
    fn drop(&mut self) {
        unsafe {
            btck_chainstate_manager_destroy(self.inner);
        }
    }
}

/// Builder for configuring and creating a [`ChainstateManager`].
///
/// Provides a fluent interface for configuring how the chainstate manager
/// will initialize and operate. Options control database locations, in-memory
/// operation, worker thread allocation, and database initialization behavior.
///
/// # Usage
/// Create a builder using [`ChainstateManager::builder`], configure options
/// by chaining method calls, then call [`build`](Self::build) to create the
/// chainstate manager.
///
/// # Example
/// ```no_run
/// use bitcoinkernel::{ChainType, ChainstateManager, ContextBuilder, KernelError};
///
/// # fn main() -> Result<(), KernelError> {
/// let context = ContextBuilder::new()
///     .chain_type(ChainType::Regtest)
///     .build()?;
///
/// let chainman = ChainstateManager::builder(&context, "/data", "/blocks")?
///     .worker_threads(4)
///     .chainstate_db_in_memory(true)
///     .block_tree_db_in_memory(true)
///     .build()?;
/// # Ok(())
/// # }
/// ```
pub struct ChainstateManagerBuilder {
    inner: *mut btck_ChainstateManagerOptions,
}

impl ChainstateManagerBuilder {
    /// Creates a new chainstate manager builder.
    ///
    /// This is typically called via [`ChainstateManager::builder`] rather than directly.
    ///
    /// # Arguments
    /// * `context` - The [`Context`] that configures chain parameters and
    ///   notification callbacks. It is recommended to keep the context in scope
    ///   for the lifetime of the [`ChainstateManager`].
    /// * `data_dir` - Path to the directory where chainstate data will be stored.
    ///   This includes the UTXO set database and other chain state information.
    /// * `blocks_dir` - Path to the directory where block data will be stored.
    ///   This includes the raw block files and the block index database.
    ///
    /// # Errors
    /// Returns [`KernelError`] if:
    /// - The paths contain null bytes (invalid C strings)
    /// - The underlying C++ library fails to create the builder
    pub fn new(context: &Context, data_dir: &str, blocks_dir: &str) -> Result<Self, KernelError> {
        let c_data_dir = CString::new(data_dir)?;
        let c_blocks_dir = CString::new(blocks_dir)?;
        let inner = unsafe {
            btck_chainstate_manager_options_create(
                context.as_ptr(),
                c_data_dir.as_ptr(),
                c_data_dir.as_bytes().len(),
                c_blocks_dir.as_ptr(),
                c_blocks_dir.as_bytes().len(),
            )
        };
        if inner.is_null() {
            return Err(KernelError::Internal(
                "Failed to create chainstate manager options.".to_string(),
            ));
        }
        Ok(Self { inner })
    }

    /// Sets the number of worker threads for validation.
    ///
    /// Block validation can be parallelized across multiple threads to improve
    /// performance. More threads generally result in faster validation, but with
    /// diminishing returns beyond the number of available CPU cores.
    ///
    /// # Arguments
    /// * `worker_threads` - Number of worker threads to use for validation.
    ///   Valid range is 0-15 (values outside this range are clamped). When set to 0,
    ///   no parallel verification is performed.
    pub fn worker_threads(self, worker_threads: i32) -> Self {
        unsafe {
            btck_chainstate_manager_options_set_worker_threads_num(self.inner, worker_threads);
        }
        self
    }

    /// Configures database wiping behavior.
    ///
    /// When enabled, this will delete and recreate the specified databases on
    /// initialization. After wiping, [`ChainstateManager::import_blocks`] will
    /// trigger a reindex to rebuild the databases from the block files.
    ///
    /// # Arguments
    /// * `wipe_block_tree` - If true, wipe the block tree database (block index).
    ///   Must be false if `wipe_chainstate` is false.
    /// * `wipe_chainstate` - If true, wipe the chainstate database (UTXO set)
    ///
    /// # Reindex Behavior
    /// - Wiping both databases triggers a full reindex
    /// - Wiping only the chainstate triggers a chainstate-only reindex
    ///
    /// # Errors
    /// Returns [`KernelError::InvalidOptions`] if `wipe_block_tree` is true but
    /// `wipe_chainstate` is false, as this combination is currently unsupported.
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::{ChainType, ChainstateManager, ContextBuilder, KernelError};
    /// # fn main() -> Result<(), KernelError> {
    /// # let context = ContextBuilder::new().chain_type(ChainType::Regtest).build()?;
    /// // Wipe both databases for a full reindex
    /// let chainman = ChainstateManager::builder(&context, "/data", "/blocks")?
    ///     .wipe_db(true, true)?
    ///     .build()?;
    ///
    /// // Only wipe chainstate (e.g., to rebuild UTXO set)
    /// let chainman = ChainstateManager::builder(&context, "/data", "/blocks")?
    ///     .wipe_db(false, true)?
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn wipe_db(
        self,
        wipe_block_tree: bool,
        wipe_chainstate: bool,
    ) -> Result<Self, KernelError> {
        let result = unsafe {
            btck_chainstate_manager_options_set_wipe_dbs(
                self.inner,
                c_helpers::to_c_bool(wipe_block_tree),
                c_helpers::to_c_bool(wipe_chainstate),
            )
        };
        if c_helpers::success(result) {
            Ok(self)
        } else {
            Err(KernelError::InvalidOptions(
                "Wiping the block tree without also wiping the chainstate is currently unsupported"
                    .to_string(),
            ))
        }
    }

    /// Configures the block tree database to run entirely in memory.
    ///
    /// When enabled, the block tree database (which stores the block index and
    /// metadata about all known blocks) will be stored in RAM rather than on disk.
    /// This can improve performance but requires sufficient memory and means the
    /// database will be lost when the process exits.
    ///
    /// # Arguments
    /// * `block_tree_db_in_memory` - If true, run the block tree database in memory
    pub fn block_tree_db_in_memory(self, block_tree_db_in_memory: bool) -> Self {
        unsafe {
            btck_chainstate_manager_options_update_block_tree_db_in_memory(
                self.inner,
                c_helpers::to_c_bool(block_tree_db_in_memory),
            );
        }
        self
    }

    /// Configures the chainstate database to run entirely in memory.
    ///
    /// When enabled, the chainstate database (which stores the current UTXO set)
    /// will be stored in RAM rather than on disk. This can significantly improve
    /// performance but requires substantial memory (several gigabytes for mainnet)
    /// and means the database will be lost when the process exits.
    ///
    /// # Arguments
    /// * `chainstate_db_in_memory` - If true, run the chainstate database in memory
    ///
    /// # Example
    /// ```no_run
    /// # use bitcoinkernel::{ChainType, ChainstateManager, ContextBuilder, KernelError};
    /// # fn main() -> Result<(), KernelError> {
    /// # let context = ContextBuilder::new().chain_type(ChainType::Regtest).build()?;
    /// // Use in-memory chainstate for fast testing
    /// let chainman = ChainstateManager::builder(&context, "/data", "/blocks")?
    ///     .chainstate_db_in_memory(true)
    ///     .build()?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn chainstate_db_in_memory(self, chainstate_db_in_memory: bool) -> Self {
        unsafe {
            btck_chainstate_manager_options_update_chainstate_db_in_memory(
                self.inner,
                c_helpers::to_c_bool(chainstate_db_in_memory),
            );
        }
        self
    }

    /// Builds the [`ChainstateManager`] with the configured options.
    ///
    /// Consumes the builder and creates a new chainstate manager instance.
    ///
    /// # Errors
    /// Returns [`KernelError::Internal`] if the underlying C++ library fails
    /// to create the chainstate manager.
    pub fn build(self) -> Result<ChainstateManager, KernelError> {
        let inner = unsafe { btck_chainstate_manager_create(self.inner) };
        if inner.is_null() {
            return Err(KernelError::Internal(
                "Failed to create chainstate manager.".to_string(),
            ));
        }
        Ok(ChainstateManager { inner })
    }
}

impl Drop for ChainstateManagerBuilder {
    fn drop(&mut self) {
        unsafe {
            btck_chainstate_manager_options_destroy(self.inner);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ChainType, ContextBuilder};
    use tempdir::TempDir;

    fn create_test_context() -> Context {
        ContextBuilder::new()
            .chain_type(ChainType::Regtest)
            .build()
            .unwrap()
    }

    fn create_test_dirs() -> (TempDir, String, String) {
        let temp_dir = TempDir::new("test_chainman").unwrap();
        let data_dir = temp_dir.path().to_str().unwrap().to_string();
        let blocks_dir = format!("{}/blocks", data_dir);
        (temp_dir, data_dir, blocks_dir)
    }

    #[test]
    fn test_chainstate_manager_options_new() {
        let context = create_test_context();
        let (_temp_dir, data_dir, blocks_dir) = create_test_dirs();

        let builder = ChainstateManagerBuilder::new(&context, &data_dir, &blocks_dir);
        assert!(builder.is_ok());
    }

    #[test]
    fn test_chainstate_manager_options_invalid_path() {
        let context = create_test_context();

        let invalid_path = "test\0path";
        let blocks_dir = "blocks";

        let builder = ChainstateManagerBuilder::new(&context, invalid_path, blocks_dir);
        assert!(builder.is_err());
    }

    #[test]
    fn test_wipe_block_tree_without_chainstate_fails() {
        let context = create_test_context();
        let (_temp_dir, data_dir, blocks_dir) = create_test_dirs();

        let result = ChainstateManagerBuilder::new(&context, &data_dir, &blocks_dir)
            .unwrap()
            .wipe_db(true, false);

        assert!(result.is_err());
        if let Err(e) = result {
            assert!(matches!(e, KernelError::InvalidOptions(_)));
        }
    }

    #[test]
    fn test_chainstate_manager_creation() {
        let context = create_test_context();
        let (_temp_dir, data_dir, blocks_dir) = create_test_dirs();

        let chainman = ChainstateManagerBuilder::new(&context, &data_dir, &blocks_dir)
            .unwrap()
            .block_tree_db_in_memory(true)
            .chainstate_db_in_memory(true)
            .wipe_db(false, true)
            .unwrap()
            .worker_threads(4)
            .build();

        assert!(chainman.is_ok());
    }

    #[test]
    fn test_process_block_result_new_block() {
        let result = ProcessBlockResult::NewBlock;

        assert_eq!(result, ProcessBlockResult::NewBlock);
        assert!(result.is_new_block());
        assert!(!result.is_duplicate());
        assert!(!result.is_rejected());
    }

    #[test]
    fn test_process_block_result_duplicate() {
        let result = ProcessBlockResult::Duplicate;

        assert_eq!(result, ProcessBlockResult::Duplicate);
        assert!(!result.is_new_block());
        assert!(result.is_duplicate());
        assert!(!result.is_rejected());
    }

    #[test]
    fn test_process_block_result_rejected() {
        let result = ProcessBlockResult::Rejected;

        assert_eq!(result, ProcessBlockResult::Rejected);
        assert!(!result.is_new_block());
        assert!(!result.is_duplicate());
        assert!(result.is_rejected());
    }

    #[test]
    fn test_process_block_result_match() {
        let result = ProcessBlockResult::NewBlock;

        let message = match result {
            ProcessBlockResult::NewBlock => "new",
            ProcessBlockResult::Duplicate => "duplicate",
            ProcessBlockResult::Rejected => "rejected",
        };

        assert_eq!(message, "new");
    }

    #[test]
    fn test_process_block_result_equality() {
        assert_eq!(ProcessBlockResult::NewBlock, ProcessBlockResult::NewBlock);
        assert_ne!(ProcessBlockResult::NewBlock, ProcessBlockResult::Rejected);
        assert_ne!(ProcessBlockResult::Duplicate, ProcessBlockResult::Rejected);
    }

    #[test]
    fn test_process_block_result_debug() {
        let result = ProcessBlockResult::NewBlock;
        let debug_str = format!("{:?}", result);
        assert_eq!(debug_str, "NewBlock");
    }
}
