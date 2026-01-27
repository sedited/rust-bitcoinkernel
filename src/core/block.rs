//! Block data structures.
//!
//! This module provides types for working with blocks, block hashes, spent
//! outputs (undo data), coins, and transaction spent outputs.
//!
//! # Core Types
//!
//! - `Block` - A block with header and transactions
//! - `BlockHash` - A 32-byte hash uniquely identifying a block
//! - `BlockSpentOutputs` - Spent outputs (undo data) for all transactions in a block
//! - `TransactionSpentOutputs` - Spent outputs for a single transaction
//! - `Coin` - A UTXO (unspent transaction output) consumed by an input
//!
//! # Common Patterns
//!
//! ## Creating and Working with Blocks
//!
//! Blocks can be created from raw serialized data:
//!
//! ```no_run
//! use bitcoinkernel::{prelude::*, Block};
//!
//! # fn example() -> Result<(), bitcoinkernel::KernelError> {
//! let block_data = vec![0u8; 100]; // placeholder
//! let block = Block::new(&block_data)?;
//!
//! // Get block hash
//! let hash = block.hash();
//! println!("Block hash: {}", hash);
//!
//! // Iterate over transactions
//! for tx in block.transactions() {
//!     println!("Transaction: {}", tx.txid());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Inspecting a block header
//!
//! ```no_run
//!  use bitcoinkernel::{prelude::*, Block};
//!
//! # fn example() -> Result<(), bitcoinkernel::KernelError> {
//! let block_data = vec![0u8; 100]; // placeholder
//! let block = Block::new(&block_data)?;
//!
//! // Get block header's bits
//! let header = block.header();
//! println!("Target nBits: {}", header.bits());
//!
//! # Ok(())
//! # }
//!
//! ```
//!
//! ## Working with Block Hashes
//!
//! Block hashes can be created from byte arrays and inspected as raw bytes
//! or as a hexadecimal string:
//!
//! ```no_run
//! use bitcoinkernel::{prelude::*, BlockHash};
//!
//! # fn example() -> Result<(), bitcoinkernel::KernelError> {
//! let bytes = [42u8; 32];
//! let hash = BlockHash::from(bytes);
//!
//! // Display as hex string (reversed byte order)
//! println!("Hash: {}", hash);
//!
//! // Get raw bytes (internal byte order)
//! let raw_bytes = hash.to_bytes();
//! # Ok(())
//! # }
//! ```
//!
//! ## Examining Spent Outputs
//!
//! ```no_run
//! # use bitcoinkernel::{prelude::*, ChainstateManager, BlockTreeEntry, KernelError};
//! # fn example(chainman: &ChainstateManager, entry: &BlockTreeEntry) -> Result<(), KernelError> {
//! // Read spent outputs (undo data) for a block
//! let spent_outputs = chainman.read_spent_outputs(entry)?;
//!
//! // Iterate through transactions' spent outputs
//! for tx_spent in spent_outputs.iter() {
//!     println!("Transaction has {} spent coins", tx_spent.count());
//!
//!     // Examine each spent coin
//!     for coin in tx_spent.coins() {
//!         println!("Spent output value: {}", coin.output().value());
//!         println!("Created at height: {}", coin.confirmation_height());
//!         println!("Is coinbase: {}", coin.is_coinbase());
//!     }
//! }
//! # Ok(())
//! # }
//! ```
//!
//! # Extension Traits
//!
//! The module defines extension traits that provide common functionality for
//! both owned and borrowed types:
//!
//! - [`BlockHashExt`] - Operations on block hashes
//! - [`BlockHeaderExt`]  - Operations on block headers
//! - [`BlockSpentOutputsExt`] - Operations on block spent outputs
//! - [`TransactionSpentOutputsExt`] - Operations on transaction spent outputs
//! - [`CoinExt`] - Operations on coins
//!
//! These traits allow writing generic code that works with either owned or
//! borrowed types.
//!
//! # Iterators
//!
//! Several iterator types are provided for traversal:
//!
//! - [`BlockTransactionIter`] - Iterates over transactions in a block
//! - [`BlockSpentOutputsIter`] - Iterates over transaction spent outputs in a block
//! - [`TransactionSpentOutputsIter`] - Iterates over coins spent by a transaction
//!

use std::{
    ffi::c_void,
    fmt::{self, Debug, Display, Formatter},
    marker::PhantomData,
};

use libbitcoinkernel_sys::{
    btck_Block, btck_BlockHash, btck_BlockHeader, btck_BlockSpentOutputs, btck_Coin,
    btck_TransactionSpentOutputs, btck_block_copy, btck_block_count_transactions,
    btck_block_create, btck_block_destroy, btck_block_get_hash, btck_block_get_header,
    btck_block_get_transaction_at, btck_block_hash_copy, btck_block_hash_create,
    btck_block_hash_destroy, btck_block_hash_equals, btck_block_hash_to_bytes,
    btck_block_header_copy, btck_block_header_create, btck_block_header_destroy,
    btck_block_header_get_bits, btck_block_header_get_hash, btck_block_header_get_nonce,
    btck_block_header_get_prev_hash, btck_block_header_get_timestamp,
    btck_block_header_get_version, btck_block_spent_outputs_copy, btck_block_spent_outputs_count,
    btck_block_spent_outputs_create, btck_block_spent_outputs_destroy,
    btck_block_spent_outputs_get_transaction_spent_outputs_at, btck_block_to_bytes,
    btck_coin_confirmation_height, btck_coin_copy, btck_coin_create, btck_coin_destroy,
    btck_coin_get_output, btck_coin_is_coinbase, btck_transaction_spent_outputs_copy,
    btck_transaction_spent_outputs_count, btck_transaction_spent_outputs_destroy,
    btck_transaction_spent_outputs_get_coin_at,
};

use crate::{
    c_helpers, c_serialize,
    ffi::{
        c_helpers::present,
        sealed::{AsPtr, FromMutPtr, FromPtr},
    },
    KernelError, TxOut,
};

use super::transaction::{TransactionRef, TxOutRef};

/// Common operations for block hashes, implemented by both owned and borrowed types.
///
/// This trait provides shared functionality for [`BlockHash`] and [`BlockHashRef`],
/// allowing code to work with either owned or borrowed block hashes.
///
/// # Examples
///
/// ```no_run
/// use bitcoinkernel::{prelude::*, BlockHash};
///
/// fn display_hash<H: BlockHashExt>(hash: &H) {
///     let bytes = hash.to_bytes();
///     println!("Hash bytes: {:?}", bytes);
/// }
///
/// let hash = BlockHash::from([1u8; 32]);
/// display_hash(&hash);
/// ```
pub trait BlockHashExt: AsPtr<btck_BlockHash> + Display {
    /// Serializes the block hash to raw bytes.
    ///
    /// Returns the 32-byte representation of the block hash in internal byte order.
    ///
    /// # Returns
    /// A 32-byte array containing the block hash.
    ///
    /// # Example
    /// ```no_run
    /// use bitcoinkernel::{prelude::*, BlockHash};
    ///
    /// let hash = BlockHash::from([42u8; 32]);
    /// let bytes = hash.to_bytes();
    /// assert_eq!(bytes.len(), 32);
    /// ```
    fn to_bytes(&self) -> [u8; 32] {
        let mut output = [0u8; 32];
        unsafe { btck_block_hash_to_bytes(self.as_ptr(), output.as_mut_ptr()) };
        output
    }
}

/// A 32-byte hash uniquely identifying a block.
///
/// Block hashes are the double SHA256 hash of a block header and serve as
/// the block's unique identifier.
///
/// # Byte Order
///
/// Bitcoin uses two different representations of block hashes:
/// - **Internal byte order**: Used in memory and on disk
/// - **Display byte order**: Reversed for human-readable hex strings
///
/// The [`to_bytes`](BlockHashExt::to_bytes) method returns internal byte order,
/// while [`Display`] formatting shows the reversed bytes.
///
/// # Thread Safety
///
/// `BlockHash` is both [`Send`] and [`Sync`], allowing it to be safely
/// shared across threads.
///
/// # Examples
///
/// ```no_run
/// use bitcoinkernel::{prelude::*, BlockHash};
///
/// // Create from raw bytes
/// let hash = BlockHash::from([42u8; 32]);
///
/// // Display as hex (reversed byte order)
/// println!("Block: {}", hash);
///
/// // Get internal representation
/// let bytes = hash.to_bytes();
/// ```
pub struct BlockHash {
    inner: *mut btck_BlockHash,
}

unsafe impl Send for BlockHash {}
unsafe impl Sync for BlockHash {}

impl BlockHash {
    /// Creates a new block hash from raw bytes.
    ///
    /// # Arguments
    /// * `raw_bytes` - A slice containing exactly 32 bytes
    ///
    /// # Errors
    /// Returns [`KernelError::InvalidLength`] if the slice is not exactly 32 bytes.
    /// Returns [`KernelError::Internal`] if the underlying C++ library fails
    /// to create the hash.
    ///
    /// # Examples
    /// ```no_run
    /// use bitcoinkernel::BlockHash;
    ///
    /// # fn example() -> Result<(), bitcoinkernel::KernelError> {
    /// let bytes = [42u8; 32];
    /// let hash = BlockHash::new(&bytes)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(raw_bytes: &[u8]) -> Result<Self, KernelError> {
        if raw_bytes.len() != 32 {
            return Err(KernelError::InvalidLength {
                expected: 32,
                actual: raw_bytes.len(),
            });
        }
        let inner = unsafe { btck_block_hash_create(raw_bytes.as_ptr()) };

        if inner.is_null() {
            Err(KernelError::Internal(
                "Failed to create block hash from bytes".to_string(),
            ))
        } else {
            Ok(BlockHash { inner })
        }
    }

    /// Creates a borrowed reference to this block hash.
    ///
    /// This allows converting from an owned [`BlockHash`] to a [`BlockHashRef`]
    /// without copying the underlying data.
    ///
    /// # Lifetime
    /// The returned reference is valid for the lifetime of this [`BlockHash`].
    pub fn as_ref(&self) -> BlockHashRef<'_> {
        unsafe { BlockHashRef::from_ptr(self.inner as *const _) }
    }
}

impl AsPtr<btck_BlockHash> for BlockHash {
    fn as_ptr(&self) -> *const btck_BlockHash {
        self.inner as *const _
    }
}

impl FromMutPtr<btck_BlockHash> for BlockHash {
    unsafe fn from_ptr(ptr: *mut btck_BlockHash) -> Self {
        BlockHash { inner: ptr }
    }
}

impl BlockHashExt for BlockHash {}

impl Clone for BlockHash {
    fn clone(&self) -> Self {
        BlockHash {
            inner: unsafe { btck_block_hash_copy(self.inner) },
        }
    }
}

impl Drop for BlockHash {
    fn drop(&mut self) {
        unsafe { btck_block_hash_destroy(self.inner) }
    }
}

impl From<[u8; 32]> for BlockHash {
    fn from(hash: [u8; 32]) -> Self {
        BlockHash::new(hash.as_slice()).expect("32-bytes array should always be valid")
    }
}

impl TryFrom<&[u8]> for BlockHash {
    type Error = KernelError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        BlockHash::new(bytes)
    }
}

impl From<BlockHash> for [u8; 32] {
    fn from(block_hash: BlockHash) -> Self {
        block_hash.to_bytes()
    }
}

impl From<&BlockHash> for [u8; 32] {
    fn from(block_hash: &BlockHash) -> Self {
        block_hash.to_bytes()
    }
}

impl PartialEq for BlockHash {
    fn eq(&self, other: &Self) -> bool {
        present(unsafe { btck_block_hash_equals(self.inner, other.inner) })
    }
}

impl Eq for BlockHash {}

impl Debug for BlockHash {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BlockHash({:?})", self.to_bytes())
    }
}

impl Display for BlockHash {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let bytes = self.to_bytes();
        for byte in bytes.iter().rev() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// A borrowed reference to a block hash.
///
/// Provides zero-copy access to block hash data. It implements [`Copy`],
/// making it cheap to pass around.
///
/// # Lifetime
/// The reference is only valid as long as the data it references remains alive.
///
/// # Thread Safety
/// `BlockHashRef` is both [`Send`] and [`Sync`].
pub struct BlockHashRef<'a> {
    inner: *const btck_BlockHash,
    marker: PhantomData<&'a ()>,
}

unsafe impl<'a> Send for BlockHashRef<'a> {}
unsafe impl<'a> Sync for BlockHashRef<'a> {}

impl<'a> BlockHashRef<'a> {
    /// Creates an owned copy of this block hash.
    ///
    /// This allocates a new [`BlockHash`] with its own copy of the hash data.
    pub fn to_owned(&self) -> BlockHash {
        BlockHash {
            inner: unsafe { btck_block_hash_copy(self.inner) },
        }
    }
}

impl<'a> AsPtr<btck_BlockHash> for BlockHashRef<'a> {
    fn as_ptr(&self) -> *const btck_BlockHash {
        self.inner
    }
}

impl<'a> FromPtr<btck_BlockHash> for BlockHashRef<'a> {
    unsafe fn from_ptr(ptr: *const btck_BlockHash) -> Self {
        BlockHashRef {
            inner: ptr,
            marker: PhantomData,
        }
    }
}

impl<'a> BlockHashExt for BlockHashRef<'a> {}

impl<'a> Clone for BlockHashRef<'a> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a> PartialEq for BlockHashRef<'a> {
    fn eq(&self, other: &Self) -> bool {
        present(unsafe { btck_block_hash_equals(self.inner, other.inner) })
    }
}

impl<'a> Debug for BlockHashRef<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "BlockHash({:?})", self.to_bytes())
    }
}

impl<'a> Display for BlockHashRef<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let bytes = self.to_bytes();
        for byte in bytes.iter().rev() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

impl<'a> Eq for BlockHashRef<'a> {}

impl<'a> Copy for BlockHashRef<'a> {}

/// Common operations for block headers, implemented by both owned and borrow types.
pub trait BlockHeaderExt: AsPtr<btck_BlockHeader> {
    /// Return the block hash of the header.
    fn hash(&self) -> BlockHash {
        unsafe { BlockHash::from_ptr(btck_block_header_get_hash(self.as_ptr())) }
    }

    /// Return the hash of the previous block.
    fn prev_hash(&self) -> BlockHashRef<'_> {
        unsafe { BlockHashRef::from_ptr(btck_block_header_get_prev_hash(self.as_ptr())) }
    }

    /// Get the timestamp from the header
    fn timestamp(&self) -> u32 {
        unsafe { btck_block_header_get_timestamp(self.as_ptr()) }
    }

    // Get the nBits from the header
    fn bits(&self) -> u32 {
        unsafe { btck_block_header_get_bits(self.as_ptr()) }
    }

    // Get the version of the header
    fn version(&self) -> i32 {
        unsafe { btck_block_header_get_version(self.as_ptr()) }
    }

    // Get the nonce of the header
    fn nonce(&self) -> u32 {
        unsafe { btck_block_header_get_nonce(self.as_ptr()) }
    }
}

/// A Bitcoin block header.
///
/// Block headers contain a block's primitive data required to verify its proof of work.
/// They are typically used for headers-first validation.
///
/// Its fields include: version, previous block hash, merkle root, timestamp, difficulty target (nBits), and nonce
///
/// The header's hash is computed on-demand.
///
/// # Creation
///
/// Block headers are created from
/// - Raw serialized data using [`new`](Self::new)
/// - Copying a header from a block with [`Block::header`]
/// - Copying a header from a block tree entry with [`BlockTreeEntry::header`](crate::BlockTreeEntry::header)
///
/// # Examples
///
/// ```no_run
/// use bitcoinkernel::BlockHeader;
/// use bitcoinkernel::prelude::BlockHeaderExt;
///
/// # fn example() -> Result<(), bitcoinkernel::KernelError> {
/// let header_data = vec![0u8; 80]; // placeholder
/// let header = BlockHeader::new(&header_data)?;
///
/// println!("Hash: {}", header.hash());
/// # Ok(())
/// # }
///
/// ```
pub struct BlockHeader {
    inner: *mut btck_BlockHeader,
}

unsafe impl Send for BlockHeader {}
unsafe impl Sync for BlockHeader {}

impl BlockHeader {
    /// Creates a new block header from raw serialized data.
    ///
    /// Deserializes a block header from its wire format representation.
    /// The data must contain a complete, valid block structure. Serialization
    /// will succeed if the first 80 bytes of the data contain a valid header.
    ///
    /// # Arguments
    /// * `raw_header` - The serialized block header in Bitcoin wire format
    ///
    /// # Errors
    /// Return [`KernelError::Internal`] if:
    /// - The data is not a valid header
    /// - Deserialization fails
    ///
    /// # Examples
    /// ```no_run
    /// use bitcoinkernel::BlockHeader;
    ///
    /// # fn example() -> Result<(), bitcoinkernel::KernelError> {
    /// let header_data = vec![0u8; 80]; //placeholder }
    /// let header = BlockHeader::new(&header_data);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(raw_header: &[u8]) -> Result<Self, KernelError> {
        let inner = unsafe {
            btck_block_header_create(raw_header.as_ptr() as *const c_void, raw_header.len())
        };

        if inner.is_null() {
            Err(KernelError::Internal(
                "Failed to create header from bytes".to_string(),
            ))
        } else {
            Ok(BlockHeader { inner })
        }
    }

    pub fn as_ref(&self) -> BlockHeaderRef<'_> {
        unsafe { BlockHeaderRef::from_ptr(self.inner as *const _) }
    }
}

impl FromMutPtr<btck_BlockHeader> for BlockHeader {
    unsafe fn from_ptr(ptr: *mut btck_BlockHeader) -> Self {
        BlockHeader { inner: ptr }
    }
}

impl AsPtr<btck_BlockHeader> for BlockHeader {
    fn as_ptr(&self) -> *const btck_BlockHeader {
        self.inner as *const _
    }
}

impl Debug for BlockHeader {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BlockHeader(hash: {}, prev_hash: {}, timestamp: {}, bits: {}, version: {}, nonce: {})",
            self.hash(),
            self.prev_hash(),
            self.timestamp(),
            self.bits(),
            self.version(),
            self.nonce()
        )
    }
}

impl BlockHeaderExt for BlockHeader {}

impl Clone for BlockHeader {
    fn clone(&self) -> Self {
        BlockHeader {
            inner: unsafe { btck_block_header_copy(self.inner) },
        }
    }
}

impl Drop for BlockHeader {
    fn drop(&mut self) {
        unsafe { btck_block_header_destroy(self.inner) }
    }
}

/// A borrowed reference to a block header.
///
/// Provides zero-copy access to block header data. It implements [`Copy`],
/// making it cheap to pass around.
///
/// # Lifetime
/// The reference is only valid as long as the data it references remains alive.
///
/// # Thread Safety
/// `BlockHeaderRef` is both [`Send`] and [`Sync`].
pub struct BlockHeaderRef<'a> {
    inner: *const btck_BlockHeader,
    marker: PhantomData<&'a ()>,
}

unsafe impl<'a> Send for BlockHeaderRef<'a> {}
unsafe impl<'a> Sync for BlockHeaderRef<'a> {}

impl<'a> BlockHeaderRef<'a> {
    pub fn to_owned(&self) -> BlockHeader {
        BlockHeader {
            inner: unsafe { btck_block_header_copy(self.inner) },
        }
    }
}

impl<'a> AsPtr<btck_BlockHeader> for BlockHeaderRef<'a> {
    fn as_ptr(&self) -> *const btck_BlockHeader {
        self.inner
    }
}

impl<'a> FromPtr<btck_BlockHeader> for BlockHeaderRef<'a> {
    unsafe fn from_ptr(ptr: *const btck_BlockHeader) -> Self {
        BlockHeaderRef {
            inner: ptr,
            marker: PhantomData,
        }
    }
}

impl<'a> Debug for BlockHeaderRef<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "BlockHeader(hash: {}, prev_hash: {}, timestamp: {}, bits: {}, version: {}, nonce: {})",
            self.hash(),
            self.prev_hash(),
            self.timestamp(),
            self.bits(),
            self.version(),
            self.nonce()
        )
    }
}

impl<'a> BlockHeaderExt for BlockHeaderRef<'a> {}

impl<'a> Copy for BlockHeaderRef<'a> {}

impl<'a> Clone for BlockHeaderRef<'a> {
    fn clone(&self) -> Self {
        *self
    }
}

/// A block containing a header and transactions.
///
/// Blocks are the fundamental units of the block chain, linking together
/// through their hashes to form a chain. Each block includes:
/// - Header fields: version, previous block hash, merkle root, timestamp, difficulty target (nBits), and nonce
/// - Transactions: one or more transactions, where the first is always the coinbase transaction
///
/// The block's hash is computed from the header fields using double SHA256.
///
/// **Note**: Individual header fields are not currently accessible directly from the block, but may
/// be retrieved through its header.
/// You can access the block hash via [`hash`](Self::hash) and transactions via
/// [`transaction`](Self::transaction) or [`transactions`](Self::transactions).
///
/// # Creation
///
/// Blocks are typically created from:
/// - Raw serialized block data using [`new`](Self::new)
/// - Reading from disk via [`ChainstateManager::read_block_data`](crate::ChainstateManager::read_block_data)
///
/// # Thread Safety
///
/// `Block` is both [`Send`] and [`Sync`], allowing it to be safely shared
/// across threads or moved between threads.
///
/// # Examples
///
/// ```no_run
/// use bitcoinkernel::Block;
///
/// # fn example() -> Result<(), bitcoinkernel::KernelError> {
/// let block_data = vec![0u8; 100]; // placeholder
/// let block = Block::new(&block_data)?;
///
/// println!("Block hash: {}", block.hash());
/// println!("Transaction count: {}", block.transaction_count());
///
/// // Access first transaction (coinbase)
/// let coinbase = block.transaction(0)?;
/// # Ok(())
/// # }
/// ```
pub struct Block {
    inner: *mut btck_Block,
}

unsafe impl Send for Block {}
unsafe impl Sync for Block {}

impl Block {
    /// Creates a new block from raw serialized data.
    ///
    /// Deserializes a block from its wire format representation.
    /// The data must contain a complete, valid block structure.
    ///
    /// # Arguments
    /// * `raw_block` - The serialized block data in Bitcoin wire format
    ///
    /// # Errors
    /// Returns [`KernelError::Internal`] if:
    /// - The data is not a valid block
    /// - The data is incomplete
    /// - Deserialization fails
    ///
    /// # Examples
    /// ```no_run
    /// use bitcoinkernel::Block;
    ///
    /// # fn example() -> Result<(), bitcoinkernel::KernelError> {
    /// let block_data = vec![0u8; 100]; // placeholder
    /// let block = Block::new(&block_data)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(raw_block: &[u8]) -> Result<Self, KernelError> {
        let inner =
            unsafe { btck_block_create(raw_block.as_ptr() as *const c_void, raw_block.len()) };

        if inner.is_null() {
            Err(KernelError::Internal(
                "Failed to create Block from bytes".to_string(),
            ))
        } else {
            Ok(Block { inner })
        }
    }

    /// Returns the hash of this block.
    ///
    /// This is the double SHA256 hash of the block header, which serves as
    /// the block's unique identifier.
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::Block;
    /// # fn example() -> Result<(), bitcoinkernel::KernelError> {
    /// # let block_data = vec![0u8; 100]; // placeholder
    /// # let block = Block::new(&block_data)?;
    /// let hash = block.hash();
    /// println!("Block: {}", hash);
    /// # Ok(())
    /// # }
    /// ```
    pub fn hash(&self) -> BlockHash {
        let hash_ptr = unsafe { btck_block_get_hash(self.inner) };
        unsafe { BlockHash::from_ptr(hash_ptr) }
    }

    /// Returns the number of transactions in this block.
    ///
    /// Every block contains at least one transaction (the coinbase transaction).
    /// The count includes the coinbase.
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::Block;
    /// # let block: Block = unimplemented!();
    /// println!("Block contains {} transactions", block.transaction_count());
    /// ```
    pub fn transaction_count(&self) -> usize {
        unsafe { btck_block_count_transactions(self.inner) }
    }

    /// Returns the header of this block.
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::Block;
    /// # fn example() -> Result<(), bitcoinkernel::KernelError> {
    /// # let block_data = vec![0u8; 100]; // placeholder
    /// # let block = Block::new(&block_data)?;
    /// let header = block.header();
    /// # Ok(())
    /// # }
    /// ```
    pub fn header(&self) -> BlockHeader {
        unsafe { BlockHeader::from_ptr(btck_block_get_header(self.inner)) }
    }

    /// Returns a reference to the transaction at the specified index.
    ///
    /// # Arguments
    /// * `index` - The zero-based index of the transaction (0 is the coinbase)
    ///
    /// # Returns
    /// A [`TransactionRef`] borrowing the transaction data from this block.
    ///
    /// # Errors
    /// Returns [`KernelError::OutOfBounds`] if the index is greater than or
    /// equal to [`transaction_count`](Self::transaction_count).
    ///
    /// # Lifetime
    /// The returned reference is valid only as long as this [`Block`] exists.
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::{prelude::*, Block, KernelError};
    /// # fn example(block: &Block) -> Result<(), KernelError> {
    /// // Get the coinbase transaction
    /// let coinbase = block.transaction(0)?;
    /// println!("Coinbase txid: {}", coinbase.txid());
    ///
    /// // Iterate through all transactions
    /// for i in 0..block.transaction_count() {
    ///     let tx = block.transaction(i)?;
    ///     println!("Transaction {}: {}", i, tx.txid());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn transaction(&self, index: usize) -> Result<TransactionRef<'_>, KernelError> {
        if index >= self.transaction_count() {
            return Err(KernelError::OutOfBounds);
        }
        let tx_ptr = unsafe { btck_block_get_transaction_at(self.inner, index) };
        Ok(unsafe { TransactionRef::from_ptr(tx_ptr) })
    }

    /// Serializes the block to Bitcoin wire format.
    ///
    /// Encodes the complete block (header and all transactions) according to
    /// the Bitcoin consensus rules. The resulting data can be transmitted over
    /// the network or stored to disk.
    ///
    /// # Errors
    /// Returns [`KernelError::Internal`] if serialization fails.
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::{Block, KernelError};
    /// # fn example(block: &Block) -> Result<(), Box<dyn std::error::Error>> {
    /// let serialized = block.consensus_encode()?;
    /// std::fs::write("block.dat", &serialized)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn consensus_encode(&self) -> Result<Vec<u8>, KernelError> {
        c_serialize(|callback, user_data| unsafe {
            btck_block_to_bytes(self.inner, Some(callback), user_data)
        })
    }

    /// Returns an iterator over all transactions in this block.
    ///
    /// The iterator yields [`TransactionRef`] instances that borrow from this block.
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::{prelude::*, Block};
    /// # fn example() -> Result<(), bitcoinkernel::KernelError> {
    /// # let block_data = vec![0u8; 100]; // placeholder
    /// # let block = Block::new(&block_data)?;
    /// for (i, tx) in block.transactions().enumerate() {
    ///     println!("Transaction {}: {}", i, tx.txid());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    pub fn transactions(&self) -> BlockTransactionIter<'_> {
        BlockTransactionIter::new(self)
    }
}

impl AsPtr<btck_Block> for Block {
    fn as_ptr(&self) -> *const btck_Block {
        self.inner as *const _
    }
}

impl FromMutPtr<btck_Block> for Block {
    unsafe fn from_ptr(ptr: *mut btck_Block) -> Self {
        Block { inner: ptr }
    }
}

impl Clone for Block {
    fn clone(&self) -> Self {
        Block {
            inner: unsafe { btck_block_copy(self.inner) },
        }
    }
}

impl Drop for Block {
    fn drop(&mut self) {
        unsafe { btck_block_destroy(self.inner) };
    }
}

impl TryFrom<&[u8]> for Block {
    type Error = KernelError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Block::new(bytes)
    }
}

impl TryFrom<Block> for Vec<u8> {
    type Error = KernelError;

    fn try_from(block: Block) -> Result<Self, Self::Error> {
        block.consensus_encode()
    }
}

impl TryFrom<&Block> for Vec<u8> {
    type Error = KernelError;

    fn try_from(block: &Block) -> Result<Self, Self::Error> {
        block.consensus_encode()
    }
}

/// Iterator over transactions in a block.
///
/// This iterator yields [`TransactionRef`] items for each transaction in the
/// block, starting from the coinbase transaction (index 0) and continuing
/// through all remaining transactions.
///
/// # Lifetime
/// The iterator is tied to the lifetime of the [`Block`] it was created from.
/// The iterator becomes invalid when the block is dropped.
///
/// # Example
/// ```no_run
/// # use bitcoinkernel::{prelude::*, Block, KernelError};
/// # fn example() -> Result<(), KernelError> {
/// # let block_data = vec![0u8; 100]; // placeholder
/// # let block = Block::new(&block_data)?;
/// // Iterate through all transactions
/// for tx in block.transactions() {
///     println!("Transaction: {}", tx.txid());
/// }
///
/// // Or with enumerate for explicit indexing
/// for (idx, tx) in block.transactions().enumerate() {
///     if idx == 0 {
///         println!("Coinbase: {}", tx.txid());
///     } else {
///         println!("Transaction {}: {}", idx, tx.txid());
///     }
/// }
///
/// // Use iterator adapters
/// let first_ten: Vec<_> = block.transactions()
///     .take(10)
///     .collect();
/// # Ok(())
/// # }
/// ```
pub struct BlockTransactionIter<'a> {
    block: &'a Block,
    current_index: usize,
}

impl<'a> BlockTransactionIter<'a> {
    fn new(block: &'a Block) -> Self {
        Self {
            block,
            current_index: 0,
        }
    }
}

impl<'a> Iterator for BlockTransactionIter<'a> {
    type Item = TransactionRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let index = self.current_index;
        self.current_index += 1;
        self.block.transaction(index).ok()
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self
            .block
            .transaction_count()
            .saturating_sub(self.current_index);
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for BlockTransactionIter<'a> {
    fn len(&self) -> usize {
        self.block
            .transaction_count()
            .saturating_sub(self.current_index)
    }
}

/// Common operations for block spent outputs, implemented by both owned and borrowed types.
///
/// This trait provides shared functionality for [`BlockSpentOutputs`] and
/// [`BlockSpentOutputsRef`], allowing code to work with either owned or borrowed
/// spent output data.
pub trait BlockSpentOutputsExt: AsPtr<btck_BlockSpentOutputs> {
    /// Returns the number of transactions that have spent output data.
    ///
    /// Note: This excludes the coinbase transaction
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::{prelude::*, BlockSpentOutputs};
    /// # fn example(spent_outputs: &BlockSpentOutputs) {
    /// println!("Block has spent outputs for {} transactions", spent_outputs.count());
    /// # }
    /// ```
    fn count(&self) -> usize {
        unsafe { btck_block_spent_outputs_count(self.as_ptr()) }
    }

    /// Returns a reference to the spent outputs for a specific transaction.
    ///
    /// # Arguments
    /// * `transaction_index` - The index of the transaction (0-based, excluding coinbase)
    ///
    /// # Returns
    /// A [`TransactionSpentOutputsRef`] borrowing the transaction's spent output data.
    ///
    /// # Errors
    /// Returns [`KernelError::OutOfBounds`] if the index is greater than or
    /// equal to [`count`](Self::count).
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::{prelude::*, BlockSpentOutputs, KernelError};
    /// # fn example(block_spent: &BlockSpentOutputs) -> Result<(), KernelError> {
    /// let tx_spent = block_spent.transaction_spent_outputs(0)?;
    /// println!("First transaction spent {} coins", tx_spent.count());
    /// # Ok(())
    /// # }
    /// ```
    fn transaction_spent_outputs(
        &self,
        transaction_index: usize,
    ) -> Result<TransactionSpentOutputsRef<'_>, KernelError> {
        if transaction_index >= self.count() {
            return Err(KernelError::OutOfBounds);
        }
        let tx_out_ptr = unsafe {
            btck_block_spent_outputs_get_transaction_spent_outputs_at(
                self.as_ptr(),
                transaction_index,
            )
        };
        if tx_out_ptr.is_null() {
            return Err(KernelError::OutOfBounds);
        }
        Ok(unsafe { TransactionSpentOutputsRef::from_ptr(tx_out_ptr) })
    }

    /// Returns an iterator over spent outputs for all transactions in the block.
    ///
    /// The iterator yields [`TransactionSpentOutputsRef`] instances in the same
    /// order as the transactions in the block (excluding the coinbase).
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::{prelude::*, BlockSpentOutputs};
    /// # fn example(block_spent: &BlockSpentOutputs) {
    /// for tx_spent in block_spent.iter() {
    ///     println!("Transaction spent {} coins", tx_spent.count());
    /// }
    /// # }
    /// ```
    fn iter(&self) -> BlockSpentOutputsIter<'_> {
        BlockSpentOutputsIter::new(unsafe { BlockSpentOutputsRef::from_ptr(self.as_ptr()) })
    }
}

/// Spent output data for all transactions in a block.
///
/// Also known as "undo data", this contains all the previous transaction outputs
/// that were consumed (spent) by a block's transactions.
///
/// # Structure
///
/// The spent outputs are ordered by transaction order in a block (excluding the coinbase
/// transaction). Each transaction's spent outputs correspond one-to-one with its inputs
/// in the same order.
///
/// # Reading from Disk
///
/// Spent outputs are read from disk using [`ChainstateManager::read_spent_outputs`](crate::ChainstateManager::read_spent_outputs).
///
/// # Thread Safety
///
/// `BlockSpentOutputs` is both [`Send`] and [`Sync`].
///
/// # Examples
///
/// ```no_run
/// # use bitcoinkernel::{prelude::*, ChainstateManager, BlockTreeEntry, KernelError};
/// # fn example(chainman: &ChainstateManager, entry: &BlockTreeEntry) -> Result<(), KernelError> {
/// let spent_outputs = chainman.read_spent_outputs(entry)?;
///
/// println!("Block has {} transactions with spent outputs", spent_outputs.count());
///
/// for tx_spent in spent_outputs.iter() {
///     for coin in tx_spent.coins() {
///         println!("Spent {} satoshis from height {}",
///             coin.output().value(),
///             coin.confirmation_height()
///         );
///     }
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct BlockSpentOutputs {
    inner: *mut btck_BlockSpentOutputs,
}

unsafe impl Send for BlockSpentOutputs {}
unsafe impl Sync for BlockSpentOutputs {}

impl BlockSpentOutputs {
    /// Creates a borrowed reference to these spent outputs.
    ///
    /// This allows converting from owned [`BlockSpentOutputs`] to
    /// [`BlockSpentOutputsRef`] without copying the underlying data.
    ///
    /// # Lifetime
    /// The returned reference is valid for the lifetime of the [`BlockSpentOutputs`].
    pub fn as_ref(&self) -> BlockSpentOutputsRef<'_> {
        unsafe { BlockSpentOutputsRef::from_ptr(self.inner as *const _) }
    }

    pub fn new(coins: &[Vec<Coin>]) -> Self {
        struct CallbackContext<'a> {
            coins: &'a [Vec<Coin>],
        }

        extern "C" fn coin_getter(
            context: *mut c_void,
            tx_index: usize,
            coin_index: usize,
        ) -> *const btck_Coin {
            let ctx = unsafe { &*(context as *const CallbackContext) };
            ctx.coins[tx_index][coin_index].as_ptr()
        }

        extern "C" fn count_getter(context: *mut c_void, tx_index: usize) -> usize {
            let ctx = unsafe { &*(context as *const CallbackContext) };
            ctx.coins[tx_index].len()
        }

        let context = CallbackContext { coins };
        unsafe {
            BlockSpentOutputs::from_ptr(btck_block_spent_outputs_create(
                &context as *const CallbackContext as *mut c_void,
                Some(coin_getter),
                Some(count_getter),
                coins.len(),
            ))
        }
    }
}

impl FromMutPtr<btck_BlockSpentOutputs> for BlockSpentOutputs {
    unsafe fn from_ptr(ptr: *mut btck_BlockSpentOutputs) -> Self {
        BlockSpentOutputs { inner: ptr }
    }
}

impl AsPtr<btck_BlockSpentOutputs> for BlockSpentOutputs {
    fn as_ptr(&self) -> *const btck_BlockSpentOutputs {
        self.inner as *const _
    }
}

impl BlockSpentOutputsExt for BlockSpentOutputs {}

impl Clone for BlockSpentOutputs {
    fn clone(&self) -> Self {
        BlockSpentOutputs {
            inner: unsafe { btck_block_spent_outputs_copy(self.inner) },
        }
    }
}

impl Drop for BlockSpentOutputs {
    fn drop(&mut self) {
        unsafe { btck_block_spent_outputs_destroy(self.inner) };
    }
}

/// A borrowed reference to block spent outputs.
///
/// This type provides zero-copy access to spent output data owned by the
/// underlying C++ library. It implements [`Copy`], making it cheap to pass around.
///
/// # Lifetime
/// The reference is valid only as long as the owner (typically returned from
/// [`ChainstateManager::read_spent_outputs`](crate::ChainstateManager::read_spent_outputs))
/// remains alive.
///
/// # Thread Safety
/// `BlockSpentOutputsRef` is both [`Send`] and [`Sync`].
pub struct BlockSpentOutputsRef<'a> {
    inner: *const btck_BlockSpentOutputs,
    marker: PhantomData<&'a ()>,
}

unsafe impl<'a> Send for BlockSpentOutputsRef<'a> {}
unsafe impl<'a> Sync for BlockSpentOutputsRef<'a> {}

impl<'a> BlockSpentOutputsRef<'a> {
    /// Creates an owned copy of these spent outputs.
    ///
    /// This allocates a new [`BlockSpentOutputs`] with its own copy of the data.
    pub fn to_owned(&self) -> BlockSpentOutputs {
        BlockSpentOutputs {
            inner: unsafe { btck_block_spent_outputs_copy(self.inner) },
        }
    }
}

impl<'a> AsPtr<btck_BlockSpentOutputs> for BlockSpentOutputsRef<'a> {
    fn as_ptr(&self) -> *const btck_BlockSpentOutputs {
        self.inner
    }
}

impl<'a> FromPtr<btck_BlockSpentOutputs> for BlockSpentOutputsRef<'a> {
    unsafe fn from_ptr(ptr: *const btck_BlockSpentOutputs) -> Self {
        BlockSpentOutputsRef {
            inner: ptr,
            marker: PhantomData,
        }
    }
}

impl<'a> BlockSpentOutputsExt for BlockSpentOutputsRef<'a> {}

impl<'a> Clone for BlockSpentOutputsRef<'a> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a> Copy for BlockSpentOutputsRef<'a> {}

/// Iterator over transaction spent outputs in a block.
///
/// This iterator yields [`TransactionSpentOutputsRef`] items for each transaction
/// in the block (excluding the coinbase transaction).
///
/// # Lifetime
/// The iterator is tied to the lifetime of the [`BlockSpentOutputs`] it was
/// created from. The iterator becomes invalid when the block spent outputs are dropped.
///
/// # Example
/// ```no_run
/// # use bitcoinkernel::{prelude::*, BlockSpentOutputs, KernelError};
/// # fn example(block_spent: &BlockSpentOutputs) -> Result<(), KernelError> {
/// // Iterate through all transaction spent outputs
/// for tx_spent in block_spent.iter() {
///     println!("Transaction spent {} coins", tx_spent.count());
/// }
///
/// // Or with enumerate for explicit indexing
/// for (idx, tx_spent) in block_spent.iter().enumerate() {
///     println!("Transaction {} spent {} coins", idx + 1, tx_spent.count());
/// }
///
/// // Use iterator adapters
/// let total_coins: usize = block_spent.iter()
///     .map(|tx| tx.count())
///     .sum();
/// println!("Block spent {} total coins", total_coins);
/// # Ok(())
/// # }
/// ```
pub struct BlockSpentOutputsIter<'a> {
    block_spent_outputs: BlockSpentOutputsRef<'a>,
    current_index: usize,
}

impl<'a> BlockSpentOutputsIter<'a> {
    fn new(block_spent_outputs: BlockSpentOutputsRef<'a>) -> Self {
        Self {
            block_spent_outputs,
            current_index: 0,
        }
    }
}

impl<'a> Iterator for BlockSpentOutputsIter<'a> {
    type Item = TransactionSpentOutputsRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_index >= self.block_spent_outputs.count() {
            return None;
        }

        let index = self.current_index;
        self.current_index += 1;

        let tx_out_ptr = unsafe {
            btck_block_spent_outputs_get_transaction_spent_outputs_at(
                self.block_spent_outputs.as_ptr(),
                index,
            )
        };

        if tx_out_ptr.is_null() {
            None
        } else {
            Some(unsafe { TransactionSpentOutputsRef::from_ptr(tx_out_ptr) })
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self
            .block_spent_outputs
            .count()
            .saturating_sub(self.current_index);
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for BlockSpentOutputsIter<'a> {
    fn len(&self) -> usize {
        self.block_spent_outputs
            .count()
            .saturating_sub(self.current_index)
    }
}

/// Common operations for transaction spent outputs, implemented by both owned and borrowed types.
///
/// This trait provides shared functionality for [`TransactionSpentOutputs`] and
/// [`TransactionSpentOutputsRef`], allowing code to work with either owned or
/// borrowed spent output data for a single transaction.
pub trait TransactionSpentOutputsExt: AsPtr<btck_TransactionSpentOutputs> {
    /// Returns the number of coins (outputs) spent by this transaction.
    ///
    /// This equals the number of inputs in the transaction.
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::{prelude::*, TransactionSpentOutputs};
    /// # fn example(tx_spent: &TransactionSpentOutputs) {
    /// println!("Transaction has {} inputs", tx_spent.count());
    /// # }
    /// ```
    fn count(&self) -> usize {
        unsafe { btck_transaction_spent_outputs_count(self.as_ptr()) }
    }

    /// Returns a reference to the coin at the specified input index.
    ///
    /// # Arguments
    /// * `coin_index` - The index corresponding to the transaction input (0-based)
    ///
    /// # Returns
    /// A [`CoinRef`] borrowing the coin data.
    ///
    /// # Errors
    /// Returns [`KernelError::OutOfBounds`] if the index is greater than or
    /// equal to [`count`](Self::count).
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::{prelude::*, TransactionSpentOutputs, KernelError};
    /// # fn example(tx_spent: &TransactionSpentOutputs) -> Result<(), KernelError> {
    /// let first_coin = tx_spent.coin(0)?;
    /// println!("First input spent {} satoshis", first_coin.output().value());
    /// # Ok(())
    /// # }
    /// ```
    fn coin(&self, coin_index: usize) -> Result<CoinRef<'_>, KernelError> {
        if coin_index >= self.count() {
            return Err(KernelError::OutOfBounds);
        }
        let coin_ptr =
            unsafe { btck_transaction_spent_outputs_get_coin_at(self.as_ptr(), coin_index) };
        Ok(unsafe { CoinRef::from_ptr(coin_ptr) })
    }

    /// Returns an iterator over the coins spent by this transaction.
    ///
    /// The coins are yielded in the same order as the transaction's inputs.
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::{prelude::*, TransactionSpentOutputs};
    /// # fn example(tx_spent: &TransactionSpentOutputs) {
    /// for coin in tx_spent.coins() {
    ///     println!("Spent {} satoshis", coin.output().value());
    /// }
    /// # }
    /// ```
    fn coins(&self) -> TransactionSpentOutputsIter<'_> {
        TransactionSpentOutputsIter::new(unsafe {
            TransactionSpentOutputsRef::from_ptr(self.as_ptr())
        })
    }
}

/// Spent output data for a single transaction.
///
/// Contains all the coins (UTXOs) that were consumed by a specific transaction's
/// inputs, in the same order as the inputs. Each coin represents a previous
/// transaction output that was spent.
///
/// # Thread Safety
///
/// `TransactionSpentOutputs` is both [`Send`] and [`Sync`].
///
/// # Examples
///
/// ```no_run
/// # use bitcoinkernel::{prelude::*, BlockSpentOutputs, KernelError};
/// # fn example(block_spent: &BlockSpentOutputs) -> Result<(), KernelError> {
/// // Get spent outputs for the second transaction in a block
/// let tx_spent = block_spent.transaction_spent_outputs(0)?;
///
/// // Iterate through the coins
/// for coin in tx_spent.coins() {
///     println!("Input spent: {} satoshis", coin.output().value());
///     println!("Output was created at height: {}", coin.confirmation_height());
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct TransactionSpentOutputs {
    inner: *mut btck_TransactionSpentOutputs,
}

unsafe impl Send for TransactionSpentOutputs {}
unsafe impl Sync for TransactionSpentOutputs {}

impl TransactionSpentOutputs {
    /// Creates a borrowed reference to these spent outputs.
    ///
    /// This allows converting from owned [`TransactionSpentOutputs`] to
    /// [`TransactionSpentOutputsRef`] without copying the underlying data.
    ///
    /// # Lifetime
    /// The returned reference is valid for the lifetime of the [`TransactionSpentOutputs`].
    pub fn as_ref(&self) -> TransactionSpentOutputsRef<'_> {
        unsafe { TransactionSpentOutputsRef::from_ptr(self.inner as *const _) }
    }
}

impl AsPtr<btck_TransactionSpentOutputs> for TransactionSpentOutputs {
    fn as_ptr(&self) -> *const btck_TransactionSpentOutputs {
        self.inner as *const _
    }
}

impl FromMutPtr<btck_TransactionSpentOutputs> for TransactionSpentOutputs {
    unsafe fn from_ptr(ptr: *mut btck_TransactionSpentOutputs) -> Self {
        TransactionSpentOutputs { inner: ptr }
    }
}

impl TransactionSpentOutputsExt for TransactionSpentOutputs {}

impl Clone for TransactionSpentOutputs {
    fn clone(&self) -> Self {
        TransactionSpentOutputs {
            inner: unsafe { btck_transaction_spent_outputs_copy(self.inner) },
        }
    }
}

impl Drop for TransactionSpentOutputs {
    fn drop(&mut self) {
        unsafe { btck_transaction_spent_outputs_destroy(self.inner) };
    }
}

/// A borrowed reference to transaction spent outputs.
///
/// This type provides zero-copy access to spent output data owned by the
/// underlying C++ library. It implements [`Copy`], making it cheap to pass around.
///
/// # Lifetime
/// The reference is valid only as long as the owner remains alive.
///
/// # Thread Safety
/// `TransactionSpentOutputsRef` is both [`Send`] and [`Sync`].
pub struct TransactionSpentOutputsRef<'a> {
    inner: *const btck_TransactionSpentOutputs,
    marker: PhantomData<&'a ()>,
}

unsafe impl<'a> Send for TransactionSpentOutputsRef<'a> {}
unsafe impl<'a> Sync for TransactionSpentOutputsRef<'a> {}

impl<'a> TransactionSpentOutputsRef<'a> {
    /// Creates an owned copy of these spent outputs.
    ///
    /// This allocates a new [`TransactionSpentOutputs`] with its own copy of the data.
    pub fn to_owned(&self) -> TransactionSpentOutputs {
        TransactionSpentOutputs {
            inner: unsafe { btck_transaction_spent_outputs_copy(self.inner) },
        }
    }
}

impl<'a> AsPtr<btck_TransactionSpentOutputs> for TransactionSpentOutputsRef<'a> {
    fn as_ptr(&self) -> *const btck_TransactionSpentOutputs {
        self.inner
    }
}

impl<'a> FromPtr<btck_TransactionSpentOutputs> for TransactionSpentOutputsRef<'a> {
    unsafe fn from_ptr(ptr: *const btck_TransactionSpentOutputs) -> Self {
        TransactionSpentOutputsRef {
            inner: ptr,
            marker: PhantomData,
        }
    }
}

impl<'a> TransactionSpentOutputsExt for TransactionSpentOutputsRef<'a> {}

impl<'a> Clone for TransactionSpentOutputsRef<'a> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a> Copy for TransactionSpentOutputsRef<'a> {}

/// Iterator over coins in transaction spent outputs.
///
/// This iterator yields [`CoinRef`] items for each coin (UTXO) spent by a
/// transaction. The coins correspond one-to-one with the transaction's inputs,
/// yielded in the same order.
///
/// # Lifetime
/// The iterator is tied to the lifetime of the [`TransactionSpentOutputs`] it was
/// created from. The iterator becomes invalid when the transaction spent outputs are dropped.
///
/// # Example
/// ```no_run
/// # use bitcoinkernel::{prelude::*, TransactionSpentOutputs, KernelError};
/// # fn example(tx_spent: &TransactionSpentOutputs) -> Result<(), KernelError> {
/// // Iterate through all spent coins
/// for coin in tx_spent.coins() {
///     println!("Spent {} satoshis from height {}",
///              coin.output().value(),
///              coin.confirmation_height());
/// }
///
/// // Or with enumerate for explicit input indexing
/// for (input_idx, coin) in tx_spent.coins().enumerate() {
///     println!("Input {}: {} satoshis",
///              input_idx,
///              coin.output().value());
/// }
///
/// // Use iterator adapters
/// let total_value: i64 = tx_spent.coins()
///     .map(|coin| coin.output().value())
///     .sum();
/// println!("Transaction spent {} satoshis total", total_value);
/// # Ok(())
/// # }
/// ```
pub struct TransactionSpentOutputsIter<'a> {
    tx_spent_outputs: TransactionSpentOutputsRef<'a>,
    current_index: usize,
}

impl<'a> TransactionSpentOutputsIter<'a> {
    fn new(tx_spent_outputs: TransactionSpentOutputsRef<'a>) -> Self {
        Self {
            tx_spent_outputs,
            current_index: 0,
        }
    }
}

impl<'a> Iterator for TransactionSpentOutputsIter<'a> {
    type Item = CoinRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_index >= self.tx_spent_outputs.count() {
            return None;
        }

        let index = self.current_index;
        self.current_index += 1;

        let coin_ptr = unsafe {
            btck_transaction_spent_outputs_get_coin_at(self.tx_spent_outputs.as_ptr(), index)
        };

        Some(unsafe { CoinRef::from_ptr(coin_ptr) })
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self
            .tx_spent_outputs
            .count()
            .saturating_sub(self.current_index);
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for TransactionSpentOutputsIter<'a> {
    fn len(&self) -> usize {
        self.tx_spent_outputs
            .count()
            .saturating_sub(self.current_index)
    }
}

/// Common operations for coins, implemented by both owned and borrowed types.
///
/// This trait provides shared functionality for [`Coin`] and [`CoinRef`],
/// allowing code to work with either owned or borrowed coin data.
pub trait CoinExt: AsPtr<btck_Coin> {
    /// Returns the height of the block where this coin was created.
    ///
    /// This is the block height at which the transaction containing this
    /// output was confirmed.
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::{prelude::*, Coin};
    /// # fn example(coin: &Coin) {
    /// println!("Coin created at height {}", coin.confirmation_height());
    /// # }
    /// ```
    fn confirmation_height(&self) -> u32 {
        unsafe { btck_coin_confirmation_height(self.as_ptr()) }
    }

    /// Returns true if this coin came from a coinbase transaction.
    ///
    /// Coinbase outputs have special rules: they cannot be spent until they
    /// mature (100 blocks on mainnet).
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::{prelude::*, Coin};
    /// # fn example(coin: &Coin) {
    /// if coin.is_coinbase() {
    ///     println!("This is a coinbase output");
    /// }
    /// # }
    /// ```
    fn is_coinbase(&self) -> bool {
        let result = unsafe { btck_coin_is_coinbase(self.as_ptr()) };
        c_helpers::present(result)
    }

    /// Returns a reference to the transaction output data for this coin.
    ///
    /// The output contains the value (amount in satoshis) and the script
    /// that must be satisfied to spend the coin.
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::{prelude::*, Coin};
    /// # fn example(coin: &Coin) {
    /// let output = coin.output();
    /// println!("Value: {} satoshis", output.value());
    /// println!("Script length: {} bytes", output.script_pubkey().to_bytes().len());
    /// # }
    /// ```
    fn output(&self) -> TxOutRef<'_> {
        let output_ptr = unsafe { btck_coin_get_output(self.as_ptr()) };
        unsafe { TxOutRef::from_ptr(output_ptr) }
    }
}

/// A coin (UTXO) representing a spendable transaction output.
///
/// A coin contains:
/// - The transaction output (value and locking script)
/// - The height at which it was created
/// - Whether it came from a coinbase transaction
///
/// Coins are the fundamental unit of the UTXO (Unspent Transaction Output)
/// set. When found in spent output data, they represent outputs that have been
/// consumed by transaction inputs.
///
/// # Thread Safety
///
/// `Coin` is both [`Send`] and [`Sync`].
///
/// # Examples
///
/// ```no_run
/// # use bitcoinkernel::{prelude::*, TransactionSpentOutputs, KernelError};
/// # fn example(tx_spent: &TransactionSpentOutputs) -> Result<(), KernelError> {
/// let coin = tx_spent.coin(0)?;
///
/// println!("Output value: {} satoshis", coin.output().value());
/// println!("Created at height: {}", coin.confirmation_height());
/// println!("Is coinbase: {}", coin.is_coinbase());
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct Coin {
    inner: *mut btck_Coin,
}

unsafe impl Send for Coin {}
unsafe impl Sync for Coin {}

impl Coin {
    pub fn new(output: &TxOut) -> Coin {
        unsafe { Coin::from_ptr(btck_coin_create(output.as_ptr(), 0, 0)) }
    }

    /// Creates a borrowed reference to this coin.
    ///
    /// This allows converting from owned [`Coin`] to [`CoinRef`] without
    /// copying the underlying data.
    ///
    /// # Lifetime
    /// The returned reference is valid for the lifetime of the [`Coin`].
    pub fn as_ref(&self) -> CoinRef<'_> {
        unsafe { CoinRef::from_ptr(self.inner as *const _) }
    }
}

impl AsPtr<btck_Coin> for Coin {
    fn as_ptr(&self) -> *const btck_Coin {
        self.inner as *const _
    }
}

impl FromMutPtr<btck_Coin> for Coin {
    unsafe fn from_ptr(ptr: *mut btck_Coin) -> Self {
        Coin { inner: ptr }
    }
}

impl CoinExt for Coin {}

impl Clone for Coin {
    fn clone(&self) -> Self {
        Coin {
            inner: unsafe { btck_coin_copy(self.inner) },
        }
    }
}

impl Drop for Coin {
    fn drop(&mut self) {
        unsafe { btck_coin_destroy(self.inner) };
    }
}

/// A borrowed reference to a coin.
///
/// This type provides zero-copy access to coin data owned by the underlying
/// C++ library. It implements [`Copy`], making it cheap to pass around.
///
/// # Lifetime
/// The reference is valid only as long as the owner remains alive.
///
/// # Thread Safety
/// `CoinRef` is both [`Send`] and [`Sync`].
pub struct CoinRef<'a> {
    inner: *const btck_Coin,
    marker: PhantomData<&'a ()>,
}

unsafe impl<'a> Send for CoinRef<'a> {}
unsafe impl<'a> Sync for CoinRef<'a> {}

impl<'a> CoinRef<'a> {
    /// Creates an owned copy of this coin.
    ///
    /// This allocates a new [`Coin`] with its own copy of the data.
    pub fn to_owned(&self) -> Coin {
        Coin {
            inner: unsafe { btck_coin_copy(self.inner) },
        }
    }
}

impl<'a> AsPtr<btck_Coin> for CoinRef<'a> {
    fn as_ptr(&self) -> *const btck_Coin {
        self.inner
    }
}

impl<'a> FromPtr<btck_Coin> for CoinRef<'a> {
    unsafe fn from_ptr(ptr: *const btck_Coin) -> Self {
        CoinRef {
            inner: ptr,
            marker: PhantomData,
        }
    }
}

impl<'a> CoinExt for CoinRef<'a> {}

impl<'a> Clone for CoinRef<'a> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a> Copy for CoinRef<'a> {}

#[cfg(test)]
mod tests {

    use super::*;
    use crate::ffi::test_utils::{
        test_owned_clone_and_send, test_owned_trait_requirements, test_ref_trait_requirements,
    };
    use std::{
        fs::File,
        io::{BufRead, BufReader},
    };

    fn read_block_data() -> Vec<Vec<u8>> {
        let file = File::open("tests/block_data.txt").unwrap();
        let reader = BufReader::new(file);
        let mut lines = vec![];
        for line in reader.lines() {
            lines.push(hex::decode(line.unwrap()).unwrap());
        }
        lines
    }

    const VALID_HASH_BYTES1: [u8; 32] = [1u8; 32];
    const VALID_HASH_BYTES2: [u8; 32] = [2u8; 32];

    test_owned_trait_requirements!(test_block_hash_requirements, BlockHash, btck_BlockHash);
    test_ref_trait_requirements!(
        test_block_hash_ref_requirements,
        BlockHashRef<'static>,
        btck_BlockHash
    );

    test_owned_trait_requirements!(test_block_requirements, Block, btck_Block);

    test_owned_trait_requirements!(
        test_block_header_requirements,
        BlockHeader,
        btck_BlockHeader
    );
    test_ref_trait_requirements!(
        test_block_header_ref_requirements,
        BlockHeaderRef<'static>,
        btck_BlockHeader
    );

    test_owned_trait_requirements!(
        test_block_spent_outputs_requirements,
        BlockSpentOutputs,
        btck_BlockSpentOutputs
    );
    test_ref_trait_requirements!(
        test_block_spent_outputs_ref_requirements,
        BlockSpentOutputsRef<'static>,
        btck_BlockSpentOutputs
    );

    test_owned_trait_requirements!(
        test_transaction_spent_outputs_requirements,
        TransactionSpentOutputs,
        btck_TransactionSpentOutputs
    );
    test_ref_trait_requirements!(
        test_transaction_spent_outputs_ref_requirements,
        TransactionSpentOutputsRef<'static>,
        btck_TransactionSpentOutputs
    );

    test_owned_trait_requirements!(test_coin_requirements, Coin, btck_Coin);
    test_ref_trait_requirements!(test_coin_ref_requirements, CoinRef<'static>, btck_Coin);

    test_owned_clone_and_send!(
        test_block_hash_clone_send,
        BlockHash::from(VALID_HASH_BYTES1),
        BlockHash::from(VALID_HASH_BYTES2)
    );

    test_owned_clone_and_send!(
        test_block_clone_send,
        Block::new(&read_block_data()[0]).unwrap(),
        Block::new(&read_block_data()[1]).unwrap()
    );

    test_owned_clone_and_send!(
        test_block_header_clone_send,
        Block::new(&read_block_data()[0]).unwrap().header(),
        Block::new(&read_block_data()[1]).unwrap()
    );

    #[test]
    fn test_blockhash_new() {
        let bytes = [42u8; 32];
        let hash = BlockHash::new(bytes.as_slice());
        assert!(hash.is_ok());
    }

    #[test]
    fn test_blockhash_new_invalid_length() {
        let bytes = [1u8; 31];
        let hash = BlockHash::new(bytes.as_slice());
        assert!(matches!(hash, Err(KernelError::InvalidLength { .. })));
    }

    #[test]
    fn test_blockhash_try_from() {
        let bytes = [7u8; 32];
        let hash = BlockHash::try_from(bytes.as_slice());
        assert!(hash.is_ok());

        let short_bytes = [1u8; 16];
        let hash_err = BlockHash::try_from(short_bytes.as_slice());
        assert!(hash_err.is_err());
    }

    #[test]
    fn test_blockhash_into_array() {
        let original_bytes = VALID_HASH_BYTES1;
        let hash = BlockHash::from(original_bytes);
        let bytes: [u8; 32] = hash.into();
        assert_eq!(bytes, original_bytes);
    }

    #[test]
    fn test_blockhash_ref_into_array() {
        let original_bytes = VALID_HASH_BYTES1;
        let hash = BlockHash::from(original_bytes);
        let bytes: [u8; 32] = (&hash).into();
        assert_eq!(bytes, original_bytes);
    }

    #[test]
    fn test_blockhash_to_bytes() {
        let original_bytes = VALID_HASH_BYTES1;
        let hash = BlockHash::from(original_bytes);
        let bytes = hash.to_bytes();
        assert_eq!(bytes, original_bytes);
    }

    #[test]
    fn test_blockhash_equality() {
        let hash1 = BlockHash::from(VALID_HASH_BYTES1);
        let hash2 = BlockHash::from(VALID_HASH_BYTES2);
        let hash1_copy = BlockHash::from(VALID_HASH_BYTES1);

        assert_eq!(hash1, hash1_copy);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_blockhash_from_blocks() {
        let block_data = read_block_data();

        let block1 = Block::new(&block_data[0]).unwrap();
        let block2 = Block::new(&block_data[1]).unwrap();

        let hash1 = block1.hash();
        let hash2 = block2.hash();
        let hash1_again = block1.hash();

        assert_eq!(hash1, hash1_again);

        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_blockhash_bytes_roundtrip() {
        let original_bytes = VALID_HASH_BYTES1;
        let hash = BlockHash::from(original_bytes);
        let converted_bytes: [u8; 32] = hash.into();

        assert_eq!(original_bytes, converted_bytes);

        let hash2 = BlockHash::from(converted_bytes);
        let hash1_recreated = BlockHash::from(original_bytes);

        assert_eq!(hash1_recreated, hash2);
    }

    #[test]
    fn test_blockhash_debug() {
        let bytes = [5u8; 32];
        let hash = BlockHash::from(bytes);
        let debug_str = format!("{:?}", hash);
        assert!(debug_str.contains("BlockHash"));
    }

    #[test]
    fn test_multiple_conversions() {
        let original_bytes = VALID_HASH_BYTES1;
        let hash = BlockHash::from(original_bytes);

        let bytes1: [u8; 32] = (&hash).into();
        let bytes2: [u8; 32] = (&hash).into();
        let bytes3: [u8; 32] = (&hash).into();

        assert_eq!(bytes1, original_bytes);
        assert_eq!(bytes2, original_bytes);
        assert_eq!(bytes3, original_bytes);
    }

    #[test]
    fn test_block_header_from_block() {
        let block_data = read_block_data();
        let block = Block::new(&block_data[0]).unwrap();
        let block_hash = block.hash();
        let header = block.header();
        assert_eq!(header.hash(), block_hash);
        assert_ne!(header.prev_hash().to_owned(), block_hash);
        assert_eq!(header.timestamp(), 1714234522);
        assert_eq!(header.bits(), 545259519);
        assert_eq!(header.version(), 536870912);
        assert_eq!(header.nonce(), 0);
    }

    #[test]
    fn test_block_header_new() {
        let block_data = read_block_data();
        let block = Block::new(&block_data[0]).unwrap();
        let header = BlockHeader::new(&block_data[0]).unwrap();
        assert_eq!(block.hash(), header.hash());
    }

    #[test]
    fn test_block_new() {
        let block_data = read_block_data();
        let block = Block::new(&block_data[0]);
        assert!(block.is_ok());
    }

    #[test]
    fn test_block_new_invalid() {
        let invalid_data = [0u8; 10];
        let block = Block::new(invalid_data.as_slice());
        assert!(block.is_err());
    }

    #[test]
    fn test_block_empty() {
        let block = Block::new([].as_slice());
        assert!(block.is_err());
    }

    #[test]
    fn test_block_try_from() {
        let block_data = read_block_data();
        let block = Block::try_from(block_data[0].as_slice());
        assert!(block.is_ok());
    }

    #[test]
    fn test_block_transaction_count() {
        let block_data = read_block_data();
        let block = Block::new(&block_data[0]).unwrap();
        let count = block.transaction_count();
        assert!(count > 0);
    }

    #[test]
    fn test_block_transaction() {
        let block_data = read_block_data();
        let block = Block::new(&block_data[0]).unwrap();
        let tx = block.transaction(0);
        assert!(tx.is_ok());
    }

    #[test]
    fn test_block_transaction_out_of_bounds() {
        let block_data = read_block_data();
        let block = Block::new(&block_data[0]).unwrap();
        let count = block.transaction_count();
        let tx = block.transaction(count);
        assert!(matches!(tx, Err(KernelError::OutOfBounds)));
    }

    #[test]
    fn test_block_consensus_encode() {
        let block_data = read_block_data();
        let block = Block::new(&block_data[0]).unwrap();
        let encoded = block.consensus_encode();
        assert!(encoded.is_ok());
        let encoded_bytes = encoded.unwrap();
        assert!(!encoded_bytes.is_empty());
        assert_eq!(encoded_bytes.len(), block_data[0].len());
    }

    #[test]
    fn test_block_multiple_consensus_encode() {
        let block_data = read_block_data();
        let block = Block::new(&block_data[0]).unwrap();

        let bytes1 = block.consensus_encode().unwrap();
        let bytes2 = block.consensus_encode().unwrap();
        let bytes3 = block.consensus_encode().unwrap();

        assert_eq!(bytes1, block_data[0]);
        assert_eq!(bytes2, block_data[0]);
        assert_eq!(bytes3, block_data[0]);
    }

    #[test]
    fn test_block_try_into_vec() {
        let block_data = read_block_data();
        let block = Block::new(&block_data[0]).unwrap();
        let vec_result: Result<Vec<u8>, _> = block.clone().try_into();
        assert!(vec_result.is_ok());
    }

    #[test]
    fn test_block_try_into_vec_ref() {
        let block_data = read_block_data();
        let block = Block::new(&block_data[0]).unwrap();
        let vec_result: Result<Vec<u8>, _> = (&block).try_into();
        assert!(vec_result.is_ok());
    }

    #[test]
    fn test_block_multiple_transactions() {
        let block_data = read_block_data();
        let block = Block::new(&block_data[0]).unwrap();
        let count = block.transaction_count();

        for i in 0..count {
            let tx = block.transaction(i);
            assert!(tx.is_ok());
        }
    }

    #[test]
    fn test_different_blocks_different_hashes() {
        let block_data = read_block_data();

        let block1 = Block::new(&block_data[0]).unwrap();
        let block2 = Block::new(&block_data[1]).unwrap();

        assert_ne!(block1.hash(), block2.hash());
    }

    #[test]
    fn test_block_hash_display() {
        let block = Block::new(
            hex::decode(
                "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd\
                1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299\
                0101000000010000000000000000000000000000000000000000000000000000000000000000ffff\
                ffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec1\
                1600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf62\
                1e73a82cbf2342c858eeac00000000",
            )
            .unwrap()
            .as_slice(),
        )
        .unwrap();

        let block_hash = block.hash().to_owned();

        assert_eq!(
            format!("{block_hash}"),
            "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
        );
    }

    #[test]
    fn test_block_hash_ref_display() {
        let block = Block::new(
            hex::decode(
                "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd\
                1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299\
                0101000000010000000000000000000000000000000000000000000000000000000000000000ffff\
                ffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec1\
                1600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf62\
                1e73a82cbf2342c858eeac00000000",
            )
            .unwrap()
            .as_slice(),
        )
        .unwrap();

        let block_hash_ref = block.hash();

        assert_eq!(
            format!("{block_hash_ref}"),
            "00000000839a8e6886ab5951d76f411475428afc90947ee320161bbf18eb6048"
        );
    }
}
