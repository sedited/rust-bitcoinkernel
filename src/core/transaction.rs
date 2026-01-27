//! Transaction data structures.
//!
//! This module provides types for working with transactions, their inputs, outputs
//! outpoints, and transaction IDs.
//!
//! # Core Types
//!
//! - [`Transaction`] - A complete transaction with inputs and outputs
//! - [`Txid`] - A 32-byte hash uniquely identifying a transaction
//! - [`TxIn`] - A transaction input that spends a previous output
//! - [`TxOut`] - A transaction output containing value and spending conditions
//! - [`TxOutPoint`] - A reference to a specific output in a previous transaction
//!
//! # Common Patterns
//!
//! ## Creating and Working with Transactions
//!
//! Transactions can be created from raw serialized data or retrieved from blocks:
//!
//! ```no_run
//! use bitcoinkernel::{prelude::*, Transaction};
//!
//! # fn example() -> Result<(), bitcoinkernel::KernelError> {
//! let tx_data = vec![0u8; 100]; // placeholder
//! let tx = Transaction::new(&tx_data)?;
//!
//! // Get transaction ID
//! let txid = tx.txid();
//! println!("Transaction ID: {}", txid);
//!
//! // Iterate over inputs and outputs
//! for input in tx.inputs() {
//!     let outpoint = input.outpoint();
//!     println!("Spending {}:{}", outpoint.txid(), outpoint.index());
//! }
//!
//! for output in tx.outputs() {
//!     println!("Output value: {} satoshis", output.value());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Working with Transaction IDs
//!
//! Transaction IDs can be obtained from transactions and inspected as raw bytes
//! or as a hexadecimal string:
//!
//! ```no_run
//! # use bitcoinkernel::{prelude::*, Transaction};
//! # fn example() -> Result<(), bitcoinkernel::KernelError> {
//! # let tx_data = vec![0u8; 100]; // placeholder
//! # let tx = Transaction::new(&tx_data)?;
//! let txid = tx.txid();
//!
//! // Display as hex string (reversed byte order)
//! println!("Txid: {}", txid);
//!
//! // Get raw bytes (internal byte order)
//! let raw_bytes = txid.to_bytes();
//! # Ok(())
//! # }
//! ```
//!
//! ## Creating Transaction Outputs
//!
//! ```no_run
//! use bitcoinkernel::{prelude::*, TxOut, ScriptPubkey};
//!
//! # fn example() -> Result<(), bitcoinkernel::KernelError> {
//! // Create a script pubkey
//! let script = ScriptPubkey::new(&[0x76, 0xa9, 0x14])?;
//!
//! // Create an output with 50,000 satoshis
//! let output = TxOut::new(&script, 50_000);
//!
//! println!("Output value: {} satoshis", output.value());
//! println!("Script: {:?}", output.script_pubkey().to_bytes());
//! # Ok(())
//! # }
//! ```
//!
//! ## Examining Transaction Inputs
//!
//! ```no_run
//! # use bitcoinkernel::{prelude::*, Transaction, KernelError};
//! # fn example(tx: &Transaction) -> Result<(), KernelError> {
//! // Get the first input
//! let input = tx.input(0)?;
//! let outpoint = input.outpoint();
//!
//! // Check if this is a coinbase transaction
//! if outpoint.is_null() {
//!     println!("This is a coinbase transaction");
//! } else {
//!     println!("Spending output {} from transaction {}",
//!              outpoint.index(), outpoint.txid());
//! }
//! # Ok(())
//! # }
//! ```
//!
//! ## Calculating Transaction Statistics
//!
//! ```no_run
//! # use bitcoinkernel::{prelude::*, Transaction};
//! # fn example() -> Result<(), bitcoinkernel::KernelError> {
//! # let tx_data = vec![0u8; 100]; // placeholder
//! # let tx = Transaction::new(&tx_data)?;
//! // Calculate total output value
//! let total: i64 = tx.outputs().map(|out| out.value()).sum();
//! println!("Total output value: {} satoshis", total);
//!
//! // Count outputs above a threshold
//! let large_outputs = tx.outputs()
//!     .filter(|out| out.value() > 1_000_000)
//!     .count();
//! println!("Outputs > 1 BTC: {}", large_outputs);
//! # Ok(())
//! # }
//! ```
//!
//! # Extension Traits
//!
//! The module defines extension traits that provide common functionality for
//! both owned and borrowed types:
//!
//! - [`TransactionExt`] - Operations on transactions
//! - [`TxidExt`] - Operations on transaction IDs
//! - [`TxInExt`] - Operations on transaction inputs
//! - [`TxOutExt`] - Operations on transaction outputs
//! - [`TxOutPointExt`] - Operations on outpoints
//!
//! These traits allow writing generic code that works with either owned or
//! borrowed types.
//!
//! # Iterators
//!
//! Iterator types are provided for traversal:
//!
//! - [`TxInIter`] - Iterates over inputs in a transaction
//! - [`TxOutIter`] - Iterates over outputs in a transaction

use std::{
    ffi::c_void,
    fmt::{self, Debug, Display, Formatter},
    marker::PhantomData,
};

use libbitcoinkernel_sys::{
    btck_Transaction, btck_TransactionInput, btck_TransactionOutPoint, btck_TransactionOutput,
    btck_Txid, btck_transaction_copy, btck_transaction_count_inputs,
    btck_transaction_count_outputs, btck_transaction_create, btck_transaction_destroy,
    btck_transaction_get_input_at, btck_transaction_get_output_at, btck_transaction_get_txid,
    btck_transaction_input_copy, btck_transaction_input_destroy,
    btck_transaction_input_get_out_point, btck_transaction_is_coinbase,
    btck_transaction_out_point_copy, btck_transaction_out_point_destroy,
    btck_transaction_out_point_get_index, btck_transaction_out_point_get_txid,
    btck_transaction_output_copy, btck_transaction_output_create, btck_transaction_output_destroy,
    btck_transaction_output_get_amount, btck_transaction_output_get_script_pubkey,
    btck_transaction_to_bytes, btck_txid_copy, btck_txid_destroy, btck_txid_equals,
    btck_txid_to_bytes,
};

use crate::{
    c_serialize,
    ffi::{
        c_helpers::{self, present},
        sealed::{AsPtr, FromMutPtr, FromPtr},
    },
    KernelError, ScriptPubkeyExt,
};

use super::script::ScriptPubkeyRef;

/// Common operations for transactions, implemented by both owned and borrowed types.
///
/// This trait provides shared functionality for [`Transaction`] and [`TransactionRef`],
/// allowing code to work with either owned or borrowed transactions.
///
/// # Examples
///
/// ```no_run
/// use bitcoinkernel::{prelude::*, Transaction};
///
/// fn count_outputs<T: TransactionExt>(tx: &T) -> usize {
///     tx.output_count()
/// }
///
/// # fn example() -> Result<(), bitcoinkernel::KernelError> {
/// # let tx_data = vec![0u8; 100];
/// let tx = Transaction::new(&tx_data)?;
/// let count = count_outputs(&tx);
/// # Ok(())
/// # }
/// ```
pub trait TransactionExt: AsPtr<btck_Transaction> {
    /// Returns the number of outputs in this transaction.
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::{prelude::*, Transaction};
    /// # fn example() -> Result<(), bitcoinkernel::KernelError> {
    /// # let tx_data = vec![0u8; 100]; // placeholder
    /// # let tx = Transaction::new(&tx_data)?;
    /// println!("Transaction has {} outputs", tx.output_count());
    /// # Ok(())
    /// # }
    /// ```
    fn output_count(&self) -> usize {
        unsafe { btck_transaction_count_outputs(self.as_ptr()) as usize }
    }

    /// Returns a reference to the output at the specified index.
    ///
    /// # Arguments
    /// * `index` - The zero-based index of the output to retrieve
    ///
    /// # Returns
    /// * `Ok([`TxOutRef`])` - A reference to the output
    /// * `Err(KernelError::OutOfBounds)` - If the index is invalid
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::{prelude::*, Transaction, KernelError};
    /// # fn example() -> Result<(), KernelError> {
    /// # let tx_data = vec![0u8; 100]; // placeholder
    /// # let tx = Transaction::new(&tx_data)?;
    /// let first_output = tx.output(0)?;
    /// println!("First output value: {} satoshis", first_output.value());
    /// # Ok(())
    /// # }
    /// ```
    fn output(&self, index: usize) -> Result<TxOutRef<'_>, KernelError> {
        if index >= self.output_count() {
            return Err(KernelError::OutOfBounds);
        }

        let tx_out_ref =
            unsafe { TxOutRef::from_ptr(btck_transaction_get_output_at(self.as_ptr(), index)) };

        Ok(tx_out_ref)
    }

    /// Returns the number of inputs in this transaction.
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::{prelude::*, Transaction};
    /// # fn example() -> Result<(), bitcoinkernel::KernelError> {
    /// # let tx_data = vec![0u8; 100]; // placeholder
    /// # let tx = Transaction::new(&tx_data)?;
    /// println!("Transaction has {} inputs", tx.input_count());
    /// # Ok(())
    /// # }
    /// ```
    fn input_count(&self) -> usize {
        unsafe { btck_transaction_count_inputs(self.as_ptr()) as usize }
    }

    /// Returns a reference to the input at the specified index.
    ///
    /// # Arguments
    /// * `index` - The zero-based index of the input to retrieve
    ///
    /// # Returns
    /// * `Ok([`TxInRef`])` - A reference to the input
    /// * `Err(KernelError::OutOfBounds)` - If the index is invalid
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::{prelude::*, Transaction, KernelError};
    /// # fn example() -> Result<(), KernelError> {
    /// # let tx_data = vec![0u8; 100]; // placeholder
    /// # let tx = Transaction::new(&tx_data)?;
    /// let first_input = tx.input(0)?;
    /// let outpoint = first_input.outpoint();
    /// println!("Spending output {} from transaction {}",
    ///          outpoint.index(), outpoint.txid());
    /// # Ok(())
    /// # }
    /// ```
    fn input(&self, index: usize) -> Result<TxInRef<'_>, KernelError> {
        if index >= self.input_count() {
            return Err(KernelError::OutOfBounds);
        }

        let tx_in_ref =
            unsafe { TxInRef::from_ptr(btck_transaction_get_input_at(self.as_ptr(), index)) };
        Ok(tx_in_ref)
    }

    /// Returns a reference to the transaction ID (txid) of this transaction.
    ///
    /// The txid is the double SHA256 hash of the serialized transaction and serves
    /// as the transaction's unique identifier.
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::{prelude::*, Transaction};
    /// # fn example() -> Result<(), bitcoinkernel::KernelError> {
    /// # let tx_data = vec![0u8; 100]; // placeholder
    /// # let tx = Transaction::new(&tx_data)?;
    /// let txid = tx.txid();
    /// println!("Transaction ID: {}", txid);
    /// # Ok(())
    /// # }
    /// ```
    fn txid(&self) -> TxidRef<'_> {
        let ptr = unsafe { btck_transaction_get_txid(self.as_ptr()) };
        unsafe { TxidRef::from_ptr(ptr) }
    }

    /// Serializes the transaction to Bitcoin wire format.
    ///
    /// Encodes the complete transaction according to Bitcoin consensus rules.
    /// The resulting data can be transmitted over the network or stored to disk.
    ///
    /// # Errors
    /// Returns [`KernelError::Internal`] if serialization fails.
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::{prelude::*, Transaction, KernelError};
    /// # fn example() -> Result<(), KernelError> {
    /// # let tx_data = vec![0u8; 100]; // placeholder
    /// # let tx = Transaction::new(&tx_data)?;
    /// let serialized = tx.consensus_encode()?;
    /// println!("Transaction is {} bytes", serialized.len());
    /// # Ok(())
    /// # }
    /// ```
    fn consensus_encode(&self) -> Result<Vec<u8>, KernelError> {
        c_serialize(|callback, user_data| unsafe {
            btck_transaction_to_bytes(self.as_ptr(), Some(callback), user_data)
        })
    }

    /// Returns an iterator over all inputs in this transaction.
    ///
    /// The iterator yields [`TxInRef`] instances in the order they appear in the
    /// transaction.
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::{prelude::*, Transaction};
    /// # fn example() -> Result<(), bitcoinkernel::KernelError> {
    /// # let tx_data = vec![0u8; 100]; // placeholder
    /// # let tx = Transaction::new(&tx_data)?;
    /// for (i, input) in tx.inputs().enumerate() {
    ///     let outpoint = input.outpoint();
    ///     println!("Input {}: spending output {} from {}",
    ///              i, outpoint.index(), outpoint.txid());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    fn inputs(&self) -> TxInIter<'_> {
        TxInIter::new(unsafe { TransactionRef::from_ptr(self.as_ptr()) })
    }

    /// Returns an iterator over all outputs in this transaction.
    ///
    /// The iterator yields [`TxOutRef`] instances in the order they appear in the
    /// transaction.
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::{prelude::*, Transaction};
    /// # fn example() -> Result<(), bitcoinkernel::KernelError> {
    /// # let tx_data = vec![0u8; 100]; // placeholder
    /// # let tx = Transaction::new(&tx_data)?;
    /// for (i, output) in tx.outputs().enumerate() {
    ///     println!("Output {}: {} satoshis", i, output.value());
    /// }
    /// # Ok(())
    /// # }
    /// ```
    fn outputs(&self) -> TxOutIter<'_> {
        TxOutIter::new(unsafe { TransactionRef::from_ptr(self.as_ptr()) })
    }

    fn is_coinbase(&self) -> bool {
        unsafe { c_helpers::enabled(btck_transaction_is_coinbase(self.as_ptr())) }
    }
}

/// A Bitcoin transaction.
///
/// # Creation
///
/// Transactions are created from:
/// - Raw serialized transaction data using [`new`](Self::new)
/// - Read from Blocks via [`Block::transaction`](crate::Block::transaction)
///
/// # Thread Safety
///
/// `Transaction` is both [`Send`] and [`Sync`], allowing it to be safely shared
/// across threads or moved between threads.
///
/// # Examples
///
/// ```no_run
/// use bitcoinkernel::{prelude::*, Transaction};
///
/// # fn example() -> Result<(), bitcoinkernel::KernelError> {
/// let tx_data = vec![0u8; 100]; // placeholder
/// let tx = Transaction::new(&tx_data)?;
///
/// println!("Transaction ID: {}", tx.txid());
/// println!("Inputs: {}, Outputs: {}", tx.input_count(), tx.output_count());
///
/// // Calculate total output value
/// let total: i64 = tx.outputs().map(|out| out.value()).sum();
/// println!("Total output value: {} satoshis", total);
/// # Ok(())
/// # }
/// ```
pub struct Transaction {
    inner: *mut btck_Transaction,
}

unsafe impl Send for Transaction {}
unsafe impl Sync for Transaction {}

impl Transaction {
    /// Creates a new transaction from raw serialized data.
    ///
    /// Deserializes a transaction from its wire format representation.
    ///
    /// # Arguments
    /// * `transaction_bytes` - The serialized transaction data in Bitcoin wire format
    ///
    /// # Errors
    /// Returns [`KernelError::Internal`] if:
    /// - The data is not a valid transaction
    /// - The data is incomplete
    /// - Deserialization fails
    ///
    /// # Examples
    /// ```no_run
    /// use bitcoinkernel::Transaction;
    ///
    /// # fn example() -> Result<(), bitcoinkernel::KernelError> {
    /// let tx_data = vec![0u8; 100]; // placeholder
    /// let tx = Transaction::new(&tx_data)?;
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(transaction_bytes: &[u8]) -> Result<Self, KernelError> {
        let inner = unsafe {
            btck_transaction_create(
                transaction_bytes.as_ptr() as *const c_void,
                transaction_bytes.len(),
            )
        };

        if inner.is_null() {
            Err(KernelError::Internal(
                "Failed to create transaction from bytes".to_string(),
            ))
        } else {
            Ok(Transaction { inner })
        }
    }

    /// Creates a borrowed reference to this transaction.
    ///
    /// This allows converting from an owned [`Transaction`] to a [`TransactionRef`]
    /// without copying the underlying data.
    ///
    /// # Lifetime
    /// The returned reference is valid for the lifetime of this [`Transaction`].
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::{prelude::*, Transaction};
    /// # fn example() -> Result<(), bitcoinkernel::KernelError> {
    /// # let tx_data = vec![0u8; 100]; // placeholder
    /// # let tx = Transaction::new(&tx_data)?;
    /// let tx_ref = tx.as_ref();
    /// assert_eq!(tx.input_count(), tx_ref.input_count());
    /// # Ok(())
    /// # }
    /// ```
    pub fn as_ref(&self) -> TransactionRef<'_> {
        unsafe { TransactionRef::from_ptr(self.inner as *const _) }
    }
}

impl AsPtr<btck_Transaction> for Transaction {
    fn as_ptr(&self) -> *const btck_Transaction {
        self.inner as *const _
    }
}

impl FromMutPtr<btck_Transaction> for Transaction {
    unsafe fn from_ptr(ptr: *mut btck_Transaction) -> Self {
        Transaction { inner: ptr }
    }
}

impl TransactionExt for Transaction {}

impl Clone for Transaction {
    fn clone(&self) -> Self {
        Transaction {
            inner: unsafe { btck_transaction_copy(self.inner) },
        }
    }
}

impl Drop for Transaction {
    fn drop(&mut self) {
        unsafe { btck_transaction_destroy(self.inner) }
    }
}

impl TryFrom<&[u8]> for Transaction {
    type Error = KernelError;

    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error> {
        Transaction::new(bytes)
    }
}

impl TryFrom<Transaction> for Vec<u8> {
    type Error = KernelError;

    fn try_from(transaction: Transaction) -> Result<Self, Self::Error> {
        transaction.consensus_encode()
    }
}

impl TryFrom<&Transaction> for Vec<u8> {
    type Error = KernelError;

    fn try_from(transaction: &Transaction) -> Result<Self, Self::Error> {
        transaction.consensus_encode()
    }
}

/// A borrowed reference to a transaction.
///
/// Provides zero-copy access to transaction data. It implements [`Copy`],
/// making it cheap to pass around.
///
/// # Lifetime
/// The reference is only valid as long as the data it references remains alive.
///
/// # Thread Safety
/// `TransactionRef` is both [`Send`] and [`Sync`].
pub struct TransactionRef<'a> {
    inner: *const btck_Transaction,
    marker: PhantomData<&'a ()>,
}

unsafe impl<'a> Send for TransactionRef<'a> {}
unsafe impl<'a> Sync for TransactionRef<'a> {}

impl<'a> TransactionRef<'a> {
    /// Creates an owned copy of this transaction.
    ///
    /// This allocates a new [`Transaction`] with its own copy of the transaction data.
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::{prelude::*, Transaction};
    /// # fn example() -> Result<(), bitcoinkernel::KernelError> {
    /// # let tx_data = vec![0u8; 100]; // placeholder
    /// # let tx = Transaction::new(&tx_data)?;
    /// let tx_ref = tx.as_ref();
    /// let owned = tx_ref.to_owned();
    /// assert_eq!(tx.txid(), owned.txid());
    /// # Ok(())
    /// # }
    /// ```
    pub fn to_owned(&self) -> Transaction {
        Transaction {
            inner: unsafe { btck_transaction_copy(self.inner) },
        }
    }
}

impl<'a> AsPtr<btck_Transaction> for TransactionRef<'a> {
    fn as_ptr(&self) -> *const btck_Transaction {
        self.inner
    }
}

impl<'a> FromPtr<btck_Transaction> for TransactionRef<'a> {
    unsafe fn from_ptr(ptr: *const btck_Transaction) -> Self {
        TransactionRef {
            inner: ptr,
            marker: PhantomData,
        }
    }
}
impl<'a> TransactionExt for TransactionRef<'a> {}

impl<'a> Clone for TransactionRef<'a> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a> Copy for TransactionRef<'a> {}

/// Iterator over transaction inputs.
///
/// This iterator yields [`TxInRef`] items for each input in the transaction,
/// in the order they appear in the transaction.
///
/// # Lifetime
/// The iterator is tied to the lifetime of the [`Transaction`] it was created from.
/// The iterator becomes invalid when the transaction is dropped.
///
/// # Examples
/// ```no_run
/// # use bitcoinkernel::{prelude::*, Transaction, KernelError};
/// # fn example() -> Result<(), KernelError> {
/// # let tx_data = vec![0u8; 100]; // placeholder
/// # let tx = Transaction::new(&tx_data)?;
/// // Iterate through all inputs
/// for input in tx.inputs() {
///     let outpoint = input.outpoint();
///     println!("Spending: {}:{}", outpoint.txid(), outpoint.index());
/// }
///
/// // Or with enumerate for explicit indexing
/// for (idx, input) in tx.inputs().enumerate() {
///     println!("Input {}: {}", idx, input.outpoint().txid());
/// }
///
/// // Use iterator adapters
/// let input_count = tx.inputs().count();
/// println!("Transaction has {} inputs", input_count);
/// # Ok(())
/// # }
/// ```
pub struct TxInIter<'a> {
    transaction: TransactionRef<'a>,
    current_index: usize,
}

impl<'a> TxInIter<'a> {
    fn new(transaction: TransactionRef<'a>) -> Self {
        Self {
            transaction,
            current_index: 0,
        }
    }
}

impl<'a> Iterator for TxInIter<'a> {
    type Item = TxInRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_index >= self.transaction.input_count() {
            return None;
        }

        let index = self.current_index;
        self.current_index += 1;

        let tx_in_ptr = unsafe { btck_transaction_get_input_at(self.transaction.as_ptr(), index) };

        if tx_in_ptr.is_null() {
            None
        } else {
            Some(unsafe { TxInRef::from_ptr(tx_in_ptr) })
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self
            .transaction
            .input_count()
            .saturating_sub(self.current_index);
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for TxInIter<'a> {
    fn len(&self) -> usize {
        self.transaction
            .input_count()
            .saturating_sub(self.current_index)
    }
}

/// Iterator over transaction outputs.
///
/// This iterator yields [`TxOutRef`] items for each output in the transaction,
/// in the order they appear in the transaction.
///
/// # Lifetime
/// The iterator is tied to the lifetime of the [`Transaction`] it was created from.
/// The iterator becomes invalid when the transaction is dropped.
///
/// # Examples
/// ```no_run
/// # use bitcoinkernel::{prelude::*, Transaction, KernelError};
/// # fn example() -> Result<(), KernelError> {
/// # let tx_data = vec![0u8; 100]; // placeholder
/// # let tx = Transaction::new(&tx_data)?;
/// // Iterate through all outputs
/// for output in tx.outputs() {
///     println!("Output value: {} satoshis", output.value());
/// }
///
/// // Calculate total output value
/// let total: i64 = tx.outputs()
///     .map(|out| out.value())
///     .sum();
/// println!("Total: {} satoshis", total);
///
/// // Find outputs above a threshold
/// let large_outputs: Vec<_> = tx.outputs()
///     .filter(|out| out.value() > 1_000_000)
///     .collect();
/// # Ok(())
/// # }
/// ```
pub struct TxOutIter<'a> {
    transaction: TransactionRef<'a>,
    current_index: usize,
}

impl<'a> TxOutIter<'a> {
    fn new(transaction: TransactionRef<'a>) -> Self {
        Self {
            transaction,
            current_index: 0,
        }
    }
}

impl<'a> Iterator for TxOutIter<'a> {
    type Item = TxOutRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.current_index >= self.transaction.output_count() {
            return None;
        }

        let index = self.current_index;
        self.current_index += 1;

        let tx_out_ptr =
            unsafe { btck_transaction_get_output_at(self.transaction.as_ptr(), index) };

        if tx_out_ptr.is_null() {
            None
        } else {
            Some(unsafe { TxOutRef::from_ptr(tx_out_ptr) })
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self
            .transaction
            .input_count()
            .saturating_sub(self.current_index);
        (remaining, Some(remaining))
    }
}

impl<'a> ExactSizeIterator for TxOutIter<'a> {
    fn len(&self) -> usize {
        self.transaction
            .output_count()
            .saturating_sub(self.current_index)
    }
}

/// Common operations for transaction outputs, implemented by both owned and borrowed types.
///
/// This trait provides shared functionality for [`TxOut`] and [`TxOutRef`],
/// allowing code to work with either owned or borrowed outputs.
///
/// # Examples
///
/// ```no_run
/// use bitcoinkernel::{prelude::*, TxOut, ScriptPubkey};
///
/// fn print_value<T: TxOutExt>(output: &T) {
///     println!("Output value: {} satoshis", output.value());
/// }
///
/// # fn example() -> Result<(), bitcoinkernel::KernelError> {
/// let script = ScriptPubkey::new(&[0x76, 0xa9])?;
/// let output = TxOut::new(&script, 50000);
/// print_value(&output);
/// # Ok(())
/// # }
/// ```
pub trait TxOutExt: AsPtr<btck_TransactionOutput> {
    /// Returns the amount of this output in satoshis.
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::{prelude::*, TxOut, ScriptPubkey};
    /// # fn example() -> Result<(), bitcoinkernel::KernelError> {
    /// # let script = ScriptPubkey::new(&[0x76, 0xa9])?;
    /// let output = TxOut::new(&script, 50000);
    /// assert_eq!(output.value(), 50000);
    /// # Ok(())
    /// # }
    /// ```
    fn value(&self) -> i64 {
        unsafe { btck_transaction_output_get_amount(self.as_ptr()) }
    }

    /// Returns a reference to the script pubkey that defines how this output can be spent.
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::{prelude::*, TxOut, ScriptPubkey};
    /// # fn example() -> Result<(), bitcoinkernel::KernelError> {
    /// # let script = ScriptPubkey::new(&[0x76, 0xa9])?;
    /// let output = TxOut::new(&script, 50000);
    /// let script_bytes = output.script_pubkey().to_bytes();
    /// println!("Script is {} bytes", script_bytes.len());
    /// # Ok(())
    /// # }
    /// ```
    fn script_pubkey(&self) -> ScriptPubkeyRef<'_> {
        let ptr = unsafe { btck_transaction_output_get_script_pubkey(self.as_ptr()) };
        unsafe { ScriptPubkeyRef::from_ptr(ptr) }
    }
}

/// A single transaction output containing a value and spending conditions.
///
/// Transaction outputs can be created from a script pubkey and amount, or retrieved
/// from existing transactions. They represent spendable coins in the UTXO set.
///
/// # Thread Safety
///
/// `TxOut` is both [`Send`] and [`Sync`].
///
/// # Examples
///
/// ```no_run
/// use bitcoinkernel::{prelude::*, TxOut, ScriptPubkey};
///
/// # fn example() -> Result<(), bitcoinkernel::KernelError> {
/// // Create a new output
/// let script = ScriptPubkey::new(&[0x76, 0xa9, 0x14])?;
/// let output = TxOut::new(&script, 50000);
///
/// println!("Value: {} satoshis", output.value());
/// println!("Script: {:?}", output.script_pubkey().to_bytes());
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct TxOut {
    inner: *mut btck_TransactionOutput,
}

unsafe impl Send for TxOut {}
unsafe impl Sync for TxOut {}

impl TxOut {
    /// Creates a new transaction output with the specified script and amount.
    ///
    /// # Arguments
    /// * `script_pubkey` - The script defining how this output can be spent
    /// * `amount` - The amount in satoshis
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::{prelude::*, TxOut, ScriptPubkey};
    /// # fn example() -> Result<(), bitcoinkernel::KernelError> {
    /// let script = ScriptPubkey::new(&[0x76, 0xa9])?;
    /// let output = TxOut::new(&script, 50000);
    /// assert_eq!(output.value(), 50000);
    /// # Ok(())
    /// # }
    /// ```
    pub fn new(script_pubkey: &impl ScriptPubkeyExt, amount: i64) -> Self {
        TxOut {
            inner: unsafe { btck_transaction_output_create(script_pubkey.as_ptr(), amount) },
        }
    }

    /// Creates a borrowed reference to this output.
    ///
    /// This allows converting from an owned [`TxOut`] to a [`TxOutRef`]
    /// without copying the underlying data.
    ///
    /// # Lifetime
    /// The returned reference is valid for the lifetime of this [`TxOut`].
    pub fn as_ref(&self) -> TxOutRef<'_> {
        unsafe { TxOutRef::from_ptr(self.inner as *const _) }
    }
}

impl AsPtr<btck_TransactionOutput> for TxOut {
    fn as_ptr(&self) -> *const btck_TransactionOutput {
        self.inner as *const _
    }
}

impl FromMutPtr<btck_TransactionOutput> for TxOut {
    unsafe fn from_ptr(ptr: *mut btck_TransactionOutput) -> Self {
        TxOut { inner: ptr }
    }
}

impl TxOutExt for TxOut {}

impl Clone for TxOut {
    fn clone(&self) -> Self {
        TxOut {
            inner: unsafe { btck_transaction_output_copy(self.inner) },
        }
    }
}

impl Drop for TxOut {
    fn drop(&mut self) {
        unsafe { btck_transaction_output_destroy(self.inner) }
    }
}

/// A borrowed reference to a transaction output.
///
/// Provides zero-copy access to output data. It implements [`Copy`],
/// making it cheap to pass around.
///
/// # Lifetime
/// The reference is valid only as long as the data it references remains alive.
///
/// # Thread Safety
/// `TxOutRef` is both [`Send`] and [`Sync`].
pub struct TxOutRef<'a> {
    inner: *const btck_TransactionOutput,
    marker: PhantomData<&'a ()>,
}

unsafe impl<'a> Send for TxOutRef<'a> {}
unsafe impl<'a> Sync for TxOutRef<'a> {}

impl<'a> TxOutRef<'a> {
    /// Creates an owned copy of this output.
    ///
    /// This allocates a new [`TxOut`] with its own copy of the output data.
    pub fn to_owned(&self) -> TxOut {
        TxOut {
            inner: unsafe { btck_transaction_output_copy(self.inner) },
        }
    }
}

impl<'a> AsPtr<btck_TransactionOutput> for TxOutRef<'a> {
    fn as_ptr(&self) -> *const btck_TransactionOutput {
        self.inner as *const _
    }
}

impl<'a> FromPtr<btck_TransactionOutput> for TxOutRef<'a> {
    unsafe fn from_ptr(ptr: *const btck_TransactionOutput) -> Self {
        TxOutRef {
            inner: ptr,
            marker: PhantomData,
        }
    }
}

impl<'a> TxOutExt for TxOutRef<'a> {}

impl<'a> Clone for TxOutRef<'a> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a> Copy for TxOutRef<'a> {}

/// Common operations for transaction inputs, implemented by both owned and borrowed types.
///
/// This trait provides shared functionality for [`TxIn`] and [`TxInRef`],
/// allowing code to work with either owned or borrowed inputs.
///
/// # Examples
///
/// ```no_run
/// use bitcoinkernel::{prelude::*, Transaction};
///
/// fn print_outpoint<T: TxInExt>(input: &T) {
///     let outpoint = input.outpoint();
///     println!("Spending {}:{}", outpoint.txid(), outpoint.index());
/// }
/// ```
pub trait TxInExt: AsPtr<btck_TransactionInput> {
    /// Returns a reference to the outpoint being spent by this input.
    ///
    /// The outpoint identifies which previous transaction output this input is spending
    /// by referencing the transaction ID and output index.
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::{prelude::*, Transaction, KernelError};
    /// # fn example(tx: &Transaction) -> Result<(), KernelError> {
    /// let input = tx.input(0)?;
    /// let outpoint = input.outpoint();
    ///
    /// println!("Spending output {} from transaction {}",
    ///          outpoint.index(),
    ///          outpoint.txid());
    /// # Ok(())
    /// # }
    /// ```
    fn outpoint(&self) -> TxOutPointRef<'_> {
        let ptr = unsafe { btck_transaction_input_get_out_point(self.as_ptr()) };
        unsafe { TxOutPointRef::from_ptr(ptr) }
    }
}

/// A single transaction input referencing a previous output to be spent.
///
/// # Thread Safety
///
/// `TxIn` is both [`Send`] and [`Sync`].
#[derive(Debug)]
pub struct TxIn {
    inner: *mut btck_TransactionInput,
}

unsafe impl Send for TxIn {}
unsafe impl Sync for TxIn {}

impl TxIn {
    /// Creates a borrowed reference to this input.
    ///
    /// This allows converting from an owned [`TxIn`] to a [`TxInRef`]
    /// without copying the underlying data.
    ///
    /// # Lifetime
    /// The returned reference is valid for the lifetime of this [`TxIn`].
    pub fn as_ref(&self) -> TxInRef<'_> {
        unsafe { TxInRef::from_ptr(self.inner as *const _) }
    }
}

impl AsPtr<btck_TransactionInput> for TxIn {
    fn as_ptr(&self) -> *const btck_TransactionInput {
        self.inner as *const _
    }
}

impl FromMutPtr<btck_TransactionInput> for TxIn {
    unsafe fn from_ptr(ptr: *mut btck_TransactionInput) -> Self {
        TxIn { inner: ptr }
    }
}

impl TxInExt for TxIn {}

impl Clone for TxIn {
    fn clone(&self) -> Self {
        TxIn {
            inner: unsafe { btck_transaction_input_copy(self.inner) },
        }
    }
}

impl Drop for TxIn {
    fn drop(&mut self) {
        unsafe { btck_transaction_input_destroy(self.inner) }
    }
}

/// A borrowed reference to a transaction input.
///
/// Provides zero-copy access to input data. It implements [`Copy`],
/// making it cheap to pass around.
///
/// # Lifetime
/// The reference is valid only as long as the data it references remains alive.
///
/// # Thread Safety
/// `TxInRef` is both [`Send`] and [`Sync`].
pub struct TxInRef<'a> {
    inner: *const btck_TransactionInput,
    marker: PhantomData<&'a ()>,
}

unsafe impl<'a> Send for TxInRef<'a> {}
unsafe impl<'a> Sync for TxInRef<'a> {}

impl<'a> TxInRef<'a> {
    /// Creates an owned copy of this transaction input.
    ///
    /// This allocates a new [`TxIn`] with its own copy of the input data.
    pub fn to_owned(&self) -> TxIn {
        TxIn {
            inner: unsafe { btck_transaction_input_copy(self.inner) },
        }
    }
}

impl<'a> AsPtr<btck_TransactionInput> for TxInRef<'a> {
    fn as_ptr(&self) -> *const btck_TransactionInput {
        self.inner as *const _
    }
}

impl<'a> FromPtr<btck_TransactionInput> for TxInRef<'a> {
    unsafe fn from_ptr(ptr: *const btck_TransactionInput) -> Self {
        TxInRef {
            inner: ptr,
            marker: PhantomData,
        }
    }
}

impl<'a> TxInExt for TxInRef<'a> {}

impl<'a> Clone for TxInRef<'a> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a> Copy for TxInRef<'a> {}

/// Common operations for transaction outpoints, implemented by both owned and borrowed types.
///
/// This trait provides shared functionality for [`TxOutPoint`] and [`TxOutPointRef`],
/// allowing code to work with either owned or borrowed outpoints.
///
/// # Examples
///
/// ```no_run
/// use bitcoinkernel::{prelude::*, Transaction};
///
/// fn is_coinbase<T: TxOutPointExt>(outpoint: &T) -> bool {
///     outpoint.is_null()
/// }
/// ```
pub trait TxOutPointExt: AsPtr<btck_TransactionOutPoint> {
    /// Returns the output index within the referenced transaction.
    ///
    /// This is the zero-based index of the output in the transaction's output list.
    ///
    /// # Special Value
    /// Returns `u32::MAX` (0xFFFFFFFF) for coinbase transactions, indicating a null outpoint.
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::{prelude::*, Transaction, KernelError};
    /// # fn example(tx: &Transaction) -> Result<(), KernelError> {
    /// let input = tx.input(0)?;
    /// let outpoint = input.outpoint();
    /// println!("Spending output at index {}", outpoint.index());
    /// # Ok(())
    /// # }
    /// ```
    fn index(&self) -> u32 {
        unsafe { btck_transaction_out_point_get_index(self.as_ptr()) }
    }

    /// Returns a reference to the transaction ID of the transaction containing this output.
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::{prelude::*, Transaction, KernelError};
    /// # fn example(tx: &Transaction) -> Result<(), KernelError> {
    /// let input = tx.input(0)?;
    /// let outpoint = input.outpoint();
    /// println!("Previous transaction: {}", outpoint.txid());
    /// # Ok(())
    /// # }
    /// ```
    fn txid(&self) -> TxidRef<'_> {
        let ptr = unsafe { btck_transaction_out_point_get_txid(self.as_ptr()) };
        unsafe { TxidRef::from_ptr(ptr) }
    }

    /// Returns true if this outpoint is the "null" coinbase outpoint.
    ///
    /// A null outpoint has:
    /// - Index: `u32::MAX` (0xFFFFFFFF)
    /// - Txid: All zeros
    ///
    /// This indicates a coinbase transaction input, which creates new coins rather
    /// than spending existing outputs.
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::{prelude::*, Transaction, KernelError};
    /// # fn example(tx: &Transaction) -> Result<(), KernelError> {
    /// let input = tx.input(0)?;
    /// let outpoint = input.outpoint();
    ///
    /// if outpoint.is_null() {
    ///     println!("This is a coinbase transaction");
    /// } else {
    ///     println!("This transaction spends existing outputs");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    fn is_null(&self) -> bool {
        self.index() == u32::MAX && self.txid().is_all_zeros()
    }
}

/// A reference to a specific output in a previous transaction.
///
/// An outpoint uniquely identifies a transaction output by combining a transaction ID
/// with an output index. Outpoints are used in transaction inputs to specify which
/// previous outputs are being spent.
///
/// # Structure
///
/// Each outpoint contains:
/// - **Txid**: The transaction ID (32-byte hash)
/// - **Index**: The zero-based index of the output in that transaction
///
/// # Special Case: Coinbase
///
/// Coinbase transaction inputs use a "null" outpoint where the txid is all zeros and
/// the index is `u32::MAX`. Use [`is_null`](TxOutPointExt::is_null) to check for this.
///
/// # Thread Safety
///
/// `TxOutPoint` is both [`Send`] and [`Sync`].
///
/// # Examples
///
/// ```no_run
/// use bitcoinkernel::{prelude::*, Transaction};
///
/// # fn example() -> Result<(), bitcoinkernel::KernelError> {
/// # let tx_data = vec![0u8; 100]; // placeholder
/// # let tx = Transaction::new(&tx_data)?;
/// let input = tx.input(0)?;
/// let outpoint = input.outpoint();
///
/// if outpoint.is_null() {
///     println!("Coinbase transaction");
/// } else {
///     println!("Spending {}:{}", outpoint.txid(), outpoint.index());
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug)]
pub struct TxOutPoint {
    inner: *mut btck_TransactionOutPoint,
}

unsafe impl Send for TxOutPoint {}
unsafe impl Sync for TxOutPoint {}

impl TxOutPoint {
    /// Returns a borrowed reference to this outpoint.
    ///
    /// This allows converting from an owned [`TxOutPoint`] to a [`TxOutPointRef`]
    /// without copying the underlying data.
    ///
    /// # Lifetime
    /// The returned reference is valid for the lifetime of this [`TxOutPoint`].
    pub fn as_ref(&self) -> TxOutPointRef<'_> {
        unsafe { TxOutPointRef::from_ptr(self.inner as *const _) }
    }
}

impl AsPtr<btck_TransactionOutPoint> for TxOutPoint {
    fn as_ptr(&self) -> *const btck_TransactionOutPoint {
        self.inner as *const _
    }
}

impl FromMutPtr<btck_TransactionOutPoint> for TxOutPoint {
    unsafe fn from_ptr(ptr: *mut btck_TransactionOutPoint) -> Self {
        TxOutPoint { inner: ptr }
    }
}

impl TxOutPointExt for TxOutPoint {}

impl Clone for TxOutPoint {
    fn clone(&self) -> Self {
        TxOutPoint {
            inner: unsafe { btck_transaction_out_point_copy(self.inner) },
        }
    }
}

impl Drop for TxOutPoint {
    fn drop(&mut self) {
        unsafe { btck_transaction_out_point_destroy(self.inner) }
    }
}

/// A borrowed reference to an outpoint.
///
/// Provides zero-copy access to outpoint data. It implements [`Copy`],
/// making it cheap to pass around.
///
/// # Lifetime
/// The reference is valid only as long as the data it references remains alive.
///
/// # Thread Safety
/// `TxOutPointRef` is both [`Send`] and [`Sync`].
pub struct TxOutPointRef<'a> {
    inner: *const btck_TransactionOutPoint,
    marker: PhantomData<&'a ()>,
}

unsafe impl<'a> Send for TxOutPointRef<'a> {}
unsafe impl<'a> Sync for TxOutPointRef<'a> {}

impl<'a> TxOutPointRef<'a> {
    /// Creates an owned copy of this outpoint.
    ///
    /// This allocates a new [`TxOutPoint`] with its own copy of the outpoint data.
    pub fn to_owned(&self) -> TxOutPoint {
        TxOutPoint {
            inner: unsafe { btck_transaction_out_point_copy(self.inner) },
        }
    }
}

impl<'a> AsPtr<btck_TransactionOutPoint> for TxOutPointRef<'a> {
    fn as_ptr(&self) -> *const btck_TransactionOutPoint {
        self.inner as *const _
    }
}

impl<'a> FromPtr<btck_TransactionOutPoint> for TxOutPointRef<'a> {
    unsafe fn from_ptr(ptr: *const btck_TransactionOutPoint) -> Self {
        TxOutPointRef {
            inner: ptr,
            marker: PhantomData,
        }
    }
}

impl<'a> TxOutPointExt for TxOutPointRef<'a> {}

impl<'a> Clone for TxOutPointRef<'a> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a> Copy for TxOutPointRef<'a> {}

/// Common operations for transaction IDs, implemented by both owned and borrowed types.
///
/// This trait provides shared functionality for [`Txid`] and [`TxidRef`],
/// allowing code to work with either owned or borrowed transaction IDs.
///
/// # Examples
///
/// ```no_run
/// use bitcoinkernel::{prelude::*, Transaction};
///
/// fn print_txid<T: TxidExt>(txid: &T) {
///     println!("Transaction ID: {}", txid);
/// }
/// ```
pub trait TxidExt: AsPtr<btck_Txid> + Display {
    /// Serializes the txid to raw bytes.
    ///
    /// Returns the 32-byte representation of the transaction ID in internal byte order.
    ///
    /// # Byte Order
    /// The bytes are in internal order.
    ///
    /// # Returns
    /// A 32-byte array containing the transaction ID.
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::{prelude::*, Transaction};
    /// # fn example() -> Result<(), bitcoinkernel::KernelError> {
    /// # let tx_data = vec![0u8; 100]; // placeholder
    /// # let tx = Transaction::new(&tx_data)?;
    /// let txid = tx.txid();
    /// let bytes = txid.to_bytes();
    /// assert_eq!(bytes.len(), 32);
    /// # Ok(())
    /// # }
    /// ```
    fn to_bytes(&self) -> [u8; 32] {
        let mut bytes = [0u8; 32];
        unsafe {
            btck_txid_to_bytes(self.as_ptr(), bytes.as_mut_ptr());
        }
        bytes
    }

    /// Returns true if all bytes of the txid are zero (null txid).
    ///
    /// A null txid (all zeros) is used in coinbase transaction outpoints to indicate
    /// that no previous output is being spent.
    ///
    /// # Examples
    /// ```no_run
    /// # use bitcoinkernel::{prelude::*, Transaction, KernelError};
    /// # fn example(tx: &Transaction) -> Result<(), KernelError> {
    /// let input = tx.input(0)?;
    /// let outpoint = input.outpoint();
    /// let txid = outpoint.txid();
    ///
    /// if txid.is_all_zeros() {
    ///     println!("This is a null txid (coinbase)");
    /// }
    /// # Ok(())
    /// # }
    /// ```
    fn is_all_zeros(&self) -> bool {
        self.to_bytes().iter().all(|&b| b == 0)
    }
}

/// A 32-byte hash uniquely identifying a transaction.
///
/// Transaction IDs are the double SHA256 hash of the serialized transaction and
/// serve as the transaction's unique identifier.
///
/// # Byte Order
///
/// Bitcoin uses two different representations of transaction IDs:
/// - **Internal byte order**: Used in memory, on disk, and for hashing
/// - **Display byte order**: Reversed for human-readable hex strings
///
/// The [`to_bytes`](TxidExt::to_bytes) method returns internal byte order,
/// while [`Display`] formatting shows the reversed bytes.
///
/// # Thread Safety
///
/// `Txid` is both [`Send`] and [`Sync`], allowing it to be safely
/// shared across threads.
///
/// # Examples
///
/// ```no_run
/// use bitcoinkernel::{prelude::*, Transaction};
///
/// # fn example() -> Result<(), bitcoinkernel::KernelError> {
/// # let tx_data = vec![0u8; 100]; // placeholder
/// let tx = Transaction::new(&tx_data)?;
/// let txid = tx.txid().to_owned();
///
/// // Display as hex (reversed byte order)
/// println!("Transaction: {}", txid);
///
/// // Get internal representation
/// let bytes = txid.to_bytes();
/// # Ok(())
/// # }
/// ```
pub struct Txid {
    inner: *mut btck_Txid,
}

unsafe impl Send for Txid {}
unsafe impl Sync for Txid {}

impl Txid {
    /// Creates a borrowed reference to this transaction ID.
    ///
    /// This allows converting from an owned [`Txid`] to a [`TxidRef`]
    /// without copying the underlying data.
    ///
    /// # Lifetime
    /// The returned reference is valid for the lifetime of this [`Txid`].
    pub fn as_ref(&self) -> TxidRef<'_> {
        unsafe { TxidRef::from_ptr(self.inner as *const _) }
    }
}

impl AsPtr<btck_Txid> for Txid {
    fn as_ptr(&self) -> *const btck_Txid {
        self.inner as *const _
    }
}

impl FromMutPtr<btck_Txid> for Txid {
    unsafe fn from_ptr(ptr: *mut btck_Txid) -> Self {
        Txid { inner: ptr }
    }
}

impl TxidExt for Txid {}

impl Clone for Txid {
    fn clone(&self) -> Self {
        Txid {
            inner: unsafe { btck_txid_copy(self.inner) },
        }
    }
}

impl Drop for Txid {
    fn drop(&mut self) {
        unsafe { btck_txid_destroy(self.inner) }
    }
}

impl PartialEq for Txid {
    fn eq(&self, other: &Self) -> bool {
        present(unsafe { btck_txid_equals(self.inner, other.inner) })
    }
}

impl PartialEq<TxidRef<'_>> for Txid {
    fn eq(&self, other: &TxidRef<'_>) -> bool {
        present(unsafe { btck_txid_equals(self.inner, other.inner) })
    }
}

impl Eq for Txid {}

impl Debug for Txid {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Txid({:?})", self.to_bytes())
    }
}

impl Display for Txid {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let bytes = self.to_bytes();
        for byte in bytes.iter().rev() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

/// A borrowed reference to a transaction ID.
///
/// Provides zero-copy access to transaction ID data. It implements [`Copy`],
/// making it cheap to pass around.
///
/// # Lifetime
/// The reference is valid only as long as the data it references remains alive.
///
/// # Thread Safety
/// `TxidRef` is both [`Send`] and [`Sync`].
pub struct TxidRef<'a> {
    inner: *const btck_Txid,
    marker: PhantomData<&'a ()>,
}

unsafe impl<'a> Send for TxidRef<'a> {}
unsafe impl<'a> Sync for TxidRef<'a> {}

impl<'a> TxidRef<'a> {
    /// Creates an owned copy of this transaction ID.
    ///
    /// This allocates a new [`Txid`] with its own copy of the ID data.
    pub fn to_owned(&self) -> Txid {
        Txid {
            inner: unsafe { btck_txid_copy(self.inner) },
        }
    }
}

impl<'a> AsPtr<btck_Txid> for TxidRef<'a> {
    fn as_ptr(&self) -> *const btck_Txid {
        self.inner as *const _
    }
}

impl<'a> FromPtr<btck_Txid> for TxidRef<'a> {
    unsafe fn from_ptr(ptr: *const btck_Txid) -> Self {
        TxidRef {
            inner: ptr,
            marker: PhantomData,
        }
    }
}

impl<'a> TxidExt for TxidRef<'a> {}

impl<'a> Clone for TxidRef<'a> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a> Copy for TxidRef<'a> {}

impl<'a> PartialEq for TxidRef<'a> {
    fn eq(&self, other: &Self) -> bool {
        present(unsafe { btck_txid_equals(self.inner, other.inner) })
    }
}

impl<'a> Eq for TxidRef<'a> {}

impl PartialEq<Txid> for TxidRef<'_> {
    fn eq(&self, other: &Txid) -> bool {
        present(unsafe { btck_txid_equals(self.inner, other.inner) })
    }
}

impl<'a> Debug for TxidRef<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "Txid({:?})", self.to_bytes())
    }
}

impl<'a> Display for TxidRef<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let bytes = self.to_bytes();
        for byte in bytes.iter().rev() {
            write!(f, "{:02x}", byte)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ffi::test_utils::{
        test_owned_clone_and_send, test_owned_trait_requirements, test_ref_copy,
        test_ref_trait_requirements,
    };
    use crate::{Block, ScriptPubkey};
    use std::fs::File;
    use std::io::{BufRead, BufReader};

    fn read_block_data() -> Vec<Vec<u8>> {
        let file = File::open("tests/block_data.txt").unwrap();
        let reader = BufReader::new(file);
        let mut lines = vec![];
        for line in reader.lines() {
            lines.push(hex::decode(line.unwrap()).unwrap());
        }
        lines
    }

    fn get_test_transactions() -> (Transaction, Transaction) {
        let block_data = read_block_data();
        let tx1 = Block::new(&block_data[204])
            .unwrap()
            .transaction(1)
            .unwrap()
            .to_owned();
        let tx2 = Block::new(&block_data[205])
            .unwrap()
            .transaction(1)
            .unwrap()
            .to_owned();
        (tx1, tx2)
    }

    fn get_test_coinbase_transactions() -> (Transaction, Transaction) {
        let block_data = read_block_data();
        let tx1 = Block::new(&block_data[204])
            .unwrap()
            .transaction(0)
            .unwrap()
            .to_owned();
        let tx2 = Block::new(&block_data[205])
            .unwrap()
            .transaction(0)
            .unwrap()
            .to_owned();
        (tx1, tx2)
    }

    fn get_test_txids() -> (Txid, Txid) {
        let (tx1, tx2) = get_test_transactions();
        (tx1.txid().to_owned(), tx2.txid().to_owned())
    }

    fn get_test_txins() -> (TxIn, TxIn) {
        let (tx1, tx2) = get_test_transactions();
        (
            tx1.as_ref().input(0).unwrap().to_owned(),
            tx2.as_ref().input(0).unwrap().to_owned(),
        )
    }

    fn get_test_txoutpoints() -> (TxOutPoint, TxOutPoint) {
        let (txin1, txin2) = get_test_txins();
        (txin1.outpoint().to_owned(), txin2.outpoint().to_owned())
    }

    test_owned_trait_requirements!(test_transaction_requirements, Transaction, btck_Transaction);
    test_ref_trait_requirements!(
        test_transaction_ref_requirements,
        TransactionRef<'static>,
        btck_Transaction
    );
    test_owned_clone_and_send!(
        test_transaction_clone_send,
        get_test_transactions().0,
        get_test_transactions().1
    );
    test_ref_copy!(test_transaction_ref_behavior, get_test_transactions().0);

    test_owned_trait_requirements!(test_txout_requirements, TxOut, btck_TransactionOutput);
    test_ref_trait_requirements!(
        test_txout_ref_requirements,
        TxOutRef<'static>,
        btck_TransactionOutput
    );
    test_owned_clone_and_send!(
        test_txout_clone_send,
        TxOut::new(&ScriptPubkey::new(&[0x76, 0xa9]).unwrap(), 100),
        TxOut::new(&ScriptPubkey::new(&[0x51]).unwrap(), 200)
    );
    test_ref_copy!(
        test_txout_ref_copy,
        TxOut::new(&ScriptPubkey::new(&[0x76, 0xa9]).unwrap(), 100)
    );

    test_owned_trait_requirements!(test_txin_requirements, TxIn, btck_TransactionInput);
    test_ref_trait_requirements!(
        test_txin_ref_requirements,
        TxInRef<'static>,
        btck_TransactionInput
    );
    test_owned_clone_and_send!(test_txin_clone_send, get_test_txins().0, get_test_txins().1);
    test_ref_copy!(test_txin_ref_copy, get_test_txins().0);

    test_owned_trait_requirements!(
        test_txoutpoint_requirements,
        TxOutPoint,
        btck_TransactionOutPoint
    );
    test_ref_trait_requirements!(
        test_txoutpoint_ref_requirements,
        TxOutPointRef<'static>,
        btck_TransactionOutPoint
    );
    test_owned_clone_and_send!(
        test_txoutpoint_clone_send,
        get_test_txoutpoints().0,
        get_test_txoutpoints().1
    );
    test_ref_copy!(test_txoutpoint_ref_copy, get_test_txoutpoints().0);

    test_owned_trait_requirements!(test_txid_requirements, Txid, btck_Txid);
    test_ref_trait_requirements!(test_txid_ref_requirements, TxidRef<'static>, btck_Txid);
    test_owned_clone_and_send!(test_txid_clone_send, get_test_txids().0, get_test_txids().1);
    test_ref_copy!(test_txid_ref_copy, get_test_txids().0);

    #[test]
    fn test_transaction_new() {
        let (tx, _) = get_test_transactions();
        let encoded = tx.consensus_encode().unwrap();
        let new_tx = Transaction::new(&encoded);
        assert!(new_tx.is_ok());
    }

    #[test]
    fn test_transaction_new_invalid() {
        let invalid_data = [0xFF; 10];
        let tx = Transaction::new(invalid_data.as_slice());
        assert!(tx.is_err());
    }

    #[test]
    fn test_transaction_empty() {
        let tx = Transaction::new([].as_slice());
        assert!(tx.is_err());
    }

    #[test]
    fn test_transaction_try_from() {
        let (tx, _) = get_test_transactions();
        let encoded = tx.consensus_encode().unwrap();
        let new_tx = Transaction::try_from(encoded.as_slice());
        assert!(new_tx.is_ok());
    }

    #[test]
    fn test_transaction_output_count() {
        let (tx, _) = get_test_transactions();
        let count = tx.output_count();
        assert!(count > 0);
    }

    #[test]
    fn test_transaction_input_count() {
        let (tx, _) = get_test_transactions();
        let count = tx.input_count();
        assert!(count > 0);
    }

    #[test]
    fn test_transaction_output() {
        let (tx, _) = get_test_transactions();
        let output = tx.output(0);
        assert!(output.is_ok());
    }

    #[test]
    fn test_transaction_output_out_of_bounds() {
        let (tx, _) = get_test_transactions();
        let count = tx.output_count();
        let output = tx.output(count);
        assert!(matches!(output, Err(KernelError::OutOfBounds)));
    }

    #[test]
    fn test_transaction_input() {
        let (tx, _) = get_test_transactions();
        let input = tx.input(0);
        assert!(input.is_ok());
    }

    #[test]
    fn test_transaction_input_out_of_bounds() {
        let (tx, _) = get_test_transactions();
        let count = tx.input_count();
        let input = tx.input(count);
        assert!(matches!(input, Err(KernelError::OutOfBounds)));
    }

    #[test]
    fn test_transaction_txid() {
        let (tx, _) = get_test_transactions();
        let txid1 = tx.txid();
        let txid2 = tx.txid();
        assert_eq!(txid1, txid2);
    }

    #[test]
    fn test_transaction_consensus_encode() {
        let (tx, _) = get_test_transactions();
        let encoded = tx.consensus_encode();
        assert!(encoded.is_ok());
        let encoded_bytes = encoded.unwrap();
        assert!(!encoded_bytes.is_empty());
    }

    #[test]
    fn test_transaction_multiple_consensus_encode() {
        let (tx, _) = get_test_transactions();

        let bytes1 = tx.consensus_encode().unwrap();
        let bytes2 = tx.consensus_encode().unwrap();
        let bytes3 = tx.consensus_encode().unwrap();

        assert_eq!(bytes1, bytes2);
        assert_eq!(bytes2, bytes3);
    }

    #[test]
    fn test_transaction_try_into_vec() {
        let (tx, _) = get_test_transactions();
        let vec_result: Result<Vec<u8>, _> = tx.clone().try_into();
        assert!(vec_result.is_ok());
    }

    #[test]
    fn test_transaction_try_into_vec_ref() {
        let (tx, _) = get_test_transactions();
        let vec_result: Result<Vec<u8>, _> = (&tx).try_into();
        assert!(vec_result.is_ok());
    }

    #[test]
    fn test_transaction_as_ref() {
        let (tx, _) = get_test_transactions();
        let tx_ref = tx.as_ref();

        assert_eq!(tx.output_count(), tx_ref.output_count());
        assert_eq!(tx.input_count(), tx_ref.input_count());
    }

    #[test]
    fn test_transaction_ref_to_owned() {
        let (tx, _) = get_test_transactions();
        let tx_ref = tx.as_ref();
        let owned_tx = tx_ref.to_owned();

        assert_eq!(tx.output_count(), owned_tx.output_count());
        assert_eq!(tx.input_count(), owned_tx.input_count());
    }

    #[test]
    fn test_transaction_multiple_outputs() {
        let (tx, _) = get_test_transactions();
        let count = tx.output_count();

        for i in 0..count {
            let output = tx.output(i);
            assert!(output.is_ok());
        }
    }

    #[test]
    fn test_transaction_multiple_inputs() {
        let (tx, _) = get_test_transactions();
        let count = tx.input_count();

        for i in 0..count {
            let input = tx.input(i);
            assert!(input.is_ok());
        }
    }

    #[test]
    fn test_different_transactions_different_txids() {
        let (tx1, tx2) = get_test_transactions();
        assert_ne!(tx1.txid(), tx2.txid());
    }

    // TxOut tests
    #[test]
    fn test_txout_new() {
        let script = ScriptPubkey::new([0x76, 0xa9].as_slice()).unwrap();
        let txout = TxOut::new(&script, 100);
        assert_eq!(txout.value(), 100);
    }

    #[test]
    fn test_txout_value() {
        let script = ScriptPubkey::new([0x51].as_slice()).unwrap();
        let amount = 50000;
        let txout = TxOut::new(&script, amount);
        assert_eq!(txout.value(), amount);
    }

    #[test]
    fn test_txout_script_pubkey() {
        let script_data = vec![0x76, 0xa9, 0x14];
        let script = ScriptPubkey::new(&script_data).unwrap();
        let txout = TxOut::new(&script, 100);

        let retrieved_script = txout.script_pubkey();
        assert_eq!(retrieved_script.to_bytes(), script_data);
    }

    #[test]
    fn test_txout_as_ref() {
        let script = ScriptPubkey::new([0x76, 0xa9].as_slice()).unwrap();
        let txout = TxOut::new(&script, 100);
        let txout_ref = txout.as_ref();

        assert_eq!(txout.value(), txout_ref.value());
    }

    #[test]
    fn test_txout_ref_to_owned() {
        let script = ScriptPubkey::new([0x76, 0xa9].as_slice()).unwrap();
        let txout = TxOut::new(&script, 100);
        let txout_ref = txout.as_ref();
        let owned_txout = txout_ref.to_owned();

        assert_eq!(txout.value(), owned_txout.value());
    }

    #[test]
    fn test_txout_zero_value() {
        let script = ScriptPubkey::new([0x51].as_slice()).unwrap();
        let txout = TxOut::new(&script, 0);
        assert_eq!(txout.value(), 0);
    }

    #[test]
    fn test_txout_large_value() {
        let script = ScriptPubkey::new([0x51].as_slice()).unwrap();
        let amount = 21_000_000 * 100_000_000i64;
        let txout = TxOut::new(&script, amount);
        assert_eq!(txout.value(), amount);
    }

    #[test]
    fn test_txout_from_transaction() {
        let (tx, _) = get_test_transactions();
        let txout = tx.output(0).unwrap();

        assert!(txout.value() >= 0);
        let script_bytes = txout.script_pubkey().to_bytes();
        assert!(!script_bytes.is_empty());
    }

    // TxIn tests
    #[test]
    fn test_txin_from_transaction() {
        let (tx, _) = get_test_transactions();
        let txin = tx.input(0).unwrap();
        let outpoint = txin.outpoint();

        let _ = outpoint.index();
        let _ = outpoint.txid();
    }

    #[test]
    fn test_txin_as_ref() {
        let (tx, _) = get_test_transactions();
        let txin = tx.input(0).unwrap().to_owned();
        let txin_ref = txin.as_ref();

        assert_eq!(txin.outpoint().index(), txin_ref.outpoint().index());
    }

    #[test]
    fn test_txin_ref_to_owned() {
        let (tx, _) = get_test_transactions();
        let txin = tx.input(0).unwrap().to_owned();
        let txin_ref = txin.as_ref();
        let owned_txin = txin_ref.to_owned();

        assert_eq!(txin.outpoint().index(), owned_txin.outpoint().index());
    }

    // TxOutPoint tests
    #[test]
    fn test_txoutpoint_index() {
        let (tx, _) = get_test_transactions();
        let txin = tx.input(0).unwrap();
        let outpoint = txin.outpoint();

        let index = outpoint.index();
        assert_eq!(index, 0);
    }

    #[test]
    fn test_txoutpoint_coinbase_is_null() {
        let (tx, _) = get_test_coinbase_transactions();
        let txin = tx.input(0).unwrap();
        let outpoint_ref = txin.outpoint();
        let outpoint = outpoint_ref.to_owned();

        assert!(outpoint_ref.is_null());
        assert_eq!(outpoint_ref.index(), u32::MAX);
        assert!(outpoint_ref.txid().is_all_zeros());

        assert!(outpoint.is_null());
        assert_eq!(outpoint.index(), u32::MAX);
        assert!(outpoint.txid().is_all_zeros());
    }

    #[test]
    fn test_txoutpoint_is_null() {
        let (tx, _) = get_test_transactions();
        let txin = tx.input(0).unwrap();
        let outpoint_ref = txin.outpoint();
        let outpoint = outpoint_ref.to_owned();

        assert!(!outpoint_ref.is_null());
        assert!(!outpoint.is_null());
    }

    #[test]
    fn test_txoutpoint_txid() {
        let (tx, _) = get_test_transactions();
        let txin = tx.input(0).unwrap();
        let outpoint = txin.outpoint();

        let txid1 = outpoint.txid();
        let txid2 = outpoint.txid();
        assert_eq!(txid1, txid2);
    }

    #[test]
    fn test_txoutpoint_as_ref() {
        let (tx, _) = get_test_transactions();
        let txin = tx.input(0).unwrap();
        let outpoint = txin.outpoint().to_owned();
        let outpoint_ref = outpoint.as_ref();

        assert_eq!(outpoint.index(), outpoint_ref.index());
    }

    #[test]
    fn test_txoutpoint_ref_to_owned() {
        let (tx, _) = get_test_transactions();
        let txin = tx.input(0).unwrap();
        let outpoint = txin.outpoint().to_owned();
        let outpoint_ref = outpoint.as_ref();
        let owned_outpoint = outpoint_ref.to_owned();

        assert_eq!(outpoint.index(), owned_outpoint.index());
    }

    // Txid tests
    #[test]
    fn test_txid_equality() {
        let (tx1, tx2) = get_test_transactions();

        let txid1 = tx1.txid().to_owned();
        let txid2 = tx2.txid().to_owned();
        let txid1_copy = tx1.txid().to_owned();

        assert_eq!(txid1, txid1_copy,);
        assert_ne!(txid1, txid2,);

        let txid1_ref = txid1.as_ref();
        assert_eq!(txid1, txid1_ref,);
        assert_eq!(txid1_ref, txid1,);

        let txid2_ref = txid2.as_ref();
        assert_eq!(txid1_ref, txid1_ref);
        assert_ne!(txid1_ref, txid2_ref,);
    }

    #[test]
    fn test_txid_to_bytes() {
        let (tx, _) = get_test_transactions();
        let txid = tx.txid().to_owned();
        let bytes = txid.to_bytes();

        assert_eq!(bytes.len(), 32);
    }

    #[test]
    fn test_txid_multiple_to_bytes() {
        let (tx, _) = get_test_transactions();
        let txid = tx.txid().to_owned();

        let bytes1 = txid.to_bytes();
        let bytes2 = txid.to_bytes();
        let bytes3 = txid.to_bytes();

        assert_eq!(bytes1, bytes2);
        assert_eq!(bytes2, bytes3);
    }

    #[test]
    fn test_txid_as_ref() {
        let (tx, _) = get_test_transactions();
        let txid = tx.txid().to_owned();
        let txid_ref = txid.as_ref();

        assert_eq!(txid.to_bytes(), txid_ref.to_bytes());
    }

    #[test]
    fn test_txid_ref_to_owned() {
        let (tx, _) = get_test_transactions();
        let txid = tx.txid().to_owned();
        let txid_ref = txid.as_ref();
        let owned_txid = txid_ref.to_owned();

        assert_eq!(txid.to_bytes(), owned_txid.to_bytes());
    }

    #[test]
    fn test_txid_is_all_zeros() {
        let (tx, _) = get_test_transactions();
        let txid = tx.txid().to_owned();
        let txid_ref = txid.as_ref();

        assert!(!txid.is_all_zeros());
        assert!(!txid_ref.is_all_zeros());
    }

    // Polymorphism tests
    #[test]
    fn test_transaction_polymorphism() {
        let (tx, _) = get_test_transactions();
        let tx_ref = tx.as_ref();

        fn get_output_count(transaction: &impl TransactionExt) -> usize {
            transaction.output_count()
        }

        let count_from_owned = get_output_count(&tx);
        let count_from_ref = get_output_count(&tx_ref);

        assert_eq!(count_from_owned, count_from_ref);
    }

    #[test]
    fn test_txout_polymorphism() {
        let script = ScriptPubkey::new([0x76, 0xa9].as_slice()).unwrap();
        let txout = TxOut::new(&script, 100);
        let txout_ref = txout.as_ref();

        fn get_value(output: &impl TxOutExt) -> i64 {
            output.value()
        }

        let value_from_owned = get_value(&txout);
        let value_from_ref = get_value(&txout_ref);

        assert_eq!(value_from_owned, value_from_ref);
    }

    #[test]
    fn test_txid_polymorphism() {
        let (tx, _) = get_test_transactions();
        let txid = tx.txid().to_owned();
        let txid_ref = txid.as_ref();

        fn get_bytes(txid: &impl TxidExt) -> [u8; 32] {
            txid.to_bytes()
        }

        let bytes_from_owned = get_bytes(&txid);
        let bytes_from_ref = get_bytes(&txid_ref);

        assert_eq!(bytes_from_owned, bytes_from_ref);
    }

    #[test]
    fn test_transaction_inputs_iterator() {
        let (tx, _) = get_test_transactions();
        let count = tx.input_count();

        let mut iter_count = 0;
        for input in tx.inputs() {
            let _ = input.outpoint();
            iter_count += 1;
        }

        assert_eq!(iter_count, count);
    }

    #[test]
    fn test_transaction_outputs_iterator() {
        let (tx, _) = get_test_transactions();
        let count = tx.output_count();

        let mut iter_count = 0;
        for output in tx.outputs() {
            let _ = output.value();
            iter_count += 1;
        }

        assert_eq!(iter_count, count);
    }

    #[test]
    fn test_txid_display() {
        let (tx, _) = get_test_transactions();
        let txid = tx.txid().to_owned();

        let display = format!("{}", txid);

        assert_eq!(
            display,
            "9beec3326c1efee76b743e667f9043941552c0803d12b94406e0e037c899e294"
        );
    }

    #[test]
    fn test_txid_ref_display() {
        let (tx, _) = get_test_transactions();
        let txid = tx.txid();

        let display = format!("{}", txid);

        assert_eq!(
            display,
            "9beec3326c1efee76b743e667f9043941552c0803d12b94406e0e037c899e294"
        );
    }
}
