//! Script verification and validation.
//!
//! This module provides functionality for verifying that transaction inputs satisfy
//! the spending conditions defined by their corresponding output scripts.
//!
//! # Overview
//!
//! Script verification involves checking that a transaction input's
//! unlocking script (scriptSig) and witness data satisfy the conditions
//! specified in the output's locking script (scriptPubkey). The verification
//! process depends on the script type and the consensus rules active at the
//! time.
//!
//! # Verification Flags
//!
//! Consensus rules have evolved over time through soft forks. Verification flags
//! allow you to specify which consensus rules to enforce:
//!
//! | Flag | Description | BIP |
//! |------|-------------|-----|
//! | [`VERIFY_P2SH`] | Pay-to-Script-Hash validation | BIP 16 |
//! | [`VERIFY_DERSIG`] | Strict DER signature encoding | BIP 66 |
//! | [`VERIFY_NULLDUMMY`] | Dummy stack element must be empty | BIP 147 |
//! | [`VERIFY_CHECKLOCKTIMEVERIFY`] | CHECKLOCKTIMEVERIFY opcode | BIP 65 |
//! | [`VERIFY_CHECKSEQUENCEVERIFY`] | CHECKSEQUENCEVERIFY opcode | BIP 112 |
//! | [`VERIFY_WITNESS`] | Segregated Witness validation | BIP 141/143 |
//! | [`VERIFY_TAPROOT`] | Taproot validation | BIP 341/342 |
//!
//! # Common Flag Combinations
//!
//! - [`VERIFY_ALL_PRE_TAPROOT`]: All rules except Taproot (for pre-Taproot blocks)
//! - [`VERIFY_ALL`]: All consensus rules including Taproot
//!
//! # Examples
//!
//! ## Basic verification with all consensus rules
//!
//! ```no_run
//! # use bitcoinkernel::{prelude::*, PrecomputedTransactionData, Transaction, verify, VERIFY_ALL};
//! # let spending_tx_bytes = vec![];
//! # let prev_tx_bytes = vec![];
//! # let spending_tx = Transaction::new(&spending_tx_bytes).unwrap();
//! # let prev_tx = Transaction::new(&prev_tx_bytes).unwrap();
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
//! ## Verifying pre-Taproot transactions
//!
//! ```no_run
//! # use bitcoinkernel::{prelude::*, Transaction, PrecomputedTransactionData, verify, VERIFY_ALL_PRE_TAPROOT};
//! # let spending_tx_bytes = vec![];
//! # let prev_tx_bytes = vec![];
//! # let spending_tx = Transaction::new(&spending_tx_bytes).unwrap();
//! # let prev_tx = Transaction::new(&prev_tx_bytes).unwrap();
//! # let prev_output = prev_tx.output(0).unwrap();
//! let tx_data = PrecomputedTransactionData::new(&prev_tx, &[prev_output]).unwrap();
//! let result = verify(
//!     &prev_output.script_pubkey(),
//!     Some(prev_output.value()),
//!     &spending_tx,
//!     0,
//!     Some(VERIFY_ALL_PRE_TAPROOT),
//!     &tx_data,
//! );
//! ```
//!
//! ## Verifying with multiple spent outputs
//!
//! ```no_run
//! # use bitcoinkernel::{prelude::*, PrecomputedTransactionData, Transaction, verify, VERIFY_ALL};
//! # let spending_tx_bytes = vec![];
//! # let prev_tx1_bytes = vec![];
//! # let prev_tx2_bytes = vec![];
//! # let spending_tx = Transaction::new(&spending_tx_bytes).unwrap();
//! # let prev_tx1 = Transaction::new(&prev_tx1_bytes).unwrap();
//! # let prev_tx2 = Transaction::new(&prev_tx2_bytes).unwrap();
//! let spent_outputs = vec![
//!     prev_tx1.output(0).unwrap(),
//!     prev_tx2.output(1).unwrap(),
//! ];
//! let tx_data = PrecomputedTransactionData::new(&prev_tx1, &spent_outputs).unwrap();
//!
//! let result = verify(
//!     &spent_outputs[0].script_pubkey(),
//!     Some(spent_outputs[0].value()),
//!     &spending_tx,
//!     0,
//!     Some(VERIFY_ALL),
//!     &tx_data,
//! );
//! ```
//!
//! ## Handling verification errors
//!
//! ```no_run
//! # use bitcoinkernel::{prelude::*, PrecomputedTransactionData, Transaction, verify, VERIFY_ALL, KernelError, ScriptVerifyError};
//! # let spending_tx_bytes = vec![];
//! # let prev_tx_bytes = vec![];
//! # let spending_tx = Transaction::new(&spending_tx_bytes).unwrap();
//! # let prev_tx = Transaction::new(&prev_tx_bytes).unwrap();
//! # let prev_output = prev_tx.output(0).unwrap();
//! # let tx_data = PrecomputedTransactionData::new(&prev_tx, &[prev_output]).unwrap();
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
//!     Ok(()) => {
//!         println!("Valid transaction");
//!     }
//!     Err(KernelError::ScriptVerify(ScriptVerifyError::SpentOutputsRequired)) => {
//!         println!("This script type requires spent outputs");
//!     }
//!     Err(KernelError::ScriptVerify(ScriptVerifyError::InvalidFlagsCombination)) => {
//!         println!("Invalid combination of verification flags");
//!     }
//!     Err(KernelError::ScriptVerify(ScriptVerifyError::Invalid)) => {
//!         println!("Script verification failed - invalid script");
//!     }
//!     Err(e) => {
//!         println!("Other error: {}", e);
//!     }
//! }
//! ```
//!
//! # Thread Safety
//!
//! The [`verify`] function is thread-safe and can be called concurrently from multiple
//! threads. All types used in verification are `Send + Sync`.

use std::{
    error::Error,
    fmt::{self, Display, Formatter},
};

use libbitcoinkernel_sys::{
    btck_PrecomputedTransactionData, btck_ScriptVerificationFlags,
    btck_ScriptVerificationFlags_ALL, btck_ScriptVerificationFlags_CHECKLOCKTIMEVERIFY,
    btck_ScriptVerificationFlags_CHECKSEQUENCEVERIFY, btck_ScriptVerificationFlags_DERSIG,
    btck_ScriptVerificationFlags_NONE, btck_ScriptVerificationFlags_NULLDUMMY,
    btck_ScriptVerificationFlags_P2SH, btck_ScriptVerificationFlags_SCRIPT_RESTORATION,
    btck_ScriptVerificationFlags_TAPROOT, btck_ScriptVerificationFlags_WITNESS,
    btck_ScriptVerifyStatus, btck_ScriptVerifyStatus_ERROR_INVALID_FLAGS_COMBINATION,
    btck_ScriptVerifyStatus_ERROR_SPENT_OUTPUTS_REQUIRED, btck_ScriptVerifyStatus_OK,
    btck_TransactionOutput, btck_precomputed_transaction_data_copy,
    btck_precomputed_transaction_data_create, btck_precomputed_transaction_data_destroy,
    btck_script_pubkey_verify,
};

use crate::{
    c_helpers, ffi::sealed::AsPtr, KernelError, ScriptPubkeyExt, TransactionExt, TxOutExt,
};

/// Bitmask of flags controlling which consensus rules [`verify`] enforces.
pub type ScriptVerificationFlags = btck_ScriptVerificationFlags;

/// No verification flags.
pub const VERIFY_NONE: ScriptVerificationFlags = btck_ScriptVerificationFlags_NONE;

/// Validate Pay-to-Script-Hash (BIP 16).
pub const VERIFY_P2SH: ScriptVerificationFlags = btck_ScriptVerificationFlags_P2SH;

/// Require strict DER encoding for ECDSA signatures (BIP 66).
pub const VERIFY_DERSIG: ScriptVerificationFlags = btck_ScriptVerificationFlags_DERSIG;

/// Require the dummy element in OP_CHECKMULTISIG to be empty (BIP 147).
pub const VERIFY_NULLDUMMY: ScriptVerificationFlags = btck_ScriptVerificationFlags_NULLDUMMY;

/// Enable OP_CHECKLOCKTIMEVERIFY (BIP 65).
pub const VERIFY_CHECKLOCKTIMEVERIFY: ScriptVerificationFlags =
    btck_ScriptVerificationFlags_CHECKLOCKTIMEVERIFY;

/// Enable OP_CHECKSEQUENCEVERIFY (BIP 112).
pub const VERIFY_CHECKSEQUENCEVERIFY: ScriptVerificationFlags =
    btck_ScriptVerificationFlags_CHECKSEQUENCEVERIFY;

/// Validate Segregated Witness programs (BIP 141/143).
pub const VERIFY_WITNESS: ScriptVerificationFlags = btck_ScriptVerificationFlags_WITNESS;

/// Validate Taproot spends (BIP 341/342). Requires spent outputs.
pub const VERIFY_TAPROOT: ScriptVerificationFlags = btck_ScriptVerificationFlags_TAPROOT;

/// Enable BIP 440/441 script restoration and tapscript v2. Requires Taproot.
pub const VERIFY_SCRIPT_RESTORATION: ScriptVerificationFlags =
    btck_ScriptVerificationFlags_SCRIPT_RESTORATION;

/// All consensus rules.
pub const VERIFY_ALL: ScriptVerificationFlags = btck_ScriptVerificationFlags_ALL;

/// All consensus rules except Taproot.
pub const VERIFY_ALL_PRE_TAPROOT: ScriptVerificationFlags = VERIFY_P2SH
    | VERIFY_DERSIG
    | VERIFY_NULLDUMMY
    | VERIFY_CHECKLOCKTIMEVERIFY
    | VERIFY_CHECKSEQUENCEVERIFY
    | VERIFY_WITNESS;

/// Precomputed transaction data for verifying a transaction's scripts.
///
/// Precomputes the hashes required to verify a transaction and avoids quadratic
/// hashing costs when verifying multiple scripts from a transaction.
///
/// PrecomputedTransactionData is created from a transaction, and if doing
/// taproot verification, its previous outputs [`crate::TxOut`]. It is required
/// to perform script verification.
///
/// Previous outputs are only required if verifying a taproot transaction. An
/// empty slice may be passed in otherwise.
///
/// # Arguments
///
/// * `tx` - The transaction to precompute data for
/// * `spent_outputs` - Previous transaction outputs being spent (required for taproot)
///
/// # Returns
///
/// * `Ok(...)` - The PrecomputedTransactionData
/// * `Err(KernelError::MismatchedOutputsSize)` - Number of outputs does not match
/// the number of the transaction's inputs.
///
/// # Examples
///
/// Creating a PrecomputedTransactionData:
///
/// ```no_run
/// # use bitcoinkernel::{prelude::*, Transaction, TxOut, PrecomputedTransactionData};
/// # let raw_tx = vec![0u8; 100]; // placeholder
/// # let tx = Transaction::new(&raw_tx).unwrap();
/// # let tx_data = PrecomputedTransactionData::new(&tx, &Vec::<TxOut>::new());
/// ```
#[derive(Debug)]
pub struct PrecomputedTransactionData {
    inner: *mut btck_PrecomputedTransactionData,
}

impl PrecomputedTransactionData {
    pub fn new(
        tx: &impl TransactionExt,
        spent_outputs: &[impl TxOutExt],
    ) -> Result<PrecomputedTransactionData, KernelError> {
        let kernel_spent_outputs: Vec<*const btck_TransactionOutput> =
            spent_outputs.iter().map(|utxo| utxo.as_ptr()).collect();

        let kernel_spent_outputs_ptr = if kernel_spent_outputs.is_empty() {
            std::ptr::null_mut()
        } else {
            if spent_outputs.len() != tx.input_count() {
                return Err(KernelError::MismatchedOutputsSize);
            }
            kernel_spent_outputs.as_ptr() as *mut *const btck_TransactionOutput
        };

        let inner = unsafe {
            btck_precomputed_transaction_data_create(
                tx.as_ptr(),
                kernel_spent_outputs_ptr,
                spent_outputs.len(),
            )
        };
        if inner.is_null() {
            return Err(KernelError::Internal(
                "Failed to create PrecomputedTransactionData".to_string(),
            ));
        }
        Ok(PrecomputedTransactionData { inner })
    }
}

impl AsPtr<btck_PrecomputedTransactionData> for PrecomputedTransactionData {
    fn as_ptr(&self) -> *const btck_PrecomputedTransactionData {
        self.inner as *const _
    }
}

impl Clone for PrecomputedTransactionData {
    fn clone(&self) -> Self {
        PrecomputedTransactionData {
            inner: unsafe { btck_precomputed_transaction_data_copy(self.inner) },
        }
    }
}

impl Drop for PrecomputedTransactionData {
    fn drop(&mut self) {
        unsafe {
            btck_precomputed_transaction_data_destroy(self.inner);
        }
    }
}

unsafe impl Send for PrecomputedTransactionData {}
unsafe impl Sync for PrecomputedTransactionData {}

/// Verifies a transaction input against its corresponding output script.
///
/// This function checks that the transaction input at the specified index properly
/// satisfies the spending conditions defined by the output script. The verification
/// process depends on the script type and the consensus rules specified by the flags.
///
/// # Arguments
///
/// * `script_pubkey` - The output script (locking script) to verify against
/// * `amount` - The amount in satoshis of the output being spent. Required for SegWit
///   and Taproot scripts (when [`VERIFY_WITNESS`] or [`VERIFY_TAPROOT`] flags are set).
///   Optional for pre-SegWit scripts.
/// * `tx_to` - The transaction containing the input to verify (the spending transaction)
/// * `input_index` - The zero-based index of the input within `tx_to` to verify
/// * `flags` - Verification flags specifying which consensus rules to enforce. If `None`,
///   defaults to [`VERIFY_ALL`]. Combine multiple flags using bitwise OR (`|`).
/// * `precomputed_txdata` - The pre-computed hashes required to verify the script. For verifying taproot scripts,
///   this must contain all outputs spent by all inputs in the transaction.
///
/// # Returns
///
/// * `Ok(())` - Verification succeeded; the input properly spends the output
/// * `Err(KernelError::ScriptVerify(ScriptVerifyError::TxInputIndex))` - Input index out of bounds
/// * `Err(KernelError::ScriptVerify(ScriptVerifyError::SpentOutputsMismatch))` - The spent_outputs
///   length is non-zero but doesn't match the number of inputs
/// * `Err(KernelError::ScriptVerify(ScriptVerifyError::InvalidFlags))` - Invalid verification flags
/// * `Err(KernelError::ScriptVerify(ScriptVerifyError::InvalidFlagsCombination))` - Incompatible
///   combination of flags
/// * `Err(KernelError::ScriptVerify(ScriptVerifyError::SpentOutputsRequired))` - Spent outputs
///   are required for this script type but were not provided
/// * `Err(KernelError::ScriptVerify(ScriptVerifyError::Invalid))` - Script verification failed;
///   the input does not properly satisfy the output's spending conditions
///
/// # Examples
///
/// ## Verifying a P2PKH transaction
///
/// ```no_run
/// # use bitcoinkernel::{prelude::*, PrecomputedTransactionData, Transaction, TxOut, verify, VERIFY_ALL};
/// # let tx_bytes = vec![];
/// # let spending_tx = Transaction::new(&tx_bytes).unwrap();
/// # let prev_tx = Transaction::new(&tx_bytes).unwrap();
/// let prev_output = prev_tx.output(0).unwrap();
/// let tx_data = PrecomputedTransactionData::new(&spending_tx, &Vec::<TxOut>::new()).unwrap();
///
/// let result = verify(
///     &prev_output.script_pubkey(),
///     None,
///     &spending_tx,
///     0,
///     Some(VERIFY_ALL),
///     &tx_data,
/// );
/// ```
///
/// ## Using custom flags
///
/// ```no_run
/// # use bitcoinkernel::{prelude::*, PrecomputedTransactionData, Transaction, TxOut, verify, VERIFY_P2SH, VERIFY_DERSIG};
/// # let tx_bytes = vec![];
/// # let spending_tx = Transaction::new(&tx_bytes).unwrap();
/// # let prev_output = spending_tx.output(0).unwrap();
/// // Only verify P2SH and DERSIG rules
/// let custom_flags = VERIFY_P2SH | VERIFY_DERSIG;
/// let tx_data = PrecomputedTransactionData::new(&spending_tx, &Vec::<TxOut>::new()).unwrap();
///
/// let result = verify(
///     &prev_output.script_pubkey(),
///     None,
///     &spending_tx,
///     0,
///     Some(custom_flags),
///     &tx_data,
/// );
/// ```
///
/// # Panics
///
/// This function does not panic under normal circumstances. All error conditions
/// are returned as `Result::Err`.
pub fn verify(
    script_pubkey: &impl ScriptPubkeyExt,
    amount: Option<i64>,
    tx_to: &impl TransactionExt,
    input_index: usize,
    flags: Option<ScriptVerificationFlags>,
    precomputed_txdata: &PrecomputedTransactionData,
) -> Result<(), KernelError> {
    let input_count = tx_to.input_count();

    if input_index >= input_count {
        return Err(KernelError::ScriptVerify(ScriptVerifyError::TxInputIndex));
    }

    let kernel_flags = if let Some(flag) = flags {
        if (flag & !VERIFY_ALL) != 0 {
            return Err(KernelError::ScriptVerify(ScriptVerifyError::InvalidFlags));
        }
        flag
    } else {
        VERIFY_ALL
    };

    let kernel_amount = amount.unwrap_or_default();
    let mut status = ScriptVerifyStatus::Ok.into();

    let ret = unsafe {
        btck_script_pubkey_verify(
            script_pubkey.as_ptr(),
            kernel_amount,
            tx_to.as_ptr(),
            precomputed_txdata.as_ptr(),
            input_index as u32,
            kernel_flags,
            &mut status,
        )
    };

    let script_status = ScriptVerifyStatus::from(status);

    if !c_helpers::verification_passed(ret) {
        let err = match script_status {
            ScriptVerifyStatus::ErrorInvalidFlagsCombination => {
                ScriptVerifyError::InvalidFlagsCombination
            }
            ScriptVerifyStatus::ErrorSpentOutputsRequired => {
                ScriptVerifyError::SpentOutputsRequired
            }
            _ => ScriptVerifyError::Invalid,
        };
        Err(KernelError::ScriptVerify(err))
    } else {
        Ok(())
    }
}

/// Internal status codes from the C verification function.
///
/// These are used internally to distinguish between setup errors (invalid flags,
/// missing data) and actual script verification failures. Converted to
/// [`KernelError::ScriptVerify`] variants in the public API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
enum ScriptVerifyStatus {
    /// Script verification completed successfully
    Ok = btck_ScriptVerifyStatus_OK,

    /// Invalid or inconsistent verification flags were provided.
    ///
    /// This occurs when the supplied `script_verify_flags` combination violates
    /// internal consistency rules. For example:
    ///
    /// - `SCRIPT_VERIFY_CLEANSTACK` is set without also enabling either
    ///   `SCRIPT_VERIFY_P2SH` or `SCRIPT_VERIFY_WITNESS`.
    /// - `SCRIPT_VERIFY_WITNESS` is set without also enabling `SCRIPT_VERIFY_P2SH`.
    ///
    /// These combinations are considered invalid and result in an immediate
    /// verification setup failure rather than a script execution failure.
    ErrorInvalidFlagsCombination = btck_ScriptVerifyStatus_ERROR_INVALID_FLAGS_COMBINATION,

    /// Spent outputs are required but were not provided.
    ///
    /// Taproot scripts require the complete set of outputs being spent to properly
    /// validate witness data. This occurs when the TAPROOT flag is set but no spent
    /// outputs were provided.
    ErrorSpentOutputsRequired = btck_ScriptVerifyStatus_ERROR_SPENT_OUTPUTS_REQUIRED,
}

impl From<ScriptVerifyStatus> for btck_ScriptVerifyStatus {
    fn from(status: ScriptVerifyStatus) -> Self {
        status as btck_ScriptVerifyStatus
    }
}

#[allow(non_upper_case_globals)]
impl From<btck_ScriptVerifyStatus> for ScriptVerifyStatus {
    fn from(value: btck_ScriptVerifyStatus) -> Self {
        match value {
            btck_ScriptVerifyStatus_OK => ScriptVerifyStatus::Ok,
            btck_ScriptVerifyStatus_ERROR_INVALID_FLAGS_COMBINATION => {
                ScriptVerifyStatus::ErrorInvalidFlagsCombination
            }
            btck_ScriptVerifyStatus_ERROR_SPENT_OUTPUTS_REQUIRED => {
                ScriptVerifyStatus::ErrorSpentOutputsRequired
            }
            _ => panic!("Unknown script verify status: {}", value),
        }
    }
}

/// Errors that can occur during script verification.
///
/// These errors represent both configuration problems (incorrect parameters)
/// and actual verification failures (invalid scripts).
#[derive(Debug)]
pub enum ScriptVerifyError {
    /// The specified input index is out of bounds.
    ///
    /// The `input_index` parameter is greater than or equal to the number
    /// of inputs in the transaction.
    TxInputIndex,

    /// Invalid verification flags were provided.
    ///
    /// The flags parameter contains bits that don't correspond to any
    /// defined verification flag.
    InvalidFlags,

    /// Invalid or inconsistent verification flags were provided.
    ///
    /// This occurs when the supplied `script_verify_flags` combination violates
    /// internal consistency rules.
    InvalidFlagsCombination,

    /// Spent outputs are required but were not provided.
    SpentOutputsRequired,

    /// Script verification failed.
    Invalid,
}

impl Display for ScriptVerifyError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ScriptVerifyError::TxInputIndex => write!(f, "Transaction input index out of bounds"),
            ScriptVerifyError::InvalidFlags => write!(f, "Invalid verification flags"),
            ScriptVerifyError::InvalidFlagsCombination => {
                write!(f, "Invalid combination of verification flags")
            }
            ScriptVerifyError::SpentOutputsRequired => {
                write!(f, "Spent outputs required for verification")
            }
            ScriptVerifyError::Invalid => write!(f, "Script verification failed"),
        }
    }
}

impl Error for ScriptVerifyError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_constants() {
        assert_eq!(VERIFY_NONE, btck_ScriptVerificationFlags_NONE);
        assert_eq!(VERIFY_P2SH, btck_ScriptVerificationFlags_P2SH);
        assert_eq!(VERIFY_DERSIG, btck_ScriptVerificationFlags_DERSIG);
        assert_eq!(VERIFY_NULLDUMMY, btck_ScriptVerificationFlags_NULLDUMMY);
        assert_eq!(
            VERIFY_CHECKLOCKTIMEVERIFY,
            btck_ScriptVerificationFlags_CHECKLOCKTIMEVERIFY
        );
        assert_eq!(
            VERIFY_CHECKSEQUENCEVERIFY,
            btck_ScriptVerificationFlags_CHECKSEQUENCEVERIFY
        );
        assert_eq!(VERIFY_WITNESS, btck_ScriptVerificationFlags_WITNESS);
        assert_eq!(VERIFY_TAPROOT, btck_ScriptVerificationFlags_TAPROOT);
        assert_eq!(
            VERIFY_SCRIPT_RESTORATION,
            btck_ScriptVerificationFlags_SCRIPT_RESTORATION
        );
        assert_eq!(VERIFY_ALL, btck_ScriptVerificationFlags_ALL);
    }

    #[test]
    fn test_verify_all_pre_taproot() {
        let expected = VERIFY_P2SH
            | VERIFY_DERSIG
            | VERIFY_NULLDUMMY
            | VERIFY_CHECKLOCKTIMEVERIFY
            | VERIFY_CHECKSEQUENCEVERIFY
            | VERIFY_WITNESS;

        assert_eq!(VERIFY_ALL_PRE_TAPROOT, expected);

        assert_eq!(VERIFY_ALL_PRE_TAPROOT & VERIFY_TAPROOT, 0);
    }

    #[test]
    fn test_verification_flag_combinations() {
        let flags = VERIFY_P2SH | VERIFY_WITNESS;
        assert!(flags & VERIFY_P2SH != 0);
        assert!(flags & VERIFY_WITNESS != 0);
        assert!(flags & VERIFY_TAPROOT == 0);
    }

    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn test_verify_all_includes_all_flags() {
        assert!((VERIFY_ALL & VERIFY_P2SH) != 0);
        assert!((VERIFY_ALL & VERIFY_DERSIG) != 0);
        assert!((VERIFY_ALL & VERIFY_NULLDUMMY) != 0);
        assert!((VERIFY_ALL & VERIFY_CHECKLOCKTIMEVERIFY) != 0);
        assert!((VERIFY_ALL & VERIFY_CHECKSEQUENCEVERIFY) != 0);
        assert!((VERIFY_ALL & VERIFY_WITNESS) != 0);
        assert!((VERIFY_ALL & VERIFY_TAPROOT) != 0);
        assert!((VERIFY_ALL & VERIFY_SCRIPT_RESTORATION) != 0);
    }

    #[test]
    fn test_script_verify_status_from_kernel() {
        let ok: ScriptVerifyStatus = btck_ScriptVerifyStatus_OK.into();
        assert_eq!(ok, ScriptVerifyStatus::Ok);

        let invalid_flags: ScriptVerifyStatus =
            btck_ScriptVerifyStatus_ERROR_INVALID_FLAGS_COMBINATION.into();
        assert_eq!(
            invalid_flags,
            ScriptVerifyStatus::ErrorInvalidFlagsCombination
        );

        let spent_required: ScriptVerifyStatus =
            btck_ScriptVerifyStatus_ERROR_SPENT_OUTPUTS_REQUIRED.into();
        assert_eq!(
            spent_required,
            ScriptVerifyStatus::ErrorSpentOutputsRequired
        );
    }

    #[test]
    fn test_script_verify_status_to_kernel() {
        let ok: btck_ScriptVerifyStatus = ScriptVerifyStatus::Ok.into();
        assert_eq!(ok, btck_ScriptVerifyStatus_OK);

        let invalid_flags: btck_ScriptVerifyStatus =
            ScriptVerifyStatus::ErrorInvalidFlagsCombination.into();
        assert_eq!(
            invalid_flags,
            btck_ScriptVerifyStatus_ERROR_INVALID_FLAGS_COMBINATION
        );

        let spent_required: btck_ScriptVerifyStatus =
            ScriptVerifyStatus::ErrorSpentOutputsRequired.into();
        assert_eq!(
            spent_required,
            btck_ScriptVerifyStatus_ERROR_SPENT_OUTPUTS_REQUIRED
        );
    }

    #[test]
    fn test_script_verify_status_round_trip() {
        let statuses = vec![
            ScriptVerifyStatus::Ok,
            ScriptVerifyStatus::ErrorInvalidFlagsCombination,
            ScriptVerifyStatus::ErrorSpentOutputsRequired,
        ];

        for status in statuses {
            let kernel: btck_ScriptVerifyStatus = status.into();
            let back: ScriptVerifyStatus = kernel.into();
            assert_eq!(status, back);
        }
    }

    #[test]
    #[should_panic(expected = "Unknown script verify status")]
    fn test_script_verify_status_invalid_value() {
        let _: ScriptVerifyStatus = 255.into();
    }

    #[test]
    fn test_script_verify_status_traits() {
        let status1 = ScriptVerifyStatus::Ok;
        let status2 = ScriptVerifyStatus::Ok;

        let cloned = status1.clone();
        assert_eq!(cloned, status2);

        let copied = status1;
        assert_eq!(copied, status2);

        assert_eq!(status1, status2);
        assert_ne!(status1, ScriptVerifyStatus::ErrorInvalidFlagsCombination);

        let debug_str = format!("{:?}", status1);
        assert!(debug_str.contains("Ok"));
    }

    #[test]
    fn test_script_verify_error_debug() {
        let errors = vec![
            ScriptVerifyError::TxInputIndex,
            ScriptVerifyError::InvalidFlags,
            ScriptVerifyError::InvalidFlagsCombination,
            ScriptVerifyError::SpentOutputsRequired,
            ScriptVerifyError::Invalid,
        ];

        for err in errors {
            let debug_str = format!("{:?}", err);
            assert!(!debug_str.is_empty());
        }
    }
}
