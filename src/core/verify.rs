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
//! # use bitcoinkernel::{prelude::*, PrecomputedTransactionData, Transaction, verify, VERIFY_ALL, KernelError, ScriptVerifyError, ScriptError};
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
//!     Err(KernelError::ScriptVerify(ScriptVerifyError::Script(e))) => {
//!         println!("Script verification failed: {}", e);
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
    btck_PrecomputedTransactionData, btck_ScriptError, btck_ScriptVerificationFlags,
    btck_ScriptVerifyStatus, btck_TransactionOutput, btck_precomputed_transaction_data_copy,
    btck_precomputed_transaction_data_create, btck_precomputed_transaction_data_destroy,
    btck_script_pubkey_verify,
};

use crate::{
    c_helpers,
    ffi::{
        sealed::AsPtr, BTCK_SCRIPT_ERROR_BAD_OPCODE, BTCK_SCRIPT_ERROR_CHECKMULTISIGVERIFY,
        BTCK_SCRIPT_ERROR_CHECKSIGVERIFY, BTCK_SCRIPT_ERROR_CLEANSTACK,
        BTCK_SCRIPT_ERROR_DISABLED_OPCODE, BTCK_SCRIPT_ERROR_DISCOURAGE_OP_SUCCESS,
        BTCK_SCRIPT_ERROR_DISCOURAGE_UPGRADABLE_NOPS,
        BTCK_SCRIPT_ERROR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
        BTCK_SCRIPT_ERROR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
        BTCK_SCRIPT_ERROR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM, BTCK_SCRIPT_ERROR_EQUALVERIFY,
        BTCK_SCRIPT_ERROR_EVAL_FALSE, BTCK_SCRIPT_ERROR_INVALID_ALTSTACK_OPERATION,
        BTCK_SCRIPT_ERROR_INVALID_STACK_OPERATION, BTCK_SCRIPT_ERROR_MINIMALDATA,
        BTCK_SCRIPT_ERROR_MINIMALIF, BTCK_SCRIPT_ERROR_NEGATIVE_LOCKTIME,
        BTCK_SCRIPT_ERROR_NUMEQUALVERIFY, BTCK_SCRIPT_ERROR_OK, BTCK_SCRIPT_ERROR_OP_CODESEPARATOR,
        BTCK_SCRIPT_ERROR_OP_COUNT, BTCK_SCRIPT_ERROR_OP_RETURN, BTCK_SCRIPT_ERROR_PUBKEYTYPE,
        BTCK_SCRIPT_ERROR_PUBKEY_COUNT, BTCK_SCRIPT_ERROR_PUSH_SIZE, BTCK_SCRIPT_ERROR_SCHNORR_SIG,
        BTCK_SCRIPT_ERROR_SCHNORR_SIG_HASHTYPE, BTCK_SCRIPT_ERROR_SCHNORR_SIG_SIZE,
        BTCK_SCRIPT_ERROR_SCRIPT_SIZE, BTCK_SCRIPT_ERROR_SIG_COUNT, BTCK_SCRIPT_ERROR_SIG_DER,
        BTCK_SCRIPT_ERROR_SIG_FINDANDDELETE, BTCK_SCRIPT_ERROR_SIG_HASHTYPE,
        BTCK_SCRIPT_ERROR_SIG_HIGH_S, BTCK_SCRIPT_ERROR_SIG_NULLDUMMY,
        BTCK_SCRIPT_ERROR_SIG_NULLFAIL, BTCK_SCRIPT_ERROR_SIG_PUSHONLY,
        BTCK_SCRIPT_ERROR_STACK_SIZE, BTCK_SCRIPT_ERROR_TAPROOT_WRONG_CONTROL_SIZE,
        BTCK_SCRIPT_ERROR_TAPSCRIPT_CHECKMULTISIG, BTCK_SCRIPT_ERROR_TAPSCRIPT_EMPTY_PUBKEY,
        BTCK_SCRIPT_ERROR_TAPSCRIPT_MINIMALIF, BTCK_SCRIPT_ERROR_TAPSCRIPT_VALIDATION_WEIGHT,
        BTCK_SCRIPT_ERROR_UNBALANCED_CONDITIONAL, BTCK_SCRIPT_ERROR_UNKNOWN,
        BTCK_SCRIPT_ERROR_UNSATISFIED_LOCKTIME, BTCK_SCRIPT_ERROR_VERIFY,
        BTCK_SCRIPT_ERROR_WITNESS_MALLEATED, BTCK_SCRIPT_ERROR_WITNESS_MALLEATED_P2SH,
        BTCK_SCRIPT_ERROR_WITNESS_PROGRAM_MISMATCH,
        BTCK_SCRIPT_ERROR_WITNESS_PROGRAM_WITNESS_EMPTY,
        BTCK_SCRIPT_ERROR_WITNESS_PROGRAM_WRONG_LENGTH, BTCK_SCRIPT_ERROR_WITNESS_PUBKEYTYPE,
        BTCK_SCRIPT_ERROR_WITNESS_UNEXPECTED, BTCK_SCRIPT_VERIFICATION_FLAGS_ALL,
        BTCK_SCRIPT_VERIFICATION_FLAGS_CHECKLOCKTIMEVERIFY,
        BTCK_SCRIPT_VERIFICATION_FLAGS_CHECKSEQUENCEVERIFY, BTCK_SCRIPT_VERIFICATION_FLAGS_DERSIG,
        BTCK_SCRIPT_VERIFICATION_FLAGS_NONE, BTCK_SCRIPT_VERIFICATION_FLAGS_NULLDUMMY,
        BTCK_SCRIPT_VERIFICATION_FLAGS_P2SH, BTCK_SCRIPT_VERIFICATION_FLAGS_TAPROOT,
        BTCK_SCRIPT_VERIFICATION_FLAGS_WITNESS,
        BTCK_SCRIPT_VERIFY_STATUS_ERROR_INVALID_FLAGS_COMBINATION,
        BTCK_SCRIPT_VERIFY_STATUS_ERROR_SPENT_OUTPUTS_REQUIRED, BTCK_SCRIPT_VERIFY_STATUS_OK,
    },
    KernelError, ScriptPubkeyExt, TransactionExt, TxOutExt,
};

/// No verification flags.
pub const VERIFY_NONE: btck_ScriptVerificationFlags = BTCK_SCRIPT_VERIFICATION_FLAGS_NONE;

/// Validate Pay-to-Script-Hash (BIP 16).
pub const VERIFY_P2SH: btck_ScriptVerificationFlags = BTCK_SCRIPT_VERIFICATION_FLAGS_P2SH;

/// Require strict DER encoding for ECDSA signatures (BIP 66).
pub const VERIFY_DERSIG: btck_ScriptVerificationFlags = BTCK_SCRIPT_VERIFICATION_FLAGS_DERSIG;

/// Require the dummy element in OP_CHECKMULTISIG to be empty (BIP 147).
pub const VERIFY_NULLDUMMY: btck_ScriptVerificationFlags = BTCK_SCRIPT_VERIFICATION_FLAGS_NULLDUMMY;

/// Enable OP_CHECKLOCKTIMEVERIFY (BIP 65).
pub const VERIFY_CHECKLOCKTIMEVERIFY: btck_ScriptVerificationFlags =
    BTCK_SCRIPT_VERIFICATION_FLAGS_CHECKLOCKTIMEVERIFY;

/// Enable OP_CHECKSEQUENCEVERIFY (BIP 112).
pub const VERIFY_CHECKSEQUENCEVERIFY: btck_ScriptVerificationFlags =
    BTCK_SCRIPT_VERIFICATION_FLAGS_CHECKSEQUENCEVERIFY;

/// Validate Segregated Witness programs (BIP 141/143).
pub const VERIFY_WITNESS: btck_ScriptVerificationFlags = BTCK_SCRIPT_VERIFICATION_FLAGS_WITNESS;

/// Validate Taproot spends (BIP 341/342). Requires spent outputs.
pub const VERIFY_TAPROOT: btck_ScriptVerificationFlags = BTCK_SCRIPT_VERIFICATION_FLAGS_TAPROOT;

/// All consensus rules.
pub const VERIFY_ALL: btck_ScriptVerificationFlags = BTCK_SCRIPT_VERIFICATION_FLAGS_ALL;

/// All consensus rules except Taproot.
pub const VERIFY_ALL_PRE_TAPROOT: btck_ScriptVerificationFlags = VERIFY_P2SH
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
/// * `Err(KernelError::ScriptVerify(ScriptVerifyError::Script(..)))` - Script verification failed;
///   the input does not properly satisfy the output's spending conditions. The inner
///   [`ScriptError`] indicates the specific reason for failure.
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
    flags: Option<u32>,
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
    let mut script_error: btck_ScriptError = BTCK_SCRIPT_ERROR_OK;

    let ret = unsafe {
        btck_script_pubkey_verify(
            script_pubkey.as_ptr(),
            kernel_amount,
            tx_to.as_ptr(),
            precomputed_txdata.as_ptr(),
            input_index as u32,
            kernel_flags,
            &mut status,
            &mut script_error,
        )
    };

    let script_status = ScriptVerifyStatus::try_from(status).map_err(|_| {
        KernelError::Internal(format!("Invalid script verify status: {:?}", status))
    })?;

    if !c_helpers::verification_passed(ret) {
        let err = match script_status {
            ScriptVerifyStatus::ErrorInvalidFlagsCombination => {
                ScriptVerifyError::InvalidFlagsCombination
            }
            ScriptVerifyStatus::ErrorSpentOutputsRequired => {
                ScriptVerifyError::SpentOutputsRequired
            }
            _ => {
                let se = ScriptError::try_from(script_error).unwrap_or(ScriptError::Unknown);
                ScriptVerifyError::Script(se)
            }
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
    Ok = BTCK_SCRIPT_VERIFY_STATUS_OK,

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
    ErrorInvalidFlagsCombination = BTCK_SCRIPT_VERIFY_STATUS_ERROR_INVALID_FLAGS_COMBINATION,

    /// Spent outputs are required but were not provided.
    ///
    /// Taproot scripts require the complete set of outputs being spent to properly
    /// validate witness data. This occurs when the TAPROOT flag is set but no spent
    /// outputs were provided.
    ErrorSpentOutputsRequired = BTCK_SCRIPT_VERIFY_STATUS_ERROR_SPENT_OUTPUTS_REQUIRED,
}

impl From<ScriptVerifyStatus> for btck_ScriptVerifyStatus {
    fn from(status: ScriptVerifyStatus) -> Self {
        status as btck_ScriptVerifyStatus
    }
}

impl From<btck_ScriptVerifyStatus> for ScriptVerifyStatus {
    fn from(value: btck_ScriptVerifyStatus) -> Self {
        match value {
            BTCK_SCRIPT_VERIFY_STATUS_OK => ScriptVerifyStatus::Ok,
            BTCK_SCRIPT_VERIFY_STATUS_ERROR_INVALID_FLAGS_COMBINATION => {
                ScriptVerifyStatus::ErrorInvalidFlagsCombination
            }
            BTCK_SCRIPT_VERIFY_STATUS_ERROR_SPENT_OUTPUTS_REQUIRED => {
                ScriptVerifyStatus::ErrorSpentOutputsRequired
            }
            _ => panic!("Unknown script verify status: {}", value),
        }
    }
}

/// Specific error codes from Bitcoin script execution.
///
/// These correspond to the script interpreter's error taxonomy and indicate
/// exactly why a script failed verification. Values match the C++
/// `ScriptError_t` enum in `script_error.h`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ScriptError {
    /// Unknown error from the script interpreter (C++ `SCRIPT_ERR_UNKNOWN_ERROR`).
    Unknown,
    /// Script finished with false/empty top stack element.
    EvalFalse,
    /// OP_RETURN was encountered.
    OpReturn,
    /// Script exceeds maximum size.
    ScriptSize,
    /// Push value exceeds size limit.
    PushSize,
    /// Opcode count exceeded.
    OpCount,
    /// Stack size limit exceeded.
    StackSize,
    /// Signature count negative or exceeds pubkey count.
    SigCount,
    /// Pubkey count negative or limit exceeded.
    PubkeyCount,
    /// OP_VERIFY failed.
    Verify,
    /// OP_EQUALVERIFY failed.
    EqualVerify,
    /// OP_CHECKMULTISIGVERIFY failed.
    CheckMultisigVerify,
    /// OP_CHECKSIGVERIFY failed.
    CheckSigVerify,
    /// OP_NUMEQUALVERIFY failed.
    NumEqualVerify,
    /// Opcode missing or not understood.
    BadOpcode,
    /// Disabled opcode encountered.
    DisabledOpcode,
    /// Invalid stack operation for current stack size.
    InvalidStackOperation,
    /// Invalid altstack operation for current altstack size.
    InvalidAltstackOperation,
    /// Unbalanced OP_IF/OP_ELSE/OP_ENDIF.
    UnbalancedConditional,
    /// Negative locktime.
    NegativeLocktime,
    /// Locktime requirement not satisfied.
    UnsatisfiedLocktime,
    /// Signature hash type missing or not understood.
    SigHashtype,
    /// Non-canonical DER signature.
    SigDer,
    /// Data push larger than necessary.
    MinimalData,
    /// Non-push operators in scriptSig.
    SigPushOnly,
    /// Non-canonical signature: S value unnecessarily high.
    SigHighS,
    /// Dummy CHECKMULTISIG argument must be zero.
    SigNullDummy,
    /// Public key is neither compressed nor uncompressed.
    PubkeyType,
    /// Stack must contain exactly one element after execution.
    CleanStack,
    /// OP_IF/NOTIF argument must be minimal.
    MinimalIf,
    /// Signature must be zero for failed CHECK(MULTI)SIG.
    SigNullFail,
    /// NOPx reserved for soft-fork upgrades.
    DiscourageUpgradableNops,
    /// Witness version reserved for soft-fork upgrades.
    DiscourageUpgradableWitnessProgram,
    /// Taproot version reserved for soft-fork upgrades.
    DiscourageUpgradableTaprootVersion,
    /// OP_SUCCESSx reserved for soft-fork upgrades.
    DiscourageOpSuccess,
    /// Public key version reserved for soft-fork upgrades.
    DiscourageUpgradablePubkeyType,
    /// Witness program has incorrect length.
    WitnessProgramWrongLength,
    /// Witness program was passed an empty witness.
    WitnessProgramWitnessEmpty,
    /// Witness program hash mismatch.
    WitnessProgramMismatch,
    /// Witness requires empty scriptSig.
    WitnessMalleated,
    /// Witness requires only-redeemscript scriptSig.
    WitnessMalleatedP2sh,
    /// Witness provided for non-witness script.
    WitnessUnexpected,
    /// Using non-compressed keys in segwit.
    WitnessPubkeyType,
    /// Invalid Schnorr signature size.
    SchnorrSigSize,
    /// Invalid Schnorr signature hash type.
    SchnorrSigHashtype,
    /// Invalid Schnorr signature.
    SchnorrSig,
    /// Invalid Taproot control block size.
    TaprootWrongControlSize,
    /// Too much signature validation relative to witness weight.
    TapscriptValidationWeight,
    /// OP_CHECKMULTISIG(VERIFY) not available in tapscript.
    TapscriptCheckMultisig,
    /// OP_IF/NOTIF argument must be minimal in tapscript.
    TapscriptMinimalIf,
    /// Empty public key in tapscript.
    TapscriptEmptyPubkey,
    /// OP_CODESEPARATOR in non-witness script.
    OpCodeseparator,
    /// Signature found in scriptCode.
    SigFindAndDelete,
}

impl Display for ScriptError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            ScriptError::Unknown => write!(f, "unknown error"),
            ScriptError::EvalFalse => write!(
                f,
                "Script evaluated without error but finished with a false/empty top stack element"
            ),
            ScriptError::OpReturn => write!(f, "OP_RETURN was encountered"),
            ScriptError::ScriptSize => write!(f, "Script is too big"),
            ScriptError::PushSize => write!(f, "Push value size limit exceeded"),
            ScriptError::OpCount => write!(f, "Operation limit exceeded"),
            ScriptError::StackSize => write!(f, "Stack size limit exceeded"),
            ScriptError::SigCount => {
                write!(f, "Signature count negative or greater than pubkey count")
            }
            ScriptError::PubkeyCount => write!(f, "Pubkey count negative or limit exceeded"),
            ScriptError::Verify => write!(f, "Script failed an OP_VERIFY operation"),
            ScriptError::EqualVerify => write!(f, "Script failed an OP_EQUALVERIFY operation"),
            ScriptError::CheckMultisigVerify => {
                write!(f, "Script failed an OP_CHECKMULTISIGVERIFY operation")
            }
            ScriptError::CheckSigVerify => {
                write!(f, "Script failed an OP_CHECKSIGVERIFY operation")
            }
            ScriptError::NumEqualVerify => {
                write!(f, "Script failed an OP_NUMEQUALVERIFY operation")
            }
            ScriptError::BadOpcode => write!(f, "Opcode missing or not understood"),
            ScriptError::DisabledOpcode => write!(f, "Attempted to use a disabled opcode"),
            ScriptError::InvalidStackOperation => {
                write!(f, "Operation not valid with the current stack size")
            }
            ScriptError::InvalidAltstackOperation => {
                write!(f, "Operation not valid with the current altstack size")
            }
            ScriptError::UnbalancedConditional => write!(f, "Invalid OP_IF construction"),
            ScriptError::NegativeLocktime => write!(f, "Negative locktime"),
            ScriptError::UnsatisfiedLocktime => write!(f, "Locktime requirement not satisfied"),
            ScriptError::SigHashtype => write!(f, "Signature hash type missing or not understood"),
            ScriptError::SigDer => write!(f, "Non-canonical DER signature"),
            ScriptError::MinimalData => write!(f, "Data push larger than necessary"),
            ScriptError::SigPushOnly => write!(f, "Only push operators allowed in signatures"),
            ScriptError::SigHighS => {
                write!(f, "Non-canonical signature: S value is unnecessarily high")
            }
            ScriptError::SigNullDummy => write!(f, "Dummy CHECKMULTISIG argument must be zero"),
            ScriptError::PubkeyType => {
                write!(f, "Public key is neither compressed or uncompressed")
            }
            ScriptError::CleanStack => write!(f, "Stack size must be exactly one after execution"),
            ScriptError::MinimalIf => write!(f, "OP_IF/NOTIF argument must be minimal"),
            ScriptError::SigNullFail => write!(
                f,
                "Signature must be zero for failed CHECK(MULTI)SIG operation"
            ),
            ScriptError::DiscourageUpgradableNops => {
                write!(f, "NOPx reserved for soft-fork upgrades")
            }
            ScriptError::DiscourageUpgradableWitnessProgram => {
                write!(f, "Witness version reserved for soft-fork upgrades")
            }
            ScriptError::DiscourageUpgradableTaprootVersion => {
                write!(f, "Taproot version reserved for soft-fork upgrades")
            }
            ScriptError::DiscourageOpSuccess => {
                write!(f, "OP_SUCCESSx reserved for soft-fork upgrades")
            }
            ScriptError::DiscourageUpgradablePubkeyType => {
                write!(f, "Public key version reserved for soft-fork upgrades")
            }
            ScriptError::WitnessProgramWrongLength => {
                write!(f, "Witness program has incorrect length")
            }
            ScriptError::WitnessProgramWitnessEmpty => {
                write!(f, "Witness program was passed an empty witness")
            }
            ScriptError::WitnessProgramMismatch => write!(f, "Witness program hash mismatch"),
            ScriptError::WitnessMalleated => write!(f, "Witness requires empty scriptSig"),
            ScriptError::WitnessMalleatedP2sh => {
                write!(f, "Witness requires only-redeemscript scriptSig")
            }
            ScriptError::WitnessUnexpected => write!(f, "Witness provided for non-witness script"),
            ScriptError::WitnessPubkeyType => write!(f, "Using non-compressed keys in segwit"),
            ScriptError::SchnorrSigSize => write!(f, "Invalid Schnorr signature size"),
            ScriptError::SchnorrSigHashtype => write!(f, "Invalid Schnorr signature hash type"),
            ScriptError::SchnorrSig => write!(f, "Invalid Schnorr signature"),
            ScriptError::TaprootWrongControlSize => write!(f, "Invalid Taproot control block size"),
            ScriptError::TapscriptValidationWeight => write!(
                f,
                "Too much signature validation relative to witness weight"
            ),
            ScriptError::TapscriptCheckMultisig => {
                write!(f, "OP_CHECKMULTISIG(VERIFY) is not available in tapscript")
            }
            ScriptError::TapscriptMinimalIf => {
                write!(f, "OP_IF/NOTIF argument must be minimal in tapscript")
            }
            ScriptError::TapscriptEmptyPubkey => write!(f, "Empty public key in tapscript"),
            ScriptError::OpCodeseparator => {
                write!(f, "Using OP_CODESEPARATOR in non-witness script")
            }
            ScriptError::SigFindAndDelete => write!(f, "Signature is found in scriptCode"),
        }
    }
}

impl Error for ScriptError {}

impl TryFrom<btck_ScriptError> for ScriptError {
    type Error = btck_ScriptError;

    fn try_from(value: btck_ScriptError) -> Result<Self, Self::Error> {
        match value {
            BTCK_SCRIPT_ERROR_OK => Err(value), // OK is not an error
            BTCK_SCRIPT_ERROR_UNKNOWN => Ok(ScriptError::Unknown),
            BTCK_SCRIPT_ERROR_EVAL_FALSE => Ok(ScriptError::EvalFalse),
            BTCK_SCRIPT_ERROR_OP_RETURN => Ok(ScriptError::OpReturn),
            BTCK_SCRIPT_ERROR_SCRIPT_SIZE => Ok(ScriptError::ScriptSize),
            BTCK_SCRIPT_ERROR_PUSH_SIZE => Ok(ScriptError::PushSize),
            BTCK_SCRIPT_ERROR_OP_COUNT => Ok(ScriptError::OpCount),
            BTCK_SCRIPT_ERROR_STACK_SIZE => Ok(ScriptError::StackSize),
            BTCK_SCRIPT_ERROR_SIG_COUNT => Ok(ScriptError::SigCount),
            BTCK_SCRIPT_ERROR_PUBKEY_COUNT => Ok(ScriptError::PubkeyCount),
            BTCK_SCRIPT_ERROR_VERIFY => Ok(ScriptError::Verify),
            BTCK_SCRIPT_ERROR_EQUALVERIFY => Ok(ScriptError::EqualVerify),
            BTCK_SCRIPT_ERROR_CHECKMULTISIGVERIFY => Ok(ScriptError::CheckMultisigVerify),
            BTCK_SCRIPT_ERROR_CHECKSIGVERIFY => Ok(ScriptError::CheckSigVerify),
            BTCK_SCRIPT_ERROR_NUMEQUALVERIFY => Ok(ScriptError::NumEqualVerify),
            BTCK_SCRIPT_ERROR_BAD_OPCODE => Ok(ScriptError::BadOpcode),
            BTCK_SCRIPT_ERROR_DISABLED_OPCODE => Ok(ScriptError::DisabledOpcode),
            BTCK_SCRIPT_ERROR_INVALID_STACK_OPERATION => Ok(ScriptError::InvalidStackOperation),
            BTCK_SCRIPT_ERROR_INVALID_ALTSTACK_OPERATION => {
                Ok(ScriptError::InvalidAltstackOperation)
            }
            BTCK_SCRIPT_ERROR_UNBALANCED_CONDITIONAL => Ok(ScriptError::UnbalancedConditional),
            BTCK_SCRIPT_ERROR_NEGATIVE_LOCKTIME => Ok(ScriptError::NegativeLocktime),
            BTCK_SCRIPT_ERROR_UNSATISFIED_LOCKTIME => Ok(ScriptError::UnsatisfiedLocktime),
            BTCK_SCRIPT_ERROR_SIG_HASHTYPE => Ok(ScriptError::SigHashtype),
            BTCK_SCRIPT_ERROR_SIG_DER => Ok(ScriptError::SigDer),
            BTCK_SCRIPT_ERROR_MINIMALDATA => Ok(ScriptError::MinimalData),
            BTCK_SCRIPT_ERROR_SIG_PUSHONLY => Ok(ScriptError::SigPushOnly),
            BTCK_SCRIPT_ERROR_SIG_HIGH_S => Ok(ScriptError::SigHighS),
            BTCK_SCRIPT_ERROR_SIG_NULLDUMMY => Ok(ScriptError::SigNullDummy),
            BTCK_SCRIPT_ERROR_PUBKEYTYPE => Ok(ScriptError::PubkeyType),
            BTCK_SCRIPT_ERROR_CLEANSTACK => Ok(ScriptError::CleanStack),
            BTCK_SCRIPT_ERROR_MINIMALIF => Ok(ScriptError::MinimalIf),
            BTCK_SCRIPT_ERROR_SIG_NULLFAIL => Ok(ScriptError::SigNullFail),
            BTCK_SCRIPT_ERROR_DISCOURAGE_UPGRADABLE_NOPS => {
                Ok(ScriptError::DiscourageUpgradableNops)
            }
            BTCK_SCRIPT_ERROR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM => {
                Ok(ScriptError::DiscourageUpgradableWitnessProgram)
            }
            BTCK_SCRIPT_ERROR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION => {
                Ok(ScriptError::DiscourageUpgradableTaprootVersion)
            }
            BTCK_SCRIPT_ERROR_DISCOURAGE_OP_SUCCESS => Ok(ScriptError::DiscourageOpSuccess),
            BTCK_SCRIPT_ERROR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE => {
                Ok(ScriptError::DiscourageUpgradablePubkeyType)
            }
            BTCK_SCRIPT_ERROR_WITNESS_PROGRAM_WRONG_LENGTH => {
                Ok(ScriptError::WitnessProgramWrongLength)
            }
            BTCK_SCRIPT_ERROR_WITNESS_PROGRAM_WITNESS_EMPTY => {
                Ok(ScriptError::WitnessProgramWitnessEmpty)
            }
            BTCK_SCRIPT_ERROR_WITNESS_PROGRAM_MISMATCH => Ok(ScriptError::WitnessProgramMismatch),
            BTCK_SCRIPT_ERROR_WITNESS_MALLEATED => Ok(ScriptError::WitnessMalleated),
            BTCK_SCRIPT_ERROR_WITNESS_MALLEATED_P2SH => Ok(ScriptError::WitnessMalleatedP2sh),
            BTCK_SCRIPT_ERROR_WITNESS_UNEXPECTED => Ok(ScriptError::WitnessUnexpected),
            BTCK_SCRIPT_ERROR_WITNESS_PUBKEYTYPE => Ok(ScriptError::WitnessPubkeyType),
            BTCK_SCRIPT_ERROR_SCHNORR_SIG_SIZE => Ok(ScriptError::SchnorrSigSize),
            BTCK_SCRIPT_ERROR_SCHNORR_SIG_HASHTYPE => Ok(ScriptError::SchnorrSigHashtype),
            BTCK_SCRIPT_ERROR_SCHNORR_SIG => Ok(ScriptError::SchnorrSig),
            BTCK_SCRIPT_ERROR_TAPROOT_WRONG_CONTROL_SIZE => {
                Ok(ScriptError::TaprootWrongControlSize)
            }
            BTCK_SCRIPT_ERROR_TAPSCRIPT_VALIDATION_WEIGHT => {
                Ok(ScriptError::TapscriptValidationWeight)
            }
            BTCK_SCRIPT_ERROR_TAPSCRIPT_CHECKMULTISIG => Ok(ScriptError::TapscriptCheckMultisig),
            BTCK_SCRIPT_ERROR_TAPSCRIPT_MINIMALIF => Ok(ScriptError::TapscriptMinimalIf),
            BTCK_SCRIPT_ERROR_TAPSCRIPT_EMPTY_PUBKEY => Ok(ScriptError::TapscriptEmptyPubkey),
            BTCK_SCRIPT_ERROR_OP_CODESEPARATOR => Ok(ScriptError::OpCodeseparator),
            BTCK_SCRIPT_ERROR_SIG_FINDANDDELETE => Ok(ScriptError::SigFindAndDelete),
            _ => Err(value),
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

    /// Script execution failed with a specific error.
    Script(ScriptError),
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
            ScriptVerifyError::Script(e) => write!(f, "Script verification failed: {}", e),
        }
    }
}

impl Error for ScriptVerifyError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            ScriptVerifyError::Script(e) => Some(e),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_verify_constants() {
        assert_eq!(VERIFY_NONE, BTCK_SCRIPT_VERIFICATION_FLAGS_NONE);
        assert_eq!(VERIFY_P2SH, BTCK_SCRIPT_VERIFICATION_FLAGS_P2SH);
        assert_eq!(VERIFY_DERSIG, BTCK_SCRIPT_VERIFICATION_FLAGS_DERSIG);
        assert_eq!(VERIFY_NULLDUMMY, BTCK_SCRIPT_VERIFICATION_FLAGS_NULLDUMMY);
        assert_eq!(
            VERIFY_CHECKLOCKTIMEVERIFY,
            BTCK_SCRIPT_VERIFICATION_FLAGS_CHECKLOCKTIMEVERIFY
        );
        assert_eq!(
            VERIFY_CHECKSEQUENCEVERIFY,
            BTCK_SCRIPT_VERIFICATION_FLAGS_CHECKSEQUENCEVERIFY
        );
        assert_eq!(VERIFY_WITNESS, BTCK_SCRIPT_VERIFICATION_FLAGS_WITNESS);
        assert_eq!(VERIFY_TAPROOT, BTCK_SCRIPT_VERIFICATION_FLAGS_TAPROOT);
        assert_eq!(VERIFY_ALL, BTCK_SCRIPT_VERIFICATION_FLAGS_ALL);
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
    }

    #[test]
    fn test_script_verify_status_from_kernel() {
        let ok: ScriptVerifyStatus = BTCK_SCRIPT_VERIFY_STATUS_OK.into();
        assert_eq!(ok, ScriptVerifyStatus::Ok);

        let invalid_flags: ScriptVerifyStatus =
            BTCK_SCRIPT_VERIFY_STATUS_ERROR_INVALID_FLAGS_COMBINATION.into();
        assert_eq!(
            invalid_flags,
            ScriptVerifyStatus::ErrorInvalidFlagsCombination
        );

        let spent_required: ScriptVerifyStatus =
            BTCK_SCRIPT_VERIFY_STATUS_ERROR_SPENT_OUTPUTS_REQUIRED.into();
        assert_eq!(
            spent_required,
            ScriptVerifyStatus::ErrorSpentOutputsRequired
        );
    }

    #[test]
    fn test_script_verify_status_to_kernel() {
        let ok: btck_ScriptVerifyStatus = ScriptVerifyStatus::Ok.into();
        assert_eq!(ok, BTCK_SCRIPT_VERIFY_STATUS_OK);

        let invalid_flags: btck_ScriptVerifyStatus =
            ScriptVerifyStatus::ErrorInvalidFlagsCombination.into();
        assert_eq!(
            invalid_flags,
            BTCK_SCRIPT_VERIFY_STATUS_ERROR_INVALID_FLAGS_COMBINATION
        );

        let spent_required: btck_ScriptVerifyStatus =
            ScriptVerifyStatus::ErrorSpentOutputsRequired.into();
        assert_eq!(
            spent_required,
            BTCK_SCRIPT_VERIFY_STATUS_ERROR_SPENT_OUTPUTS_REQUIRED
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
            ScriptVerifyError::Script(ScriptError::EvalFalse),
        ];

        for err in errors {
            let debug_str = format!("{:?}", err);
            assert!(!debug_str.is_empty());
        }
    }
}
