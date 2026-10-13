//! Direct evaluation of tapscript v2 leaf scripts.
//!
//! [`verify`](crate::verify()) checks a whole transaction input against the output
//! it spends. This module is for the narrower job of running a single tapscript
//! v2 (BIP 440/441) leaf script against a stack you supply, without building a
//! taproot spend and a control block around it.
//!
//! [`eval_tapscript_v2`] runs the full consensus path for a leaf with version
//! `0xc2`: `OP_SUCCESSx` handling, the initial stack limits, evaluation, and the
//! final cleanstack and truthiness check. It does **not** verify that the script
//! is committed to by any output, so a successful result says the script was
//! satisfied, not that a spend of it would be valid.
//!
//! [`VERIFY_SCRIPT_RESTORATION`](crate::VERIFY_SCRIPT_RESTORATION)
//! must be set in the flags.
//!
//! Without a [`TapscriptV2SpendContext`], signature and locktime opcodes fail as
//! if the signature were invalid. That is usually what you want when stepping
//! through a script that does not depend on one. To evaluate a script that does,
//! build a context with [`TapscriptV2SpendContext::with_transaction`].
//!
//! # Examples
//!
//! ```no_run
//! # use bitcoinkernel::{eval_tapscript_v2, ScriptPubkey, ScriptStack, TapscriptV2Result};
//! // OP_2 OP_3 OP_ADD OP_5 OP_EQUAL, starting from an empty stack
//! let script = ScriptPubkey::new(&[0x52, 0x53, 0x93, 0x55, 0x87])?;
//! let outcome = eval_tapscript_v2(&script, &ScriptStack::new(), None, None, None)?;
//! assert!(matches!(outcome, TapscriptV2Result::Valid { .. }));
//! # Ok::<(), bitcoinkernel::KernelError>(())
//! ```
//!
//! The same script split in two, with the first half's result supplied as the
//! initial stack -- which is the shape a debugger wants, since it can resume
//! from any point:
//!
//! ```no_run
//! # use bitcoinkernel::{eval_tapscript_v2, ScriptPubkey, ScriptStack, TapscriptV2Result};
//! // OP_5 OP_EQUAL, with 5 already on the stack
//! let stack: ScriptStack = [vec![0x05]].into_iter().collect();
//! let script = ScriptPubkey::new(&[0x55, 0x87])?;
//! let outcome = eval_tapscript_v2(&script, &stack, None, None, None)?;
//! assert!(matches!(outcome, TapscriptV2Result::Valid { .. }));
//! # Ok::<(), bitcoinkernel::KernelError>(())
//! ```

use std::{
    error::Error,
    ffi::c_void,
    fmt::{self, Debug, Display, Formatter},
    marker::PhantomData,
};

use libbitcoinkernel_sys::{
    btck_PrecomputedTransactionData, btck_ScriptStack, btck_TapscriptV2EvalStatus,
    btck_TapscriptV2EvalStatus_ERROR_INVALID_FLAGS_COMBINATION,
    btck_TapscriptV2EvalStatus_ERROR_INVALID_INPUT_INDEX,
    btck_TapscriptV2EvalStatus_ERROR_SCRIPT_RESTORATION_REQUIRED,
    btck_TapscriptV2EvalStatus_ERROR_SPENT_OUTPUTS_REQUIRED,
    btck_TapscriptV2EvalStatus_ERROR_TAPLEAF_HASH_REQUIRED, btck_TapscriptV2EvalStatus_OK,
    btck_TapscriptV2SpendContext, btck_Transaction, btck_VaropsBudget_UNMETERED,
    btck_script_stack_copy, btck_script_stack_count_items, btck_script_stack_create,
    btck_script_stack_destroy, btck_script_stack_item_to_bytes, btck_script_stack_push,
    btck_tapscript_v2_eval,
};

use crate::{
    c_serialize,
    core::{ScriptPubkeyExt, TransactionExt},
    ffi::{
        c_helpers,
        sealed::{AsPtr, FromMutPtr},
    },
    KernelError, PrecomputedTransactionData, ScriptVerificationFlags, VERIFY_ALL,
};

/// The initial stack handed to a script evaluation.
///
/// The bottom of the stack is index `0`; the top is the last element pushed.
///
/// # Examples
///
/// ```no_run
/// # use bitcoinkernel::ScriptStack;
/// let mut stack = ScriptStack::new();
/// stack.push(&[0x01]);
/// stack.push(&[0x02, 0x03]);
///
/// assert_eq!(stack.len(), 2);
/// assert_eq!(stack.item(1)?, vec![0x02, 0x03]);
///
/// // Or collect one from anything byte-like.
/// let collected: ScriptStack = [vec![0x01], vec![0x02, 0x03]].into_iter().collect();
/// assert_eq!(collected.to_vec()?, stack.to_vec()?);
/// # Ok::<(), bitcoinkernel::KernelError>(())
/// ```
pub struct ScriptStack {
    inner: *mut btck_ScriptStack,
}

unsafe impl Send for ScriptStack {}
unsafe impl Sync for ScriptStack {}

impl ScriptStack {
    /// Creates an empty stack.
    pub fn new() -> Self {
        ScriptStack {
            inner: unsafe { btck_script_stack_create() },
        }
    }

    /// Pushes an element onto the top of the stack.
    pub fn push(&mut self, element: &[u8]) {
        unsafe {
            btck_script_stack_push(self.inner, element.as_ptr() as *const c_void, element.len())
        }
    }

    /// The number of elements on the stack.
    pub fn len(&self) -> usize {
        unsafe { btck_script_stack_count_items(self.as_ptr()) }
    }

    /// Whether the stack is empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Copies the element at `index` out of the kernel, counting from the
    /// bottom of the stack. The top of the stack is at `len() - 1`.
    ///
    /// # Errors
    ///
    /// [`KernelError::OutOfBounds`] if `index` is not less than [`len`](Self::len).
    pub fn item(&self, index: usize) -> Result<Vec<u8>, KernelError> {
        if index >= self.len() {
            return Err(KernelError::OutOfBounds);
        }
        c_serialize(|writer, user_data| unsafe {
            btck_script_stack_item_to_bytes(self.as_ptr(), index, writer, user_data)
        })
    }

    /// Copies every element out of the kernel, bottom first.
    pub fn to_vec(&self) -> Result<Vec<Vec<u8>>, KernelError> {
        (0..self.len()).map(|index| self.item(index)).collect()
    }
}

impl Default for ScriptStack {
    fn default() -> Self {
        ScriptStack::new()
    }
}

impl AsPtr<btck_ScriptStack> for ScriptStack {
    fn as_ptr(&self) -> *const btck_ScriptStack {
        self.inner as *const _
    }
}

impl FromMutPtr<btck_ScriptStack> for ScriptStack {
    unsafe fn from_ptr(ptr: *mut btck_ScriptStack) -> Self {
        ScriptStack { inner: ptr }
    }
}

impl Clone for ScriptStack {
    fn clone(&self) -> Self {
        ScriptStack {
            inner: unsafe { btck_script_stack_copy(self.inner) },
        }
    }
}

impl<T: AsRef<[u8]>> FromIterator<T> for ScriptStack {
    fn from_iter<I: IntoIterator<Item = T>>(iter: I) -> Self {
        let mut stack = ScriptStack::new();
        for element in iter {
            stack.push(element.as_ref());
        }
        stack
    }
}

impl Debug for ScriptStack {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("ScriptStack")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

impl Drop for ScriptStack {
    fn drop(&mut self) {
        unsafe { btck_script_stack_destroy(self.inner) }
    }
}

/// The spending context a tapscript v2 evaluation is run in.
///
/// Only needed when the script performs a signature or locktime check. Build one
/// with [`with_transaction`](Self::with_transaction).
///
/// # Lifetime
///
/// Borrows the transaction, precomputed data and annex for as long as the
/// context exists.
#[derive(Clone)]
pub struct TapscriptV2SpendContext<'a> {
    tx_to: *const btck_Transaction,
    precomputed_txdata: *const btck_PrecomputedTransactionData,
    amount: i64,
    input_index: u32,
    annex: Option<&'a [u8]>,
    tapleaf_hash: [u8; 32],
    marker: PhantomData<&'a ()>,
}

impl<'a> TapscriptV2SpendContext<'a> {
    /// Builds a context for the input at `input_index` of `tx_to`.
    ///
    /// `precomputed_txdata` must have been created with the outputs spent by
    /// `tx_to`, the same requirement taproot verification has. `tapleaf_hash` is
    /// the BIP 341 tapleaf hash of the script being evaluated; it is committed
    /// to by the signature message, so a wrong value produces a wrong sighash
    /// rather than an error.
    pub fn with_transaction(
        tx_to: &'a impl TransactionExt,
        input_index: usize,
        amount: i64,
        precomputed_txdata: &'a PrecomputedTransactionData,
        tapleaf_hash: [u8; 32],
    ) -> Result<Self, KernelError> {
        if input_index >= tx_to.input_count() {
            return Err(KernelError::TapscriptV2Eval(
                TapscriptV2EvalError::InvalidInputIndex,
            ));
        }

        Ok(TapscriptV2SpendContext {
            tx_to: tx_to.as_ptr(),
            precomputed_txdata: precomputed_txdata.as_ptr(),
            amount,
            input_index: input_index as u32,
            annex: None,
            tapleaf_hash,
            marker: PhantomData,
        })
    }

    /// Sets the annex of the input's witness, including its `0x50` tag byte.
    ///
    /// The annex is committed to by the signature message, so it has to be set
    /// for a signature check over a witness that carries one to succeed.
    pub fn annex(mut self, annex: &'a [u8]) -> Self {
        self.annex = Some(annex);
        self
    }

    fn to_ffi(&self) -> btck_TapscriptV2SpendContext {
        btck_TapscriptV2SpendContext {
            tx_to: self.tx_to,
            precomputed_txdata: self.precomputed_txdata,
            amount: self.amount,
            input_index: self.input_index,
            annex: self
                .annex
                .map_or(std::ptr::null(), |annex| annex.as_ptr() as *const c_void),
            annex_len: self.annex.map_or(0, |annex| annex.len()),
            tapleaf_hash: self.tapleaf_hash.as_ptr(),
        }
    }
}

impl Debug for TapscriptV2SpendContext<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("TapscriptV2SpendContext")
            .field("amount", &self.amount)
            .field("input_index", &self.input_index)
            .field("annex_len", &self.annex.map_or(0, |annex| annex.len()))
            .finish_non_exhaustive()
    }
}

/// The result of an evaluation that ran to completion.
///
/// A script that is not satisfied is not an error: it ran, and it did not meet
/// its spending conditions. Errors are reserved for the evaluation not running
/// at all, and are reported through [`TapscriptV2EvalError`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TapscriptV2Result {
    /// The script ran and was satisfied.
    Valid {
        /// The unspent varops budget, or `None` if the evaluation was
        /// unmetered.
        varops_remaining: Option<u64>,
    },

    /// The script ran and was not satisfied.
    Invalid {
        /// The interpreter's script error code.
        ///
        /// This is the raw `ScriptError` value from the kernel, which the C API
        /// does not yet name, so there is nothing to match against but the
        /// number. The values are the positions of Core's `ScriptError`
        /// enumerators, so they are not stable across versions.
        script_error: i32,

        /// The unspent varops budget, or `None` if the evaluation was
        /// unmetered. `Some(0)` usually means the script was cut short by the
        /// budget rather than by its own logic.
        varops_remaining: Option<u64>,
    },
}

impl TapscriptV2Result {
    /// The unspent varops budget, whether or not the script was satisfied.
    pub fn varops_remaining(&self) -> Option<u64> {
        match self {
            TapscriptV2Result::Valid { varops_remaining }
            | TapscriptV2Result::Invalid {
                varops_remaining, ..
            } => *varops_remaining,
        }
    }
}

/// Reasons a tapscript v2 evaluation could not be run.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TapscriptV2EvalError {
    /// The flags contain bits that are not verification flags.
    InvalidFlags,

    /// The flags were combined in a way the interpreter rejects.
    InvalidFlagsCombination,

    /// The script restoration flag was not set. Tapscript v2 cannot be
    /// evaluated without it.
    ScriptRestorationRequired,

    /// A spending transaction was given without precomputed data carrying the
    /// outputs it spends.
    SpentOutputsRequired,

    /// A spending transaction was given without a tapleaf hash.
    TapleafHashRequired,

    /// The input index is out of range for the given transaction.
    InvalidInputIndex,

    /// The kernel reported a status these bindings do not recognize,
    /// usually because the bindings and the kernel are out of sync.
    UnknownStatus(btck_TapscriptV2EvalStatus),
}

impl Display for TapscriptV2EvalError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        match self {
            TapscriptV2EvalError::InvalidFlags => write!(f, "Invalid verification flags"),
            TapscriptV2EvalError::InvalidFlagsCombination => {
                write!(f, "Invalid combination of verification flags")
            }
            TapscriptV2EvalError::ScriptRestorationRequired => {
                write!(f, "Script restoration flag required for tapscript v2")
            }
            TapscriptV2EvalError::SpentOutputsRequired => {
                write!(f, "Spent outputs required for the given transaction")
            }
            TapscriptV2EvalError::TapleafHashRequired => {
                write!(f, "Tapleaf hash required for the given transaction")
            }
            TapscriptV2EvalError::InvalidInputIndex => {
                write!(f, "Transaction input index out of bounds")
            }
            TapscriptV2EvalError::UnknownStatus(raw) => {
                write!(f, "Unknown tapscript v2 eval status from the kernel: {raw}")
            }
        }
    }
}

impl Error for TapscriptV2EvalError {}

/// Internal status codes from the C tapscript v2 evaluation function.
///
/// These distinguish setup errors -- bad flags, missing data -- from the script
/// itself failing, which is not an error and is reported through
/// [`TapscriptV2Result`]. Converted to [`KernelError::TapscriptV2Eval`]
/// variants in the public API.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
enum TapscriptV2EvalStatus {
    /// The evaluation ran to completion.
    Ok = btck_TapscriptV2EvalStatus_OK,

    /// The supplied verification flags violate the interpreter's internal
    /// consistency rules, for example `WITNESS` without `P2SH`.
    ErrorInvalidFlagsCombination = btck_TapscriptV2EvalStatus_ERROR_INVALID_FLAGS_COMBINATION,

    /// The script restoration flag was not set. Tapscript v2 only exists under
    /// that flag, so there is nothing to evaluate without it.
    ErrorScriptRestorationRequired = btck_TapscriptV2EvalStatus_ERROR_SCRIPT_RESTORATION_REQUIRED,

    /// A spending transaction was given, but its precomputed data does not
    /// carry the outputs being spent. Taproot sighashes commit to all of them.
    ErrorSpentOutputsRequired = btck_TapscriptV2EvalStatus_ERROR_SPENT_OUTPUTS_REQUIRED,

    /// A spending transaction was given without a tapleaf hash, which the
    /// signature message commits to.
    ErrorTapleafHashRequired = btck_TapscriptV2EvalStatus_ERROR_TAPLEAF_HASH_REQUIRED,

    /// The input index is out of range for the given transaction.
    ErrorInvalidInputIndex = btck_TapscriptV2EvalStatus_ERROR_INVALID_INPUT_INDEX,
}

impl From<TapscriptV2EvalStatus> for btck_TapscriptV2EvalStatus {
    fn from(status: TapscriptV2EvalStatus) -> Self {
        status as btck_TapscriptV2EvalStatus
    }
}

#[allow(non_upper_case_globals)]
impl TryFrom<btck_TapscriptV2EvalStatus> for TapscriptV2EvalStatus {
    type Error = btck_TapscriptV2EvalStatus;

    fn try_from(value: btck_TapscriptV2EvalStatus) -> Result<Self, Self::Error> {
        Ok(match value {
            btck_TapscriptV2EvalStatus_OK => TapscriptV2EvalStatus::Ok,
            btck_TapscriptV2EvalStatus_ERROR_INVALID_FLAGS_COMBINATION => {
                TapscriptV2EvalStatus::ErrorInvalidFlagsCombination
            }
            btck_TapscriptV2EvalStatus_ERROR_SCRIPT_RESTORATION_REQUIRED => {
                TapscriptV2EvalStatus::ErrorScriptRestorationRequired
            }
            btck_TapscriptV2EvalStatus_ERROR_SPENT_OUTPUTS_REQUIRED => {
                TapscriptV2EvalStatus::ErrorSpentOutputsRequired
            }
            btck_TapscriptV2EvalStatus_ERROR_TAPLEAF_HASH_REQUIRED => {
                TapscriptV2EvalStatus::ErrorTapleafHashRequired
            }
            btck_TapscriptV2EvalStatus_ERROR_INVALID_INPUT_INDEX => {
                TapscriptV2EvalStatus::ErrorInvalidInputIndex
            }
            other => return Err(other),
        })
    }
}

/// Evaluates a tapscript v2 leaf script against an initial stack.
///
/// # Arguments
///
/// * `script` - The leaf script to evaluate.
/// * `stack` - The initial stack. Not modified by the evaluation.
/// * `flags` - Verification flags. Defaults to
///   [`VERIFY_ALL`] when `None`. Must include
///   [`VERIFY_SCRIPT_RESTORATION`](crate::VERIFY_SCRIPT_RESTORATION).
/// * `spend_context` - The spending context. Without one, signature and
///   locktime opcodes fail.
/// * `varops_budget` - The varops budget, or `None` to evaluate unmetered.
///   Consensus derives this from the weight of the whole transaction, so a
///   single-script budget can only ever approximate it.
///
/// # Returns
///
/// * [`TapscriptV2Result::Valid`] - the script ran and was satisfied.
/// * [`TapscriptV2Result::Invalid`] - the script ran and was not satisfied,
///   carrying the interpreter's script error.
/// * [`Err`] - the evaluation could not be run, see [`TapscriptV2EvalError`].
///
/// # Examples
///
/// ```no_run
/// # use bitcoinkernel::{eval_tapscript_v2, ScriptPubkey, ScriptStack, TapscriptV2Result};
/// // OP_2 OP_3 OP_ADD OP_5 OP_EQUAL
/// let script = ScriptPubkey::new(&[0x52, 0x53, 0x93, 0x55, 0x87])?;
/// let outcome = eval_tapscript_v2(&script, &ScriptStack::new(), None, None, None)?;
///
/// match outcome {
///     TapscriptV2Result::Valid { .. } => println!("satisfied"),
///     TapscriptV2Result::Invalid { script_error, .. } => {
///         println!("failed with script error {script_error}")
///     }
/// }
/// # Ok::<(), bitcoinkernel::KernelError>(())
/// ```
pub fn eval_tapscript_v2(
    script: &impl ScriptPubkeyExt,
    stack: &ScriptStack,
    flags: Option<ScriptVerificationFlags>,
    spend_context: Option<&TapscriptV2SpendContext<'_>>,
    varops_budget: Option<u64>,
) -> Result<TapscriptV2Result, KernelError> {
    let kernel_flags = match flags {
        // The kernel asserts on flag bits it does not know, so reject them here
        // rather than aborting the process.
        Some(flags) if (flags & !VERIFY_ALL) != 0 => {
            return Err(KernelError::TapscriptV2Eval(
                TapscriptV2EvalError::InvalidFlags,
            ))
        }
        Some(flags) => flags,
        None => VERIFY_ALL,
    };

    let ffi_context = spend_context.map(|context| context.to_ffi());
    let context_ptr = ffi_context
        .as_ref()
        .map_or(std::ptr::null(), |context| context as *const _);

    let budget = varops_budget.unwrap_or(btck_VaropsBudget_UNMETERED);

    let mut status = TapscriptV2EvalStatus::Ok.into();
    let mut script_error: i32 = 0;
    let mut varops_remaining: u64 = 0;

    let ret = unsafe {
        btck_tapscript_v2_eval(
            script.as_ptr(),
            stack.as_ptr(),
            kernel_flags,
            context_ptr,
            budget,
            &mut varops_remaining,
            &mut script_error,
            &mut status,
        )
    };

    let status = TapscriptV2EvalStatus::try_from(status)
        .map_err(|raw| KernelError::TapscriptV2Eval(TapscriptV2EvalError::UnknownStatus(raw)))?;

    let error = match status {
        TapscriptV2EvalStatus::Ok => None,
        TapscriptV2EvalStatus::ErrorInvalidFlagsCombination => {
            Some(TapscriptV2EvalError::InvalidFlagsCombination)
        }
        TapscriptV2EvalStatus::ErrorScriptRestorationRequired => {
            Some(TapscriptV2EvalError::ScriptRestorationRequired)
        }
        TapscriptV2EvalStatus::ErrorSpentOutputsRequired => {
            Some(TapscriptV2EvalError::SpentOutputsRequired)
        }
        TapscriptV2EvalStatus::ErrorTapleafHashRequired => {
            Some(TapscriptV2EvalError::TapleafHashRequired)
        }
        TapscriptV2EvalStatus::ErrorInvalidInputIndex => {
            Some(TapscriptV2EvalError::InvalidInputIndex)
        }
    };

    if let Some(error) = error {
        return Err(KernelError::TapscriptV2Eval(error));
    }

    let varops_remaining =
        (varops_remaining != btck_VaropsBudget_UNMETERED).then_some(varops_remaining);

    if c_helpers::verification_passed(ret) {
        Ok(TapscriptV2Result::Valid { varops_remaining })
    } else {
        Ok(TapscriptV2Result::Invalid {
            script_error,
            varops_remaining,
        })
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        ffi::test_utils::{test_owned_clone_and_send, test_owned_trait_requirements},
        ScriptPubkey, VERIFY_ALL_PRE_TAPROOT,
    };

    use super::*;

    const FLAGS: ScriptVerificationFlags = VERIFY_ALL;

    const BUDGET: u64 = 1_000_000;

    // BIP 440: a byte count rounded up to the next 8-byte word boundary.
    const fn wordspan(len: u64) -> u64 {
        (len + 7) / 8 * 8
    }

    // BIP 441: cost of the final success check on an element of `len` bytes.
    const fn final_check(len: u64) -> u64 {
        wordspan(len) * 2
    }

    test_owned_trait_requirements!(
        test_script_stack_implementations,
        ScriptStack,
        btck_ScriptStack
    );

    test_owned_clone_and_send!(
        test_script_stack_clone_send,
        [vec![0x01u8]].into_iter().collect::<ScriptStack>(),
        [vec![0x02u8]].into_iter().collect::<ScriptStack>()
    );

    fn eval(script: &[u8], stack: &ScriptStack) -> Result<TapscriptV2Result, KernelError> {
        eval_tapscript_v2(
            &ScriptPubkey::new(script).unwrap(),
            stack,
            Some(FLAGS),
            None,
            None,
        )
    }

    fn eval_metered(script: &[u8], stack: &ScriptStack, budget: u64) -> TapscriptV2Result {
        eval_tapscript_v2(
            &ScriptPubkey::new(script).unwrap(),
            stack,
            Some(FLAGS),
            None,
            Some(budget),
        )
        .unwrap()
    }

    #[test]
    fn test_op_1_succeeds() {
        let outcome = eval(&[0x51], &ScriptStack::new()).unwrap();
        assert_eq!(
            outcome,
            TapscriptV2Result::Valid {
                varops_remaining: None
            }
        );
    }

    #[test]
    fn test_op_0_leaves_a_false_result() {
        let outcome = eval(&[0x00], &ScriptStack::new()).unwrap();
        let TapscriptV2Result::Invalid { script_error, .. } = outcome else {
            panic!("expected the script to fail, got {outcome:?}");
        };
        assert_ne!(script_error, 0);
    }

    #[test]
    fn test_two_elements_violate_cleanstack() {
        let outcome = eval(&[0x51, 0x51], &ScriptStack::new()).unwrap();
        let TapscriptV2Result::Invalid { script_error, .. } = outcome else {
            panic!("expected cleanstack to be violated, got {outcome:?}");
        };
        assert_ne!(script_error, 0);
    }

    #[test]
    fn test_empty_script_uses_the_initial_stack() {
        let stack: ScriptStack = [vec![0x01]].into_iter().collect();
        let outcome = eval(&[], &stack).unwrap();
        assert_eq!(
            outcome,
            TapscriptV2Result::Valid {
                varops_remaining: None
            }
        );
    }

    #[test]
    fn test_script_restoration_flag_is_required() {
        let err = eval_tapscript_v2(
            &ScriptPubkey::new(&[0x51]).unwrap(),
            &ScriptStack::new(),
            Some(VERIFY_ALL_PRE_TAPROOT),
            None,
            None,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            KernelError::TapscriptV2Eval(TapscriptV2EvalError::ScriptRestorationRequired)
        ));
    }

    #[test]
    fn test_unknown_flag_bits_are_rejected() {
        let err = eval_tapscript_v2(
            &ScriptPubkey::new(&[0x51]).unwrap(),
            &ScriptStack::new(),
            Some(VERIFY_ALL | (1 << 30)),
            None,
            None,
        )
        .unwrap_err();

        assert!(matches!(
            err,
            KernelError::TapscriptV2Eval(TapscriptV2EvalError::InvalidFlags)
        ));
    }

    #[test]
    fn test_final_success_check_cost() {
        let script = [
            0x51, // OP_1
        ];

        // Pushes are free, so the only charge is the final check.
        assert_eq!(
            eval_metered(&script, &ScriptStack::new(), BUDGET),
            TapscriptV2Result::Valid {
                varops_remaining: Some(BUDGET - final_check(1))
            }
        );

        // Exaclty enough budget: the cost does not exceed what remains.
        assert_eq!(
            eval_metered(&script, &ScriptStack::new(), final_check(1)),
            TapscriptV2Result::Valid {
                varops_remaining: Some(0)
            }
        );

        // One unit short: the check must fail before looking at the element.
        let outcome = eval_metered(&script, &ScriptStack::new(), final_check(1) - 1);
        assert!(
            matches!(outcome, TapscriptV2Result::Invalid { .. }),
            "expected the final check to exhaust the budget, go {outcome:?}"
        );
    }

    #[test]
    fn test_op_cat_concatenates_and_is_costed() {
        // Stack (bottom first): the expected "joi!", then the halves "jo" and "i!".
        let stack: ScriptStack = [b"joi!".to_vec(), b"jo".to_vec(), b"i!".to_vec()]
            .into_iter()
            .collect();
        let script = [
            0x7e, // OP_CAT
            0x87, // OP_EQUAL
        ];

        let cost = (2 + 2) * 3 // OP_CAT: (length(A) + length(B)) * 3
            + 4 * 2 // OP_EQUAL: equal lengths, length(A) * 2
            + final_check(1);

        assert_eq!(
            eval_metered(&script, &stack, BUDGET),
            TapscriptV2Result::Valid {
                varops_remaining: Some(BUDGET - cost)
            }
        );
    }

    #[test]
    fn test_op_mul_multiplies_and_is_costed() {
        let script = [
            0x53, // OP_3
            0x55, // OP_5
            0x95, // OP_MUL
            0x5f, // OP_15
            0x87, // OP_EQUAL
        ];

        // OP_MUL: (length(A) + length(B)) * 3 + wordspan(A) / 8 * wordspan(B) * 27
        let mul = (1 + 1) * 3 + wordspan(1) / 8 * wordspan(1) * 27;
        // OP_EQUAL: the result is normalized to one byte, so length 1, times 2
        let equal = 2;

        assert_eq!(
            eval_metered(&script, &ScriptStack::new(), BUDGET),
            TapscriptV2Result::Valid {
                varops_remaining: Some(BUDGET - (mul + equal + final_check(1)))
            }
        );
    }

    #[test]
    fn test_op_success_short_circuits() {
        // OP_0 alonw would leave a false result, but OP_1NEGATE is OP_SUCCESS79
        // in a tapscript v2, so the script succeeds before anything executes.
        let script = [
            0x00, // OP_0
            0x4f, // OP_1NEGATE, i.e. OP_SUCCESS79
        ];

        // Nothing runs, so nothing is charged. This also catches the C side not
        // writing varops_remaining on the OP_SUCCESS path: the Rust side
        // initializes it to 0, which would show up her as Some(0).
        assert_eq!(
            eval_metered(&script, &ScriptStack::new(), BUDGET),
            TapscriptV2Result::Valid {
                varops_remaining: Some(BUDGET)
            }
        );
    }

    #[test]
    fn test_stack_push_and_read_back() {
        let mut stack = ScriptStack::new();
        assert!(stack.is_empty());

        stack.push(&[]);
        stack.push(&[0x01, 0x02]);

        assert_eq!(stack.len(), 2);
        assert_eq!(stack.item(0).unwrap(), Vec::<u8>::new());
        assert_eq!(stack.item(1).unwrap(), vec![0x01, 0x02]);
        assert!(matches!(stack.item(2), Err(KernelError::OutOfBounds)));
        assert_eq!(stack.to_vec().unwrap(), vec![vec![], vec![0x01, 0x02]]);
    }

    #[test]
    fn test_stack_clone_is_independent() {
        let mut stack: ScriptStack = [vec![0x01]].into_iter().collect();
        let mut cloned = stack.clone();

        cloned.push(&[0x02]);
        stack.push(&[0x03]);

        assert_eq!(cloned.to_vec().unwrap(), vec![vec![0x01], vec![0x02]]);
        assert_eq!(stack.to_vec().unwrap(), vec![vec![0x01], vec![0x03]]);
    }

    #[test]
    fn test_tapscript_v2_eval_status_from_kernel() {
        let ok = TapscriptV2EvalStatus::try_from(btck_TapscriptV2EvalStatus_OK).unwrap();
        assert_eq!(ok, TapscriptV2EvalStatus::Ok);

        let invalid_flags = TapscriptV2EvalStatus::try_from(
            btck_TapscriptV2EvalStatus_ERROR_INVALID_FLAGS_COMBINATION,
        )
        .unwrap();
        assert_eq!(
            invalid_flags,
            TapscriptV2EvalStatus::ErrorInvalidFlagsCombination
        );

        let restoration_required = TapscriptV2EvalStatus::try_from(
            btck_TapscriptV2EvalStatus_ERROR_SCRIPT_RESTORATION_REQUIRED,
        )
        .unwrap();
        assert_eq!(
            restoration_required,
            TapscriptV2EvalStatus::ErrorScriptRestorationRequired
        );

        let spent_required = TapscriptV2EvalStatus::try_from(
            btck_TapscriptV2EvalStatus_ERROR_SPENT_OUTPUTS_REQUIRED,
        )
        .unwrap();
        assert_eq!(
            spent_required,
            TapscriptV2EvalStatus::ErrorSpentOutputsRequired
        );

        let tapleaf_required =
            TapscriptV2EvalStatus::try_from(btck_TapscriptV2EvalStatus_ERROR_TAPLEAF_HASH_REQUIRED)
                .unwrap();
        assert_eq!(
            tapleaf_required,
            TapscriptV2EvalStatus::ErrorTapleafHashRequired
        );

        let invalid_index =
            TapscriptV2EvalStatus::try_from(btck_TapscriptV2EvalStatus_ERROR_INVALID_INPUT_INDEX)
                .unwrap();
        assert_eq!(invalid_index, TapscriptV2EvalStatus::ErrorInvalidInputIndex);
    }

    #[test]
    fn test_tapscript_v2_eval_status_to_kernel() {
        let ok: btck_TapscriptV2EvalStatus = TapscriptV2EvalStatus::Ok.into();
        assert_eq!(ok, btck_TapscriptV2EvalStatus_OK);

        let invalid_flags: btck_TapscriptV2EvalStatus =
            TapscriptV2EvalStatus::ErrorInvalidFlagsCombination.into();
        assert_eq!(
            invalid_flags,
            btck_TapscriptV2EvalStatus_ERROR_INVALID_FLAGS_COMBINATION
        );

        let restoration_required: btck_TapscriptV2EvalStatus =
            TapscriptV2EvalStatus::ErrorScriptRestorationRequired.into();
        assert_eq!(
            restoration_required,
            btck_TapscriptV2EvalStatus_ERROR_SCRIPT_RESTORATION_REQUIRED
        );

        let spent_required: btck_TapscriptV2EvalStatus =
            TapscriptV2EvalStatus::ErrorSpentOutputsRequired.into();
        assert_eq!(
            spent_required,
            btck_TapscriptV2EvalStatus_ERROR_SPENT_OUTPUTS_REQUIRED
        );

        let tapleaf_required: btck_TapscriptV2EvalStatus =
            TapscriptV2EvalStatus::ErrorTapleafHashRequired.into();
        assert_eq!(
            tapleaf_required,
            btck_TapscriptV2EvalStatus_ERROR_TAPLEAF_HASH_REQUIRED
        );

        let invalid_index: btck_TapscriptV2EvalStatus =
            TapscriptV2EvalStatus::ErrorInvalidInputIndex.into();
        assert_eq!(
            invalid_index,
            btck_TapscriptV2EvalStatus_ERROR_INVALID_INPUT_INDEX
        );
    }

    #[test]
    fn test_tapscript_v2_eval_status_round_trip() {
        let statuses = vec![
            TapscriptV2EvalStatus::Ok,
            TapscriptV2EvalStatus::ErrorInvalidFlagsCombination,
            TapscriptV2EvalStatus::ErrorScriptRestorationRequired,
            TapscriptV2EvalStatus::ErrorSpentOutputsRequired,
            TapscriptV2EvalStatus::ErrorTapleafHashRequired,
            TapscriptV2EvalStatus::ErrorInvalidInputIndex,
        ];

        for status in statuses {
            let kernel: btck_TapscriptV2EvalStatus = status.into();
            assert_eq!(Ok(status), TapscriptV2EvalStatus::try_from(kernel));
        }
    }

    #[test]
    fn test_tapscript_v2_eval_status_invalid_value() {
        let result = TapscriptV2EvalStatus::try_from(255);
        assert_eq!(result, Err(255));
    }
}
