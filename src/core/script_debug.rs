//! Script execution debug hooks.
//!
//! Provides a safe wrapper around the global script debug callback, allowing
//! inspection of stack state at each opcode during script verification.

use std::panic;
use std::sync::Mutex;

use libbitcoinkernel_sys::{
    btck_ScriptDebugState, btck_register_script_debug_callback,
    btck_unregister_script_debug_callback,
};

/// Script execution context (signature version).
///
/// Indicates which script system rules apply during execution.
/// Key-path taproot spends (`Taproot`) bypass `EvalScript` entirely,
/// so they will not appear in debug callbacks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
#[repr(u8)]
pub enum SigVersion {
    /// Bare scripts and BIP16 P2SH-wrapped redeemscripts.
    Base = 0,
    /// Witness v0 (P2WPKH and P2WSH); see BIP 141.
    WitnessV0 = 1,
    /// Witness v1 key path spending; see BIP 341.
    Taproot = 2,
    /// Witness v1 script path spending, leaf version 0xc0; see BIP 342.
    Tapscript = 3,
}

impl TryFrom<u8> for SigVersion {
    type Error = u8;
    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            0 => Ok(SigVersion::Base),
            1 => Ok(SigVersion::WitnessV0),
            2 => Ok(SigVersion::Taproot),
            3 => Ok(SigVersion::Tapscript),
            other => Err(other),
        }
    }
}

/// A snapshot of script execution state at a single opcode step.
#[derive(Debug, Clone)]
pub struct ScriptDebugFrame {
    /// Stack items (bottom-to-top).
    pub stack: Vec<Vec<u8>>,
    /// Altstack items (bottom-to-top).
    pub altstack: Vec<Vec<u8>>,
    /// Full script bytes being executed.
    pub script: Vec<u8>,
    /// Iteration index within EvalScript (opcode position).
    pub opcode_pos: u32,
    /// Whether the current branch is being executed (`true` = active, `false` = inside a false IF).
    pub f_exec: bool,
    /// Decoded opcode value for the current instruction.
    /// `0xff` (`OP_INVALIDOPCODE`) on the final callback or for empty scripts.
    pub opcode: u8,
    /// Cumulative count of non-push opcodes executed so far (tracks the 201-op limit).
    pub op_count: u32,
    /// Script execution context (legacy, segwit v0, tapscript, etc.).
    pub sig_version: SigVersion,
}

/// Guard that keeps a script debug callback registered.
///
/// Only one `ScriptDebugger` can be active at a time (enforced by a mutex).
/// Dropping the `ScriptDebugger` unregisters the callback.
pub struct ScriptDebugger {
    /// Double-boxed so the outer Box provides a stable thin pointer for C.
    _closure: Box<Box<dyn FnMut(ScriptDebugFrame)>>,
}

/// Global mutex guarding callback registration.
static REGISTERED: Mutex<bool> = Mutex::new(false);

impl ScriptDebugger {
    /// Register a debug callback that receives a [`ScriptDebugFrame`] for each opcode step.
    ///
    /// Returns `None` if a debugger is already registered.
    pub fn new<F>(callback: F) -> Option<Self>
    where
        F: FnMut(ScriptDebugFrame) + 'static,
    {
        let mut guard = REGISTERED.lock().unwrap();
        if *guard {
            return None;
        }

        let mut closure: Box<Box<dyn FnMut(ScriptDebugFrame)>> = Box::new(Box::new(callback));
        let user_data =
            &mut *closure as *mut Box<dyn FnMut(ScriptDebugFrame)> as *mut std::ffi::c_void;

        unsafe {
            btck_register_script_debug_callback(user_data, Some(trampoline));
        }

        *guard = true;
        Some(ScriptDebugger { _closure: closure })
    }
}

impl Drop for ScriptDebugger {
    fn drop(&mut self) {
        let mut guard = REGISTERED.lock().unwrap();
        unsafe {
            btck_unregister_script_debug_callback();
        }
        *guard = false;
    }
}

/// C-compatible trampoline that converts the raw state into a `ScriptDebugFrame` and
/// forwards it to the user's closure.
unsafe extern "C" fn trampoline(
    user_data: *mut std::ffi::c_void,
    state: *const btck_ScriptDebugState,
) {
    if user_data.is_null() || state.is_null() {
        return;
    }

    let _ = panic::catch_unwind(|| {
        let state = unsafe { &*state };

        let stack = read_stack(state.stack_items, state.stack_item_sizes, state.stack_size);
        let altstack = read_stack(
            state.altstack_items,
            state.altstack_item_sizes,
            state.altstack_size,
        );
        let script = if state.script.is_null() || state.script_size == 0 {
            Vec::new()
        } else {
            unsafe { std::slice::from_raw_parts(state.script, state.script_size) }.to_vec()
        };

        let sig_version = SigVersion::try_from(state.sig_version).unwrap_or(SigVersion::Base);

        let frame = ScriptDebugFrame {
            stack,
            altstack,
            script,
            opcode_pos: state.opcode_pos,
            f_exec: state.f_exec != 0,
            opcode: state.opcode,
            op_count: state.op_count as u32,
            sig_version,
        };

        let closure = unsafe { &mut **(user_data as *mut Box<dyn FnMut(ScriptDebugFrame)>) };
        closure(frame);
    });
}

/// Read a C stack (array of byte-slices) into `Vec<Vec<u8>>`.
unsafe fn read_stack(items: *const *const u8, sizes: *const usize, count: usize) -> Vec<Vec<u8>> {
    if items.is_null() || sizes.is_null() || count == 0 {
        return Vec::new();
    }
    let items = unsafe { std::slice::from_raw_parts(items, count) };
    let sizes = unsafe { std::slice::from_raw_parts(sizes, count) };
    items
        .iter()
        .zip(sizes.iter())
        .map(|(&ptr, &len)| {
            if ptr.is_null() || len == 0 {
                Vec::new()
            } else {
                unsafe { std::slice::from_raw_parts(ptr, len) }.to_vec()
            }
        })
        .collect()
}
