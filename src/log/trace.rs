use std::{
    ffi::c_void,
    fmt::{Debug, Formatter},
    marker::PhantomData,
    panic,
    sync::atomic::{AtomicBool, Ordering},
};

use libbitcoinkernel_sys::{
    btck_ScriptEvalStack, btck_ScriptEvalStackItem, btck_ScriptTraceFrame,
    btck_ScriptTraceFrameKind, btck_ScriptTraceFrameKind_BEGIN, btck_ScriptTraceFrameKind_END,
    btck_ScriptTraceFrameKind_STEP, btck_SigVersion, btck_SigVersion_BASE, btck_SigVersion_TAPROOT,
    btck_SigVersion_TAPSCRIPT, btck_SigVersion_WITNESS_V0, btck_script_eval_stack_count_items,
    btck_script_eval_stack_get_item_at, btck_script_eval_stack_item_to_bytes,
    btck_script_trace_frame_get_altstack, btck_script_trace_frame_get_codeseparator_pos,
    btck_script_trace_frame_get_exec, btck_script_trace_frame_get_kind,
    btck_script_trace_frame_get_op_count, btck_script_trace_frame_get_opcode,
    btck_script_trace_frame_get_opcode_pos, btck_script_trace_frame_get_script,
    btck_script_trace_frame_get_script_error, btck_script_trace_frame_get_sig_version,
    btck_script_trace_frame_get_stack, btck_script_trace_frame_get_tapleaf_hash,
    btck_script_trace_register_callback, btck_script_trace_unregister_callback,
};

use crate::{
    c_serialize,
    ffi::{
        c_helpers,
        sealed::{AsPtr, FromPtr},
    },
    KernelError,
};

pub trait ScriptTraceCallback: Send + Sync {
    fn on_script_trace<'a>(&self, frame: ScriptTraceFrameRef<'a>);
}

impl<F> ScriptTraceCallback for F
where
    F: for<'a> Fn(ScriptTraceFrameRef<'a>) + Send + Sync + 'static,
{
    fn on_script_trace<'a>(&self, frame: ScriptTraceFrameRef<'a>) {
        self(frame)
    }
}

unsafe extern "C" fn trace_callback<T: ScriptTraceCallback + 'static>(
    user_data: *mut c_void,
    frame: *const btck_ScriptTraceFrame,
) {
    let _ = panic::catch_unwind(panic::AssertUnwindSafe(|| {
        let tracer = &*(user_data as *const T);
        tracer.on_script_trace(ScriptTraceFrameRef::from_ptr(frame));
    }));
}

unsafe extern "C" fn destroy_trace_callback<T>(user_data: *mut c_void) {
    if !user_data.is_null() {
        let _ = Box::from_raw(user_data as *mut T);
    }
}

// Guards a single global registration. The kernel silently replaces an
// existing callback, which would leave a stale handle whose `Drop` unregisters
// somebody else's tracer, so reject the second registration instead.
static TRACER_REGISTERED: AtomicBool = AtomicBool::new(false);

/// An active script trace registration.
///
/// Tracing stops when this handle is dropped. Only one may exist at a time.
#[must_use = "dropping the handle immediately unregisters the tracer"]
pub struct ScriptTracer {
    _marker: PhantomData<()>,
}

impl ScriptTracer {
    /// Register `tracer` as the global script trace callback.
    ///
    /// # Errors
    ///
    /// Returns [`KernelError::Internal`] if a tracer is already registered.
    pub fn new<T: ScriptTraceCallback + 'static>(tracer: T) -> Result<Self, KernelError> {
        if TRACER_REGISTERED.swap(true, Ordering::SeqCst) {
            return Err(KernelError::Internal(
                "A script tracer is already registered".to_string(),
            ));
        }

        let tracer_ptr = Box::into_raw(Box::new(tracer));

        let result = unsafe {
            btck_script_trace_register_callback(
                trace_callback::<T>,
                tracer_ptr as *mut c_void,
                Some(destroy_trace_callback::<T>),
            )
        };

        if !c_helpers::success(result) {
            // Unreachable with this feature enabled, since the kernel only
            // fails registration on the stubbed-out path. Handle it anyway: the
            // kernel runs the destroy callback before returning there, so the
            // box is already freed and `tracer_ptr` must not be touched here.
            TRACER_REGISTERED.store(false, Ordering::SeqCst);
            return Err(KernelError::Internal(
                "Failed to register the script trace callback.".to_string(),
            ));
        }

        Ok(ScriptTracer {
            _marker: PhantomData,
        })
    }
}

impl Drop for ScriptTracer {
    fn drop(&mut self) {
        unsafe {
            btck_script_trace_unregister_callback();
        }
        TRACER_REGISTERED.store(false, Ordering::SeqCst);
    }
}

/// Which point of script evaluation a frame was emitted from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ScriptTraceFrameKind {
    /// Emitted once on entry to script evaluation.
    Begin = btck_ScriptTraceFrameKind_BEGIN,
    /// Emitted once per decoded opcode.
    Step = btck_ScriptTraceFrameKind_STEP,
    /// Emitted once on exit, carrying the final stack and script error.
    End = btck_ScriptTraceFrameKind_END,
}

impl From<ScriptTraceFrameKind> for btck_ScriptTraceFrameKind {
    fn from(kind: ScriptTraceFrameKind) -> Self {
        kind as btck_ScriptTraceFrameKind
    }
}

#[allow(non_upper_case_globals)]
impl From<btck_ScriptTraceFrameKind> for ScriptTraceFrameKind {
    fn from(value: btck_ScriptTraceFrameKind) -> Self {
        match value {
            btck_ScriptTraceFrameKind_BEGIN => ScriptTraceFrameKind::Begin,
            btck_ScriptTraceFrameKind_STEP => ScriptTraceFrameKind::Step,
            btck_ScriptTraceFrameKind_END => ScriptTraceFrameKind::End,
            _ => panic!("Unknown script trace frame kind: {}", value),
        }
    }
}

/// The signature hashing scheme in use for the script being evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SigVersion {
    /// Bare scripts and P2SH.
    Base = btck_SigVersion_BASE,
    /// Witness v0 (BIP143).
    WitnessV0 = btck_SigVersion_WITNESS_V0,
    /// Taproot key path spend (BIP341).
    Taproot = btck_SigVersion_TAPROOT,
    /// Taproot script path spend (BIP342).
    Tapscript = btck_SigVersion_TAPSCRIPT,
}

impl From<SigVersion> for btck_SigVersion {
    fn from(version: SigVersion) -> Self {
        version as btck_SigVersion
    }
}

#[allow(non_upper_case_globals)]
impl From<btck_SigVersion> for SigVersion {
    fn from(value: btck_SigVersion) -> Self {
        match value {
            btck_SigVersion_BASE => SigVersion::Base,
            btck_SigVersion_WITNESS_V0 => SigVersion::WitnessV0,
            btck_SigVersion_TAPROOT => SigVersion::Taproot,
            btck_SigVersion_TAPSCRIPT => SigVersion::Tapscript,
            _ => panic!("Unknown sig version: {}", value),
        }
    }
}

/// A borrowed view of the interpreter state at one point in the script evaluation.
///
/// Only valid for the duration of the [`ScriptTraceCallback::on_script_trace`] call
/// it was handed to. Use [`to_owned`](Self::to_owned) to keep a copy.
#[derive(Clone, Copy)]
pub struct ScriptTraceFrameRef<'a> {
    inner: *const btck_ScriptTraceFrame,
    marker: PhantomData<&'a btck_ScriptTraceFrame>,
}

impl FromPtr<btck_ScriptTraceFrame> for ScriptTraceFrameRef<'_> {
    unsafe fn from_ptr(ptr: *const btck_ScriptTraceFrame) -> Self {
        ScriptTraceFrameRef {
            inner: ptr,
            marker: PhantomData,
        }
    }
}

impl<'a> ScriptTraceFrameRef<'a> {
    /// Whether this is a begin, step or end frame.
    pub fn kind(&self) -> ScriptTraceFrameKind {
        unsafe { btck_script_trace_frame_get_kind(self.as_ptr()) }.into()
    }

    /// The main evaluation stack, bottom first.
    pub fn stack(&self) -> ScriptEvalStackRef<'a> {
        unsafe { ScriptEvalStackRef::from_ptr(btck_script_trace_frame_get_stack(self.as_ptr())) }
    }

    /// The alt stack, bottom first.
    pub fn altstack(&self) -> ScriptEvalStackRef<'a> {
        unsafe { ScriptEvalStackRef::from_ptr(btck_script_trace_frame_get_altstack(self.as_ptr())) }
    }

    /// The script being evaluated.
    ///
    /// This copies the whole script out of the kernel on every call, so avoid
    /// calling it once per step frame if the script is large.
    pub fn script(&self) -> Result<Vec<u8>, KernelError> {
        c_serialize(|writer, user_data| unsafe {
            btck_script_trace_frame_get_script(self.as_ptr(), writer, user_data)
        })
    }

    /// Index of the current opcode, counting opcodes rather than bytes.
    pub fn opcode_pos(&self) -> u32 {
        unsafe { btck_script_trace_frame_get_opcode_pos(self.as_ptr()) }
    }

    /// Whether this opcode is executed, as opposed to skipped by a conditional
    /// branch. Only meaningful in [`ScriptTraceFrameKind::Step`] frames.
    pub fn exec(&self) -> bool {
        c_helpers::enabled(unsafe { btck_script_trace_frame_get_exec(self.as_ptr()) })
    }

    /// The current opcode. Only meaningful in [`ScriptTraceFrameKind::Step`]
    /// frames.
    pub fn opcode(&self) -> u8 {
        unsafe { btck_script_trace_frame_get_opcode(self.as_ptr()) }
    }

    /// The interpreter's opcode budget, checked against `MAX_OPS_PER_SCRIPT`.
    /// Counts opcodes above `OP_16` executed before this one; note that
    /// `OP_CHECKMULTISIG` charges one per key, so it can jump by more than one.
    pub fn op_count(&self) -> i32 {
        unsafe { btck_script_trace_frame_get_op_count(self.as_ptr()) }
    }

    /// The signature hashing scheme of the script being evaluated.
    pub fn sig_version(&self) -> SigVersion {
        unsafe { btck_script_trace_frame_get_sig_version(self.as_ptr()) }.into()
    }

    /// The tapleaf hash, present only for tapscript evaluation.
    pub fn tapleaf_hash(&self) -> Option<[u8; 32]> {
        let mut hash = [0u8; 32];
        let result =
            unsafe { btck_script_trace_frame_get_tapleaf_hash(self.as_ptr(), hash.as_mut_ptr()) };
        c_helpers::success(result).then_some(hash)
    }

    /// Byte offset of the last executed `OP_CODESEPARATOR`.
    ///
    /// Returns [`u32::MAX`] when no code separator has been executed, matching
    /// the interpreter's own sentinel.
    pub fn codeseparator_pos(&self) -> u32 {
        unsafe { btck_script_trace_frame_get_codeseparator_pos(self.as_ptr()) }
    }

    /// The script error code. Only meaningful for [`ScriptTraceFrameKind::End`] frames.
    pub fn script_error(&self) -> i32 {
        unsafe { btck_script_trace_frame_get_script_error(self.as_ptr()) }
    }

    /// Copy the frame out of the kernel so it can outlive the callback.
    pub fn to_owned(&self) -> Result<ScriptTraceFrame, KernelError> {
        Ok(ScriptTraceFrame {
            kind: self.kind(),
            stack: self.stack().to_vec()?,
            altstack: self.altstack().to_vec()?,
            script: self.script()?,
            opcode_pos: self.opcode_pos(),
            exec: self.exec(),
            opcode: self.opcode(),
            op_count: self.op_count(),
            sig_version: self.sig_version(),
            tapleaf_hash: self.tapleaf_hash(),
            codeseparator_pos: self.codeseparator_pos(),
            script_error: self.script_error(),
        })
    }
}

impl AsPtr<btck_ScriptTraceFrame> for ScriptTraceFrameRef<'_> {
    fn as_ptr(&self) -> *const btck_ScriptTraceFrame {
        self.inner
    }
}

impl Debug for ScriptTraceFrameRef<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScriptTraceFrameRef")
            .field("kind", &self.kind())
            .field("opcode", &self.opcode())
            .field("opcode_pos", &self.opcode_pos())
            .field("exec", &self.exec())
            .field("op_count", &self.op_count())
            .field("sig_version", &self.sig_version())
            .field("stack_len", &self.stack().len())
            .field("altstack_len", &self.altstack().len())
            .field("script_error", &self.script_error())
            .finish_non_exhaustive()
    }
}

/// An owned snapshot of a [`ScriptTraceFrameRef`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptTraceFrame {
    pub kind: ScriptTraceFrameKind,
    pub stack: Vec<Vec<u8>>,
    pub altstack: Vec<Vec<u8>>,
    pub script: Vec<u8>,
    pub opcode_pos: u32,
    pub exec: bool,
    pub opcode: u8,
    pub op_count: i32,
    pub sig_version: SigVersion,
    pub tapleaf_hash: Option<[u8; 32]>,
    pub codeseparator_pos: u32,
    pub script_error: i32,
}

/// A borrowed view of one of the interpreter's stacks.
#[derive(Clone, Copy)]
pub struct ScriptEvalStackRef<'a> {
    inner: *const btck_ScriptEvalStack,
    marker: PhantomData<&'a btck_ScriptEvalStack>,
}

impl FromPtr<btck_ScriptEvalStack> for ScriptEvalStackRef<'_> {
    unsafe fn from_ptr(ptr: *const btck_ScriptEvalStack) -> Self {
        ScriptEvalStackRef {
            inner: ptr,
            marker: PhantomData,
        }
    }
}

impl<'a> ScriptEvalStackRef<'a> {
    /// Number of items on the stack.
    pub fn len(&self) -> usize {
        unsafe { btck_script_eval_stack_count_items(self.as_ptr()) }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Item at `index`, counting from the bottom of the stack. The top of the
    /// stack is at `len() - 1`.
    pub fn get(&self, index: usize) -> Option<ScriptEvalStackItemRef<'a>> {
        if index >= self.len() {
            return None;
        }
        Some(unsafe {
            ScriptEvalStackItemRef::from_ptr(btck_script_eval_stack_get_item_at(
                self.as_ptr(),
                index,
            ))
        })
    }

    /// Iterate the stack from bottom to top.
    pub fn iter(&self) -> ScriptEvalStackIter<'a> {
        ScriptEvalStackIter {
            stack: *self,
            index: 0,
            len: self.len(),
        }
    }

    /// Copy every item out of the kernel.
    pub fn to_vec(&self) -> Result<Vec<Vec<u8>>, KernelError> {
        self.iter().map(|item| item.to_bytes()).collect()
    }
}

impl AsPtr<btck_ScriptEvalStack> for ScriptEvalStackRef<'_> {
    fn as_ptr(&self) -> *const btck_ScriptEvalStack {
        self.inner
    }
}

impl<'a> IntoIterator for ScriptEvalStackRef<'a> {
    type Item = ScriptEvalStackItemRef<'a>;
    type IntoIter = ScriptEvalStackIter<'a>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl Debug for ScriptEvalStackRef<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScriptEvalStackRef")
            .field("len", &self.len())
            .finish()
    }
}

/// Iterator over the items in a [`ScriptEvalStackRef`], bottom to top.
pub struct ScriptEvalStackIter<'a> {
    stack: ScriptEvalStackRef<'a>,
    index: usize,
    len: usize,
}

impl<'a> Iterator for ScriptEvalStackIter<'a> {
    type Item = ScriptEvalStackItemRef<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        let item = self.stack.get(self.index)?;
        self.index += 1;
        Some(item)
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        let remaining = self.len - self.index;
        (remaining, Some(remaining))
    }
}

impl ExactSizeIterator for ScriptEvalStackIter<'_> {}

/// A borrowed view of a single stack item.
#[derive(Clone, Copy)]
pub struct ScriptEvalStackItemRef<'a> {
    inner: *const btck_ScriptEvalStackItem,
    marker: PhantomData<&'a btck_ScriptEvalStackItem>,
}

impl FromPtr<btck_ScriptEvalStackItem> for ScriptEvalStackItemRef<'_> {
    unsafe fn from_ptr(ptr: *const btck_ScriptEvalStackItem) -> Self {
        ScriptEvalStackItemRef {
            inner: ptr,
            marker: PhantomData,
        }
    }
}

impl ScriptEvalStackItemRef<'_> {
    /// Copy the item's bytes out of the kernel.
    pub fn to_bytes(&self) -> Result<Vec<u8>, KernelError> {
        c_serialize(|writer, user_data| unsafe {
            btck_script_eval_stack_item_to_bytes(self.as_ptr(), writer, user_data)
        })
    }
}

impl AsPtr<btck_ScriptEvalStackItem> for ScriptEvalStackItemRef<'_> {
    fn as_ptr(&self) -> *const btck_ScriptEvalStackItem {
        self.inner
    }
}

impl Debug for ScriptEvalStackItemRef<'_> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ScriptEvalStackItemRef").finish()
    }
}

/// A [`ScriptTraceCallback`] implementation that records every frame it is handed.
///
/// Useful for tests and for driving a debugger UI off a completed evaluation.
#[derive(Debug, Default, Clone)]
pub struct ScriptTraceCollector {
    frames: std::sync::Arc<std::sync::Mutex<Vec<ScriptTraceFrame>>>,
}

impl ScriptTraceCollector {
    pub fn new() -> Self {
        Self::default()
    }

    /// Every frame recorded so far, in the order it was emitted.
    pub fn frames(&self) -> Vec<ScriptTraceFrame> {
        self.frames.lock().unwrap().clone()
    }

    /// Take the recorded frames, leaving the collector empty.
    pub fn take(&self) -> Vec<ScriptTraceFrame> {
        std::mem::take(&mut *self.frames.lock().unwrap())
    }
}

impl ScriptTraceCallback for ScriptTraceCollector {
    fn on_script_trace(&self, frame: ScriptTraceFrameRef<'_>) {
        if let Ok(frame) = frame.to_owned() {
            self.frames.lock().unwrap().push(frame);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct NoopTracer;

    impl ScriptTraceCallback for NoopTracer {
        fn on_script_trace<'a>(&self, _frame: ScriptTraceFrameRef<'a>) {}
    }

    #[test]
    fn test_closure_trait_implementation() {
        let handler = |_frame: ScriptTraceFrameRef<'_>| {};
        let _: Box<dyn ScriptTraceCallback> = Box::new(handler);
    }

    #[test]
    fn test_frame_kind_conversions() {
        for kind in [
            ScriptTraceFrameKind::Begin,
            ScriptTraceFrameKind::Step,
            ScriptTraceFrameKind::End,
        ] {
            let raw: btck_ScriptTraceFrameKind = kind.into();
            assert_eq!(kind, raw.into());
        }
    }

    #[test]
    fn test_sig_version_conversions() {
        for version in [
            SigVersion::Base,
            SigVersion::WitnessV0,
            SigVersion::Taproot,
            SigVersion::Tapscript,
        ] {
            let raw: btck_SigVersion = version.into();
            assert_eq!(version, raw.into());
        }
    }

    #[test]
    fn test_register_unregister() {
        let tracer = ScriptTracer::new(NoopTracer).unwrap();

        assert!(matches!(
            ScriptTracer::new(NoopTracer),
            Err(KernelError::Internal(_))
        ));

        drop(tracer);

        let _tracer = ScriptTracer::new(NoopTracer).unwrap();
    }
}
