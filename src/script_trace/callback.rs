use std::ffi::c_void;

use libbitcoinkernel_sys::{
    btck_ScriptTraceFrame as RawScriptTraceFrame, btck_script_trace_register_callback,
    btck_script_trace_unregister_callback,
};

use crate::{ffi::c_helpers, KernelError};

use super::ScriptTraceFrame;

/// Handles script execution trace frames emitted by the library.
///
/// Requires the library to have been compiled with the
/// `ENABLE_SCRIPT_TRACE` Cmake option (see the `script-trace` feature on
/// `libbitcoinkernel-sys`); otherwise [`set_script_trace_callback`] returns
/// [`KernelError::ScriptTraceUnavailable`].
pub trait ScriptTracer: Send + Sync {
    fn on_script_trace(&self, frame: ScriptTraceFrame);
}

impl<F> ScriptTracer for F
where
    F: Fn(ScriptTraceFrame) + Send + Sync + 'static,
{
    fn on_script_trace(&self, frame: ScriptTraceFrame) {
        self(frame)
    }
}

unsafe extern "C" fn script_trace_wrapper<T: ScriptTracer + 'static>(
    user_data: *mut c_void,
    state: *const RawScriptTraceFrame,
) {
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let tracer = &*(user_data as *mut T);
        let frame = ScriptTraceFrame::from_raw(&*state);
        tracer.on_script_trace(frame);
    }));

    if result.is_err() {
        // Either ABI skew in from_raw, or a panic in the user's tracer.
        // Either way we can't safely unwind across the FFI boundary/
        std::process::abort();
    }
}

unsafe extern "C" fn destroy_script_tracer<T>(user_data: *mut c_void) {
    if !user_data.is_null() {
        let _ = Box::from_raw(user_data as *mut T);
    }
}

/// Registers a global script execution trace callback.
///
/// Only one callback may be registered at a time; registering a new one
/// replaces any previously registered callback.
///
/// # Errors
///
/// Returns [`KernelError::ScriptTraceUnavailable`] if the library was not compiled
/// with `ENABLE_SCRIPT_TRACE`. In that case the kernel destroys `tracer`
/// synchronously before this returns, so no memory is leaked.
pub fn set_script_trace_callback<T: ScriptTracer + 'static>(tracer: T) -> Result<(), KernelError> {
    let ptr = Box::into_raw(Box::new(tracer)) as *mut c_void;

    let ret = unsafe {
        btck_script_trace_register_callback(
            script_trace_wrapper::<T>,
            ptr,
            Some(destroy_script_tracer::<T>),
        )
    };

    if c_helpers::success(ret) {
        Ok(())
    } else {
        Err(KernelError::ScriptTraceUnavailable)
    }
}

/// Unregisters the global script execution trace callback, if any.
///
/// After this returns, no new invocations of a previously registered
/// callback will begin; an invocation already in progress on another thread
/// is allowed to finish.
pub fn unset_script_trace_callback() {
    unsafe {
        btck_script_trace_unregister_callback();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    #[test]
    fn test_closure_trait_implementation() {
        let handler = |_frame: ScriptTraceFrame| {};
        let _: Box<dyn ScriptTracer> = Box::new(handler);
    }

    #[test]
    fn test_set_and_unset_script_trace_callback() {
        let called = Arc::new(Mutex::new(false));
        let called_clone = called.clone();

        // Whether this succeeds depends on whether ENABLE_SCRIPT_TRACE was
        // compiled in; either outcome is a valid `Result`, so just check it
        // doesn't panic and cleans up correctly either way.
        let result = set_script_trace_callback(move |_frame: ScriptTraceFrame| {
            *called_clone.lock().unwrap() = true;
        });

        unset_script_trace_callback();

        match result {
            Ok(()) | Err(KernelError::ScriptTraceUnavailable) => {}
            Err(e) => panic!("unexpected error: {e}"),
        }
    }
}
