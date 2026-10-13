pub mod logging;
#[cfg(feature = "script-trace")]
#[cfg_attr(docsrs, doc(cfg(feature = "script-trace")))]
pub mod trace;

pub use logging::{disable_logging, Log, LogCategory, LogLevel, Logger};
#[cfg(feature = "script-trace")]
pub use trace::{
    ScriptEvalStackItemRef, ScriptEvalStackIter, ScriptEvalStackRef, ScriptTraceCallback,
    ScriptTraceCollector, ScriptTraceFrame, ScriptTraceFrameKind, ScriptTraceFrameRef,
    ScriptTracer, SigVersion,
};
