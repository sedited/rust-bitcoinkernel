//! Why a method failed, and how each failure is reported.

/// Why a method failed.
#[derive(Debug)]
pub enum Error {
    /// The kernel rejected the operation (e.g. the C API returned null).
    /// Reported to the runner as `{"error": {}}`.
    Kernel,
    /// The kernel failed with a specific C API error code.
    /// Reported as `{"error": {"code": {"type": ..., "member": ...}}}`.
    Code(&'static str, &'static str),
    /// The request itself is invalid (unknown reference, malformed params, ...).
    /// The handler reports it on stderr and exits.
    Protocol(String),
}

impl Error {
    pub fn protocol(msg: impl Into<String>) -> Error {
        Error::Protocol(msg.into())
    }
}

impl From<bitcoinkernel::KernelError> for Error {
    fn from(_: bitcoinkernel::KernelError) -> Self {
        Error::Kernel
    }
}
