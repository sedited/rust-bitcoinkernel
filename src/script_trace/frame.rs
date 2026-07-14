use libbitcoinkernel_sys::{
    btck_ScriptTraceFrame as RawScriptTraceFrame, btck_ScriptTraceFrameKind,
    btck_ScriptTraceFrameKind_BEGIN, btck_ScriptTraceFrameKind_END, btck_ScriptTraceFrameKind_STEP,
    btck_SigVersion, btck_SigVersion_BASE, btck_SigVersion_TAPROOT, btck_SigVersion_TAPSCRIPT,
    btck_SigVersion_WITNESS_V0,
};

/// Which point in script execution a [`ScriptTraceFrame`] was captured at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum ScriptTraceFrameKind {
    /// Captured before the first opcode of the script is evaluated.
    Begin = btck_ScriptTraceFrameKind_BEGIN,
    /// Captured before each opcode is evaluated (or skipped in a not-taken branch).
    Step = btck_ScriptTraceFrameKind_STEP,
    /// Captured after the script has finished evaluating, whether or not it succeeded.
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

/// Signatures hashing scheme in effect for the script being evaluated.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum SigVersion {
    /// Pre-SegWit (legacy) scripts.
    Base = btck_SigVersion_BASE,
    /// SegWit v0 scripts (BIP 143).
    WitnessV0 = btck_SigVersion_WITNESS_V0,
    /// Taproot key path spends (BIP 341).
    Taproot = btck_SigVersion_TAPROOT,
    /// Taproot script path spends (BIP 342).
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ScriptTraceFrame {
    /// Whether this frame was captured at the start, an intermediate step, or the end.
    pub kind: ScriptTraceFrameKind,
    /// The main stack at the time this frame was captured.
    pub stack: Vec<Vec<u8>>,
    /// The alt stack at the time this frame was captured.
    pub altstack: Vec<Vec<u8>>,
    /// The script currently being evaluated.
    pub script: Vec<u8>,
    /// Index of the current opcode, counting opcodes rather than bytes.
    pub opcode_pos: u32,
    /// `false` if this opcode is being skipped because it's a not-taken conditional branch.
    pub exec: bool,
    /// The opcode under evaluation. Only meaningful for [`ScriptTraceFrameKind::Step`] frames.
    pub opcode: u8,
    /// Running counter towards the per-script operation limit.
    pub op_count: i32,
    /// Signature hashing scheme in effect.
    pub sig_version: SigVersion,
    /// The tapleaf hash, if a tapscript is being evaluated.
    pub tapleaf_hash: Option<[u8; 32]>,
    /// Opcode position of the last-evaluated `OP_CODESEPARATOR`, or `0xFFFFFFFF` if none yet.
    pub codeseparator_pos: u32,
    /// The script error code. Only meaningful for [`ScriptTraceFrameKind::End`] frames.
    pub script_error: i32,
}

impl ScriptTraceFrame {
    /// Copies a [`ScriptTraceFrame`] out of the raw kernel struct.
    pub(super) unsafe fn from_raw(frame: &RawScriptTraceFrame) -> Self {
        // Safe wrapper: `from_raw_parts` requires a non-null, aligned pointer even
        // for a zero-length slice, but the kernel may hand back null for empty items.
        unsafe fn slice_or_empty<'a>(ptr: *const u8, len: usize) -> &'a [u8] {
            if len == 0 {
                &[]
            } else {
                std::slice::from_raw_parts(ptr, len)
            }
        }

        let mut stack = Vec::with_capacity(frame.stack_size);
        for i in 0..frame.stack_size {
            let ptr = *frame.stack_items.add(i);
            let len = *frame.stack_item_sizes.add(i);
            stack.push(slice_or_empty(ptr, len).to_vec());
        }

        let mut altstack = Vec::with_capacity(frame.altstack_size);
        for i in 0..frame.altstack_size {
            let ptr = *frame.altstack_items.add(i);
            let len = *frame.altstack_item_sizes.add(i);
            altstack.push(slice_or_empty(ptr, len).to_vec());
        }

        let script = slice_or_empty(frame.script, frame.script_size).to_vec();

        let tapleaf_hash = if frame.tapleaf_hash.is_null() {
            None
        } else {
            let mut buf = [0u8; 32];
            std::ptr::copy_nonoverlapping(frame.tapleaf_hash, buf.as_mut_ptr(), 32);
            Some(buf)
        };

        ScriptTraceFrame {
            kind: frame.kind.into(),
            stack,
            altstack,
            script,
            opcode_pos: frame.opcode_pos,
            exec: frame.f_exec != 0,
            opcode: frame.opcode,
            op_count: frame.op_count,
            sig_version: frame.sig_version.into(),
            tapleaf_hash,
            codeseparator_pos: frame.codeseparator_pos,
            script_error: frame.script_error,
        }
    }
}

#[cfg(test)]
mod tests {
    use libbitcoinkernel_sys::btck_ScriptTraceFrameKind;

    use super::*;

    #[test]
    fn test_frame_kind_conversion() {
        for kind in [
            ScriptTraceFrameKind::Begin,
            ScriptTraceFrameKind::Step,
            ScriptTraceFrameKind::End,
        ] {
            let raw: btck_ScriptTraceFrameKind = kind.into();
            let back: ScriptTraceFrameKind = raw.into();
            assert_eq!(kind, back);
        }
    }

    #[test]
    #[should_panic(expected = "Unknown script trace frame kind")]
    fn test_frame_kind_invalid_value() {
        let _: ScriptTraceFrameKind = 255.into();
    }

    #[test]
    fn test_sig_version_conversion() {
        for version in [
            SigVersion::Base,
            SigVersion::WitnessV0,
            SigVersion::Taproot,
            SigVersion::Tapscript,
        ] {
            let raw: btck_SigVersion = version.into();
            let back: SigVersion = raw.into();
            assert_eq!(version, back);
        }
    }

    #[test]
    #[should_panic(expected = "Unknown sig version")]
    fn test_sig_version_invalid_value() {
        let _: SigVersion = 255.into();
    }
}
