//! Evaluate a tapscript v2 (BIP 440/441) script directly, with a trace.
//!
//! `gsr_scripttrace` builds a whole taproot spend -- a key pair, a script tree,
//! a control block committing to the 0xc2 leaf, a funding and a spending
//! transaction -- just to get the interpreter to run a handful of opcodes.
//! `eval_tapscript_v2` skips all of that and runs the leaf script against a
//! stack you hand it, which is what you actually want when the script is under
//! test.
//!
//! The trade-off: there is no transaction, so signature and locktime opcodes
//! fail. Scripts that need one still have to go through `verify`.
//!
//! Stack items are pushed bottom first, so the last one given is on top when
//! the script starts. Each step shows the stack *before* its opcode runs,
//! followed by what that opcode charged once the next frame reveals it.
//!
//! Every run is metered, by default against the largest budget any
//! transaction can have, so for a satisfied script the reported total
//! includes the final success check, which runs after the trace ends and
//! never appears in a frame. Pass `--budget <varops>` to check a script
//! against a tighter limit, such as one derived from a specific transaction's weight.
//!
//! Usage:
//!
//! ```text
//! cargo run -p examples --features examples/script-trace --bin gsr_eval -- \
//!     [--budget <varops>] <script-hex> [stack-item-hex ...]
//!
//! # OP_2 OP_3 OP_ADD OP_5 OP_EQUAL, starting from an empty stack
//! cargo run -p examples --features examples/script-trace --bin gsr_eval -- 5253935587
//!
//! # OP_CAT OP_EQUAL over three stack items: the expected value, then the two
//! # halves to concatenate.
//! cargo run -p examples --features examples/script-trace --bin gsr_eval -- \
//!     7e87 6a6f6921 6a6f 6921
//!
//! # The same, checked against a budget of 30 varops: it needs 36, so it fails
//! cargo run -p examples --features examples/script-trace --bin gsr_eval -- \
//!     --budget 30 7e87 6a6f6921 6a6f 6921
//! ```
use std::{process::ExitCode, sync::Mutex};

use bitcoinkernel::{
    eval_tapscript_v2, ScriptPubkey, ScriptStack, ScriptTraceCallback, ScriptTraceFrameKind,
    ScriptTraceFrameRef, ScriptTracer, TapscriptV2Result, VERIFY_ALL,
};

/// Items longer than this are abbreviated: tapscript v2 allows stack elements
/// of up to 4,000,000 bytes.
const MAX_SHOWN_BYTES: usize = 32;

/// The largest budget any transaction can have: a transaction filling a
/// whole block (4,000,000 weight units) times BIP 440's 10,000 per unit.
const MAX_TX_BUDGET: u64 = 4_000_000 * 10_000;

fn format_item(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        "<empty>".to_string()
    } else if bytes.len() <= MAX_SHOWN_BYTES {
        hex::encode(bytes)
    } else {
        format!(
            "{}..{} ({} bytes)",
            hex::encode(&bytes[..8]),
            hex::encode(&bytes[bytes.len() - 8..]),
            bytes.len()
        )
    }
}

/// The opcode whose charge has not been reported yet, and the running total
/// before it ran. Frames report the state *before* each opcode, so an opcode's
/// cost only becomes visible on the frame after it.
#[derive(Default)]
struct Pending {
    opcode: Option<u8>,
    varops: u64,
}

/// A single evaluation runs here, so one shared accumulator is enough;
/// `gsr_scripttrace` needs a thread-local because it traces several.
#[derive(Default)]
struct EvalTracer {
    pending: Mutex<Pending>,
}

impl EvalTracer {
    fn print_stack(label: &str, frame: &ScriptTraceFrameRef<'_>) {
        let items: Vec<String> = frame
            .stack()
            .iter()
            .map(|item| match item.to_bytes() {
                Ok(bytes) => format_item(&bytes),
                Err(err) => format!("<{}>", err),
            })
            .collect();

        if items.is_empty() {
            println!("{label:>6}: <empty stack>");
        } else {
            println!("{label:>6}: [{}]", items.join(", "));
        }
    }

    fn reset(&self, varops: u64) {
        *self.pending.lock().unwrap() = Pending {
            opcode: None,
            varops,
        };
    }

    /// Reports what the previous opcode charged, then remembers this frame.
    fn settle(&self, varops: u64, next_opcode: Option<u8>) {
        let mut pending = self.pending.lock().unwrap();
        if let Some(opcode) = pending.opcode {
            println!(
                "         0x{opcode:02x} charged {}",
                varops.saturating_sub(pending.varops)
            );
        }
        *pending = Pending {
            opcode: next_opcode,
            varops,
        };
    }
}

impl ScriptTraceCallback for EvalTracer {
    fn on_script_trace<'a>(&self, frame: ScriptTraceFrameRef<'a>) {
        let varops = frame.varops();

        match frame.kind() {
            ScriptTraceFrameKind::Begin => {
                self.reset(varops);
                println!("  sigversion: {:?}", frame.sig_version());
                Self::print_stack("begin", &frame);
            }
            ScriptTraceFrameKind::Step => {
                self.settle(varops, Some(frame.opcode()));
                if !frame.exec() {
                    println!(
                        "  {:>3}: 0x{:02x} (skipped)",
                        frame.opcode_pos(),
                        frame.opcode()
                    );
                    return;
                }
                println!("  {:>3}: 0x{:02x}", frame.opcode_pos(), frame.opcode());
                Self::print_stack("stack", &frame);
            }
            ScriptTraceFrameKind::End => {
                self.settle(varops, None);
                Self::print_stack("end", &frame);
                println!("  varops in trace: {varops} (excludes the final success check)");
            }
        }
    }
}

fn usage() -> ExitCode {
    eprintln!("usage: gsr_eval [--budget <varops>] <script-hex> [stack-item-hex ...]");
    eprintln!("       stack items are pushed bottom first");
    ExitCode::FAILURE
}

fn main() -> ExitCode {
    let mut args: Vec<String> = std::env::args().skip(1).collect();

    let budget = if args.first().map(String::as_str) == Some("--budget") {
        let Some(value) = args.get(1) else {
            return usage();
        };

        let budget = match value.parse::<u64>() {
            Ok(budget) => budget,
            Err(err) => {
                eprintln!("could not parse the budget: {err}");
                return ExitCode::FAILURE;
            }
        };
        args.drain(..2);
        budget
    } else {
        MAX_TX_BUDGET
    };

    let Some((script_hex, stack_hex)) = args.split_first() else {
        return usage();
    };

    let script_bytes = match hex::decode(script_hex) {
        Ok(bytes) => bytes,
        Err(err) => {
            eprintln!("could not decode the script: {err}");
            return ExitCode::FAILURE;
        }
    };

    let mut stack = ScriptStack::new();
    for (index, item) in stack_hex.iter().enumerate() {
        match hex::decode(item) {
            Ok(bytes) => stack.push(&bytes),
            Err(err) => {
                eprintln!("could not decode stack item {index}: {err}");
                return ExitCode::FAILURE;
            }
        }
    }

    let script = match ScriptPubkey::new(&script_bytes) {
        Ok(script) => script,
        Err(err) => {
            eprintln!("could not create the script: {err}");
            return ExitCode::FAILURE;
        }
    };

    println!("script: {script_hex}");

    let _tracer = match ScriptTracer::new(EvalTracer::default()) {
        Ok(tracer) => tracer,
        Err(err) => {
            eprintln!("could not register the tracer: {err}");
            return ExitCode::FAILURE;
        }
    };

    // No spend context, so signature and locktime opcodes will fail. Consensus
    // derives the budget from the whole transaction's weight, so a budget given
    // here only approximates what a real spend would have.
    let outcome = match eval_tapscript_v2(&script, &stack, Some(VERIFY_ALL), None, Some(budget)) {
        Ok(outcome) => outcome,
        Err(err) => {
            eprintln!("could not evaluate the script: {err}");
            return ExitCode::FAILURE;
        }
    };

    let spent = outcome
        .varops_remaining()
        .map(|remaining| budget - remaining);

    match outcome {
        TapscriptV2Result::Valid { .. } => {
            if let Some(spent) = spent {
                println!("varops spent: {spent}, including the final success check");
            }
            println!("result: satisfied");
            ExitCode::SUCCESS
        }
        TapscriptV2Result::Invalid { script_error, .. } => {
            if let Some(spent) = spent {
                println!("varops spent: {spent} before the failure");
            }
            println!("result: not satisfied (script error {script_error})");
            ExitCode::FAILURE
        }
    }
}
