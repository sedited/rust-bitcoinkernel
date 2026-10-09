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
//! the script starts. Each `Step` line reports the state *before* that opcode
//! runs, so an opcode's varops cost shows up on the following line.
//!
//! Usage:
//!
//! ```text
//! cargo run -p examples --features examples/script-trace --bin gsr_eval -- \
//!     <script-hex> [stack-item-hex ...]
//!
//! # OP_2 OP_3 OP_ADD OP_5 OP_EQUAL, starting from an empty stack
//! cargo run -p examples --features examples/script-trace --bin gsr_eval -- 5253935587
//!
//! # OP_CAT OP_EQUAL over three stack items: the expected value, then the two
//! # halves to concatenate
//! cargo run -p examples --features examples/script-trace --bin gsr_eval -- \
//!     7e87 6a6f6921 6a6f 6921
//! ```
use std::process::ExitCode;

use bitcoinkernel::{
    eval_tapscript_v2, ScriptPubkey, ScriptStack, ScriptTraceCallback, ScriptTraceFrameKind,
    ScriptTraceFrameRef, ScriptTracer, TapscriptV2Result, VERIFY_ALL,
};

struct EvalTracer;

impl EvalTracer {
    fn print_stack(label: &str, frame: &ScriptTraceFrameRef<'_>) {
        let items: Vec<String> = frame
            .stack()
            .iter()
            .map(|item| match item.to_bytes() {
                Ok(bytes) if bytes.is_empty() => "<empty>".to_string(),
                Ok(bytes) => hex::encode(bytes),
                Err(err) => format!("<{}>", err),
            })
            .collect();

        if items.is_empty() {
            println!("{label:>6}: <empty stack>");
        } else {
            println!("{label:>6}: [{}]", items.join(", "));
        }
    }
}

impl ScriptTraceCallback for EvalTracer {
    fn on_script_trace<'a>(&self, frame: ScriptTraceFrameRef<'a>) {
        match frame.kind() {
            ScriptTraceFrameKind::Begin => {
                println!("  sigversion: {:?}", frame.sig_version());
                Self::print_stack("begin", &frame);
            }
            ScriptTraceFrameKind::Step => {
                if !frame.exec() {
                    println!(
                        "  {:>3}: 0x{:02x} (skipped)",
                        frame.opcode_pos(),
                        frame.opcode()
                    );
                    return;
                }
                println!(
                    "  {:>3}: 0x{:02x} varops={}",
                    frame.opcode_pos(),
                    frame.opcode(),
                    frame.varops()
                );
                Self::print_stack("stack", &frame);
            }
            ScriptTraceFrameKind::End => {
                Self::print_stack("end", &frame);
                println!("  varops total: {}", frame.varops());
            }
        }
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();

    let Some((script_hex, stack_hex)) = args.split_first() else {
        eprintln!("usage: gsr_eval <script-hex> [stack-item-hex ...]");
        eprintln!("       stack items are pushed bottom first");
        return ExitCode::FAILURE;
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

    let _tracer = match ScriptTracer::new(EvalTracer) {
        Ok(tracer) => tracer,
        Err(err) => {
            eprintln!("could not register the tracer: {err}");
            return ExitCode::FAILURE;
        }
    };

    // No spend context, so signature and locktime opcodes will fail. Unmetered,
    // since a budget only means something relevant to a whole transaction.
    let outcome = match eval_tapscript_v2(&script, &stack, Some(VERIFY_ALL), None, None) {
        Ok(outcome) => outcome,
        Err(err) => {
            eprintln!("could not evaluate the script: {err}");
            return ExitCode::FAILURE;
        }
    };

    match outcome {
        TapscriptV2Result::Valid { .. } => {
            println!("result: satisfied");
            ExitCode::SUCCESS
        }
        TapscriptV2Result::Invalid { script_error, .. } => {
            println!("result: not satisfied (script error {})", script_error);
            ExitCode::FAILURE
        }
    }
}
