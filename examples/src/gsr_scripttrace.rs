use std::cell::Cell;

use bitcoin::{
    absolute::LockTime,
    consensus::serialize,
    opcodes::all as opcodes,
    taproot::{ControlBlock, LeafVersion, TaprootBuilder},
    transaction::Version,
    Amount, ScriptBuf, XOnlyPublicKey,
};
use bitcoinkernel::{
    core::{TransactionExt, TxOutExt},
    verify, KernelError, PrecomputedTransactionData, ScriptEvalStackRef, ScriptTraceCallback,
    ScriptTraceFrameKind, ScriptTraceFrameRef, ScriptTracer, ScriptVerificationFlags, Transaction,
    VERIFY_ALL, VERIFY_P2SH, VERIFY_TAPROOT, VERIFY_WITNESS,
};
use secp256k1::Secp256k1;

const TAPROOT_LEAF_TAPSCRIPT_V2: u8 = 0xc2;

const NUMS: [u8; 32] = [
    0x50, 0x92, 0x9b, 0x74, 0xc1, 0xa0, 0x49, 0x54, 0xb7, 0x8b, 0x4b, 0x60, 0x35, 0xe9, 0x7a, 0x5e,
    0x07, 0x8a, 0x5a, 0x0f, 0x28, 0xec, 0x96, 0xd5, 0x47, 0xbf, 0xee, 0x9a, 0xce, 0x80, 0x3a, 0xc0,
];

const AMOUNT: Amount = Amount::from_sat(50_000);

const VERIFY_NO_RESTORATION: ScriptVerificationFlags =
    VERIFY_P2SH | VERIFY_WITNESS | VERIFY_TAPROOT;

/// Per-evaluation accumulator for the varops delta.
///
/// varops() is cumulative, so a per-opcode charge mean remembering the
/// previous total. Thread-local because frames carry no evaluation id: one
/// evaluation's frames are sequential on one thread, while the tracer is a
/// single global registration the kernel may invoke from several.
#[derive(Clone, Copy)]
struct EvalState {
    prev_varops: u64,
    seen_frame: bool,
}

impl EvalState {
    const NEW: Self = Self {
        prev_varops: 0,
        seen_frame: false,
    };
}

thread_local! {
    static EVAL: Cell<EvalState> = const { Cell::new(EvalState::NEW) };
}

/// Prints each frame with its running varops total and the charge attributable
/// to the preceding opcode.
struct VaropsTracer;

impl VaropsTracer {
    /// Each evaluation meters from scratch, so seed from the frame rather than
    /// assuming zero.
    fn reset(&self, varops: u64) {
        EVAL.with(|eval| {
            eval.set(EvalState {
                prev_varops: varops,
                seen_frame: false,
            })
        });
    }

    /// The varops charged since the previous frame of this evaluation, or
    /// `None` on the first frame after `Begin`, where no previous opcode exists
    /// to attribute a charge to.
    fn delta(&self, varops: u64) -> Option<u64> {
        EVAL.with(|eval| {
            let state = eval.get();
            eval.set(EvalState {
                prev_varops: varops,
                seen_frame: true,
            });
            state
                .seen_frame
                .then(|| varops.saturating_sub(state.prev_varops))
        })
    }
}

impl ScriptTraceCallback for VaropsTracer {
    fn on_script_trace<'a>(&self, frame: ScriptTraceFrameRef<'a>) {
        let varops = frame.varops();

        match frame.kind() {
            ScriptTraceFrameKind::Begin => {
                self.reset(varops);
                // `script()` copies the whole script out of the kernel, so it is
                // read here and not once per step.
                let script_len = frame.script().map(|script| script.len()).unwrap_or(0);
                println!(
                    "== begin: {} byte script, sig_version {:?}, tapleaf {}, varops {} ==",
                    script_len,
                    frame.sig_version(),
                    frame
                        .tapleaf_hash()
                        .map(hex::encode)
                        .unwrap_or_else(|| "<none>".into()),
                    varops
                );
                dump_stacks(frame);
            }
            ScriptTraceFrameKind::Step => {
                let delta = self.delta(varops);
                println!(
                    "[step {}] opcode=0x{:02x} exec={} {}",
                    frame.opcode_pos(),
                    frame.opcode(),
                    frame.exec(),
                    format_varops(varops, delta)
                );
                dump_stacks(frame);
            }
            ScriptTraceFrameKind::End => {
                let delta = self.delta(varops);
                println!(
                    "== end: script_error={} {} ==",
                    frame.script_error(),
                    format_varops(varops, delta)
                );
                dump_stacks(frame);
            }
        }
    }
}

fn format_varops(varops: u64, delta: Option<u64>) -> String {
    match delta {
        Some(delta) => format!("varops={varops} (+{delta} charged by the previous opcode)"),
        None => format!("varops={varops} (nothing charged yet)"),
    }
}

fn main() {
    let _tracer = ScriptTracer::new(VaropsTracer).expect("failed to register the script tracer");

    let script = ScriptBuf::builder()
        .push_opcode(opcodes::OP_CAT)
        .into_script();
    let stack = vec![vec![0x01u8], vec![0x02u8]];

    // Every case below opens with two `Base` evaluations before the tapscript
    // one: the empty scriptSig, then the 34-byte scriptPubKey holding the
    // witness program. That is the ordinary P2TR spend path, not an artifact of
    // this harness. Neither is varops-metered, so both report 0 throughout.
    //
    // Note also that the kernel's single-input `verify()` has no
    // transaction-wide budget to draw on, so the evluation runs against
    // `varops::Budget::Unmetered()`: costs are accumulated and reported
    // faithfully, but nothing is ever refused. SCRIPT_ERR_VAROP_COUNT is
    // uncreachable here regardless of operand size.
    println!("### tapscript v2, restoration enabled ###");
    {
        let result = run(&script, &stack, VERIFY_ALL);
        println!("verify -> {result:?}\n");
    }

    // Same spend without the restoration flag: the 0xc2 leaf is an unknown
    // leaf version, so it succeeds without executing anything. The two Base frames
    // still appear; what is missing is the TapscriptV2 evaluation, and with it
    // any varops reading at all. A missing reading is not the same as a zero one.
    println!("### same spend, restoration disabled (expect no tapscript frames) ###");
    {
        let result = run(&script, &stack, VERIFY_NO_RESTORATION);
        println!("verify -> {result:?}\n");
    }

    // --- case 2: a script that fails ---------------------------------------
    // OP_CAT with only one item on the stack: INVALID_STACK_OPERATION. Nothing
    // is charged, because the interpreter returns on the stack-depth check
    // before reaching the cost calculation.
    println!("### tapscript v2, failing script ###");
    {
        let result = run(&script, &[vec![0x01u8]], VERIFY_ALL);
        println!("verify -> {result:?}\n");
    }

    // --- case 3: leaves the stack empty -----------------------------------
    // NOTE: this fails CLEANSTACK, but that check runs *after* the trace scope
    // is destroyed, so the END frame will report script_error=0. Two things to watch
    // in the frames below. The step 1 frame reports the total carried over from
    // OP_CAT, which reads as though OP_DROP cost 6 -- the delta on the END frame
    // is OP_DROP's real cost of 0. And the END total omits the CompareZeroCost
    // charged by the result check, which is spent against the budget after the
    // trace scope closes and so is invisible to every frame.
    let drop_script = ScriptBuf::builder()
        .push_opcode(opcodes::OP_CAT)
        .push_opcode(opcodes::OP_DROP)
        .into_script();
    println!("### tapscript v2, cleanstack failure (END frame lies) ###");
    {
        let result = run(&drop_script, &stack, VERIFY_ALL);
        println!("verify -> {result:?}\n");
    }
}

fn dump_stacks(frame: ScriptTraceFrameRef<'_>) {
    let stack = frame.stack();
    if stack.is_empty() {
        println!("    stack: <empty>");
    }
    dump_stack("stack", stack);
    dump_stack("altstack", frame.altstack());
}

fn dump_stack(label: &str, stack: ScriptEvalStackRef<'_>) {
    for (i, item) in stack.iter().enumerate() {
        match item.to_bytes() {
            Ok(bytes) if bytes.is_empty() => println!("    {label}[{i}]: <empty>"),
            Ok(bytes) => println!("    {label}[{i}]: {}", hex::encode(bytes)),
            Err(err) => println!("    {label}[{i}]: <unavailable: {err}>"),
        }
    }
}

fn run(
    script: &ScriptBuf,
    stack: &[Vec<u8>],
    flags: ScriptVerificationFlags,
) -> Result<(), KernelError> {
    let (spk, control_block) = taproot_output(script);

    let credit = bitcoin::Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint::null(),
            script_sig: ScriptBuf::builder().push_int(0).push_int(0).into_script(),
            sequence: bitcoin::Sequence::MAX,
            witness: bitcoin::Witness::new(),
        }],
        output: vec![bitcoin::TxOut {
            value: AMOUNT,
            script_pubkey: spk,
        }],
    };

    let mut witness = bitcoin::Witness::new();
    for item in stack {
        witness.push(item);
    }
    witness.push(script.as_bytes());
    witness.push(control_block.serialize());

    let spend = bitcoin::Transaction {
        version: Version::ONE,
        lock_time: LockTime::ZERO,
        input: vec![bitcoin::TxIn {
            previous_output: bitcoin::OutPoint {
                txid: credit.txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: bitcoin::Sequence::MAX,
            witness,
        }],
        output: vec![bitcoin::TxOut {
            value: AMOUNT,
            script_pubkey: ScriptBuf::new(),
        }],
    };

    let credit_tx = Transaction::new(serialize(&credit).as_slice()).unwrap();
    let spend_tx = Transaction::new(serialize(&spend).as_slice()).unwrap();

    let spent_output = credit_tx.output(0).unwrap();
    let tx_data = PrecomputedTransactionData::new(&spend_tx, &[spent_output]).unwrap();

    verify(
        &spent_output.script_pubkey(),
        Some(AMOUNT.to_sat() as i64),
        &spend_tx,
        0,
        Some(flags),
        &tx_data,
    )
}

fn taproot_output(script: &ScriptBuf) -> (ScriptBuf, ControlBlock) {
    let secp = Secp256k1::new();
    let internal_key = XOnlyPublicKey::from_slice(&NUMS).expect("valid nums point");
    let leaf_version = LeafVersion::from_consensus(TAPROOT_LEAF_TAPSCRIPT_V2)
        .expect("0xc2 is a valid leaf version");

    let spend_info = TaprootBuilder::new()
        .add_leaf_with_ver(0, script.clone(), leaf_version)
        .expect("single leaf at depth 0")
        .finalize(&secp, internal_key)
        .expect("finalize single-leaf tree");

    let control_block = spend_info
        .control_block(&(script.clone(), leaf_version))
        .expect("leaf is in the tree");

    let spk = ScriptBuf::new_p2tr_tweaked(spend_info.output_key());

    (spk, control_block)
}
