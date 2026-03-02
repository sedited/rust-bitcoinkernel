use bitcoin::Script;
use bitcoinkernel::{
    prelude::*, verify, PrecomputedTransactionData, ScriptDebugger, ScriptPubkey, Transaction,
    TxOut, VERIFY_ALL_PRE_TAPROOT,
};

fn main() {
    let _debugger = ScriptDebugger::new(|frame| {
        println!("\nMain Stack ({} items, top last):", frame.stack.len());
        if frame.stack.is_empty() {
            println!("  <empty>");
        } else {
            for (i, item) in frame.stack.iter().enumerate() {
                if item.is_empty() {
                    println!("  {}: <empty>", i);
                } else {
                    println!("  {}: 0x{}", i, hex::encode(item));
                }
            }
        }

        if !frame.altstack.is_empty() {
            println!("\nAlt Stack ({} items, top last):", frame.altstack.len());
            for (i, item) in frame.altstack.iter().enumerate() {
                if item.is_empty() {
                    println!("  {}: <empty>", i);
                } else {
                    println!("  {}: 0x{}", i, hex::encode(item));
                }
            }
        }

        let script = Script::from_bytes(&frame.script);
        println!("Script (f_exec={}):", frame.f_exec);
        for (i, op) in script.instructions().enumerate() {
            match op {
                Ok(instruction) => {
                    if i as u32 == frame.opcode_pos {
                        print!("  > ");
                    } else {
                        print!("    ");
                    }
                    println!("{:?}", instruction);
                }
                Err(e) => println!("    Error decoding instruction: {}", e),
            }
        }
    })
    .expect("failed to register script debugger");

    // A random old-style P2PKH transaction from the blockchain.
    verify_test(
        "76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ac",
        "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700",
        0, 0,
    )
    .unwrap();
}

fn verify_test(
    spent: &str,
    spending: &str,
    amount: i64,
    input: usize,
) -> Result<(), bitcoinkernel::KernelError> {
    let spent_script_pubkey =
        ScriptPubkey::try_from(hex::decode(spent).unwrap().as_slice()).unwrap();
    let spending_tx = Transaction::new(hex::decode(spending).unwrap().as_slice()).unwrap();
    let tx_data = PrecomputedTransactionData::new(&spending_tx, &Vec::<TxOut>::new()).unwrap();
    verify(
        &spent_script_pubkey,
        Some(amount),
        &spending_tx,
        input,
        Some(VERIFY_ALL_PRE_TAPROOT),
        &tx_data,
    )
}
