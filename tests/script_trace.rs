#![cfg(feature = "script-trace")]

mod common;

use std::sync::{Arc, Mutex};

use bitcoinkernel::{
    ScriptTraceFrame, ScriptTraceFrameKind, ScriptTraceFrameRef, ScriptTracer,
    VERIFY_ALL_PRE_TAPROOT,
};
use common::verify_test;

#[test]
fn script_trace_p2pkh() {
    // Spending a P2PKH output using a mainnet tx with id aca326a724eda9a461c10a876534ecd5ae7b27f10f26c3862fb996f80ea2d45d
    let spk = "76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ac";
    let tx_valid = "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700";

    let frames: Arc<Mutex<Vec<ScriptTraceFrame>>> = Arc::new(Mutex::new(Vec::new()));
    let frames_clone = frames.clone();

    let tracer = ScriptTracer::new(move |frame: ScriptTraceFrameRef<'_>| {
        frames_clone
            .lock()
            .unwrap()
            .push(frame.to_owned().expect("failed to copy the frame"))
    })
    .expect("failed to register the script tracer");

    verify_test(spk, tx_valid, 0, 0, vec![], VERIFY_ALL_PRE_TAPROOT).unwrap();

    drop(tracer);

    let frames = frames.lock().unwrap();
    assert_eq!(frames.len(), 11);

    assert_eq!(frames[0].kind, ScriptTraceFrameKind::Begin);
    assert_eq!(frames[3].kind, ScriptTraceFrameKind::End);

    assert_eq!(frames[4].kind, ScriptTraceFrameKind::Begin);
    assert_eq!(frames[10].kind, ScriptTraceFrameKind::End);

    for i in [1, 2, 5, 6, 7, 8, 9] {
        assert_eq!(frames[i].kind, ScriptTraceFrameKind::Step);
    }

    assert_eq!(frames[3].script_error, 0);
    assert_eq!(frames[10].script_error, 0);
}
