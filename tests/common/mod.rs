use std::sync::atomic::{AtomicU64, Ordering};
use std::{env, fs, path::PathBuf};

use bitcoinkernel::{
    verify, KernelError, PrecomputedTransactionData, ScriptPubkey, ScriptVerificationFlags,
    Transaction, TxOut,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

// Utility to create temporary directories that are cleaned on drop. Duplicated in `src/test_utils.rs` and `tests/common/mod.rs`.
pub struct TempDir {
    data_dir: PathBuf,
    blocks_dir: PathBuf,
}

// compiled per test binary; not all binaries use TempDir
#[allow(dead_code)]
impl TempDir {
    pub fn new(name: &str) -> Self {
        let id = COUNTER.fetch_add(1, Ordering::Relaxed);

        let data_dir = env::temp_dir().join(format!("{name}_{id}"));
        let blocks_dir = data_dir.join("blocks");

        fs::create_dir_all(&blocks_dir).expect("failed to create temp dir");

        Self {
            data_dir,
            blocks_dir,
        }
    }

    pub fn data_dir(&self) -> &str {
        self.data_dir
            .to_str()
            .expect("temp dir path is not valid UTF-8")
    }

    pub fn blocks_dir(&self) -> &str {
        self.blocks_dir
            .to_str()
            .expect("temp dir path is not valid UTF-8")
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.data_dir);
    }
}

pub fn verify_test(
    spent: &str,
    spending: &str,
    amount: i64,
    input: usize,
    outputs: Vec<TxOut>,
    flags: ScriptVerificationFlags,
) -> Result<(), KernelError> {
    let spent_script_pubkey =
        ScriptPubkey::try_from(hex::decode(spent).unwrap().as_slice()).unwrap();
    let spending_tx = Transaction::new(hex::decode(spending).unwrap().as_slice()).unwrap();
    let tx_data = PrecomputedTransactionData::new(&spending_tx, &outputs).unwrap();
    verify(
        &spent_script_pubkey,
        Some(amount),
        &spending_tx,
        input,
        Some(flags),
        &tx_data,
    )?;
    Ok(())
}
