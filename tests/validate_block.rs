use std::{
    collections::HashMap,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
};
mod common;

use bitcoinkernel::{
    core::{TransactionExt, TxInExt, TxOutPointExt, TxidExt},
    prelude::BlockValidationStateExt,
    Block, ChainstateManager, Coin, Context, FetchCoinCallback, KernelError,
    ProcessBlockHeaderResult, TxOutPointRef, ValidateBlockResult, ValidationMode,
};

use crate::common::{read_block_data, testing_setup, TempDir};

type OutPointKey = ([u8; 32], u32);

fn key(out_point: &impl TxOutPointExt) -> OutPointKey {
    (out_point.txid().to_bytes(), out_point.index())
}

#[derive(Default)]
struct UtxoSet {
    coins: HashMap<OutPointKey, Coin>,
    fetches: AtomicUsize,
}

impl UtxoSet {
    fn apply(&mut self, block: &Block, height: u32) {
        for tx in block.transactions() {
            let is_coinbase = tx.is_coinbase();

            if !is_coinbase {
                for input in tx.inputs() {
                    let k = key(&input.outpoint());
                    assert!(self.coins.remove(&k).is_some(), "spent an unknown output");
                }
            }

            let txid = tx.txid();
            for (vout, output) in tx.outputs().enumerate() {
                self.coins.insert(
                    (txid.to_bytes(), vout as u32),
                    Coin::new(&output, height, is_coinbase),
                );
            }
        }
    }

    fn fetch_count(&self) -> usize {
        self.fetches.load(Ordering::Relaxed)
    }
}

impl FetchCoinCallback for UtxoSet {
    fn fetch_coin(&self, out_point: TxOutPointRef<'_>) -> Option<Coin> {
        self.fetches.fetch_add(1, Ordering::Relaxed);
        self.coins.get(&key(&out_point)).cloned()
    }
}

pub fn setup_chainman_with_headers(
    context: &Arc<Context>,
    temp_dir: &TempDir,
) -> Result<(ChainstateManager, Vec<Block>), KernelError> {
    let block_data = read_block_data();

    let chainman = ChainstateManager::new(context, temp_dir.data_dir(), temp_dir.blocks_dir())?;

    let mut blocks = vec![];
    for raw_block in block_data.iter() {
        let block = Block::new(raw_block.as_slice())?;
        let result = chainman.process_block_header(&block.header())?;
        assert!(matches!(result, ProcessBlockHeaderResult::Valid));
        blocks.push(block);
    }

    assert_eq!(chainman.active_chain().height(), 0);

    Ok((chainman, blocks))
}

#[test]
fn test_validate_block_against_caller_utxo_set() {
    let (context, temp_dir) = testing_setup("chainman_validate_blocks");
    let (chainman, blocks) = setup_chainman_with_headers(&context, &temp_dir).unwrap();

    let mut utxos = UtxoSet::default();

    for block in blocks.iter() {
        let entry = chainman.get_block_tree_entry(&block.hash()).unwrap();

        match chainman.validate_block(block, &entry, &utxos).unwrap() {
            ValidateBlockResult::Valid => {}
            ValidateBlockResult::Invalid(state) => panic!(
                "block at height {} rejected: {:?}",
                entry.height(),
                state.mode()
            ),
        }

        utxos.apply(block, entry.height() as u32);
    }

    assert!(utxos.fetch_count() > 0, "callback was never consulted");

    assert_eq!(chainman.active_chain().height(), 0);
}

#[test]
fn test_validate_block_missing_coin() {
    let (context, temp_dir) = testing_setup("chainman_validate_blocks");
    let (chainman, blocks) = setup_chainman_with_headers(&context, &temp_dir).unwrap();

    let mut utxos = UtxoSet::default();

    for block in blocks.iter() {
        let entry = chainman.get_block_tree_entry(&block.hash()).unwrap();

        // At the first block that spends something, drop one of its inputs
        // from the map and check the block is rejected.
        if block.transaction_count() > 1 {
            let spent = key(&block.transaction(1).unwrap().input(0).unwrap().outpoint());
            assert!(utxos.coins.remove(&spent).is_some());

            let result = chainman.validate_block(block, &entry, &utxos).unwrap();
            let ValidateBlockResult::Invalid(state) = result else {
                panic!("expected Invalid when a spent coin is unavailable");
            };
            assert_eq!(state.mode(), ValidationMode::Invalid);
            assert_eq!(chainman.active_chain().height(), 0);
            return;
        }

        assert!(matches!(
            chainman.validate_block(block, &entry, &utxos).unwrap(),
            ValidateBlockResult::Valid
        ));

        utxos.apply(block, entry.height() as u32);
    }

    panic!("no block in block_data.txt spends a previous output");
}
