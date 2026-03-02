#[cfg(test)]
mod tests {
    use bitcoinkernel::notifications::types::BlockValidationState;
    use bitcoinkernel::state::chainstate::ProcessBlockHeaderResult;
    use bitcoinkernel::{
        prelude::*, verify, Block, BlockHash, BlockHeader, BlockSpentOutputs, BlockTreeEntry,
        BlockValidationStateRef, ChainParams, ChainType, ChainstateManager,
        ChainstateManagerBuilder, Coin, Context, ContextBuilder, KernelError, Log, Logger,
        PrecomputedTransactionData, ScriptPubkey, ScriptVerifyError, Transaction,
        TransactionSpentOutputs, TxIn, TxOut, ValidationMode, VERIFY_ALL, VERIFY_ALL_PRE_TAPROOT,
        VERIFY_TAPROOT, VERIFY_WITNESS,
    };
    use libbitcoinkernel_sys::btck_ScriptVerificationFlags;
    use std::fs::File;
    use std::io::{BufRead, BufReader};
    use std::sync::{Arc, Once};
    use tempdir::TempDir;

    struct TestLog {}

    impl Log for TestLog {
        fn log(&self, message: &str) {
            log::info!(
                target: "libbitcoinkernel",
                "{}", message.strip_suffix("\r\n").or_else(|| message.strip_suffix('\n')).unwrap_or(message));
        }
    }

    static START: Once = Once::new();
    static mut GLOBAL_LOG_CALLBACK_HOLDER: Option<Logger> = None;

    fn setup_logging() {
        let _ = env_logger::Builder::from_default_env()
            .is_test(true)
            .try_init();
        unsafe { GLOBAL_LOG_CALLBACK_HOLDER = Some(Logger::new(TestLog {}).unwrap()) };
    }

    fn create_context() -> Context {
        fn pow_handler(_entry: BlockTreeEntry, _block: Block) {
            log::info!("New PoW valid block!");
        }

        fn connected_handler(_block: Block, _entry: BlockTreeEntry) {
            log::info!("Block connected!");
        }

        fn disconnected_handler(_block: Block, _entry: BlockTreeEntry) {
            log::info!("Block disconnected!");
        }

        let builder = ContextBuilder::new()
            .chain_type(ChainType::Regtest)
            .with_block_tip_notification(|_state, _block_tip, _verification_progress| {
                log::info!("Received block tip.");
            })
            .with_header_tip_notification(|_state, height, timestamp, _presync| {
                assert!(timestamp > 0);
                log::info!(
                    "Received header tip at height {} and time {}",
                    height,
                    timestamp
                );
            })
            .with_progress_notification(|_state, progress, _resume_possible| {
                log::info!("Made progress: {}", progress);
            })
            .with_warning_set_notification(|_warning, message| {
                log::info!("Received warning: {}", message);
            })
            .with_warning_unset_notification(|_warning| {
                log::info!("Unsetting warning.");
            })
            .with_flush_error_notification(|message| {
                log::info!("Flush error! {}", message);
            })
            .with_fatal_error_notification(|message| {
                log::info!("Fatal error! {}", message);
            })
            .with_block_checked_validation(|_block, _state: BlockValidationStateRef<'_>| {
                log::info!("Block checked!");
            })
            .with_new_pow_valid_block_validation(pow_handler)
            .with_block_connected_validation(connected_handler)
            .with_block_disconnected_validation(disconnected_handler);

        builder.build().unwrap()
    }

    fn testing_setup() -> (Arc<Context>, String) {
        START.call_once(|| {
            setup_logging();
        });
        let context = Arc::new(create_context());

        let temp_dir = TempDir::new("test_chainman_regtest").unwrap();
        let data_dir = temp_dir.path();
        (context, data_dir.to_str().unwrap().to_string())
    }

    fn read_block_data() -> Vec<Vec<u8>> {
        let file = File::open("tests/block_data.txt").unwrap();
        let reader = BufReader::new(file);
        let mut lines = vec![];
        for line in reader.lines() {
            lines.push(hex::decode(line.unwrap()).unwrap().to_vec());
        }
        lines
    }

    fn setup_chainman_with_blocks(
        context: &Arc<Context>,
        data_dir: &str,
    ) -> Result<ChainstateManager, KernelError> {
        let blocks_dir = data_dir.to_string() + "/blocks";
        let block_data = read_block_data();

        let chainman = ChainstateManager::new(context, data_dir, &blocks_dir)?;

        for raw_block in block_data.iter() {
            let block = Block::new(raw_block.as_slice())?;
            let result = chainman.process_block(&block);
            assert!(result.is_new_block());
            assert!(!result.is_duplicate());
            assert!(!result.is_rejected());
        }

        Ok(chainman)
    }

    #[test]
    fn test_reindex() {
        let (context, data_dir) = testing_setup();
        let blocks_dir = data_dir.clone() + "/blocks";
        {
            let block_data = read_block_data();

            let chainman = ChainstateManagerBuilder::new(&context, &data_dir, &blocks_dir)
                .unwrap()
                .build()
                .unwrap();
            for raw_block in block_data.iter() {
                let block = Block::try_from(raw_block.as_slice()).unwrap();
                let result = chainman.process_block(&block);
                assert!(result.is_new_block());
                assert!(!result.is_duplicate());
                assert!(!result.is_rejected());
            }
        }

        let chainman_builder = ChainstateManager::builder(&context, &data_dir, &blocks_dir)
            .unwrap()
            .wipe_db(false, true)
            .unwrap();

        let chainman = chainman_builder.build().unwrap();
        chainman.import_blocks().unwrap();
        drop(chainman);
    }

    #[test]
    fn test_invalid_block() {
        let (context, data_dir) = testing_setup();
        let blocks_dir = data_dir.clone() + "/blocks";
        for _ in 0..10 {
            let chainman = ChainstateManagerBuilder::new(&context, &data_dir, &blocks_dir)
                .unwrap()
                .build()
                .unwrap();

            // Not a block
            let block = Block::try_from(hex::decode("deadbeef").unwrap().as_slice());
            assert!(matches!(block, Err(KernelError::Internal(_))));
            drop(block);

            // Invalid block
            let block_1 = Block::new(hex::decode(
                "010000006fe28c0ab6f1b372c1a6a246ae63f74f931e8365e15a089c68d6190000000000982051fd\
                1e4ba744bbbe680e1fee14677ba1a3c3540bf7b1cdb606e857233e0e61bc6649ffff001d01e36299\
                0101000000010000000000000000000000000000000000000000000000000000000000000000ffff\
                ffff0704ffff001d0104ffffffff0100f2052a0100000043410496b538e853519c726a2c91e61ec1\
                1600ae1390813a627c66fb8be7947be63c52da7589379515d4e0a604f8141781e62294721166bf62\
                1e73a82cbf2342c858eeac00000000").unwrap().as_slice()
            )
            .unwrap();
            let result = chainman.process_block(&block_1);
            assert!(result.is_rejected());
            assert!(!result.is_new_block());
            assert!(!result.is_duplicate())
        }
    }

    #[test]
    fn test_process_data() {
        let (context, data_dir) = testing_setup();
        let blocks_dir = data_dir.clone() + "/blocks";
        let block_data = read_block_data();
        let chainman = ChainstateManagerBuilder::new(&context, &data_dir, &blocks_dir)
            .unwrap()
            .build()
            .unwrap();

        for raw_block in block_data.iter() {
            let block = Block::try_from(raw_block.as_slice()).unwrap();
            let result = chainman.process_block(&block);
            assert!(result.is_new_block());
            assert!(!result.is_rejected());
            assert!(!result.is_duplicate());
        }
    }

    #[test]
    fn test_validate_any() {
        let (context, data_dir) = testing_setup();
        let blocks_dir = data_dir.clone() + "/blocks";
        let block_data = read_block_data();
        let chainman = ChainstateManagerBuilder::new(&context, &data_dir, &blocks_dir)
            .unwrap()
            .build()
            .unwrap();

        chainman.import_blocks().unwrap();
        let block_2 = Block::try_from(block_data[1].clone().as_slice()).unwrap();
        let result = chainman.process_block(&block_2);
        assert!(result.is_rejected());
        assert!(!result.is_new_block());
        assert!(!result.is_duplicate());
    }

    #[test]
    fn test_logger() {
        let (_, _) = testing_setup();

        let logger_1 = Some(Logger::new(TestLog {}).unwrap());
        let logger_2 = Some(Logger::new(TestLog {}).unwrap());
        let logger_3 = Some(Logger::new(TestLog {}).unwrap());

        drop(logger_1);

        drop(logger_2);

        drop(logger_3);
    }

    #[test]
    fn script_verify_test() {
        // a random old-style transaction from the blockchain
        verify_test (
            "76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ac",
            "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700",
            0, 0, vec![], VERIFY_ALL_PRE_TAPROOT
        ).unwrap();

        // a random segwit transaction from the blockchain using P2SH
        verify_test (
            "a91434c06f8c87e355e123bdc6dda4ffabc64b6989ef87",
            "01000000000101d9fd94d0ff0026d307c994d0003180a5f248146efb6371d040c5973f5f66d9df0400000017160014b31b31a6cb654cfab3c50567bcf124f48a0beaecffffffff012cbd1c000000000017a914233b74bf0823fa58bbbd26dfc3bb4ae715547167870247304402206f60569cac136c114a58aedd80f6fa1c51b49093e7af883e605c212bdafcd8d202200e91a55f408a021ad2631bc29a67bd6915b2d7e9ef0265627eabd7f7234455f6012103e7e802f50344303c76d12c089c8724c1b230e3b745693bbe16aad536293d15e300000000",
            1900000, 0, vec![], VERIFY_ALL_PRE_TAPROOT
        ).unwrap();

        // a random segwit transaction from the blockchain using native segwit
        verify_test(
            "0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d",
            "010000000001011f97548fbbe7a0db7588a66e18d803d0089315aa7d4cc28360b6ec50ef36718a0100000000ffffffff02df1776000000000017a9146c002a686959067f4866b8fb493ad7970290ab728757d29f0000000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d04004730440220565d170eed95ff95027a69b313758450ba84a01224e1f7f130dda46e94d13f8602207bdd20e307f062594022f12ed5017bbf4a055a06aea91c10110a0e3bb23117fc014730440220647d2dc5b15f60bc37dc42618a370b2a1490293f9e5c8464f53ec4fe1dfe067302203598773895b4b16d37485cbe21b337f4e4b650739880098c592553add7dd4355016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000",
            18393430 , 0, vec![], VERIFY_ALL_PRE_TAPROOT
        ).unwrap();

        // a random old-style transaction from the blockchain - WITH WRONG SIGNATURE for the address
        assert!(matches!(verify_test(
            "76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ff",
            "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700",
            0, 0 , vec![], VERIFY_ALL_PRE_TAPROOT
        ), Err(KernelError::ScriptVerify(ScriptVerifyError::Invalid))));

        // a random segwit transaction from the blockchain using native segwit - WITH WRONG SEGWIT
        assert!(matches!(verify_test(
            "0020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58f",
            "010000000001011f97548fbbe7a0db7588a66e18d803d0089315aa7d4cc28360b6ec50ef36718a0100000000ffffffff02df1776000000000017a9146c002a686959067f4866b8fb493ad7970290ab728757d29f0000000000220020701a8d401c84fb13e6baf169d59684e17abd9fa216c8cc5b9fc63d622ff8c58d04004730440220565d170eed95ff95027a69b313758450ba84a01224e1f7f130dda46e94d13f8602207bdd20e307f062594022f12ed5017bbf4a055a06aea91c10110a0e3bb23117fc014730440220647d2dc5b15f60bc37dc42618a370b2a1490293f9e5c8464f53ec4fe1dfe067302203598773895b4b16d37485cbe21b337f4e4b650739880098c592553add7dd4355016952210375e00eb72e29da82b89367947f29ef34afb75e8654f6ea368e0acdfd92976b7c2103a1b26313f430c4b15bb1fdce663207659d8cac749a0e53d70eff01874496feff2103c96d495bfdd5ba4145e3e046fee45e84a8a48ad05bd8dbb395c011a32cf9f88053ae00000000",
            18393430 , 0, vec![], VERIFY_ALL_PRE_TAPROOT
        ), Err(KernelError::ScriptVerify(ScriptVerifyError::Invalid))));

        // a random taproot transaction
        let spent = "5120339ce7e165e67d93adb3fef88a6d4beed33f01fa876f05a225242b82a631abc0";
        let spending  = "01000000000101d1f1c1f8cdf6759167b90f52c9ad358a369f95284e841d7a2536cef31c0549580100000000fdffffff020000000000000000316a2f49206c696b65205363686e6f7272207369677320616e6420492063616e6e6f74206c69652e204062697462756734329e06010000000000225120a37c3903c8d0db6512e2b40b0dffa05e5a3ab73603ce8c9c4b7771e5412328f90140a60c383f71bac0ec919b1d7dbc3eb72dd56e7aa99583615564f9f99b8ae4e837b758773a5b2e4c51348854c8389f008e05029db7f464a5ff2e01d5e6e626174affd30a00";
        let spent_script_pubkey =
            ScriptPubkey::try_from(hex::decode(spent).unwrap().as_slice()).unwrap();
        let outputs: Vec<TxOut> = vec![TxOut::new(&spent_script_pubkey, 88480)];
        verify_test(spent, spending, 88480, 0, outputs, VERIFY_ALL).unwrap();
        assert!(matches!(
            verify_test(spent, spending, 88480, 0, vec![], VERIFY_ALL),
            Err(KernelError::ScriptVerify(
                ScriptVerifyError::SpentOutputsRequired
            ))
        ));
    }

    #[test]
    fn test_verify_input_validation() {
        let script_data =
            hex::decode("76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ac").unwrap();
        let script_pubkey = ScriptPubkey::try_from(script_data.as_slice()).unwrap();
        let tx_hex = "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700";
        let tx = Transaction::new(hex::decode(tx_hex).unwrap().as_slice()).unwrap();
        let dummy_output = TxOut::new(&script_pubkey, 100000);
        let tx_data =
            PrecomputedTransactionData::new(&tx, std::slice::from_ref(&dummy_output)).unwrap();

        // tx_index out of bounds
        let result = verify(
            &script_pubkey,
            Some(0),
            &tx,
            999,
            Some(VERIFY_ALL_PRE_TAPROOT),
            &tx_data,
        );
        assert!(matches!(
            result,
            Err(KernelError::ScriptVerify(ScriptVerifyError::TxInputIndex))
        ));

        let wrong_spent_outputs = vec![dummy_output.clone(), dummy_output.clone()];
        assert!(matches!(
            PrecomputedTransactionData::new(&tx, &wrong_spent_outputs),
            Err(KernelError::MismatchedOutputsSize)
        ));

        // Test Invalid flags
        let result = verify(&script_pubkey, Some(0), &tx, 0, Some(0xFFFFFFFF), &tx_data);
        assert!(matches!(
            result,
            Err(KernelError::ScriptVerify(ScriptVerifyError::InvalidFlags))
        ));

        // Test Invalid flags combination
        let result = verify(
            &script_pubkey,
            Some(0),
            &tx,
            0,
            Some(VERIFY_WITNESS),
            &tx_data,
        );
        assert!(matches!(
            result,
            Err(KernelError::ScriptVerify(
                ScriptVerifyError::InvalidFlagsCombination
            ))
        ));

        // Test Spent outputs required
        let tx_data_invalid = PrecomputedTransactionData::new(&tx, &Vec::<TxOut>::new()).unwrap();
        let result = verify(
            &script_pubkey,
            Some(0),
            &tx,
            0,
            Some(VERIFY_TAPROOT),
            &tx_data_invalid,
        );
        assert!(matches!(
            result,
            Err(KernelError::ScriptVerify(
                ScriptVerifyError::SpentOutputsRequired
            ))
        ));
    }

    #[test]
    fn test_header_validation() {
        let (context, data_dir) = testing_setup();
        let blocks_dir = data_dir.clone() + "/blocks";
        let block_data = read_block_data();
        let chainman = ChainstateManager::new(&context, &data_dir, &blocks_dir).unwrap();

        for raw_block in block_data.iter() {
            let block = Block::new(raw_block.as_slice()).unwrap();
            let result = chainman.process_block_header(&block.header());
            match result {
                ProcessBlockHeaderResult::Success(state) => {
                    assert_eq!(state.mode(), ValidationMode::Valid);
                }
                _ => assert!(false),
            };
        }
    }

    #[test]
    fn test_chain_operations() {
        let (context, data_dir) = testing_setup();

        let chainman = setup_chainman_with_blocks(&context, &data_dir).unwrap();

        let chain = chainman.active_chain();

        let genesis = chain.at_height(0).unwrap();
        assert_eq!(genesis.height(), 0);
        let genesis_hash = genesis.block_hash();

        let tip = chain.tip();
        assert_eq!(tip.height(), chain.height());
        let tip_height = tip.height();
        let tip_hash = tip.block_hash();

        assert!(tip_height > 0);
        assert_ne!(genesis_hash, tip_hash);

        let genesis_via_height = chain.at_height(0).unwrap();
        assert_eq!(genesis_via_height.height(), 0);
        assert_eq!(genesis_via_height.block_hash(), genesis_hash);

        let tip_via_height = chain.at_height(tip_height as usize).unwrap();
        assert_eq!(tip_via_height.height(), tip_height);
        assert_eq!(tip_via_height.block_hash(), tip_hash);

        let invalid_entry = chain.at_height(9999);
        assert!(invalid_entry.is_none());

        assert!(chain.contains(&genesis));
        assert!(chain.contains(&tip));

        let mut last_height = 0;
        let mut last_block_index: Option<BlockTreeEntry> = None;

        for (height, current_block_index) in chain.iter().enumerate() {
            assert_eq!(current_block_index.height(), height.try_into().unwrap());
            assert!(chain.contains(&current_block_index));
            last_height = height;
            last_block_index = Some(current_block_index);
        }

        assert_eq!(last_height, tip_height as usize);
        assert_eq!(last_block_index.unwrap().block_hash(), tip_hash);
    }

    #[test]
    fn test_block_transactions_iterator() {
        let block_data = read_block_data();

        let block = Block::try_from(block_data[5].as_slice()).unwrap();

        let tx_count_via_iterator = block.transactions().count();
        assert_eq!(tx_count_via_iterator, block.transaction_count());

        let txs: Vec<_> = block.transactions().collect();
        assert_eq!(txs.len(), block.transaction_count());

        for (i, tx) in block.transactions().enumerate() {
            let tx_via_index = block.transaction(i).unwrap();
            assert_eq!(tx.input_count(), tx_via_index.input_count());
            assert_eq!(tx.output_count(), tx_via_index.output_count());
        }

        let mut iter = block.transactions();
        let initial_len = iter.len();
        assert_eq!(initial_len, block.transaction_count());

        iter.next();
        assert_eq!(iter.len(), initial_len - 1);

        let non_coinbase_txs: Vec<_> = block.transactions().skip(1).collect();
        assert_eq!(non_coinbase_txs.len(), block.transaction_count() - 1);
    }

    #[test]
    fn test_block_spent_outputs_iterator() {
        let (context, data_dir) = testing_setup();

        let chainman = setup_chainman_with_blocks(&context, &data_dir).unwrap();

        let active_chain = chainman.active_chain();
        let block_index_tip = active_chain.tip();
        let spent_outputs = chainman.read_spent_outputs(&block_index_tip).unwrap();

        let count_via_iterator = spent_outputs.iter().count();
        assert_eq!(count_via_iterator, spent_outputs.count());

        let tx_spent_vec: Vec<_> = spent_outputs.iter().collect();
        assert_eq!(tx_spent_vec.len(), spent_outputs.count());

        for (i, tx_spent) in spent_outputs.iter().enumerate() {
            let tx_spent_via_index = spent_outputs.transaction_spent_outputs(i).unwrap();
            assert_eq!(tx_spent.count(), tx_spent_via_index.count());
        }

        let mut iter = spent_outputs.iter();
        let initial_len = iter.len();
        assert_eq!(initial_len, spent_outputs.count());

        if initial_len > 0 {
            iter.next();
            assert_eq!(iter.len(), initial_len - 1);
        }
    }

    #[test]
    fn test_transaction_spent_outputs_iterator() {
        let (context, data_dir) = testing_setup();

        let chainman = setup_chainman_with_blocks(&context, &data_dir).unwrap();

        let active_chain = chainman.active_chain();
        let block_index_tip = active_chain.tip();
        let spent_outputs = chainman.read_spent_outputs(&block_index_tip).unwrap();

        let tx_spent = spent_outputs.transaction_spent_outputs(0).unwrap();

        let count_via_iterator = tx_spent.coins().count();
        assert_eq!(count_via_iterator, tx_spent.count());

        let coins: Vec<_> = tx_spent.coins().collect();
        assert_eq!(coins.len(), tx_spent.count());

        for (i, coin) in tx_spent.coins().enumerate() {
            let coin_via_index = tx_spent.coin(i).unwrap();
            assert_eq!(
                coin.confirmation_height(),
                coin_via_index.confirmation_height()
            );
            assert_eq!(coin.is_coinbase(), coin_via_index.is_coinbase());
        }

        let mut iter = tx_spent.coins();
        let initial_len = iter.len();
        assert_eq!(initial_len, tx_spent.count());

        if initial_len > 0 {
            iter.next();
            assert_eq!(iter.len(), initial_len - 1);
        }

        let coinbase_coins: Vec<_> = tx_spent.coins().filter(|coin| coin.is_coinbase()).collect();

        for coin in coinbase_coins {
            assert!(coin.is_coinbase());
        }
    }

    #[test]
    fn test_nested_iteration() {
        let (context, data_dir) = testing_setup();

        let chainman = setup_chainman_with_blocks(&context, &data_dir).unwrap();

        let active_chain = chainman.active_chain();
        let block_index = active_chain.at_height(1).unwrap();
        let spent_outputs = chainman.read_spent_outputs(&block_index).unwrap();

        let mut total_coins = 0;
        for tx_spent in spent_outputs.iter() {
            for _ in tx_spent.coins() {
                total_coins += 1;
            }
        }

        let expected_total: usize = spent_outputs.iter().map(|tx_spent| tx_spent.count()).sum();

        assert_eq!(total_coins, expected_total);
    }

    #[test]
    fn test_iterator_with_block_transactions() {
        let (context, data_dir) = testing_setup();

        let chainman = setup_chainman_with_blocks(&context, &data_dir).unwrap();

        let active_chain = chainman.active_chain();
        let block_index = active_chain.at_height(1).unwrap();
        let block = chainman.read_block_data(&block_index).unwrap();
        let spent_outputs = chainman.read_spent_outputs(&block_index).unwrap();

        for (tx, tx_spent) in block.transactions().skip(1).zip(spent_outputs.iter()) {
            assert_eq!(tx.input_count(), tx_spent.count());
        }
    }

    fn verify_test(
        spent: &str,
        spending: &str,
        amount: i64,
        input: usize,
        outputs: Vec<TxOut>,
        flags: btck_ScriptVerificationFlags,
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

    #[cfg(feature = "script_debug")]
    #[test]
    fn test_script_debug() {
        use bitcoinkernel::{ScriptDebugFrame, ScriptDebugger};
        use std::sync::Mutex;

        let frames: Arc<Mutex<Vec<ScriptDebugFrame>>> = Arc::new(Mutex::new(Vec::new()));
        let frames_clone = frames.clone();
        let _debugger = ScriptDebugger::new(move |frame| {
            frames_clone.lock().unwrap().push(frame);
        })
        .expect("failed to register script debugger");

        // Run a P2PKH verification (same test vector as script_verify_test)
        verify_test(
            "76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ac",
            "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700",
            0, 0, vec![], VERIFY_ALL_PRE_TAPROOT,
        )
        .unwrap();

        let collected = frames.lock().unwrap();
        assert!(
            !collected.is_empty(),
            "debugger should have captured frames"
        );

        // All frames in a P2PKH execution should be on the main execution path
        for frame in collected.iter() {
            assert!(
                frame.f_exec,
                "P2PKH steps should all be in an active branch"
            );
            assert!(!frame.script.is_empty(), "script bytes should be non-empty");
        }
    }

    /// Multiple threads race to register a debugger — at most one should be active at a time.
    #[cfg(feature = "script_debug")]
    #[test]
    fn test_script_debug_concurrent_registration() {
        use bitcoinkernel::ScriptDebugger;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use std::sync::Barrier;
        use std::thread;

        let n_threads = 8;
        let barrier = Arc::new(Barrier::new(n_threads));
        let active = Arc::new(AtomicUsize::new(0));
        let max_active = Arc::new(AtomicUsize::new(0));

        let handles: Vec<_> = (0..n_threads)
            .map(|_| {
                let barrier = barrier.clone();
                let active = active.clone();
                let max_active = max_active.clone();
                thread::spawn(move || {
                    barrier.wait(); // all threads try at once
                    if let Some(debugger) = ScriptDebugger::new(|_| {}) {
                        let current = active.fetch_add(1, Ordering::SeqCst) + 1;
                        max_active.fetch_max(current, Ordering::SeqCst);
                        // hold it briefly so others see the conflict
                        thread::sleep(std::time::Duration::from_millis(10));
                        active.fetch_sub(1, Ordering::SeqCst);
                        drop(debugger);
                    }
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        assert_eq!(
            max_active.load(Ordering::SeqCst),
            1,
            "at most one debugger should be active at any time"
        );
    }

    /// Drop a debugger and immediately re-register from another thread.
    #[cfg(feature = "script_debug")]
    #[test]
    fn test_script_debug_drop_then_reregister() {
        use bitcoinkernel::{ScriptDebugFrame, ScriptDebugger};
        use std::sync::Mutex;

        for _ in 0..10 {
            let frames: Arc<Mutex<Vec<ScriptDebugFrame>>> = Arc::new(Mutex::new(Vec::new()));
            let frames_clone = frames.clone();

            let debugger = ScriptDebugger::new(move |frame| {
                frames_clone.lock().unwrap().push(frame);
            })
            .expect("first registration should succeed");

            // drop and re-register
            drop(debugger);

            let frames2: Arc<Mutex<Vec<ScriptDebugFrame>>> = Arc::new(Mutex::new(Vec::new()));
            let frames2_clone = frames2.clone();
            let debugger2 = ScriptDebugger::new(move |frame| {
                frames2_clone.lock().unwrap().push(frame);
            })
            .expect("re-registration after drop should succeed");

            // verify the second debugger actually receives frames
            verify_test(
                "76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ac",
                "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700",
                0, 0, vec![], VERIFY_ALL_PRE_TAPROOT,
            )
            .unwrap();

            let collected = frames2.lock().unwrap();
            assert!(
                !collected.is_empty(),
                "re-registered debugger should capture frames"
            );

            // first debugger should NOT have received any frames (it was dropped)
            let old = frames.lock().unwrap();
            assert!(old.is_empty(), "dropped debugger should not receive frames");

            drop(debugger2);
        }
    }

    /// Verify from multiple threads while a debugger is registered.
    #[cfg(feature = "script_debug")]
    #[test]
    fn test_script_debug_concurrent_verify() {
        use bitcoinkernel::{ScriptDebugFrame, ScriptDebugger};
        use std::sync::{Barrier, Mutex};
        use std::thread;

        let frames: Arc<Mutex<Vec<ScriptDebugFrame>>> = Arc::new(Mutex::new(Vec::new()));
        let frames_clone = frames.clone();
        let _debugger = ScriptDebugger::new(move |frame| {
            frames_clone.lock().unwrap().push(frame);
        })
        .expect("failed to register script debugger");

        let n_threads = 4;
        let barrier = Arc::new(Barrier::new(n_threads));

        let handles: Vec<_> = (0..n_threads)
            .map(|_| {
                let barrier = barrier.clone();
                thread::spawn(move || {
                    barrier.wait();
                    verify_test(
                        "76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ac",
                        "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700",
                        0, 0, vec![], VERIFY_ALL_PRE_TAPROOT,
                    )
                    .unwrap();
                })
            })
            .collect();

        for h in handles {
            h.join().unwrap();
        }

        let collected = frames.lock().unwrap();
        assert!(
            collected.len() >= n_threads,
            "should have frames from all {} threads, got {}",
            n_threads,
            collected.len()
        );
    }

    #[test]
    fn test_traits() {
        fn is_sync<T: Sync>() {}
        fn is_send<T: Send>() {}
        is_sync::<ScriptPubkey>();
        is_send::<ScriptPubkey>();
        is_sync::<ChainParams>(); // compiles only if true
        is_send::<ChainParams>();
        is_sync::<TxOut>();
        is_send::<TxOut>();
        is_sync::<TxIn>();
        is_send::<TxIn>();
        is_sync::<Transaction>();
        is_send::<Transaction>();
        is_sync::<Context>();
        is_send::<Context>();
        is_sync::<Block>();
        is_send::<Block>();
        is_sync::<BlockSpentOutputs>();
        is_send::<BlockSpentOutputs>();
        is_sync::<TransactionSpentOutputs>();
        is_send::<TransactionSpentOutputs>();
        is_sync::<Coin>();
        is_send::<Coin>();
        is_sync::<ChainstateManager>();
        is_send::<ChainstateManager>();
        is_sync::<BlockHash>();
        is_send::<BlockHash>();
        is_sync::<BlockHeader>();
        is_send::<BlockHeader>();
        is_sync::<BlockValidationState>();
        is_send::<BlockValidationState>();

        // is_sync::<Rc<u8>>(); // won't compile, kept as a failure case.
        // is_send::<Rc<u8>>(); // won't compile, kept as a failure case.
    }
}
