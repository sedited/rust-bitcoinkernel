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
        VERIFY_CHECKLOCKTIMEVERIFY, VERIFY_CHECKSEQUENCEVERIFY, VERIFY_DERSIG, VERIFY_NONE,
        VERIFY_NULLDUMMY, VERIFY_P2SH, VERIFY_TAPROOT, VERIFY_WITNESS,
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
    fn script_verify_p2pkh() {
        // Spending a P2PKH output using a mainnet tx with id aca326a724eda9a461c10a876534ecd5ae7b27f10f26c3862fb996f80ea2d45d
        let spk = "76a9144bfbaf6afb76cc5771bc6404810d1cc041a6933988ac";
        let tx = "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700";
        let base_flags = VERIFY_NONE;
        for flags in [base_flags, VERIFY_ALL_PRE_TAPROOT] {
            verify_test(spk, tx, 0, 0, vec![], flags).unwrap();
        }

        // same tx but with corrupted signature
        let tx = "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483045022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c6f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700";
        assert!(matches!(
            verify_test(spk, tx, 0, 0, vec![], base_flags),
            Err(KernelError::ScriptVerify(ScriptVerifyError::Invalid))
        ));

        // same tx but with a non-DER signature
        let tx = "02000000013f7cebd65c27431a90bba7f796914fe8cc2ddfc3f2cbd6f7e5f2fc854534da95000000006b483046022100de1ac3bcdfb0332207c4a91f3832bd2c2915840165f876ab47c5f8996b971c3602201c6c053d750fadde599e6f5c4e1963df0f01fc0d97815e8157e3d59fe09ca30d012103699b464d1d8bc9e47d4fb1cdaa89a1c5783d68363c4dbc4b524ed3d857148617feffffff02836d3c01000000001976a914fc25d6d5c94003bf5b0c7b640a248e2c637fcfb088ac7ada8202000000001976a914fbed3d9b11183209a57999d54d59f67c019e756c88ac6acb0700";
        verify_test(spk, tx, 0, 0, vec![], base_flags).unwrap();
        assert!(matches!(
            verify_test(spk, tx, 0, 0, vec![], base_flags | VERIFY_DERSIG),
            Err(KernelError::ScriptVerify(ScriptVerifyError::Invalid))
        ));
    }

    #[test]
    fn script_verify_p2sh_multisig() {
        // Spending a multisig P2SH output using a mainnet tx with id 3cd7f78499632d6f672d8a9412ae756b29c41342954c97846e0d153c7753a37e
        let spk = "a914fc8b5799cb5ae54c1be1fd97844a1cd97e820c5587";
        let tx = "0100000001dd320ee7e290ddd042332f85dd064d2ee052257a9f4761929c237a7674ff1f0d01000000fdfe0000483045022100f808cadda09bf753740a9d1f012fe9224d670d2b4337af61858e9a61d1415a6a0220296e83ac33055c8e58bcd4f7a1afc010b6da0787e41b0add9ced70bf1b5694c901483045022100ed525f5b43420c4fe745a19276e851bf21270bbb81717e4ead7d7919a1be267802201b48b9e6c92cc698f6ceb0c170321deb253d9d94c355f00bb0c6727a567d3dcf014c69522102239bbabd01dc2e4974d60dd658ca8547924f3f3fa5e583f4dea116c5a330b7d32102135d7f51e7c3aced9d0b7a5c0dc374eea814afce5e5a075f3bacf143b33af2e62102606e72be62d5fcff8764807ff676d31e7e99b5f56b79e38fdbb794d2796bbbfa53aeffffffff02846a8700000000001976a914932850c5373a1dda47027c51125b0493c026c9a388ac4da06c000000000017a91498dd7103a99f268f443fee4424a240af3d4a5aeb8700000000";
        let base_flags = VERIFY_P2SH;
        for flags in [base_flags, VERIFY_ALL_PRE_TAPROOT] {
            verify_test(spk, tx, 0, 0, vec![], flags).unwrap();
        }

        // same tx but with corrupted signature
        let tx = "0100000001dd320ee7e290ddd042332f85dd064d2ee052257a9f4761929c237a7674ff1f0d01000000fdfe0000483045023100f808cadda09bf753740a9d1f012fe9224d670d2b4337af61858e9a61d1415a6a0220296e83ac33055c8e58bcd4f7a1afc010b6da0787e41b0add9ced70bf1b5694c901483045022100ed525f5b43420c4fe745a19276e851bf21270bbb81717e4ead7d7919a1be267802201b48b9e6c92cc698f6ceb0c170321deb253d9d94c355f00bb0c6727a567d3dcf014c69522102239bbabd01dc2e4974d60dd658ca8547924f3f3fa5e583f4dea116c5a330b7d32102135d7f51e7c3aced9d0b7a5c0dc374eea814afce5e5a075f3bacf143b33af2e62102606e72be62d5fcff8764807ff676d31e7e99b5f56b79e38fdbb794d2796bbbfa53aeffffffff02846a8700000000001976a914932850c5373a1dda47027c51125b0493c026c9a388ac4da06c000000000017a91498dd7103a99f268f443fee4424a240af3d4a5aeb8700000000";
        assert!(matches!(
            verify_test(spk, tx, 0, 0, vec![], base_flags),
            Err(KernelError::ScriptVerify(ScriptVerifyError::Invalid))
        ));
        verify_test(spk, tx, 0, 0, vec![], base_flags & !VERIFY_P2SH).unwrap();

        // same tx but with a non-null dummy stack element
        let tx = "0100000001dd320ee7e290ddd042332f85dd064d2ee052257a9f4761929c237a7674ff1f0d01000000fdfe0051483045022100f808cadda09bf753740a9d1f012fe9224d670d2b4337af61858e9a61d1415a6a0220296e83ac33055c8e58bcd4f7a1afc010b6da0787e41b0add9ced70bf1b5694c901483045022100ed525f5b43420c4fe745a19276e851bf21270bbb81717e4ead7d7919a1be267802201b48b9e6c92cc698f6ceb0c170321deb253d9d94c355f00bb0c6727a567d3dcf014c69522102239bbabd01dc2e4974d60dd658ca8547924f3f3fa5e583f4dea116c5a330b7d32102135d7f51e7c3aced9d0b7a5c0dc374eea814afce5e5a075f3bacf143b33af2e62102606e72be62d5fcff8764807ff676d31e7e99b5f56b79e38fdbb794d2796bbbfa53aeffffffff02846a8700000000001976a914932850c5373a1dda47027c51125b0493c026c9a388ac4da06c000000000017a91498dd7103a99f268f443fee4424a240af3d4a5aeb8700000000";
        verify_test(spk, tx, 0, 0, vec![], base_flags).unwrap();
        assert!(matches!(
            verify_test(spk, tx, 0, 0, vec![], base_flags | VERIFY_NULLDUMMY),
            Err(KernelError::ScriptVerify(ScriptVerifyError::Invalid))
        ));
    }

    #[test]
    fn script_verify_cltv() {
        // Spending a CLTV-locked P2SH output (locked to block 100)
        let spk = "a914e6855a94d0e499a0d554b2476cb779885986575b87";
        // tx with locktime 100 (satisfying CLTV condition)
        let tx = "0200000001738df4ccd15745a9539ff632cbe903f1050807edf35a1a3835c5bca619078f19010000007047304402202124e252c265a905c02063b1235b77c2406ae3c44d5749117f0ac086e2350ba2022061b65765be68ac21b60ede916d2a6deb1e6f8c9f723e66859bf4f06d98f7112b01270164b1752102d8019ae39403a4c0b49e98a0be4ed9ad0b1ba20f324fd6268c7455841deddd0dac000000000118ddf50500000000015164000000";
        let base_flags = VERIFY_P2SH | VERIFY_CHECKLOCKTIMEVERIFY;
        for flags in [base_flags, VERIFY_ALL_PRE_TAPROOT] {
            verify_test(spk, tx, 0, 0, vec![], flags).unwrap();
        }

        // tx with locktime 50 (not satisfying CLTV condition)
        let tx = "0200000001738df4ccd15745a9539ff632cbe903f1050807edf35a1a3835c5bca619078f190100000071483045022100bdaefb402ddf25738762c57978b9f02adb9007e7c835673d8cbda6bc0b58ee78022054011b17b5d7d8b516d1ced26d124b435a5c4cccc7492778ab2a6661f5ef365801270164b1752102d8019ae39403a4c0b49e98a0be4ed9ad0b1ba20f324fd6268c7455841deddd0dac000000000118ddf50500000000015132000000";
        assert!(matches!(
            verify_test(spk, tx, 0, 0, vec![], base_flags),
            Err(KernelError::ScriptVerify(ScriptVerifyError::Invalid))
        ));
        verify_test(
            spk,
            tx,
            0,
            0,
            vec![],
            base_flags & !VERIFY_CHECKLOCKTIMEVERIFY,
        )
        .unwrap();
    }

    #[test]
    fn script_verify_csv() {
        // Spending a CSV-locked P2SH output (locked to sequence 10)
        let spk = "a914284e9e01049bc9bfe2a1f06e6e78cd29a717ffb987";
        // tx with input sequence 10 (satisfying CSV condition)
        let tx = "0200000001b4b3b5eed405f118a43e411d51eace0b7a48ad6ec061e0c6d1e2a5dbc50fa1780100000071483045022100fc82daf200e56d9500d3cdb4708a5d9cf1b62a3299dedc9cdf7b6e6412b7fa280220144b6d6c535a6a66f60d25b68c6b6ae95c0e45c8801e4007b76d0cfcf264ec4d0127010ab275210291c420b3afc1c75796653268a727d61df2edd606c243b261df61dd22f388553fac0a0000000118ddf50500000000015100000000";
        let base_flags = VERIFY_P2SH | VERIFY_CHECKSEQUENCEVERIFY;
        for flags in [base_flags, VERIFY_ALL_PRE_TAPROOT] {
            verify_test(spk, tx, 0, 0, vec![], flags).unwrap();
        }

        // tx with input sequence 5 (not satisfying CSV condition)
        let tx = "0200000001b4b3b5eed405f118a43e411d51eace0b7a48ad6ec061e0c6d1e2a5dbc50fa178010000007148304502210080c15d7432d18c78529b95f6677dfc57ae22024789eefed400dbfebcdc8341da02204775fed6dedc3b540eea67c3bf8058e1211248970cdab9980c0ed09736e13fbb0127010ab275210291c420b3afc1c75796653268a727d61df2edd606c243b261df61dd22f388553fac050000000118ddf50500000000015100000000";
        assert!(matches!(
            verify_test(spk, tx, 0, 0, vec![], base_flags),
            Err(KernelError::ScriptVerify(ScriptVerifyError::Invalid))
        ));
        verify_test(
            spk,
            tx,
            0,
            0,
            vec![],
            base_flags & !VERIFY_CHECKSEQUENCEVERIFY,
        )
        .unwrap();
    }

    #[test]
    fn script_verify_p2sh_p2wpkh() {
        // Spending a P2SH-P2WPKH output using a mainnet tx with id 07dea5918a500d7476b1d116d80507a66bc2167681b2e6ca7dd99dbc6d95c31d
        let spk = "a91434c06f8c87e355e123bdc6dda4ffabc64b6989ef87";
        let tx = "01000000000101d9fd94d0ff0026d307c994d0003180a5f248146efb6371d040c5973f5f66d9df0400000017160014b31b31a6cb654cfab3c50567bcf124f48a0beaecffffffff012cbd1c000000000017a914233b74bf0823fa58bbbd26dfc3bb4ae715547167870247304402206f60569cac136c114a58aedd80f6fa1c51b49093e7af883e605c212bdafcd8d202200e91a55f408a021ad2631bc29a67bd6915b2d7e9ef0265627eabd7f7234455f6012103e7e802f50344303c76d12c089c8724c1b230e3b745693bbe16aad536293d15e300000000";
        let amount = 1900000;
        let base_flags = VERIFY_P2SH | VERIFY_WITNESS;
        for flags in [base_flags, VERIFY_ALL_PRE_TAPROOT] {
            verify_test(spk, tx, amount, 0, vec![], flags).unwrap();
        }

        // same tx but with corrupted signature
        let tx = "01000000000101d9fd94d0ff0026d307c994d0003180a5f248146efb6371d040c5973f5f66d9df0400000017160014b31b31a6cb654cfab3c50567bcf124f48a0beaecffffffff012cbd1c000000000017a914233b74bf0823fa58bbbd26dfc3bb4ae715547167870247304402206f60569cac136c114a58aedd80f6fa1c51b49093e7af883e615c212bdafcd8d202200e91a55f408a021ad2631bc29a67bd6915b2d7e9ef0265627eabd7f7234455f6012103e7e802f50344303c76d12c089c8724c1b230e3b745693bbe16aad536293d15e300000000";
        assert!(matches!(
            verify_test(spk, tx, amount, 0, vec![], base_flags),
            Err(KernelError::ScriptVerify(ScriptVerifyError::Invalid))
        ));
        verify_test(spk, tx, amount, 0, vec![], base_flags & !VERIFY_WITNESS).unwrap();
    }

    #[test]
    fn script_verify_p2sh_p2wsh() {
        // Spending a P2SH-P2WSH output using a mainnet tx with id 017be55761bf5a3920c73778810a6be4c3315dc6efa4f31b590bc3bc1da9d75f
        let spk = "a91469abb4763c2074e22a2ab2e06208f552bf7c654387";
        let tx = "020000000001018d30fa8c3023ae9e72f44cea3525b4fe084a816830efb98b605678230cc9c48d0100000023220020a9cd0514e7793003d378df96bbe21c901421ff089ad5598a1a9b5a3cf6eaef0afdffffff0201ed11a60000000017a914194b877577228c0012e4ca3c3780198d8b09d14c87bccb510200000000160014db65e96bfbf0d6ce727ab2518a2f45635367f8b3040047304402202e679780ebe920a1e367482cace23cebaa9d8be7e7d1bd727d7439fb62c8332802204008e33b111161206cd09c947588b43114011a60c7dbaf0679c60d891e38fbb701473044022029233663e8fdbaead30f4ff806018d7ec939505fb4e11cd53195e3ca83f36f5302202010174a3b84d1128272ef1fabf23f1add09e8e074ed2443688a718be86947e40169522102282a387d21d8784fbbf28e6d0cb3f9984996771e7283bd8f5c32dc4b7a961ba8210294586ab0277cae2a8b138527816bf9f36a7203265d83e08bbeaebdd7e1568b2c21030e724028e64b78c0479a35e7c9b4cc3c13456f12ba993a8f19a38ee3b2d7743953ae00000000";
        let amount = 2825108081;
        let base_flags = VERIFY_P2SH | VERIFY_WITNESS;
        for flags in [base_flags, VERIFY_ALL_PRE_TAPROOT] {
            verify_test(spk, tx, amount, 0, vec![], flags).unwrap();
        }

        // same tx but with corrupted signature
        let tx = "020000000001018d30fa8c3023ae9e72f44cea3525b4fe084a816830efb98b605678230cc9c48d0100000023220020a9cd0514e7793003d378df96bbe21c901421ff089ad5598a1a9b5a3cf6eaef0afdffffff0201ed11a60000000017a914194b877577228c0012e4ca3c3780198d8b09d14c87bccb510200000000160014db65e96bfbf0d6ce727ab2518a2f45635367f8b3040047304402202e679780ebe920a1e367482cace23cebaa9d8be7e7d1bd727d7439fb62c8332802203008e33b111161206cd09c947588b43114011a60c7dbaf0679c60d891e38fbb701473044022029233663e8fdbaead30f4ff806018d7ec939505fb4e11cd53195e3ca83f36f5302202010174a3b84d1128272ef1fabf23f1add09e8e074ed2443688a718be86947e40169522102282a387d21d8784fbbf28e6d0cb3f9984996771e7283bd8f5c32dc4b7a961ba8210294586ab0277cae2a8b138527816bf9f36a7203265d83e08bbeaebdd7e1568b2c21030e724028e64b78c0479a35e7c9b4cc3c13456f12ba993a8f19a38ee3b2d7743953ae00000000";
        assert!(matches!(
            verify_test(spk, tx, amount, 0, vec![], base_flags),
            Err(KernelError::ScriptVerify(ScriptVerifyError::Invalid))
        ));
        verify_test(spk, tx, amount, 0, vec![], base_flags & !VERIFY_WITNESS).unwrap();
    }

    #[test]
    fn script_verify_p2wpkh() {
        // Spending a native P2WPKH output using a mainnet tx with id 00000000102d4e899ec7cc3656d91ab83aa8e95807dabb90fbe16a1a9e70b6ab
        let spk = "0014141e536966344275512b7c2f49be5b8fbe7fbd05";
        let tx = "0200000000010118cd99a3898c2b63da66ec9b7e1d15928453a0b3c2fa74fd74883042000000000000000000ffffffff011d13000000000000160014f222ad02300df72ab7129602f279b47d83b453ca02483045022100b1da3d290132155acd68dafee7c794e84922f364cf9acb1b65e806dc41bd702b02200af6003caf19a291488649be0396edb1274888beb5bb3a96e1d8e6f4903e0e7401210364b35b722e1e3590575994dad5c6c25b8b24d3777964a28cedea41bbaa297da555d2d73d";
        let base_flags = VERIFY_P2SH | VERIFY_WITNESS;
        for flags in [base_flags, VERIFY_ALL_PRE_TAPROOT] {
            verify_test(spk, tx, 5003, 0, vec![], flags).unwrap();
        }

        // using wrong amount
        assert!(matches!(
            verify_test(spk, tx, 5002, 0, vec![], base_flags),
            Err(KernelError::ScriptVerify(ScriptVerifyError::Invalid))
        ));
        verify_test(spk, tx, 5002, 0, vec![], base_flags & !VERIFY_WITNESS).unwrap();
    }

    #[test]
    fn script_verify_p2wsh() {
        // Spending a P2WSH output using a mainnet tx with id 12fc05be6778b06e77191e8fb18fee632b2d92efa0b6830e1cf63e28723a8b8f
        let spk = "0020b38c970d115bffbc7d16c5f3fc858cefe3448c8d141a679b65554de78a88a0cd";
        let tx = "01000000000102e1434357ad4d08274ed106e21f2694d35000b46e66b1dd714d63e9cd3f2ab4740000000000ffffffffb9de6f14166a841772ec53c6e384adb3dc151ba1e7b2c0a92cc9f194690be1240000000000ffffffff0198282d0000000000160014c95362dd904e547af461dbf4cc4d251a8fa1295205483045022100c8553375207dd6ef92439a22707a268629b4af08ae94d02e92c8acc355f5911902207ed6b01a97a9cc52c1fb8c6c6999b27e9c34f703a03917d8a640a45e0589ed9901210200c503dc20b66731af9d189f0a0981b148b40cb2c26f3ff15cc90037b812b6e22017e3c268fe7c34ea02effd3975038fc09ce0326b063fe0ec9356b6f558ba55ff0101616382012088a820be72730c5ba3ae4d924ef26be8a20b2e820d63916bb9db4f38214f739b897e1d8876a9148d1fe4411b3cd3a0bccafb8b57ee0c071e5abd79670428c18969b17576a914bec3dacae92ec1cd60843a8704119b0e202c6d346888ac05483045022100ae691ea4c91edf52f44e56e4f53d1ab6bb2562bb34f4f56f4f0003ea52f91fa7022001ca8196e6961b29cff64e1b5ac8917ba90a162f8230860bbc7b050624578fb701210200c503dc20b66731af9d189f0a0981b148b40cb2c26f3ff15cc90037b812b6e220362fc6c6a5b56532c27f701a067eda066ec2be426b5cd696a3a030abffc446ce0101616382012088a820360537c727eed2694b8d5493c1b0b5d79289042af10f6cdb3361f14d3fab523e8876a9148d1fe4411b3cd3a0bccafb8b57ee0c071e5abd7967043cc18969b17576a914ad27aa467040ddf17bbea8be0794e3e6953c09066888ac00000000";
        let amount = 1480000;
        let base_flags = VERIFY_P2SH | VERIFY_WITNESS;
        for flags in [base_flags, VERIFY_ALL_PRE_TAPROOT] {
            verify_test(spk, tx, amount, 1, vec![], flags).unwrap();
        }

        // same tx but with corrupted signature
        let tx = "01000000000102e1434357ad4d08274ed106e21f2694d35000b46e66b1dd714d63e9cd3f2ab4740000000000ffffffffb9de6f14166a841772ec53c6e384adb3dc151ba1e7b2c0a92cc9f194690be1240000000000ffffffff0198282d0000000000160014c95362dd904e547af461dbf4cc4d251a8fa1295205483045022100c8553375207dd6ef92439a22707a268629b4af08ae94d02e92c8acc355f5911902207ed6b01a97a9cc52c1fb8c6c6999b27e9c34f703a03917d8a640a45e0589ed9901210200c503dc20b66731af9d189f0a0981b148b40cb2c26f3ff15cc90037b812b6e22017e3c268fe7c34ea02effd3975038fc09ce0326b063fe0ec9356b6f558ba55ff0101616382012088a820be72730c5ba3ae4d924ef26be8a20b2e820d63916bb9db4f38214f739b897e1d8876a9148d1fe4411b3cd3a0bccafb8b57ee0c071e5abd79670428c18969b17576a914bec3dacae92ec1cd60843a8704119b0e202c6d346888ac05483045022100ae691ea4c91edf52f44e56e4f53d1ab6bb2562bb34f4f56f4f0003ea52f91fa7022001ca2196e6961b29cff64e1b5ac8917ba90a162f8230860bbc7b050624578fb701210200c503dc20b66731af9d189f0a0981b148b40cb2c26f3ff15cc90037b812b6e220362fc6c6a5b56532c27f701a067eda066ec2be426b5cd696a3a030abffc446ce0101616382012088a820360537c727eed2694b8d5493c1b0b5d79289042af10f6cdb3361f14d3fab523e8876a9148d1fe4411b3cd3a0bccafb8b57ee0c071e5abd7967043cc18969b17576a914ad27aa467040ddf17bbea8be0794e3e6953c09066888ac00000000";
        assert!(matches!(
            verify_test(spk, tx, amount, 1, vec![], base_flags),
            Err(KernelError::ScriptVerify(ScriptVerifyError::Invalid))
        ));
        verify_test(spk, tx, amount, 1, vec![], base_flags & !VERIFY_WITNESS).unwrap();
    }

    #[test]
    fn script_verify_p2tr_keypath() {
        // Spending a P2TR output via the key-path using a mainnet tx with id 33e794d097969002ee05d336686fc03c9e15a597c1b9827669460fac98799036
        let spk = "5120339ce7e165e67d93adb3fef88a6d4beed33f01fa876f05a225242b82a631abc0";
        let tx  = "01000000000101d1f1c1f8cdf6759167b90f52c9ad358a369f95284e841d7a2536cef31c0549580100000000fdffffff020000000000000000316a2f49206c696b65205363686e6f7272207369677320616e6420492063616e6e6f74206c69652e204062697462756734329e06010000000000225120a37c3903c8d0db6512e2b40b0dffa05e5a3ab73603ce8c9c4b7771e5412328f90140a60c383f71bac0ec919b1d7dbc3eb72dd56e7aa99583615564f9f99b8ae4e837b758773a5b2e4c51348854c8389f008e05029db7f464a5ff2e01d5e6e626174affd30a00";
        let amount = 88480;
        let base_flags = VERIFY_P2SH | VERIFY_WITNESS | VERIFY_TAPROOT;
        let outputs: Vec<TxOut> = vec![TxOut::new(
            &ScriptPubkey::try_from(hex::decode(spk).unwrap().as_slice()).unwrap(),
            amount,
        )];
        for flags in [base_flags, VERIFY_ALL] {
            verify_test(spk, tx, amount, 0, outputs.clone(), flags).unwrap();
        }

        // same tx but with corrupted signature
        let tx  = "01000000000101d1f1c1f8cdf6759167b90f52c9ad358a369f95284e841d7a2536cef31c0549580100000000fdffffff020000000000000000316a2f49206c696b65205363686e6f7272207369677320616e6420492063616e6e6f74206c69652e204062697462756734329e06010000000000225120a37c3903c8d0db6512e2b40b0dffa05e5a3ab73603ce8c9c4b7771e5412328f90140a60c383f71bac0ec919b1d7dbc3eb72dd56e7aa99583615564f9f99b8ae4e837b758772a5b2e4c51348854c8389f008e05029db7f464a5ff2e01d5e6e626174affd30a00";
        assert!(matches!(
            verify_test(spk, tx, amount, 0, outputs.clone(), base_flags),
            Err(KernelError::ScriptVerify(ScriptVerifyError::Invalid))
        ));
        verify_test(spk, tx, amount, 0, outputs, base_flags & !VERIFY_TAPROOT).unwrap();
    }

    #[test]
    fn script_verify_p2tr_scriptpath() {
        // Spending a P2TR output via the script-path using a mainnet tx with id 1ba232a8bf936cf24155292c9a4330298278f572bacc78455eb68e3552197c30
        let spk = "5120e687f4f55e3de5264cf4c4f43b53edb5c26e4adae3a3098ce918a663582785bd";
        let tx  = "02000000000102761402258bf42275f52db288dbbc8fdfe30b35dea86c5425a57feef1a4008b0b0100000000ffffffff3847ba0ccc4e1b63ed2f3b4a677bd247940f4d5669cc91d9a4eb096e7615badc0000000000ffffffff0291ad070000000000225120059715a12766bbbee8529b53dce51fe708e9895f50c6babec988c7917ff5958464d11a0000000000225120bee1246f13735551e5e5c2b5631014501a6c77f8ee2d16d33dc109096f22b2a40140ac4e4af854be645890275c8144869343752d5ceee9b361cfab3de0726c10a449cc7491a295417f7c457961fdde59bde483330364b42fddddeef65cd1d97150fc0440b78c0a5065343d451a93dcb499edd3d8994697932322be5e27fa218f5a99be8484a8ef802c3054dee442baced3c170b8afe18ec9758c860876fe4f06a5e3ccb240984299fc968b71d999354af2e991e089908adec84e1b1f04da8149aa0ffce28311b363dfd2dfc456de77746919c263e95a14952080f433ddb87b13b884812bda4420b5095be39b9f2f96a77235854af7635dd09d0324569e9b3d587fe5fb7c44720cad202b74c2011af089c849383ee527c72325de52df6a788428b68d49e9174053aabaac41c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0675a94484b3d55d76af4a2275d327a47c1ec5c7d2232596a09fc883d40bb237e00000000";
        let amount = 503185;
        let base_flags = VERIFY_P2SH | VERIFY_WITNESS | VERIFY_TAPROOT;
        let outputs = vec![
            TxOut::new(
                &ScriptPubkey::try_from(
                    hex::decode(
                        "51207ee3c4ab9c8144be0e39fc849fab95e70da97fb0d70754b34553c25f9d325fa0",
                    )
                    .unwrap()
                    .as_slice(),
                )
                .unwrap(),
                1757828,
            ),
            TxOut::new(
                &ScriptPubkey::try_from(hex::decode(spk).unwrap().as_slice()).unwrap(),
                amount,
            ),
        ];
        for flags in [base_flags, VERIFY_ALL] {
            verify_test(spk, tx, amount, 1, outputs.clone(), flags).unwrap();
        }
        // same tx but with corrupted signature
        let tx  = "02000000000102761402258bf42275f52db288dbbc8fdfe30b35dea86c5425a57feef1a4008b0b0100000000ffffffff3847ba0ccc4e1b63ed2f3b4a677bd247940f4d5669cc91d9a4eb096e7615badc0000000000ffffffff0291ad070000000000225120059715a12766bbbee8529b53dce51fe708e9895f50c6babec988c7917ff5958464d11a0000000000225120bee1246f13735551e5e5c2b5631014501a6c77f8ee2d16d33dc109096f22b2a40140ac4e4af854be645890275c8144869343752d5ceee9b361cfab3de0726c10a449cc7491a295417f7c457961fdde59bde483330364b42fddddeef65cd1d97150fc0440b78c0a5065343d451a93dcb499edd3d8994697932322be5e27fa218f5a99be8484a8ef802c3054dee442baced3c170b8afe18ec9758c860876fe4f06a5e3ccb240984299fc968b71d999354af2e991e089908adec84e1b1f04da8149aa0ffce28211b363dfd2dfc456de77746919c263e95a14952080f433ddb87b13b884812bda4420b5095be39b9f2f96a77235854af7635dd09d0324569e9b3d587fe5fb7c44720cad202b74c2011af089c849383ee527c72325de52df6a788428b68d49e9174053aabaac41c150929b74c1a04954b78b4b6035e97a5e078a5a0f28ec96d547bfee9ace803ac0675a94484b3d55d76af4a2275d327a47c1ec5c7d2232596a09fc883d40bb237e00000000";
        assert!(matches!(
            verify_test(spk, tx, amount, 1, outputs.clone(), base_flags),
            Err(KernelError::ScriptVerify(ScriptVerifyError::Invalid))
        ));
        verify_test(spk, tx, amount, 1, outputs, base_flags & !VERIFY_TAPROOT).unwrap();
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
