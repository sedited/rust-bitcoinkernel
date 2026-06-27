use std::env;
use std::fmt;
use std::process;
use std::sync::Arc;

use bitcoin::consensus::deserialize;
use bitcoin::hashes::Hash;
use bitcoin::Transaction;
use bitcoin::{PrivateKey, XOnlyPublicKey};
use bitcoinkernel::{
    prelude::*, Block, BlockSpentOutputs, BlockTreeEntry, ChainType, ChainstateManager,
    ChainstateManagerBuilder, Context, ContextBuilder, KernelError, Log, Logger,
    TransactionSpentOutputsRef,
};
use env_logger::Builder;
use log::LevelFilter;
use secp256k1::{PublicKey, Secp256k1, SecretKey};
use silentpayments::receiving::{Label, Receiver};
use silentpayments::utils::receiving::{
    calculate_shared_secret, calculate_tweak_data, get_pubkey_from_input,
};

#[derive(Debug)]
enum ScanError {
    Kernel(KernelError),
    SilentPayments(String),
    InvalidInput(String),
}

impl fmt::Display for ScanError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ScanError::Kernel(e) => write!(f, "Kernel error: {:?}", e),
            ScanError::SilentPayments(e) => write!(f, "Silent payments error: {}", e),
            ScanError::InvalidInput(e) => write!(f, "Invalid input: {}", e),
        }
    }
}

impl std::error::Error for ScanError {}

impl From<KernelError> for ScanError {
    fn from(e: KernelError) -> Self {
        ScanError::Kernel(e)
    }
}

#[derive(Debug, Clone)]
struct TransactionInput {
    prevout_script: Vec<u8>,
    script_sig: Vec<u8>,
    witness: Vec<Vec<u8>>,
    outpoint: (Vec<u8>, u32),
}

impl fmt::Display for TransactionInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "txid: {}, vout: {}",
            bitcoin::Txid::from_slice(&self.outpoint.0).unwrap(),
            self.outpoint.1
        )
    }
}

#[derive(Debug, Clone)]
struct TransactionData {
    inputs: Vec<TransactionInput>,
    outputs: Vec<Vec<u8>>,
}

struct SilentPaymentScanner {
    receiver: Receiver,
    secret_scan_key: SecretKey,
}

impl SilentPaymentScanner {
    fn new(receiver: Receiver, secret_scan_key: SecretKey) -> Self {
        Self {
            receiver,
            secret_scan_key,
        }
    }

    fn scan_chain(&mut self, chainman: &ChainstateManager) -> Result<(), ScanError> {
        let chain = chainman.active_chain();
        let tip_height = chain.height();

        log::info!("Starting scan from genesis to tip {}", tip_height);

        for block_index in chain.iter() {
            if block_index.height() % 10 == 0 {
                log::info!("Scanning block {} / {}", block_index.height(), tip_height);
            }
            self.scan_block(chainman, &block_index)?;
        }

        Ok(())
    }

    fn scan_block(
        &mut self,
        chainman: &ChainstateManager,
        block_index: &BlockTreeEntry,
    ) -> Result<(), ScanError> {
        let spent_outputs: BlockSpentOutputs = chainman.read_spent_outputs(block_index)?;
        let block: Block = chainman.read_block_data(block_index)?;

        for (index, tx_spent_output) in spent_outputs.iter().enumerate() {
            let tx_index = index + 1;
            let tx_bytes = block.transaction(tx_index).unwrap().consensus_encode()?;
            let tx: Transaction = deserialize(&tx_bytes).map_err(|e| {
                ScanError::InvalidInput(format!("Failed to deserialize transaction {}", e))
            })?;
            let tx_data = self.extract_transaction_data(tx, tx_spent_output)?;
            self.scan_transaction(&tx_data)?;
        }

        Ok(())
    }

    fn extract_transaction_data(
        &mut self,
        tx: bitcoin::Transaction,
        tx_spent_outputs: TransactionSpentOutputsRef,
    ) -> Result<TransactionData, ScanError> {
        if tx.input.len() != tx_spent_outputs.count() {
            return Err(ScanError::InvalidInput(format!(
                "Transaction input count mismatch: {} inputs vs {} spent outputs",
                tx.input.len(),
                tx_spent_outputs.count()
            )));
        }

        let mut inputs = Vec::new();
        for (index, coin) in tx_spent_outputs.coins().enumerate() {
            inputs.push(TransactionInput {
                prevout_script: coin.output().script_pubkey().to_bytes(),
                script_sig: tx.input[index].script_sig.to_bytes(),
                witness: tx.input[index].witness.to_vec(),
                outpoint: (
                    tx.input[index]
                        .previous_output
                        .txid
                        .to_byte_array()
                        .to_vec(),
                    tx.input[index].previous_output.vout,
                ),
            });
        }

        let outputs = tx
            .output
            .iter()
            .map(|output| output.script_pubkey.to_bytes())
            .collect();

        Ok(TransactionData { inputs, outputs })
    }

    fn scan_transaction(&mut self, tx_data: &TransactionData) -> Result<(), ScanError> {
        let input_pub_keys: Result<Vec<_>, _> = tx_data
            .inputs
            .iter()
            .map(|input| {
                get_pubkey_from_input(&input.script_sig, &input.witness, &input.prevout_script)
                    .map_err(|e| {
                        ScanError::SilentPayments(format!("Failed to extract pubkey: {:?}", e))
                    })
            })
            .collect();

        let input_pub_keys: Vec<PublicKey> = match input_pub_keys {
            Ok(keys) => keys.into_iter().flatten().collect(),
            Err(e) => {
                log::debug!("Failed to extract pubkeys: {}", e);
                return Ok(());
            }
        };

        if input_pub_keys.is_empty() {
            return Ok(());
        }

        let pubkeys_ref: Vec<&PublicKey> = input_pub_keys.iter().collect();

        let outpoints_data: Vec<_> = tx_data
            .inputs
            .iter()
            .map(|input| {
                let txid = bitcoin::Txid::from_slice(&input.outpoint.0)
                    .unwrap()
                    .to_string();
                (txid, input.outpoint.1)
            })
            .collect();

        let tweak_data = calculate_tweak_data(&pubkeys_ref, &outpoints_data).map_err(|e| {
            ScanError::SilentPayments(format!("Failed to calculcate tweak: {:?}", e))
        })?;

        let ecdh_shared_secret = calculate_shared_secret(tweak_data, self.secret_scan_key)
            .map_err(|e| {
                ScanError::SilentPayments(format!("Failed to calculate shared secret: {:?}", e))
            })?;

        let pubkeys_to_check: Vec<XOnlyPublicKey> = tx_data
            .outputs
            .iter()
            .filter_map(|script_pubkey| {
                if script_pubkey.len() == 34 && script_pubkey[0] == 0x51 && script_pubkey[1] == 0x20
                {
                    XOnlyPublicKey::from_slice(&script_pubkey[2..]).ok()
                } else {
                    None
                }
            })
            .collect();

        if pubkeys_to_check.is_empty() {
            log::info!("pub keys to check is empty!");
            return Ok(());
        }

        match self
            .receiver
            .scan_transaction(&ecdh_shared_secret, pubkeys_to_check)
        {
            Ok(outputs) if !outputs.is_empty() => {
                log::info!("Found {} silent payments output(s)!", outputs.len());
                for (idx, output) in outputs.iter().enumerate() {
                    log::info!("Output {}: {:?}", idx + 1, output);
                }
            }
            Ok(_) => {}
            Err(e) => {
                log::debug!("Scan failed: {:?}", e);
            }
        }

        Ok(())
    }
}

struct MainLog {}

impl Log for MainLog {
    fn log(&self, message: &str) {
        log::info!(
            target: "libbitcoinkernel",
            "{}", message.strip_suffix("\r\n").or_else(|| message.strip_suffix('\n')).unwrap_or(message));
    }
}

fn setup_logging() -> Result<Logger, KernelError> {
    let mut builder = Builder::from_default_env();
    builder.filter(None, LevelFilter::Info).init();
    Logger::new(MainLog {})
}

fn create_context() -> Arc<Context> {
    Arc::new(
        ContextBuilder::new()
            .chain_type(ChainType::Regtest)
            .build()
            .unwrap(),
    )
}

// silent payment txid:
// 4282b1727f0ebb0c035e8306c2c09764b5b637d63ae5249f7d0d1968a1554231
// silent payment tx:
// 02000000000102bbbd77f0d8c5cbc2ccc39f0501828ad4ac3a6a933393876cae5a7e49bd5341230100000000fdffffff94e299c837e0e00644b9123d80c052159443907f663e746be7fe1e6c32c3ee9b0100000000fdffffff0218e0f50500000000225120d7bf24e13daf4d6ce0ac7a34ecefb4122f070a1561e8659d4071c52edb7c1cb300e1f505000000002251207ef15780916ae0f29a0bd34e48e1a0e817e7731b82f3009cfa89c87602cf1b2b02473044022014680d9a963868b03d25f84bd81af87e127f9d7990166dad5e1dd71be8797e3402205f79713b4faaff7184fb25d0976a37970f8d6b23f95d4041180a35aa291fc8dc012102a9dfaeeebad1f7ebca371a6f02e63a8b0de287c1b0608edc259c60583a03496e0247304402201f09ecdb89f311c3ad8b6d89a040a5796f83c9db2597962969392a3d9a5be46d022052243418a89831ca0e5ddd7ae575d787178126d8495f890414ab8b4d2a1b19d80121035368c752d3ee31d9570180a1ba285659af106f9430811ec58e3b86cf26c208f100000000
// silent payment to address:
// sprt1qqw7zfpjcuwvq4zd3d4aealxq3d669s3kcde4wgr3zl5ugxs40twv2qccgvszutt7p796yg4h926kdnty66wxrfew26gu2gk5h5hcg4s2jqyascfz
// spend key:
// cRFcZbp7cAeZGsnYKdgSZwH6drJ3XLnPSGcjLNCpRy28tpGtZR11
// scan key:
// cTiSJ8p2zpGSkWGkvYFWfKurgWvSi9hdvzw9GEws18kS2VRPNS24

fn parse_keys() -> Result<(Receiver, SecretKey), ScanError> {
    let original = "sprt1qqw7zfpjcuwvq4zd3d4aealxq3d669s3kcde4wgr3zl5ugxs40twv2qccgvszutt7p796yg4h926kdnty66wxrfew26gu2gk5h5hcg4s2jqyascfz";

    let spend_key: PrivateKey =
        PrivateKey::from_wif("cRFcZbp7cAeZGsnYKdgSZwH6drJ3XLnPSGcjLNCpRy28tpGtZR11")
            .map_err(|e| ScanError::InvalidInput(format!("Invalid spend key: {}", e)))?;

    let scan_key: PrivateKey =
        PrivateKey::from_wif("cTiSJ8p2zpGSkWGkvYFWfKurgWvSi9hdvzw9GEws18kS2VRPNS24")
            .map_err(|e| ScanError::InvalidInput(format!("Invalid scan key: {}", e)))?;

    let secp = Secp256k1::new();
    let public_spend_key: secp256k1::PublicKey = spend_key.public_key(&secp).inner;
    let public_scan_key: secp256k1::PublicKey = scan_key.public_key(&secp).inner;

    let label = Label::new(spend_key.inner, 0);
    let receiver = Receiver::new(0, public_scan_key, public_spend_key, label, false)
        .map_err(|e| ScanError::SilentPayments(format!("Failed to create receiver: {:?}", e)))?;
    println!("Receiver address: {}", receiver.get_receiving_address());
    println!("Actual adress:    {}", original);

    Ok((receiver, scan_key.inner))
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        eprintln!("Usage: {} <path_to_data_dir>", args[0]);
        process::exit(1);
    }

    let _logger = setup_logging().unwrap();
    let context = create_context();
    let data_dir = args[1].clone();
    let blocks_dir = format!("{}/blocks", data_dir);

    let chainman = ChainstateManagerBuilder::new(&context, &data_dir, &blocks_dir)
        .unwrap()
        .build()
        .unwrap();

    chainman.import_blocks().unwrap();

    let (receiver, secret_scan_key) = parse_keys()?;
    let mut scanner = SilentPaymentScanner::new(receiver, secret_scan_key);

    let _ = scanner.scan_chain(&chainman);

    Ok(())
}

fn main() {
    if let Err(e) = run() {
        eprintln!("Error: {}", e);
        process::exit(1);
    }
}
