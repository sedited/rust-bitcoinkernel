use std::fs::File;
use std::io::{BufRead, BufReader};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Once};
use std::{env, fs, path::PathBuf};

use bitcoinkernel::{
    Block, BlockTreeEntry, BlockValidationStateRef, ChainType, Context, ContextBuilder, Log, Logger,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

// Utility to create temporary directories that are cleaned on drop. Duplicated in `src/test_utils.rs` and `tests/common/mod.rs`.
pub struct TempDir {
    data_dir: PathBuf,
    blocks_dir: PathBuf,
}

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

pub struct TestLog {}

impl Log for TestLog {
    fn log(&self, message: &str) {
        log::info!(
                target: "libbitcoinkernel",
                "{}", message.strip_suffix("\r\n").or_else(|| message.strip_suffix('\n')).unwrap_or(message));
    }
}

static START: Once = Once::new();
static mut GLOBAL_LOG_CALLBACK_HOLDER: Option<Logger> = None;

pub fn setup_logging() {
    let _ = env_logger::Builder::from_default_env()
        .is_test(true)
        .try_init();
    unsafe { GLOBAL_LOG_CALLBACK_HOLDER = Some(Logger::new(TestLog {}).unwrap()) };
}

pub fn create_context() -> Context {
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

pub fn testing_setup(name: &str) -> (Arc<Context>, TempDir) {
    START.call_once(|| {
        setup_logging();
    });
    let context = Arc::new(create_context());

    let temp_dir = TempDir::new(name);
    (context, temp_dir)
}

pub fn read_block_data() -> Vec<Vec<u8>> {
    let file = File::open("tests/block_data.txt").unwrap();
    let reader = BufReader::new(file);
    let mut lines = vec![];
    for line in reader.lines() {
        lines.push(hex::decode(line.unwrap()).unwrap().to_vec());
    }
    lines
}
