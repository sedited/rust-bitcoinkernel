use std::borrow::Cow;
use std::ffi::c_void;
use std::fmt::{self, Debug, Formatter};
use std::marker::PhantomData;
use std::panic;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use libbitcoinkernel_sys::{
    btck_LogCategory, btck_LogCategory_BENCH, btck_LogCategory_BLOCKSTORAGE,
    btck_LogCategory_COINDB, btck_LogCategory_KERNEL, btck_LogCategory_LEVELDB,
    btck_LogCategory_LOCK, btck_LogCategory_MEMPOOL, btck_LogCategory_NONE, btck_LogCategory_PRUNE,
    btck_LogCategory_RAND, btck_LogCategory_REINDEX, btck_LogCategory_TXPACKAGES,
    btck_LogCategory_VALIDATION, btck_LogEntry, btck_LogLevel, btck_LogLevel_DEBUG,
    btck_LogLevel_ERROR, btck_LogLevel_INFO, btck_LogLevel_TRACE, btck_LogLevel_WARNING,
    btck_LoggingConnection, btck_StringView, btck_log_entry_get_category,
    btck_log_entry_get_file_name, btck_log_entry_get_function_name, btck_log_entry_get_level,
    btck_log_entry_get_line, btck_log_entry_get_message, btck_log_entry_get_mocktime_s,
    btck_log_entry_get_thread_name, btck_log_entry_get_timestamp_ns,
    btck_logging_connection_create, btck_logging_connection_destroy, btck_logging_set_min_level,
};

use crate::KernelError;

/// A function for handling log entries produced by the kernel library.
///
/// The kernel may call [`Log::log`] from any thread, but never from two
/// threads at once.
pub trait Log: Send {
    /// Called for each entry at or above the level set with
    /// [`set_logging_min_level`]. It must not call into the kernel except to
    /// read the entry, or it may deadlock. It should return quickly, since it
    /// blocks every kernel thread that logs.
    fn log(&mut self, entry: LogEntry<'_>);
}

/// A borrowed reference to a kernel log entry.
///
/// # Lifetime
/// The reference is only valid for the duration of the [`Log::log`] call it
/// is passed to.
///
/// # Thread Safety
/// `LogEntry` is neither [`Send`] nor [`Sync`].
pub struct LogEntry<'a> {
    inner: *const btck_LogEntry,
    marker: PhantomData<&'a ()>,
}

unsafe fn string_view_to_str<'a>(view: btck_StringView) -> Cow<'a, str> {
    if view.data.is_null() {
        return Cow::Borrowed("");
    }
    String::from_utf8_lossy(std::slice::from_raw_parts(view.data as *const u8, view.len))
}

impl<'a> LogEntry<'a> {
    /// The log message. It is not escaped, so it may contain newlines and
    /// other control characters.
    pub fn message(&self) -> Cow<'a, str> {
        unsafe { string_view_to_str(btck_log_entry_get_message(self.inner)) }
    }

    /// The name of the thread that logged the entry, or an empty string if
    /// the kernel did not name the thread.
    pub fn thread_name(&self) -> Cow<'a, str> {
        unsafe { string_view_to_str(btck_log_entry_get_thread_name(self.inner)) }
    }

    /// Wall-clock time when the entry was logged.
    pub fn timestamp(&self) -> SystemTime {
        let ns = unsafe { btck_log_entry_get_timestamp_ns(self.inner) };
        let offset = Duration::from_nanos(ns.unsigned_abs());
        if ns < 0 {
            UNIX_EPOCH - offset
        } else {
            UNIX_EPOCH + offset
        }
    }

    /// Mock time in effect when the entry was logged, or `None` if no mock
    /// time is set.
    pub fn mock_time(&self) -> Option<SystemTime> {
        let secs = u64::try_from(unsafe { btck_log_entry_get_mocktime_s(self.inner) }).ok()?;
        (secs != 0).then(|| UNIX_EPOCH + Duration::from_secs(secs))
    }

    pub fn file_name(&self) -> Cow<'a, str> {
        unsafe { string_view_to_str(btck_log_entry_get_file_name(self.inner)) }
    }

    pub fn function_name(&self) -> Cow<'a, str> {
        unsafe { string_view_to_str(btck_log_entry_get_function_name(self.inner)) }
    }

    pub fn line(&self) -> u32 {
        unsafe { btck_log_entry_get_line(self.inner) }
    }

    pub fn level(&self) -> LogLevel {
        unsafe { btck_log_entry_get_level(self.inner) }.into()
    }

    pub fn category(&self) -> LogCategory {
        unsafe { btck_log_entry_get_category(self.inner) }.into()
    }
}

impl<'a> Debug for LogEntry<'a> {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.debug_struct("LogEntry")
            .field("message", &self.message())
            .field("thread_name", &self.thread_name())
            .field("timestamp", &self.timestamp())
            .field("mock_time", &self.mock_time())
            .field("file_name", &self.file_name())
            .field("function_name", &self.function_name())
            .field("line", &self.line())
            .field("level", &self.level())
            .field("category", &self.category())
            .finish()
    }
}

impl<'a> Clone for LogEntry<'a> {
    fn clone(&self) -> Self {
        *self
    }
}

impl<'a> Copy for LogEntry<'a> {}

unsafe extern "C" fn log_callback<T: Log + 'static>(
    user_data: *mut c_void,
    entry: *const btck_LogEntry,
) {
    let _ = panic::catch_unwind(|| {
        let log = &mut *(user_data as *mut T);
        log.log(LogEntry {
            inner: entry,
            marker: PhantomData,
        });
    });
}

unsafe extern "C" fn destroy_log_callback<T>(user_data: *mut c_void) {
    if !user_data.is_null() {
        let _ = Box::from_raw(user_data as *mut T);
    }
}

/// The logger object logs kernel log messages into a user-defined log function.
/// The kernel library internally uses a global logging instance.
pub struct Logger {
    inner: *mut btck_LoggingConnection,
}

impl Drop for Logger {
    fn drop(&mut self) {
        unsafe {
            btck_logging_connection_destroy(self.inner);
        }
    }
}

/// Set the minimum level of entries delivered to loggers. Defaults to
/// [`LogLevel::Info`].
///
/// This changes a global setting and affects all existing [`Logger`]
/// instances.
pub fn set_logging_min_level(level: LogLevel) {
    unsafe {
        btck_logging_set_min_level(level.into());
    }
}

impl Logger {
    /// Create a new Logger with the specified callback.
    pub fn new<T: Log + 'static>(log: T) -> Result<Logger, KernelError> {
        let log_ptr = Box::into_raw(Box::new(log));

        let inner = unsafe {
            btck_logging_connection_create(
                log_callback::<T>,
                log_ptr as *mut c_void,
                Some(destroy_log_callback::<T>),
            )
        };

        // On failure the kernel has already freed log_ptr through
        // destroy_log_callback.
        if inner.is_null() {
            return Err(KernelError::Internal(
                "Failed to create new logging connection.".to_string(),
            ));
        }

        Ok(Logger { inner })
    }
}

/// Logging categories for Bitcoin Kernel messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LogCategory {
    /// Not tied to a specific category, e.g. most info, warning and error entries
    None = btck_LogCategory_NONE,
    /// Benchmark and performance logging
    Bench = btck_LogCategory_BENCH,
    /// Block storage operations
    BlockStorage = btck_LogCategory_BLOCKSTORAGE,
    /// Coin database operations
    CoinDb = btck_LogCategory_COINDB,
    /// LevelDB operations
    LevelDb = btck_LogCategory_LEVELDB,
    /// Memory pool operations
    Mempool = btck_LogCategory_MEMPOOL,
    /// Block pruning operations
    Prune = btck_LogCategory_PRUNE,
    /// Random number generation
    Rand = btck_LogCategory_RAND,
    /// Block reindexing operations
    Reindex = btck_LogCategory_REINDEX,
    /// Block and transaction validation
    Validation = btck_LogCategory_VALIDATION,
    /// Kernel-specific operations
    Kernel = btck_LogCategory_KERNEL,
    /// Transaction package operations
    TxPackages = btck_LogCategory_TXPACKAGES,
    /// Lock contention
    Lock = btck_LogCategory_LOCK,
}

impl From<LogCategory> for btck_LogCategory {
    fn from(category: LogCategory) -> Self {
        category as btck_LogCategory
    }
}

#[allow(non_upper_case_globals)]
impl From<btck_LogCategory> for LogCategory {
    fn from(value: btck_LogCategory) -> Self {
        match value {
            btck_LogCategory_NONE => LogCategory::None,
            btck_LogCategory_BENCH => LogCategory::Bench,
            btck_LogCategory_BLOCKSTORAGE => LogCategory::BlockStorage,
            btck_LogCategory_COINDB => LogCategory::CoinDb,
            btck_LogCategory_LEVELDB => LogCategory::LevelDb,
            btck_LogCategory_MEMPOOL => LogCategory::Mempool,
            btck_LogCategory_PRUNE => LogCategory::Prune,
            btck_LogCategory_RAND => LogCategory::Rand,
            btck_LogCategory_REINDEX => LogCategory::Reindex,
            btck_LogCategory_VALIDATION => LogCategory::Validation,
            btck_LogCategory_KERNEL => LogCategory::Kernel,
            btck_LogCategory_TXPACKAGES => LogCategory::TxPackages,
            btck_LogCategory_LOCK => LogCategory::Lock,
            _ => panic!("Unknown log category: {}", value),
        }
    }
}

/// The severity of a log entry, from [`LogLevel::Trace`] (least severe) to
/// [`LogLevel::Error`] (most severe).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum LogLevel {
    /// Detailed trace information for debugging
    Trace = btck_LogLevel_TRACE,
    /// Debug information for development
    Debug = btck_LogLevel_DEBUG,
    /// General informational messages
    Info = btck_LogLevel_INFO,
    /// Warning messages
    Warning = btck_LogLevel_WARNING,
    /// Error messages
    Error = btck_LogLevel_ERROR,
}

impl From<LogLevel> for btck_LogLevel {
    fn from(level: LogLevel) -> Self {
        level as btck_LogLevel
    }
}

#[allow(non_upper_case_globals)]
impl From<btck_LogLevel> for LogLevel {
    fn from(value: btck_LogLevel) -> Self {
        match value {
            btck_LogLevel_TRACE => LogLevel::Trace,
            btck_LogLevel_DEBUG => LogLevel::Debug,
            btck_LogLevel_INFO => LogLevel::Info,
            btck_LogLevel_WARNING => LogLevel::Warning,
            btck_LogLevel_ERROR => LogLevel::Error,
            _ => panic!("Unknown log level: {}", value),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    // Tests that change the global log level hold this lock so they don't overlap.
    static LOG_LEVEL_LOCK: Mutex<()> = Mutex::new(());

    // LogCategory tests
    #[test]
    fn test_log_category_conversions() {
        let none = LogCategory::None;
        let btck_none: btck_LogCategory = none.into();
        let back_to_none: LogCategory = btck_none.into();
        assert_eq!(none, back_to_none);

        let bench = LogCategory::Bench;
        let btck_bench: btck_LogCategory = bench.into();
        let back_to_bench: LogCategory = btck_bench.into();
        assert_eq!(bench, back_to_bench);

        let block_storage = LogCategory::BlockStorage;
        let btck_block_storage: btck_LogCategory = block_storage.into();
        let back_to_block_storage: LogCategory = btck_block_storage.into();
        assert_eq!(block_storage, back_to_block_storage);

        let coin_db = LogCategory::CoinDb;
        let btck_coin_db: btck_LogCategory = coin_db.into();
        let back_to_coin_db: LogCategory = btck_coin_db.into();
        assert_eq!(coin_db, back_to_coin_db);

        let level_db = LogCategory::LevelDb;
        let btck_level_db: btck_LogCategory = level_db.into();
        let back_to_level_db: LogCategory = btck_level_db.into();
        assert_eq!(level_db, back_to_level_db);

        let mempool = LogCategory::Mempool;
        let btck_mempool: btck_LogCategory = mempool.into();
        let back_to_mempool: LogCategory = btck_mempool.into();
        assert_eq!(mempool, back_to_mempool);

        let prune = LogCategory::Prune;
        let btck_prune: btck_LogCategory = prune.into();
        let back_to_prune: LogCategory = btck_prune.into();
        assert_eq!(prune, back_to_prune);

        let rand = LogCategory::Rand;
        let btck_rand: btck_LogCategory = rand.into();
        let back_to_rand: LogCategory = btck_rand.into();
        assert_eq!(rand, back_to_rand);

        let reindex = LogCategory::Reindex;
        let btck_reindex: btck_LogCategory = reindex.into();
        let back_to_reindex: LogCategory = btck_reindex.into();
        assert_eq!(reindex, back_to_reindex);

        let validation = LogCategory::Validation;
        let btck_validation: btck_LogCategory = validation.into();
        let back_to_validation: LogCategory = btck_validation.into();
        assert_eq!(validation, back_to_validation);

        let kernel = LogCategory::Kernel;
        let btck_kernel: btck_LogCategory = kernel.into();
        let back_to_kernel: LogCategory = btck_kernel.into();
        assert_eq!(kernel, back_to_kernel);

        let tx_packages = LogCategory::TxPackages;
        let btck_tx_packages: btck_LogCategory = tx_packages.into();
        let back_to_tx_packages: LogCategory = btck_tx_packages.into();
        assert_eq!(tx_packages, back_to_tx_packages);

        let lock = LogCategory::Lock;
        let btck_lock: btck_LogCategory = lock.into();
        let back_to_lock: LogCategory = btck_lock.into();
        assert_eq!(lock, back_to_lock);
    }

    #[test]
    fn test_log_category_equality() {
        assert_eq!(LogCategory::None, LogCategory::None);
        assert_ne!(LogCategory::None, LogCategory::Bench);
        assert_ne!(LogCategory::Validation, LogCategory::Kernel);
    }

    #[test]
    fn test_log_category_clone() {
        let validation = LogCategory::Validation;
        let cloned = validation;
        assert_eq!(validation, cloned);
    }

    // LogLevel tests
    #[test]
    fn test_log_level_conversions() {
        let trace = LogLevel::Trace;
        let btck_trace: btck_LogLevel = trace.into();
        let back_to_trace: LogLevel = btck_trace.into();
        assert_eq!(trace, back_to_trace);

        let debug = LogLevel::Debug;
        let btck_debug: btck_LogLevel = debug.into();
        let back_to_debug: LogLevel = btck_debug.into();
        assert_eq!(debug, back_to_debug);

        let info = LogLevel::Info;
        let btck_info: btck_LogLevel = info.into();
        let back_to_info: LogLevel = btck_info.into();
        assert_eq!(info, back_to_info);

        let warning = LogLevel::Warning;
        let btck_warning: btck_LogLevel = warning.into();
        let back_to_warning: LogLevel = btck_warning.into();
        assert_eq!(warning, back_to_warning);

        let error = LogLevel::Error;
        let btck_error: btck_LogLevel = error.into();
        let back_to_error: LogLevel = btck_error.into();
        assert_eq!(error, back_to_error);
    }

    #[test]
    fn test_log_level_equality() {
        assert_eq!(LogLevel::Info, LogLevel::Info);
        assert_ne!(LogLevel::Info, LogLevel::Debug);
        assert_ne!(LogLevel::Debug, LogLevel::Trace);
    }

    #[test]
    fn test_log_level_clone() {
        let info = LogLevel::Info;
        let cloned = info;
        assert_eq!(info, cloned);
    }

    // Logger tests
    #[derive(Debug)]
    struct RecordedEntry {
        message: String,
        thread_name: String,
        timestamp: SystemTime,
        mock_time: Option<SystemTime>,
        file_name: String,
        function_name: String,
        line: u32,
        level: LogLevel,
        category: LogCategory,
    }

    struct TestLog {
        entries: Arc<Mutex<Vec<RecordedEntry>>>,
    }

    impl Log for TestLog {
        fn log(&mut self, entry: LogEntry<'_>) {
            self.entries.lock().unwrap().push(RecordedEntry {
                message: entry.message().into_owned(),
                thread_name: entry.thread_name().into_owned(),
                timestamp: entry.timestamp(),
                mock_time: entry.mock_time(),
                file_name: entry.file_name().into_owned(),
                function_name: entry.function_name().into_owned(),
                line: entry.line(),
                level: entry.level(),
                category: entry.category(),
            });
        }
    }

    struct PanicLog;

    impl Log for PanicLog {
        fn log(&mut self, _entry: LogEntry<'_>) {
            panic!("PanicLog panicked");
        }
    }

    #[test]
    fn test_logger_creation() {
        let entries = Arc::new(Mutex::new(Vec::new()));
        let test_log = TestLog {
            entries: entries.clone(),
        };

        let _logger = Logger::new(test_log);
        assert!(_logger.is_ok());
    }

    #[test]
    fn test_logger_receives_entries() {
        let entries = Arc::new(Mutex::new(Vec::new()));

        let _guard = LOG_LEVEL_LOCK.lock().unwrap();
        set_logging_min_level(LogLevel::Debug);
        let logger = Logger::new(TestLog {
            entries: entries.clone(),
        })
        .unwrap();
        drop(logger);
        set_logging_min_level(LogLevel::Info);

        let entries = entries.lock().unwrap();
        let connected = entries
            .iter()
            .find(|entry| entry.message == "Logger connected.")
            .unwrap();
        assert_eq!(connected.thread_name, "");
        let age = SystemTime::now()
            .duration_since(connected.timestamp)
            .unwrap_or_else(|e| e.duration());
        assert!(age < Duration::from_secs(60));
        assert_eq!(connected.mock_time, None);
        assert!(connected.file_name.ends_with("bitcoinkernel.cpp"));
        assert_eq!(connected.function_name, "btck_logging_connection_create");
        assert!(connected.line > 0);
        assert_eq!(connected.level, LogLevel::Debug);
        assert_eq!(connected.category, LogCategory::Kernel);
    }

    #[test]
    fn test_logger_panic_does_not_abort() {
        let _guard = LOG_LEVEL_LOCK.lock().unwrap();
        set_logging_min_level(LogLevel::Debug);
        let logger = Logger::new(PanicLog).unwrap();
        drop(logger);
        set_logging_min_level(LogLevel::Info);
    }
}
