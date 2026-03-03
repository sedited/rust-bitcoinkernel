use crate::{
    btck_BlockValidationResult, btck_ChainType, btck_LogCategory, btck_LogLevel, btck_ScriptError,
    btck_ScriptVerificationFlags, btck_ScriptVerifyStatus, btck_SynchronizationState,
    btck_ValidationMode, btck_Warning,
};

// Synchronization States
pub const BTCK_SYNCHRONIZATION_STATE_INIT_REINDEX: btck_SynchronizationState = 0;
pub const BTCK_SYNCHRONIZATION_STATE_INIT_DOWNLOAD: btck_SynchronizationState = 1;
pub const BTCK_SYNCHRONIZATION_STATE_POST_INIT: btck_SynchronizationState = 2;

// Warning Types
pub const BTCK_WARNING_UNKNOWN_NEW_RULES_ACTIVATED: btck_Warning = 0;
pub const BTCK_WARNING_LARGE_WORK_INVALID_CHAIN: btck_Warning = 1;

// Validation Modes
pub const BTCK_VALIDATION_MODE_VALID: btck_ValidationMode = 0;
pub const BTCK_VALIDATION_MODE_INVALID: btck_ValidationMode = 1;
pub const BTCK_VALIDATION_MODE_INTERNAL_ERROR: btck_ValidationMode = 2;

// Block Validation Results
pub const BTCK_BLOCK_VALIDATION_RESULT_UNSET: btck_BlockValidationResult = 0;
pub const BTCK_BLOCK_VALIDATION_RESULT_CONSENSUS: btck_BlockValidationResult = 1;
pub const BTCK_BLOCK_VALIDATION_RESULT_CACHED_INVALID: btck_BlockValidationResult = 2;
pub const BTCK_BLOCK_VALIDATION_RESULT_INVALID_HEADER: btck_BlockValidationResult = 3;
pub const BTCK_BLOCK_VALIDATION_RESULT_MUTATED: btck_BlockValidationResult = 4;
pub const BTCK_BLOCK_VALIDATION_RESULT_MISSING_PREV: btck_BlockValidationResult = 5;
pub const BTCK_BLOCK_VALIDATION_RESULT_INVALID_PREV: btck_BlockValidationResult = 6;
pub const BTCK_BLOCK_VALIDATION_RESULT_TIME_FUTURE: btck_BlockValidationResult = 7;
pub const BTCK_BLOCK_VALIDATION_RESULT_HEADER_LOW_WORK: btck_BlockValidationResult = 8;

// Log Categories
pub const BTCK_LOG_CATEGORY_ALL: btck_LogCategory = 0;
pub const BTCK_LOG_CATEGORY_BENCH: btck_LogCategory = 1;
pub const BTCK_LOG_CATEGORY_BLOCKSTORAGE: btck_LogCategory = 2;
pub const BTCK_LOG_CATEGORY_COINDB: btck_LogCategory = 3;
pub const BTCK_LOG_CATEGORY_LEVELDB: btck_LogCategory = 4;
pub const BTCK_LOG_CATEGORY_MEMPOOL: btck_LogCategory = 5;
pub const BTCK_LOG_CATEGORY_PRUNE: btck_LogCategory = 6;
pub const BTCK_LOG_CATEGORY_RAND: btck_LogCategory = 7;
pub const BTCK_LOG_CATEGORY_REINDEX: btck_LogCategory = 8;
pub const BTCK_LOG_CATEGORY_VALIDATION: btck_LogCategory = 9;
pub const BTCK_LOG_CATEGORY_KERNEL: btck_LogCategory = 10;

// Log Levels
pub const BTCK_LOG_LEVEL_TRACE: btck_LogLevel = 0;
pub const BTCK_LOG_LEVEL_DEBUG: btck_LogLevel = 1;
pub const BTCK_LOG_LEVEL_INFO: btck_LogLevel = 2;

// Script Verify Status
pub const BTCK_SCRIPT_VERIFY_STATUS_OK: btck_ScriptVerifyStatus = 0;
pub const BTCK_SCRIPT_VERIFY_STATUS_ERROR_INVALID_FLAGS_COMBINATION: btck_ScriptVerifyStatus = 1;
pub const BTCK_SCRIPT_VERIFY_STATUS_ERROR_SPENT_OUTPUTS_REQUIRED: btck_ScriptVerifyStatus = 2;

// Script Verification Flags
pub const BTCK_SCRIPT_VERIFICATION_FLAGS_NONE: btck_ScriptVerificationFlags = 0;
pub const BTCK_SCRIPT_VERIFICATION_FLAGS_P2SH: btck_ScriptVerificationFlags = 1 << 0;
pub const BTCK_SCRIPT_VERIFICATION_FLAGS_DERSIG: btck_ScriptVerificationFlags = 1 << 2;
pub const BTCK_SCRIPT_VERIFICATION_FLAGS_NULLDUMMY: btck_ScriptVerificationFlags = 1 << 4;
pub const BTCK_SCRIPT_VERIFICATION_FLAGS_CHECKLOCKTIMEVERIFY: btck_ScriptVerificationFlags = 1 << 9;
pub const BTCK_SCRIPT_VERIFICATION_FLAGS_CHECKSEQUENCEVERIFY: btck_ScriptVerificationFlags =
    1 << 10;
pub const BTCK_SCRIPT_VERIFICATION_FLAGS_WITNESS: btck_ScriptVerificationFlags = 1 << 11;
pub const BTCK_SCRIPT_VERIFICATION_FLAGS_TAPROOT: btck_ScriptVerificationFlags = 1 << 17;

pub const BTCK_SCRIPT_VERIFICATION_FLAGS_ALL: btck_ScriptVerificationFlags =
    BTCK_SCRIPT_VERIFICATION_FLAGS_P2SH
        | BTCK_SCRIPT_VERIFICATION_FLAGS_DERSIG
        | BTCK_SCRIPT_VERIFICATION_FLAGS_NULLDUMMY
        | BTCK_SCRIPT_VERIFICATION_FLAGS_CHECKLOCKTIMEVERIFY
        | BTCK_SCRIPT_VERIFICATION_FLAGS_CHECKSEQUENCEVERIFY
        | BTCK_SCRIPT_VERIFICATION_FLAGS_WITNESS
        | BTCK_SCRIPT_VERIFICATION_FLAGS_TAPROOT;

// Script Error Codes
pub const BTCK_SCRIPT_ERROR_OK: btck_ScriptError = 0;
pub const BTCK_SCRIPT_ERROR_UNKNOWN: btck_ScriptError = 1;
pub const BTCK_SCRIPT_ERROR_EVAL_FALSE: btck_ScriptError = 2;
pub const BTCK_SCRIPT_ERROR_OP_RETURN: btck_ScriptError = 3;
pub const BTCK_SCRIPT_ERROR_SCRIPT_SIZE: btck_ScriptError = 4;
pub const BTCK_SCRIPT_ERROR_PUSH_SIZE: btck_ScriptError = 5;
pub const BTCK_SCRIPT_ERROR_OP_COUNT: btck_ScriptError = 6;
pub const BTCK_SCRIPT_ERROR_STACK_SIZE: btck_ScriptError = 7;
pub const BTCK_SCRIPT_ERROR_SIG_COUNT: btck_ScriptError = 8;
pub const BTCK_SCRIPT_ERROR_PUBKEY_COUNT: btck_ScriptError = 9;
pub const BTCK_SCRIPT_ERROR_VERIFY: btck_ScriptError = 10;
pub const BTCK_SCRIPT_ERROR_EQUALVERIFY: btck_ScriptError = 11;
pub const BTCK_SCRIPT_ERROR_CHECKMULTISIGVERIFY: btck_ScriptError = 12;
pub const BTCK_SCRIPT_ERROR_CHECKSIGVERIFY: btck_ScriptError = 13;
pub const BTCK_SCRIPT_ERROR_NUMEQUALVERIFY: btck_ScriptError = 14;
pub const BTCK_SCRIPT_ERROR_BAD_OPCODE: btck_ScriptError = 15;
pub const BTCK_SCRIPT_ERROR_DISABLED_OPCODE: btck_ScriptError = 16;
pub const BTCK_SCRIPT_ERROR_INVALID_STACK_OPERATION: btck_ScriptError = 17;
pub const BTCK_SCRIPT_ERROR_INVALID_ALTSTACK_OPERATION: btck_ScriptError = 18;
pub const BTCK_SCRIPT_ERROR_UNBALANCED_CONDITIONAL: btck_ScriptError = 19;
pub const BTCK_SCRIPT_ERROR_NEGATIVE_LOCKTIME: btck_ScriptError = 20;
pub const BTCK_SCRIPT_ERROR_UNSATISFIED_LOCKTIME: btck_ScriptError = 21;
pub const BTCK_SCRIPT_ERROR_SIG_HASHTYPE: btck_ScriptError = 22;
pub const BTCK_SCRIPT_ERROR_SIG_DER: btck_ScriptError = 23;
pub const BTCK_SCRIPT_ERROR_MINIMALDATA: btck_ScriptError = 24;
pub const BTCK_SCRIPT_ERROR_SIG_PUSHONLY: btck_ScriptError = 25;
pub const BTCK_SCRIPT_ERROR_SIG_HIGH_S: btck_ScriptError = 26;
pub const BTCK_SCRIPT_ERROR_SIG_NULLDUMMY: btck_ScriptError = 27;
pub const BTCK_SCRIPT_ERROR_PUBKEYTYPE: btck_ScriptError = 28;
pub const BTCK_SCRIPT_ERROR_CLEANSTACK: btck_ScriptError = 29;
pub const BTCK_SCRIPT_ERROR_MINIMALIF: btck_ScriptError = 30;
pub const BTCK_SCRIPT_ERROR_SIG_NULLFAIL: btck_ScriptError = 31;
pub const BTCK_SCRIPT_ERROR_DISCOURAGE_UPGRADABLE_NOPS: btck_ScriptError = 32;
pub const BTCK_SCRIPT_ERROR_DISCOURAGE_UPGRADABLE_WITNESS_PROGRAM: btck_ScriptError = 33;
pub const BTCK_SCRIPT_ERROR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION: btck_ScriptError = 34;
pub const BTCK_SCRIPT_ERROR_DISCOURAGE_OP_SUCCESS: btck_ScriptError = 35;
pub const BTCK_SCRIPT_ERROR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE: btck_ScriptError = 36;
pub const BTCK_SCRIPT_ERROR_WITNESS_PROGRAM_WRONG_LENGTH: btck_ScriptError = 37;
pub const BTCK_SCRIPT_ERROR_WITNESS_PROGRAM_WITNESS_EMPTY: btck_ScriptError = 38;
pub const BTCK_SCRIPT_ERROR_WITNESS_PROGRAM_MISMATCH: btck_ScriptError = 39;
pub const BTCK_SCRIPT_ERROR_WITNESS_MALLEATED: btck_ScriptError = 40;
pub const BTCK_SCRIPT_ERROR_WITNESS_MALLEATED_P2SH: btck_ScriptError = 41;
pub const BTCK_SCRIPT_ERROR_WITNESS_UNEXPECTED: btck_ScriptError = 42;
pub const BTCK_SCRIPT_ERROR_WITNESS_PUBKEYTYPE: btck_ScriptError = 43;
pub const BTCK_SCRIPT_ERROR_SCHNORR_SIG_SIZE: btck_ScriptError = 44;
pub const BTCK_SCRIPT_ERROR_SCHNORR_SIG_HASHTYPE: btck_ScriptError = 45;
pub const BTCK_SCRIPT_ERROR_SCHNORR_SIG: btck_ScriptError = 46;
pub const BTCK_SCRIPT_ERROR_TAPROOT_WRONG_CONTROL_SIZE: btck_ScriptError = 47;
pub const BTCK_SCRIPT_ERROR_TAPSCRIPT_VALIDATION_WEIGHT: btck_ScriptError = 48;
pub const BTCK_SCRIPT_ERROR_TAPSCRIPT_CHECKMULTISIG: btck_ScriptError = 49;
pub const BTCK_SCRIPT_ERROR_TAPSCRIPT_MINIMALIF: btck_ScriptError = 50;
pub const BTCK_SCRIPT_ERROR_TAPSCRIPT_EMPTY_PUBKEY: btck_ScriptError = 51;
pub const BTCK_SCRIPT_ERROR_OP_CODESEPARATOR: btck_ScriptError = 52;
pub const BTCK_SCRIPT_ERROR_SIG_FINDANDDELETE: btck_ScriptError = 53;

// Chain types
pub const BTCK_CHAIN_TYPE_MAINNET: btck_ChainType = 0;
pub const BTCK_CHAIN_TYPE_TESTNET: btck_ChainType = 1;
pub const BTCK_CHAIN_TYPE_TESTNET_4: btck_ChainType = 2;
pub const BTCK_CHAIN_TYPE_SIGNET: btck_ChainType = 3;
pub const BTCK_CHAIN_TYPE_REGTEST: btck_ChainType = 4;
