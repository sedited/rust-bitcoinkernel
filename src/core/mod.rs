pub mod block;
pub mod block_tree_entry;
pub mod script;
pub mod transaction;
pub mod verify;

pub use block::{
    Block, BlockCheckFlags, BlockCheckResult, BlockHash, BlockHeader, BlockSpentOutputs,
    BlockSpentOutputsRef, Coin, CoinRef, TransactionSpentOutputs, TransactionSpentOutputsRef,
};
pub use block_tree_entry::BlockTreeEntry;
pub use script::{ScriptPubkey, ScriptPubkeyRef};
pub use transaction::{
    Transaction, TransactionRef, TxCheckResult, TxIn, TxInRef, TxOut, TxOutPoint, TxOutPointRef,
    TxOutRef, Txid, TxidRef, WitnessStack, WitnessStackRef,
};

pub use block::{
    BlockHashExt, BlockHeaderExt, BlockSpentOutputsExt, CoinExt, TransactionSpentOutputsExt,
};
pub use script::ScriptPubkeyExt;
pub use transaction::{TransactionExt, TxInExt, TxOutExt, TxOutPointExt, TxidExt, WitnessStackExt};

pub use verify::{verify, PrecomputedTransactionData, ScriptVerificationFlags, ScriptVerifyError};

pub mod verify_flags {
    pub use super::verify::{
        VERIFY_ALL, VERIFY_ALL_PRE_TAPROOT, VERIFY_CHECKLOCKTIMEVERIFY, VERIFY_CHECKSEQUENCEVERIFY,
        VERIFY_DERSIG, VERIFY_NONE, VERIFY_NULLDUMMY, VERIFY_P2SH, VERIFY_TAPROOT, VERIFY_WITNESS,
    };
}

pub mod block_check_flags {
    pub use super::block::{
        BLOCK_CHECK_ALL, BLOCK_CHECK_BASE, BLOCK_CHECK_MERKLE, BLOCK_CHECK_POW,
    };
}
