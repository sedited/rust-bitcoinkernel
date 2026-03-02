pub mod block;
pub mod block_tree_entry;
pub mod script;
#[cfg(feature = "script_debug")]
pub mod script_debug;
pub mod transaction;
pub mod verify;

pub use block::{
    Block, BlockHash, BlockHeader, BlockSpentOutputs, BlockSpentOutputsRef, Coin, CoinRef,
    TransactionSpentOutputs, TransactionSpentOutputsRef,
};
pub use block_tree_entry::BlockTreeEntry;
pub use script::{ScriptPubkey, ScriptPubkeyRef};
pub use transaction::{
    Transaction, TransactionRef, TxIn, TxInRef, TxOut, TxOutPoint, TxOutPointRef, TxOutRef, Txid,
    TxidRef,
};

pub use block::{
    BlockHashExt, BlockHeaderExt, BlockSpentOutputsExt, CoinExt, TransactionSpentOutputsExt,
};
pub use script::ScriptPubkeyExt;
pub use transaction::{TransactionExt, TxInExt, TxOutExt, TxOutPointExt, TxidExt};

pub use verify::{verify, PrecomputedTransactionData, ScriptVerifyError};

pub mod verify_flags {
    pub use super::verify::{
        VERIFY_ALL, VERIFY_ALL_PRE_TAPROOT, VERIFY_CHECKLOCKTIMEVERIFY, VERIFY_CHECKSEQUENCEVERIFY,
        VERIFY_DERSIG, VERIFY_NONE, VERIFY_NULLDUMMY, VERIFY_P2SH, VERIFY_TAPROOT, VERIFY_WITNESS,
    };
}
