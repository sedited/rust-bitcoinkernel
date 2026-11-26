//! Runs a parsed [`Method`] against the bindings.

use std::rc::Rc;

use bitcoinkernel::{
    core::{ScriptPubkeyExt, TransactionExt},
    prelude::*,
    Block, BlockHash, BlockHeader, ContextBuilder, KernelError, PrecomputedTransactionData,
    ProcessBlockResult, ScriptPubkey, ScriptVerifyError, Transaction, TxOut, TxOutRef,
};
use serde::Serialize;
use serde_json::{json, Value};

use crate::{
    chainstate::{BlockTreeEntryHandle, ChainHandle, TempChainstateManager},
    error::Error,
    registry::{Object, Registry},
    request::{Method as M, RefObject, VerifyParams},
};

pub enum Output {
    /// A new object, stored under the request's `ref`; the response is `{"ref": ...}`.
    Object(Object),
    /// A plain result value.
    Value(Value),
    /// No result, for void operations.
    Unit,
}

impl Output {
    pub fn object(obj: impl Into<Object>) -> Output {
        Output::Object(obj.into())
    }

    pub fn value(value: impl Serialize) -> Output {
        Output::Value(serde_json::to_value(value).expect("result must serialize"))
    }
}

/// Executes a method. Objects in the returned [`Output`] are stored by the caller.
pub fn execute(method: M, registry: &mut Registry) -> Result<Output, Error> {
    Ok(match method {
        // Script pubkey
        M::ScriptPubkeyCreate { script_pubkey } => {
            Output::object(ScriptPubkey::new(&script_pubkey)?)
        }
        M::ScriptPubkeyCopy { script_pubkey } => {
            Output::object(registry.script_pubkey(&script_pubkey)?.clone())
        }
        M::ScriptPubkeyToBytes { script_pubkey } => Output::value(hex::encode(
            registry.script_pubkey(&script_pubkey)?.to_bytes(),
        )),
        M::ScriptPubkeyVerify(params) => verify(registry, params)?,
        M::ScriptPubkeyDestroy { script_pubkey } => destroy(registry, &script_pubkey)?,

        // Transaction
        M::TransactionCreate { raw_transaction } => {
            Output::object(Transaction::new(&raw_transaction)?)
        }
        M::TransactionCopy { transaction } => {
            Output::object(registry.transaction(&transaction)?.clone())
        }
        M::TransactionGetTxid { transaction } => {
            Output::object(registry.transaction(&transaction)?.txid().to_owned())
        }
        M::TransactionCountInputs { transaction } => {
            Output::value(registry.transaction(&transaction)?.input_count())
        }
        M::TransactionCountOutputs { transaction } => {
            Output::value(registry.transaction(&transaction)?.output_count())
        }
        // Out-of-range indices are caller errors: the C API does not define a result.
        M::TransactionGetInputAt {
            transaction,
            input_index,
        } => Output::object(
            registry
                .transaction(&transaction)?
                .input(input_index)
                .map_err(|e| Error::protocol(format!("input {input_index}: {e}")))?
                .to_owned(),
        ),
        M::TransactionGetOutputAt {
            transaction,
            output_index,
        } => Output::object(
            registry
                .transaction(&transaction)?
                .output(output_index)
                .map_err(|e| Error::protocol(format!("output {output_index}: {e}")))?
                .to_owned(),
        ),
        M::TransactionToBytes { transaction } => Output::value(hex::encode(
            registry.transaction(&transaction)?.consensus_encode()?,
        )),
        M::TransactionDestroy { transaction } => destroy(registry, &transaction)?,

        // Txid
        M::TxidCopy { txid } => Output::object(registry.txid(&txid)?.clone()),
        M::TxidToBytes { txid } => Output::value(hex::encode(registry.txid(&txid)?.to_bytes())),
        M::TxidEquals { txid1, txid2 } => {
            Output::value(registry.txid(&txid1)? == registry.txid(&txid2)?)
        }
        M::TxidDestroy { txid } => destroy(registry, &txid)?,

        // Transaction input and out point
        M::TransactionInputCopy { transaction_input } => {
            Output::object(registry.transaction_input(&transaction_input)?.clone())
        }
        M::TransactionInputGetOutPoint { transaction_input } => Output::object(
            registry
                .transaction_input(&transaction_input)?
                .outpoint()
                .to_owned(),
        ),
        M::TransactionInputDestroy { transaction_input } => destroy(registry, &transaction_input)?,
        M::TransactionOutPointCopy {
            transaction_out_point,
        } => Output::object(
            registry
                .transaction_out_point(&transaction_out_point)?
                .clone(),
        ),
        M::TransactionOutPointGetTxid {
            transaction_out_point,
        } => Output::object(
            registry
                .transaction_out_point(&transaction_out_point)?
                .txid()
                .to_owned(),
        ),
        M::TransactionOutPointGetIndex {
            transaction_out_point,
        } => Output::value(
            registry
                .transaction_out_point(&transaction_out_point)?
                .index(),
        ),
        M::TransactionOutPointDestroy {
            transaction_out_point,
        } => destroy(registry, &transaction_out_point)?,

        // Transaction output
        M::TransactionOutputCreate {
            script_pubkey,
            amount,
        } => Output::object(TxOut::new(registry.script_pubkey(&script_pubkey)?, amount)),
        M::TransactionOutputCopy { transaction_output } => {
            Output::object(registry.transaction_output(&transaction_output)?.clone())
        }
        M::TransactionOutputGetAmount { transaction_output } => {
            Output::value(registry.transaction_output(&transaction_output)?.value())
        }
        M::TransactionOutputGetScriptPubkey { transaction_output } => Output::object(
            registry
                .transaction_output(&transaction_output)?
                .script_pubkey()
                .to_owned(),
        ),
        M::TransactionOutputDestroy { transaction_output } => {
            destroy(registry, &transaction_output)?
        }

        // Precomputed transaction data
        M::PrecomputedTransactionDataCreate {
            tx_to,
            spent_outputs,
        } => {
            let tx = registry.transaction(&tx_to)?;
            let spent_outputs = spent_outputs
                .iter()
                .map(|r| registry.transaction_output(r).map(|o| o.as_ref()))
                .collect::<Result<Vec<TxOutRef<'_>>, _>>()?;
            Output::object(PrecomputedTransactionData::new(tx, &spent_outputs)?)
        }
        M::PrecomputedTransactionDataDestroy { precomputed_txdata } => {
            destroy(registry, &precomputed_txdata)?
        }

        // Context
        M::ContextCreate { chain_parameters } => Output::object(
            ContextBuilder::new()
                .chain_type(chain_parameters.chain_type.into())
                .build()?,
        ),
        M::ContextDestroy { context } => destroy(registry, &context)?,

        // Chainstate manager
        M::ChainstateManagerCreate { context } => Output::object(Rc::new(
            TempChainstateManager::new(registry.context(&context)?)?,
        )),
        M::ChainstateManagerGetActiveChain { chainstate_manager } => {
            let chainman = Rc::clone(registry.chainstate_manager(&chainstate_manager)?);
            Output::object(ChainHandle::new(chainman))
        }
        M::ChainstateManagerProcessBlock {
            chainstate_manager,
            block,
        } => {
            let chainman = registry.chainstate_manager(&chainstate_manager)?;
            let new_block = match chainman.process_block(registry.block(&block)?) {
                ProcessBlockResult::NewBlock => true,
                ProcessBlockResult::Duplicate => false,
                ProcessBlockResult::Rejected => return Err(Error::Kernel),
            };
            Output::value(json!({"new_block": new_block}))
        }
        // The manager itself is dropped once no chain or block tree entry handle
        // refers to it anymore.
        M::ChainstateManagerDestroy { chainstate_manager } => {
            destroy(registry, &chainstate_manager)?
        }

        // Chain
        M::ChainGetHeight { chain } => Output::value(registry.chain(&chain)?.chain().height()),
        M::ChainGetByHeight {
            chain,
            block_height,
        } => {
            let handle = registry.chain(&chain)?;
            let entry = usize::try_from(block_height)
                .ok()
                .and_then(|h| handle.chain().at_height(h))
                .ok_or(Error::Kernel)?;
            Output::object(BlockTreeEntryHandle::new(
                Rc::clone(handle.chainman()),
                &entry,
            ))
        }
        M::ChainContains {
            chain,
            block_tree_entry,
        } => {
            let chain = registry.chain(&chain)?.chain();
            let entry = registry.block_tree_entry(&block_tree_entry)?.entry()?;
            Output::value(chain.contains(&entry))
        }

        // Block
        M::BlockCreate { raw_block } => Output::object(Block::new(&raw_block)?),
        M::BlockCopy { block } => Output::object(registry.block(&block)?.clone()),
        M::BlockGetHash { block } => Output::object(registry.block(&block)?.hash()),
        M::BlockGetHeader { block } => Output::object(registry.block(&block)?.header()),
        M::BlockCountTransactions { block } => {
            Output::value(registry.block(&block)?.transaction_count())
        }
        M::BlockGetTransactionAt {
            block,
            transaction_index,
        } => Output::object(
            registry
                .block(&block)?
                .transaction(transaction_index)
                .map_err(|e| Error::protocol(format!("transaction {transaction_index}: {e}")))?
                .to_owned(),
        ),
        M::BlockToBytes { block } => {
            Output::value(hex::encode(registry.block(&block)?.consensus_encode()?))
        }
        M::BlockDestroy { block } => destroy(registry, &block)?,

        // Block tree entry
        M::BlockTreeEntryGetHash { block_tree_entry } => Output::object(
            registry
                .block_tree_entry(&block_tree_entry)?
                .entry()?
                .block_hash()
                .to_owned(),
        ),

        // Block hash
        M::BlockHashCreate { block_hash } => Output::object(BlockHash::new(&block_hash)?),
        M::BlockHashCopy { block_hash } => {
            Output::object(registry.block_hash(&block_hash)?.clone())
        }
        M::BlockHashToBytes { block_hash } => {
            Output::value(hex::encode(registry.block_hash(&block_hash)?.to_bytes()))
        }
        M::BlockHashEquals { hash1, hash2 } => {
            Output::value(registry.block_hash(&hash1)? == registry.block_hash(&hash2)?)
        }
        M::BlockHashDestroy { block_hash } => destroy(registry, &block_hash)?,

        // Block header
        // The C API takes a length and returns null for invalid input.
        M::BlockHeaderCreate { raw_block_header } => {
            Output::object(BlockHeader::new(&raw_block_header)?)
        }
        M::BlockHeaderCopy { header } => Output::object(registry.block_header(&header)?.clone()),
        M::BlockHeaderGetHash { header } => Output::object(registry.block_header(&header)?.hash()),
        M::BlockHeaderGetPrevHash { header } => {
            Output::object(registry.block_header(&header)?.prev_hash().to_owned())
        }
        M::BlockHeaderGetTimestamp { header } => {
            Output::value(registry.block_header(&header)?.timestamp())
        }
        M::BlockHeaderGetBits { header } => Output::value(registry.block_header(&header)?.bits()),
        M::BlockHeaderGetVersion { header } => {
            Output::value(registry.block_header(&header)?.version())
        }
        M::BlockHeaderGetNonce { header } => Output::value(registry.block_header(&header)?.nonce()),
        M::BlockHeaderToBytes { header } => Output::value(hex::encode(
            registry.block_header(&header)?.consensus_encode()?,
        )),
        M::BlockHeaderDestroy { header } => destroy(registry, &header)?,
    })
}

fn destroy(registry: &mut Registry, reference: &RefObject) -> Result<Output, Error> {
    registry.destroy(reference)?;
    Ok(Output::Unit)
}

/// Verifies a script pubkey against an input of a transaction.
fn verify(registry: &Registry, params: VerifyParams) -> Result<Output, Error> {
    let script_pubkey = registry.script_pubkey(&params.script_pubkey)?;
    let tx = registry.transaction(&params.tx_to)?;

    // The C API accepts a null precomputed_txdata and builds one from the
    // transaction alone; the Rust API always takes one, so build the equivalent.
    let owned_txdata;
    let txdata = match &params.precomputed_txdata {
        Some(r) => registry.precomputed_transaction_data(r)?,
        None => {
            owned_txdata = PrecomputedTransactionData::new(tx, &[] as &[TxOut])?;
            &owned_txdata
        }
    };

    let result = bitcoinkernel::verify(
        script_pubkey,
        Some(params.amount),
        tx,
        params.input_index,
        Some(params.flags.bits()),
        txdata,
    );

    match result {
        Ok(()) => Ok(Output::value(true)),
        Err(KernelError::ScriptVerify(err)) => match err {
            ScriptVerifyError::Invalid => Ok(Output::value(false)),
            ScriptVerifyError::InvalidFlagsCombination => Err(Error::Code(
                "btck_ScriptVerifyStatus",
                "ERROR_INVALID_FLAGS_COMBINATION",
            )),
            ScriptVerifyError::SpentOutputsRequired => Err(Error::Code(
                "btck_ScriptVerifyStatus",
                "ERROR_SPENT_OUTPUTS_REQUIRED",
            )),
            // Checked by the Rust binding before calling C; in C these are caller errors.
            ScriptVerifyError::TxInputIndex | ScriptVerifyError::InvalidFlags => {
                Err(Error::protocol(format!("verify: {err}")))
            }
        },
        Err(e) => Err(Error::protocol(format!(
            "verify returned unexpected error: {e}"
        ))),
    }
}
