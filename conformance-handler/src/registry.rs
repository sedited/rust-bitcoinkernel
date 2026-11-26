//! Named object storage that persists across requests.

use std::collections::HashMap;
use std::rc::Rc;

use bitcoinkernel::{
    Block, BlockHash, BlockHeader, Context, PrecomputedTransactionData, ScriptPubkey, Transaction,
    TxIn, TxOut, TxOutPoint, Txid,
};

use crate::chainstate::{BlockTreeEntryHandle, ChainHandle, TempChainstateManager};
use crate::error::Error;
use crate::request::RefObject;

/// Defines [`Object`] with one variant per storable type, a `From` impl for each,
/// and a typed getter on [`Registry`] for each.
macro_rules! objects {
    ($($variant:ident($ty:ty) => $getter:ident,)*) => {
        /// Every kind of object the handler can store.
        ///
        /// View types returned by the bindings (e.g. [`bitcoinkernel::TxidRef`])
        /// borrow their parent, so they are stored as owned copies via `to_owned()`.
        pub enum Object {
            $($variant($ty),)*
        }

        impl Object {
            fn type_name(&self) -> &'static str {
                match self {
                    $(Object::$variant(_) => stringify!($variant),)*
                }
            }
        }

        $(
            impl From<$ty> for Object {
                fn from(value: $ty) -> Self {
                    Object::$variant(value)
                }
            }
        )*

            impl Registry {
                $(
                    pub fn $getter(&self, r: &RefObject) -> Result<&$ty, Error> {
                        match self.get(r)? {
                            Object::$variant(v) => Ok(v),
                            other => Err(Error::protocol(format!(
                                        "reference {} is not a {} (got {})",
                                        r.ref_,
                                        stringify!($variant),
                                        other.type_name()
                            ))),
                        }
                    }
                )*
            }
    };
}

objects! {
    Context(Context) => context,
    ChainstateManager(Rc<TempChainstateManager>) => chainstate_manager,
    Chain(ChainHandle) => chain,
    BlockTreeEntry(BlockTreeEntryHandle) => block_tree_entry,
    Block(Block) => block,
    BlockHash(BlockHash) => block_hash,
    BlockHeader(BlockHeader) => block_header,
    ScriptPubkey(ScriptPubkey) => script_pubkey,
    Transaction(Transaction) => transaction,
    TransactionInput(TxIn) => transaction_input,
    TransactionOutput(TxOut) => transaction_output,
    TransactionOutPoint(TxOutPoint) => transaction_out_point,
    Txid(Txid) => txid,
    PrecomputedTransactionData(PrecomputedTransactionData) => precomputed_transaction_data,
}

/// Stores named references to objects created during the test session.
///
/// Objects remain alive until explicitly destroyed or the registry is dropped.
/// Drop order does not matter: objects either own their data or keep the
/// chainstate manager alive through an [`Rc`].
#[derive(Default)]
pub struct Registry {
    objects: HashMap<String, Object>,
}

impl Registry {
    /// Stores an object under `ref_`, dropping any object previously stored there.
    pub fn store(&mut self, ref_: String, obj: Object) {
        self.objects.insert(ref_, obj);
    }

    /// Removes and drops the object stored under the referenced name.
    pub fn destroy(&mut self, reference: &RefObject) -> Result<(), Error> {
        self.objects
            .remove(&reference.ref_)
            .map(drop)
            .ok_or_else(|| not_found(reference))
    }

    fn get(&self, reference: &RefObject) -> Result<&Object, Error> {
        self.objects
            .get(&reference.ref_)
            .ok_or_else(|| not_found(reference))
    }
}

fn not_found(reference: &RefObject) -> Error {
    Error::protocol(format!("reference not found: {}", reference.ref_))
}
