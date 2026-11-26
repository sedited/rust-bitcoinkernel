//! Requests read from stdin: every method the handler supports, with its typed params.
//!
//! [`Method`] is the handler's view of the protocol spec: serde parses a request's
//! `method` and `params` straight into a variant, so an unknown method or a
//! malformed param is rejected before any kernel code runs.
//!
//! See <https://github.com/stringintech/kernel-bindings-spec/blob/main/docs/handler-spec.md>.

use bitcoinkernel::{
    ChainType, ScriptVerificationFlags, VERIFY_ALL, VERIFY_CHECKLOCKTIMEVERIFY,
    VERIFY_CHECKSEQUENCEVERIFY, VERIFY_DERSIG, VERIFY_NONE, VERIFY_NULLDUMMY, VERIFY_P2SH,
    VERIFY_TAPROOT, VERIFY_WITNESS,
};
use serde::Deserialize;

/// A single request read from stdin.
///
/// `method` and `params` are parsed together into a typed [`Method`].
#[derive(Debug, Deserialize)]
pub struct Request {
    pub id: String,
    #[serde(default, rename = "ref")]
    pub ref_: Option<String>,
    #[serde(flatten)]
    pub method: Method,
}

/// A reference to a registry object by name, as passed in params.
#[derive(Debug, Clone, Deserialize)]
pub struct RefObject {
    #[serde(rename = "ref")]
    pub ref_: String,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "method", content = "params")]
pub enum Method {
    // Script pubkey
    #[serde(rename = "btck_script_pubkey_create")]
    ScriptPubkeyCreate {
        #[serde(with = "hex")]
        script_pubkey: Vec<u8>,
    },
    #[serde(rename = "btck_script_pubkey_copy")]
    ScriptPubkeyCopy { script_pubkey: RefObject },
    #[serde(rename = "btck_script_pubkey_to_bytes")]
    ScriptPubkeyToBytes { script_pubkey: RefObject },
    #[serde(rename = "btck_script_pubkey_verify")]
    ScriptPubkeyVerify(VerifyParams),
    #[serde(rename = "btck_script_pubkey_destroy")]
    ScriptPubkeyDestroy { script_pubkey: RefObject },

    // Transaction
    #[serde(rename = "btck_transaction_create")]
    TransactionCreate {
        #[serde(with = "hex")]
        raw_transaction: Vec<u8>,
    },
    #[serde(rename = "btck_transaction_copy")]
    TransactionCopy { transaction: RefObject },
    #[serde(rename = "btck_transaction_get_txid")]
    TransactionGetTxid { transaction: RefObject },
    #[serde(rename = "btck_transaction_count_inputs")]
    TransactionCountInputs { transaction: RefObject },
    #[serde(rename = "btck_transaction_count_outputs")]
    TransactionCountOutputs { transaction: RefObject },
    #[serde(rename = "btck_transaction_get_input_at")]
    TransactionGetInputAt {
        transaction: RefObject,
        input_index: usize,
    },
    #[serde(rename = "btck_transaction_get_output_at")]
    TransactionGetOutputAt {
        transaction: RefObject,
        output_index: usize,
    },
    #[serde(rename = "btck_transaction_to_bytes")]
    TransactionToBytes { transaction: RefObject },
    #[serde(rename = "btck_transaction_destroy")]
    TransactionDestroy { transaction: RefObject },

    // Txid
    #[serde(rename = "btck_txid_copy")]
    TxidCopy { txid: RefObject },
    #[serde(rename = "btck_txid_to_bytes")]
    TxidToBytes { txid: RefObject },
    #[serde(rename = "btck_txid_equals")]
    TxidEquals { txid1: RefObject, txid2: RefObject },
    #[serde(rename = "btck_txid_destroy")]
    TxidDestroy { txid: RefObject },

    // Transaction input and out point
    #[serde(rename = "btck_transaction_input_copy")]
    TransactionInputCopy { transaction_input: RefObject },
    #[serde(rename = "btck_transaction_input_get_out_point")]
    TransactionInputGetOutPoint { transaction_input: RefObject },
    #[serde(rename = "btck_transaction_input_destroy")]
    TransactionInputDestroy { transaction_input: RefObject },
    #[serde(rename = "btck_transaction_out_point_copy")]
    TransactionOutPointCopy { transaction_out_point: RefObject },
    #[serde(rename = "btck_transaction_out_point_get_txid")]
    TransactionOutPointGetTxid { transaction_out_point: RefObject },
    #[serde(rename = "btck_transaction_out_point_get_index")]
    TransactionOutPointGetIndex { transaction_out_point: RefObject },
    #[serde(rename = "btck_transaction_out_point_destroy")]
    TransactionOutPointDestroy { transaction_out_point: RefObject },

    // Transaction output
    #[serde(rename = "btck_transaction_output_create")]
    TransactionOutputCreate {
        script_pubkey: RefObject,
        amount: i64,
    },
    #[serde(rename = "btck_transaction_output_copy")]
    TransactionOutputCopy { transaction_output: RefObject },
    #[serde(rename = "btck_transaction_output_get_amount")]
    TransactionOutputGetAmount { transaction_output: RefObject },
    #[serde(rename = "btck_transaction_output_get_script_pubkey")]
    TransactionOutputGetScriptPubkey { transaction_output: RefObject },
    #[serde(rename = "btck_transaction_output_destroy")]
    TransactionOutputDestroy { transaction_output: RefObject },

    // Precomputed transaction data
    #[serde(rename = "btck_precomputed_transaction_data_create")]
    PrecomputedTransactionDataCreate {
        tx_to: RefObject,
        #[serde(default)]
        spent_outputs: Vec<RefObject>,
    },
    #[serde(rename = "btck_precomputed_transaction_data_destroy")]
    PrecomputedTransactionDataDestroy { precomputed_txdata: RefObject },

    // Context
    #[serde(rename = "btck_context_create")]
    ContextCreate { chain_parameters: ChainParameters },
    #[serde(rename = "btck_context_destroy")]
    ContextDestroy { context: RefObject },

    // Chainstate manager
    #[serde(rename = "btck_chainstate_manager_create")]
    ChainstateManagerCreate { context: RefObject },
    #[serde(rename = "btck_chainstate_manager_get_active_chain")]
    ChainstateManagerGetActiveChain { chainstate_manager: RefObject },
    #[serde(rename = "btck_chainstate_manager_process_block")]
    ChainstateManagerProcessBlock {
        chainstate_manager: RefObject,
        block: RefObject,
    },
    #[serde(rename = "btck_chainstate_manager_destroy")]
    ChainstateManagerDestroy { chainstate_manager: RefObject },

    // Chain
    #[serde(rename = "btck_chain_get_height")]
    ChainGetHeight { chain: RefObject },
    #[serde(rename = "btck_chain_get_by_height")]
    ChainGetByHeight { chain: RefObject, block_height: i32 },
    #[serde(rename = "btck_chain_contains")]
    ChainContains {
        chain: RefObject,
        block_tree_entry: RefObject,
    },

    // Block
    #[serde(rename = "btck_block_create")]
    BlockCreate {
        #[serde(with = "hex")]
        raw_block: Vec<u8>,
    },
    #[serde(rename = "btck_block_copy")]
    BlockCopy { block: RefObject },
    #[serde(rename = "btck_block_get_hash")]
    BlockGetHash { block: RefObject },
    #[serde(rename = "btck_block_get_header")]
    BlockGetHeader { block: RefObject },
    #[serde(rename = "btck_block_count_transactions")]
    BlockCountTransactions { block: RefObject },
    #[serde(rename = "btck_block_get_transaction_at")]
    BlockGetTransactionAt {
        block: RefObject,
        transaction_index: usize,
    },
    #[serde(rename = "btck_block_to_bytes")]
    BlockToBytes { block: RefObject },
    #[serde(rename = "btck_block_destroy")]
    BlockDestroy { block: RefObject },

    // Block tree entry
    #[serde(rename = "btck_block_tree_entry_get_block_hash")]
    BlockTreeEntryGetHash { block_tree_entry: RefObject },

    // Block hash
    #[serde(rename = "btck_block_hash_create")]
    BlockHashCreate {
        #[serde(with = "hex")]
        block_hash: Vec<u8>,
    },
    #[serde(rename = "btck_block_hash_copy")]
    BlockHashCopy { block_hash: RefObject },
    #[serde(rename = "btck_block_hash_to_bytes")]
    BlockHashToBytes { block_hash: RefObject },
    #[serde(rename = "btck_block_hash_equals")]
    BlockHashEquals { hash1: RefObject, hash2: RefObject },
    #[serde(rename = "btck_block_hash_destroy")]
    BlockHashDestroy { block_hash: RefObject },

    // Block header
    #[serde(rename = "btck_block_header_create")]
    BlockHeaderCreate {
        #[serde(with = "hex")]
        raw_block_header: Vec<u8>,
    },
    #[serde(rename = "btck_block_header_copy")]
    BlockHeaderCopy { header: RefObject },
    #[serde(rename = "btck_block_header_get_hash")]
    BlockHeaderGetHash { header: RefObject },
    #[serde(rename = "btck_block_header_get_prev_hash")]
    BlockHeaderGetPrevHash { header: RefObject },
    #[serde(rename = "btck_block_header_get_timestamp")]
    BlockHeaderGetTimestamp { header: RefObject },
    #[serde(rename = "btck_block_header_get_bits")]
    BlockHeaderGetBits { header: RefObject },
    #[serde(rename = "btck_block_header_get_version")]
    BlockHeaderGetVersion { header: RefObject },
    #[serde(rename = "btck_block_header_get_nonce")]
    BlockHeaderGetNonce { header: RefObject },
    #[serde(rename = "btck_block_header_to_bytes")]
    BlockHeaderToBytes { header: RefObject },
    #[serde(rename = "btck_block_header_destroy")]
    BlockHeaderDestroy { header: RefObject },
}

/// Params of `btck_script_pubkey_verify`
#[derive(Debug, Deserialize)]
pub struct VerifyParams {
    pub script_pubkey: RefObject,
    pub amount: i64,
    pub tx_to: RefObject,
    pub input_index: usize,
    pub flags: Flags,
    pub precomputed_txdata: Option<RefObject>,
}

/// Script verification flags, given either as a list of names or as a bitmask.
#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum Flags {
    Names(Vec<FlagName>),
    Bits(ScriptVerificationFlags),
}

impl Flags {
    pub fn bits(&self) -> ScriptVerificationFlags {
        match self {
            Flags::Names(names) => names.iter().fold(VERIFY_NONE, |acc, n| acc | n.bits()),
            Flags::Bits(bits) => *bits,
        }
    }
}

#[derive(Debug, Deserialize)]
pub enum FlagName {
    #[serde(rename = "btck_ScriptVerificationFlags_NONE")]
    None,
    #[serde(rename = "btck_ScriptVerificationFlags_P2SH")]
    P2sh,
    #[serde(rename = "btck_ScriptVerificationFlags_DERSIG")]
    Dersig,
    #[serde(rename = "btck_ScriptVerificationFlags_NULLDUMMY")]
    Nulldummy,
    #[serde(rename = "btck_ScriptVerificationFlags_CHECKLOCKTIMEVERIFY")]
    CheckLockTimeVerify,
    #[serde(rename = "btck_ScriptVerificationFlags_CHECKSEQUENCEVERIFY")]
    CheckSequenceVerify,
    #[serde(rename = "btck_ScriptVerificationFlags_WITNESS")]
    Witness,
    #[serde(rename = "btck_ScriptVerificationFlags_TAPROOT")]
    Taproot,
    #[serde(rename = "btck_ScriptVerificationFlags_ALL")]
    All,
}

impl FlagName {
    fn bits(&self) -> ScriptVerificationFlags {
        match self {
            FlagName::None => VERIFY_NONE,
            FlagName::P2sh => VERIFY_P2SH,
            FlagName::Dersig => VERIFY_DERSIG,
            FlagName::Nulldummy => VERIFY_NULLDUMMY,
            FlagName::CheckLockTimeVerify => VERIFY_CHECKLOCKTIMEVERIFY,
            FlagName::CheckSequenceVerify => VERIFY_CHECKSEQUENCEVERIFY,
            FlagName::Witness => VERIFY_WITNESS,
            FlagName::Taproot => VERIFY_TAPROOT,
            FlagName::All => VERIFY_ALL,
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct ChainParameters {
    pub chain_type: ChainTypeParam,
}

#[derive(Debug, Deserialize)]
pub enum ChainTypeParam {
    #[serde(rename = "btck_ChainType_MAINNET")]
    Mainnet,
    #[serde(rename = "btck_ChainType_TESTNET")]
    Testnet,
    #[serde(rename = "btck_ChainType_TESTNET_4")]
    Testnet4,
    #[serde(rename = "btck_ChainType_SIGNET")]
    Signet,
    #[serde(rename = "btck_ChainType_REGTEST")]
    Regtest,
}

impl From<ChainTypeParam> for ChainType {
    fn from(param: ChainTypeParam) -> Self {
        match param {
            ChainTypeParam::Mainnet => ChainType::Mainnet,
            ChainTypeParam::Testnet => ChainType::Testnet,
            ChainTypeParam::Testnet4 => ChainType::Testnet4,
            ChainTypeParam::Signet => ChainType::Signet,
            ChainTypeParam::Regtest => ChainType::Regtest,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(json: &str) -> Result<Request, serde_json::Error> {
        serde_json::from_str(json)
    }

    #[test]
    fn parses_id_ref_and_method() {
        let req = parse(
            r#"{"id":"1","ref":"$y","method":"btck_txid_copy","params":{"txid":{"ref":"$x"}}}"#,
        )
        .unwrap();
        assert_eq!(req.id, "1");
        assert_eq!(req.ref_.as_deref(), Some("$y"));
        match req.method {
            Method::TxidCopy { txid } => assert_eq!(txid.ref_, "$x"),
            other => panic!("unexpected method: {other:?}"),
        }
    }

    #[test]
    fn ref_is_optional() {
        let req = parse(
            r#"{"id":"2","method":"btck_txid_destroy","params":{"txid":{"ref":"$x"}}}"#,
        )
        .unwrap();
        assert_eq!(req.ref_, None);
        match req.method {
            Method::TxidDestroy { txid } => assert_eq!(txid.ref_, "$x"),
            other => panic!("unexpected method: {other:?}"),
        }
    }

    #[test]
    fn parses_method_with_two_refs() {
        let req = parse(
            r#"{"id":"3","method":"btck_txid_equals","params":{"txid1":{"ref":"$a"},"txid2":{"ref":"$b"}}}"#,
        )
        .unwrap();
        match req.method {
            Method::TxidEquals { txid1, txid2 } => {
                assert_eq!(txid1.ref_, "$a");
                assert_eq!(txid2.ref_, "$b");
            }
            other => panic!("unexpected method: {other:?}"),
        }
    }

    #[test]
    fn missing_param_ref_is_rejected() {
        assert!(parse(r#"{"id":"4","method":"btck_txid_destroy","params":{"txid":{}}}"#).is_err());
    }

    fn parse_flags(json: &str) -> Result<Flags, serde_json::Error> {
        serde_json::from_str(json)
    }

    #[test]
    fn flag_names_are_ored() {
        let flags = parse_flags(
            r#"["btck_ScriptVerificationFlags_P2SH","btck_ScriptVerificationFlags_WITNESS"]"#,
        )
        .unwrap();
        assert!(matches!(flags, Flags::Names(_)));
        assert_eq!(flags.bits(), VERIFY_P2SH | VERIFY_WITNESS);
    }

    #[test]
    fn empty_flag_list_is_none() {
        let flags = parse_flags("[]").unwrap();
        assert_eq!(flags.bits(), VERIFY_NONE);
    }

    #[test]
    fn flags_as_bitmask() {
        let mask = VERIFY_P2SH | VERIFY_DERSIG;
        let flags = parse_flags(&mask.to_string()).unwrap();
        assert!(matches!(flags, Flags::Bits(_)));
        assert_eq!(flags.bits(), mask);
    }

    #[test]
    fn unknown_flag_name_is_rejected() {
        assert!(parse_flags(r#"["btck_ScriptVerificationFlags_BOGUS"]"#).is_err());
    }

    #[test]
    fn each_flag_name_maps_to_its_bit() {
        let cases = [
            ("NONE", VERIFY_NONE),
            ("P2SH", VERIFY_P2SH),
            ("DERSIG", VERIFY_DERSIG),
            ("NULLDUMMY", VERIFY_NULLDUMMY),
            ("CHECKLOCKTIMEVERIFY", VERIFY_CHECKLOCKTIMEVERIFY),
            ("CHECKSEQUENCEVERIFY", VERIFY_CHECKSEQUENCEVERIFY),
            ("WITNESS", VERIFY_WITNESS),
            ("TAPROOT", VERIFY_TAPROOT),
            ("ALL", VERIFY_ALL),
        ];
        for (name, expected) in cases {
            let json = format!(r#"["btck_ScriptVerificationFlags_{name}"]"#);
            let flags = parse_flags(&json).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(flags.bits(), expected, "{name}");
        }
    }

    #[test]
    fn each_chain_type_maps_to_kernel_chain_type() {
        let cases = [
            ("MAINNET", ChainType::Mainnet),
            ("TESTNET", ChainType::Testnet),
            ("TESTNET_4", ChainType::Testnet4),
            ("SIGNET", ChainType::Signet),
            ("REGTEST", ChainType::Regtest),
        ];
        for (name, expected) in cases {
            let json = format!(r#""btck_ChainType_{name}""#);
            let param: ChainTypeParam =
                serde_json::from_str(&json).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(ChainType::from(param), expected, "{name}");
        }
    }

    #[test]
    fn unknown_chain_type_is_rejected() {
        assert!(serde_json::from_str::<ChainTypeParam>(r#""btck_ChainType_BOGUS""#).is_err());
    }
}
