#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Test Tapscript v2 leaf version 0xc2 behavior."""

import hashlib
import random

from feature_taproot import (
    ERR_EVAL_FALSE,
    ERR_INVALID_STACK_OPERATION,
    ERR_OP_RETURN,
    ERR_PUSH_SIZE,
    ERR_SCHNORR_SIG,
    ERR_STACK_SIZE,
    ERR_TAPSCRIPT_MINIMALIF,
    ERR_WITNESS_PROGRAM_MISMATCH,
    SINGLE_SIG,
    TaprootTest,
    add_spender,
    bitflipper,
    default_controlblock,
    default_sighash,
    getter,
    make_spender,
)

from test_framework.blocktools import (
    COINBASE_MATURITY,
    MAX_BLOCK_SIGOPS_WEIGHT,
    MAX_STANDARD_TX_WEIGHT,
)
from test_framework.key import compute_xonly_pubkey, generate_privkey
from test_framework.messages import (
    COIN,
    COutPoint,
    CTransaction,
    CTxIn,
    CTxInWitness,
    CTxOut,
    MAX_BLOCK_WEIGHT,
    SEQUENCE_FINAL,
    tx_from_hex,
)
from test_framework.psbt import (
    PSBT,
    PSBTMap,
    PSBT_GLOBAL_UNSIGNED_TX,
    PSBT_IN_FINAL_SCRIPTWITNESS,
    PSBT_IN_WITNESS_UTXO,
)
from test_framework.script import (
    ANNEX_TAG,
    CScript,
    CScriptOp,
    LEAF_VERSION_TAPSCRIPT,
    LEAF_VERSION_TAPSCRIPT_V2,
    MAX_SCRIPT_ELEMENT_SIZE,
    OP_0,
    OP_1,
    OP_1NEGATE,
    OP_CAT,
    OP_CHECKLOCKTIMEVERIFY,
    OP_CHECKSEQUENCEVERIFY,
    OP_CHECKSIG,
    OP_CHECKSIGADD,
    OP_DEPTH,
    OP_DROP,
    OP_ENDIF,
    OP_EQUAL,
    OP_EQUALVERIFY,
    OP_FROMALTSTACK,
    OP_IF,
    OP_LSHIFT,
    OP_MUL,
    OP_PICK,
    OP_PUSHDATA1,
    OP_RETURN,
    OP_RSHIFT,
    OP_SHA1,
    OP_SHA256,
    OP_SIZE,
    OP_TOALTSTACK,
    taproot_construct,
)
from test_framework.util import assert_equal, assert_greater_than, assert_raises_rpc_error
from test_framework.wallet import NodeSigner


ERR_LOCKTIME = {"err_msg": "Locktime requirement not satisfied"}
ERR_EQUALVERIFY = {"err_msg": "Script failed an OP_EQUALVERIFY operation"}
ERR_VAROP_COUNT = {"err_msg": "Varops budget exceeded"}
ERR_TOTAL_STACK_SIZE = {"err_msg": "Total stack size limit exceeded"}
ERR_STACK_ELEMENT_SIZE = {"err_msg": "Stack element size limit exceeded"}
ERR_HASH_OPERAND_SIZE = {"err_msg": "OP_RIPEMD160 or OP_SHA1 operand exceeds maximum permitted size"}

MAX_TAPSCRIPT_V2_STACK_SIZE = 32_768
MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE = 4_000_000
MAX_TAPSCRIPT_V2_TOTAL_STACK_SIZE = 8_000_000

VAROPS_BUDGET_PER_WEIGHT = 10_000
VAROPS_COST_FAST = 2
VAROPS_COST_COPYING = 3
VAROPS_COST_MUL_QUAD = 27
VERSIONBITS_PERIOD = 144


def v2_num(value):
    """Return the minimal unsigned little-endian encoding used by Tapscript v2."""
    assert value >= 0
    if value == 0:
        return b""
    return value.to_bytes((value.bit_length() + 7) // 8, "little")


def word_size(size):
    return ((size + 7) // 8) * 8


def mul_cost(size_a, size_b):
    return (
        (size_a + size_b) * VAROPS_COST_COPYING
        + (word_size(size_a) // 8) * word_size(size_b) * VAROPS_COST_MUL_QUAD
    )


def lengthconv_cost(size):
    return word_size(size) * VAROPS_COST_FAST


def comparingzero_cost(size):
    return word_size(size) * VAROPS_COST_FAST


def upshift_cost(value_size, bits):
    return (
        lengthconv_cost(len(v2_num(bits)))
        + (bits // 8) * VAROPS_COST_FAST
        + value_size * VAROPS_COST_COPYING
    )


def flip_leaf_version(ctx):
    control = bytearray(default_controlblock(ctx))
    control[0] ^= 0x02
    return bytes(control)


def drop_all_then_true(count):
    return CScript([OP_DROP] * count + [OP_1])


def repeated_nonempty_unknown_pubkey_checksig_script(pubkey, checks):
    script = []
    unknown_pubkey = b"\x02" + pubkey
    for _ in range(checks):
        script += [b"\x01", unknown_pubkey, OP_CHECKSIG, OP_DROP]
    script += [OP_1]
    return CScript(script)


def tapscript_v2_spenders():
    secs = [generate_privkey() for _ in range(12)]
    pubs = [compute_xonly_pubkey(sec)[0] for sec in secs]
    spenders = []

    # Leaf version 0xc2 is committed to the tapleaf hash and the script-path
    # sighash. Both control-block and signature mismatches must fail.
    sig_script = CScript([pubs[1], OP_CHECKSIG])
    tap = taproot_construct(pubs[0], [("sig_v2", sig_script, LEAF_VERSION_TAPSCRIPT_V2)])
    add_spender(
        spenders,
        "v2/leafversion_sighash",
        tap=tap,
        leaf="sig_v2",
        key=secs[1],
        **SINGLE_SIG,
        failure={"sighash": bitflipper(default_sighash)},
        **ERR_SCHNORR_SIG,
    )
    add_spender(
        spenders,
        "v2/leafversion_controlblock",
        tap=tap,
        leaf="sig_v2",
        key=secs[1],
        **SINGLE_SIG,
        failure={"controlblock": flip_leaf_version},
        **ERR_WITNESS_PROGRAM_MISMATCH,
    )

    # Initial witness elements can exceed 520 bytes in v2, but the same leaf
    # body under 0xc0 still uses the BIP342 element limit.
    big_item = b"a" * (MAX_SCRIPT_ELEMENT_SIZE + 80)
    big_item_script = CScript([OP_SIZE, v2_num(len(big_item)), OP_EQUALVERIFY, OP_DROP, OP_1])
    tap = taproot_construct(pubs[0], [
        ("big_item_v2", big_item_script, LEAF_VERSION_TAPSCRIPT_V2),
        ("big_item_c0", big_item_script, LEAF_VERSION_TAPSCRIPT),
    ])
    add_spender(
        spenders,
        "v2/witness_item_over_520",
        tap=tap,
        leaf="big_item_v2",
        inputs=[big_item],
        failure={"leaf": "big_item_c0"},
        **ERR_PUSH_SIZE,
    )

    # Tapscript v2 final success is unsigned/non-zero-byte based. A single
    # 0x80 byte is false under CastToBool() in 0xc0, but true in 0xc2.
    negzero_script = CScript([b"\x80"])
    tap = taproot_construct(pubs[0], [
        ("negzero_v2", negzero_script, LEAF_VERSION_TAPSCRIPT_V2),
        ("negzero_c0", negzero_script, LEAF_VERSION_TAPSCRIPT),
    ])
    add_spender(
        spenders,
        "v2/final_success_unsigned",
        tap=tap,
        leaf="negzero_v2",
        failure={"leaf": "negzero_c0"},
        **ERR_EVAL_FALSE,
    )

    # OP_1NEGATE is OP_SUCCESSx in v2 and bypasses later failing opcodes.
    tap = taproot_construct(pubs[0], [
        ("1negate_success", CScript([OP_1NEGATE, OP_RETURN]), LEAF_VERSION_TAPSCRIPT_V2),
        ("return", CScript([OP_RETURN]), LEAF_VERSION_TAPSCRIPT_V2),
    ])
    add_spender(
        spenders,
        "v2/opsuccess_1negate",
        tap=tap,
        leaf="1negate_success",
        failure={"leaf": "return"},
        standard=False,
        **ERR_OP_RETURN,
    )

    # OP_SUCCESSx is detected before execution, including in unexecuted branches.
    tap = taproot_construct(pubs[0], [
        ("unexecuted_success", CScript([OP_0, OP_IF, OP_1NEGATE, OP_ENDIF, OP_RETURN]), LEAF_VERSION_TAPSCRIPT_V2),
        ("return", CScript([OP_RETURN]), LEAF_VERSION_TAPSCRIPT_V2),
    ])
    add_spender(
        spenders,
        "v2/opsuccess_unexecuted_branch",
        tap=tap,
        leaf="unexecuted_success",
        failure={"leaf": "return"},
        standard=False,
        **ERR_OP_RETURN,
    )

    # OP_SUCCESSx bypasses initial stack-count enforcement.
    tap = taproot_construct(pubs[0], [("success_overstack", CScript([OP_1NEGATE]), LEAF_VERSION_TAPSCRIPT_V2)])
    add_spender(
        spenders,
        "v2/opsuccess_bypasses_initial_stack_count",
        tap=tap,
        leaf="success_overstack",
        inputs=[b""] * (MAX_TAPSCRIPT_V2_STACK_SIZE + 1),
        standard=False,
    )

    # Non-OP_SUCCESS v2 scripts enforce the 32,768 initial stack-element limit.
    tap = taproot_construct(pubs[0], [("drop16", drop_all_then_true(16), LEAF_VERSION_TAPSCRIPT_V2)])
    add_spender(
        spenders,
        "v2/initial_stack_count_limit",
        tap=tap,
        leaf="drop16",
        inputs=[b""] * 16,
        failure={"inputs": [b""] * (MAX_TAPSCRIPT_V2_STACK_SIZE + 1)},
        **ERR_STACK_SIZE,
    )

    # The exact 32,768-element initial stack is valid, but the combined
    # stack+altstack count is enforced after each executed opcode.
    tap = taproot_construct(pubs[0], [
        ("exact_count_ok", drop_all_then_true(MAX_TAPSCRIPT_V2_STACK_SIZE), LEAF_VERSION_TAPSCRIPT_V2),
        ("altstack_count_fail", CScript([OP_TOALTSTACK, OP_1]), LEAF_VERSION_TAPSCRIPT_V2),
    ])
    add_spender(
        spenders,
        "v2/initial_stack_exact_limit_and_altstack_count",
        tap=tap,
        leaf="exact_count_ok",
        inputs=[b""] * MAX_TAPSCRIPT_V2_STACK_SIZE,
        failure={"leaf": "altstack_count_fail"},
        **ERR_STACK_SIZE,
    )

    # OP_DEPTH writes minimal unsigned values in v2.
    depth_count = 130
    depth_script = CScript([OP_DEPTH, v2_num(depth_count), OP_EQUALVERIFY] + [OP_DROP] * depth_count + [OP_1])
    tap = taproot_construct(pubs[0], [
        ("depth_v2", depth_script, LEAF_VERSION_TAPSCRIPT_V2),
        ("depth_c0", depth_script, LEAF_VERSION_TAPSCRIPT),
    ])
    add_spender(
        spenders,
        "v2/depth_unsigned_minimal",
        tap=tap,
        leaf="depth_v2",
        inputs=[b""] * depth_count,
        failure={"leaf": "depth_c0"},
        **ERR_EQUALVERIFY,
    )

    # OP_CAT is restored under 0xc2 and can produce elements over 520 bytes.
    cat_a = b"x" * 400
    cat_b = b"y" * 180
    cat_script = CScript([OP_CAT, cat_a + cat_b, OP_EQUAL])
    tap = taproot_construct(pubs[0], [
        ("cat_v2", cat_script, LEAF_VERSION_TAPSCRIPT_V2),
    ])
    add_spender(
        spenders,
        "v2/cat_restored_over_520",
        tap=tap,
        leaf="cat_v2",
        inputs=[cat_a, cat_b],
    )

    # Right shift preserves the byte-string width required by the v2 rules.
    add_spender_for_script(
        spenders,
        pubs[0],
        "v2/rshift_preserves_trailing_zero",
        CScript([OP_RSHIFT, b"\x01\x00", OP_EQUAL]),
        inputs=[b"\x02\x00", v2_num(1)],
        failure_inputs=[b"\x02\x00", v2_num(8)],
    )

    # Multiplication represents unsigned arbitrary-length arithmetic.
    add_spender_for_script(
        spenders,
        pubs[0],
        "v2/mul",
        CScript([OP_MUL, b"\x01\xfe", OP_EQUAL]),
        inputs=[b"\xff", b"\xff"],
        failure_inputs=[b"\xff", b"\xfe"],
    )
    # Preserve the BIP342 minimal-if rule under the new leaf version.
    add_spender_for_script(
        spenders,
        pubs[0],
        "v2/minimalif_still_required",
        CScript([OP_IF, OP_1, OP_ENDIF]),
        inputs=[b"\x01"],
        failure_inputs=[b"\x01\x00"],
        failure_err=ERR_TAPSCRIPT_MINIMALIF,
    )
    # OP_PICK represents v2's arbitrary-length stack indices.
    add_spender_for_script(
        spenders,
        pubs[0],
        "v2/pick_wide_index",
        CScript([OP_PICK, b"bottom", OP_EQUALVERIFY, OP_DROP, OP_DROP, OP_1]),
        inputs=[b"bottom", b"top", b"\x01\x00\x00\x00\x00"],
        failure_inputs=[b"bottom", b"top", b"\x02\x00\x00\x00\x00"],
        failure_err=ERR_INVALID_STACK_OPERATION,
    )
    # SHA256 is no longer capped at 520 bytes, while SHA1 remains capped.
    hash_data = b"h" * (MAX_SCRIPT_ELEMENT_SIZE + 17)
    add_spender_for_script(
        spenders,
        pubs[0],
        "v2/sha256_over_520",
        CScript([OP_SHA256, hashlib.sha256(hash_data).digest(), OP_EQUAL]),
        inputs=[hash_data],
        failure_inputs=[hash_data[:-1]],
    )
    add_spender_for_script(
        spenders,
        pubs[0],
        "v2/sha1_520_limit",
        CScript([OP_SHA1, hashlib.sha1(b"s" * MAX_SCRIPT_ELEMENT_SIZE).digest(), OP_EQUAL]),
        inputs=[b"s" * MAX_SCRIPT_ELEMENT_SIZE],
        failure_inputs=[b"s" * (MAX_SCRIPT_ELEMENT_SIZE + 1)],
        failure_err=ERR_HASH_OPERAND_SIZE,
    )
    # OP_CHECKSIGADD increments arbitrary-length unsigned numbers.
    checksigadd_script = CScript([pubs[2], OP_CHECKSIGADD, v2_num(0x1_0000_0000), OP_EQUAL])
    tap = taproot_construct(pubs[0], [("checksigadd", checksigadd_script, LEAF_VERSION_TAPSCRIPT_V2)])
    add_spender(
        spenders,
        "v2/checksigadd_unsigned_increment",
        tap=tap,
        leaf="checksigadd",
        key=secs[2],
        inputs=[getter("sign"), b"\xff\xff\xff\xff"],
        failure={"sighash": bitflipper(default_sighash)},
        **ERR_SCHNORR_SIG,
    )

    # Empty signatures produce false without failing, and CHECKSIGADD still
    # normalizes its unchanged numeric operand.
    empty_checksigadd_script = CScript([pubs[2], OP_CHECKSIGADD, OP_1, OP_EQUAL])
    tap = taproot_construct(pubs[0], [("checksigadd", empty_checksigadd_script, LEAF_VERSION_TAPSCRIPT_V2)])
    add_spender(
        spenders,
        "v2/checksigadd_empty_signature_normalizes",
        tap=tap,
        leaf="checksigadd",
        inputs=[b"", b"\x01\x00"],
    )

    # Reach exactly 8,000,000 stack+altstack bytes at runtime using two
    # individually valid 4,000,000-byte elements, then fail by pushing one
    # additional byte.
    exact_element_shift = v2_num((MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE - 1) * 8)
    exact_total_inputs = [
        b"\x01",
        exact_element_shift,
        b"\x01",
        exact_element_shift,
        b"pad" * 1800,
    ]
    exact_total_script = CScript([
        OP_DROP,
        OP_LSHIFT,
        OP_TOALTSTACK,
        OP_LSHIFT,
        OP_FROMALTSTACK,
        OP_DROP,
        OP_DROP,
        OP_1,
    ])
    over_total_script = CScript([
        OP_DROP,
        OP_LSHIFT,
        OP_TOALTSTACK,
        OP_LSHIFT,
        OP_1,
        OP_DROP,
        OP_DROP,
        OP_1,
    ])
    assert_equal(len(exact_total_script), len(over_total_script))
    tap = taproot_construct(pubs[0], [
        ("total_exact", exact_total_script, LEAF_VERSION_TAPSCRIPT_V2),
        ("total_over", over_total_script, LEAF_VERSION_TAPSCRIPT_V2),
    ])
    add_spender(
        spenders,
        "v2/runtime_total_stack_exact_limit",
        tap=tap,
        leaf="total_exact",
        inputs=exact_total_inputs,
        failure={"leaf": "total_over"},
        **ERR_TOTAL_STACK_SIZE,
    )

    add_spender_for_script(
        spenders,
        pubs[0],
        "v2/runtime_stack_element_exact_limit",
        CScript([OP_DROP, OP_LSHIFT]),
        inputs=[b"\x01", v2_num((MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE - 1) * 8), b"p" * 1000],
        failure_inputs=[b"\x01", v2_num(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE * 8), b"p" * 1000],
        failure_err=ERR_STACK_ELEMENT_SIZE,
    )

    # Non-empty signature opcodes spend from the same varops budget in v2,
    # independent of the older BIP342 validation-weight-left accounting.
    tap = taproot_construct(pubs[0], [
        ("sig_budget_ok", CScript([OP_1]), LEAF_VERSION_TAPSCRIPT_V2),
        ("sig_budget_fail", repeated_nonempty_unknown_pubkey_checksig_script(pubs[3], 250), LEAF_VERSION_TAPSCRIPT_V2),
    ])
    add_spender(
        spenders,
        "v2/checksig_varops_budget",
        tap=tap,
        leaf="sig_budget_ok",
        failure={"leaf": "sig_budget_fail"},
        **ERR_VAROP_COUNT,
    )

    return spenders


def add_spender_for_script(
    spenders,
    internal_pubkey,
    comment,
    script,
    *,
    inputs,
    failure_inputs,
    failure_err=ERR_EVAL_FALSE,
):
    tap = taproot_construct(internal_pubkey, [("leaf", script, LEAF_VERSION_TAPSCRIPT_V2)])
    add_spender(
        spenders,
        comment,
        tap=tap,
        leaf="leaf",
        inputs=inputs,
        failure={"inputs": failure_inputs},
        **failure_err,
    )


class TapScriptV2Test(TaprootTest):
    def set_test_params(self):
        super().set_test_params()
        self.extra_args = [["-vbparams=script_restoration:0:3999999999"]]

    def run_test(self):
        random.seed(441)
        self.nodesigner = NodeSigner(self.nodes[0])

        self.generatetoaddress(
            self.nodes[0],
            COINBASE_MATURITY + 1,
            self.nodesigner.getnewaddress(address_type="bech32")[2],
        )

        self.log.info("Tapscript v2 pre-activation unknown leaf test")
        self.test_tapscript_v2_leaf_before_activation()

        self.log.info("Tapscript v2 activation rollback/reapply test")
        self.test_script_restoration_activation_rollback_reapply()

        self.log.info("Tapscript v2 spender tests")
        self.test_spenders(self.nodes[0], tapscript_v2_spenders(), input_counts=[1, 2, 3])

        self.log.info("Tapscript v2 locktime and sequence Val64 tests")
        self.test_locktime_sequence_val64()

        self.log.info("Tapscript v2 transaction-wide varops budget test")
        self.test_transaction_wide_varops_budget()

        self.log.info("Tapscript v2 final success varops budget test")
        self.test_final_success_varops_budget()

        self.log.info("Tapscript v2 standard transaction weight policy test")
        self.test_standard_tx_weight_policy()

        self.log.info("Tapscript v2 upgrade-semantics policy tests")
        self.test_upgrade_semantics_policy()

    def test_tapscript_v2_leaf_before_activation(self):
        """Before SCRIPT_RESTORATION activation, 0xc2 has unknown-leaf consensus semantics."""
        node = self.nodes[0]
        host_pubkey, _host_spk, _host_addr = self.nodesigner.getnewaddress(address_type="bech32")

        cases = [
            ("false", CScript([OP_0]), []),
            ("return", CScript([OP_RETURN]), []),
            ("malformed_push", CScript([OP_PUSHDATA1]), []),
            ("oversized_initial_stack", CScript([OP_0]), [b""] * (MAX_TAPSCRIPT_V2_STACK_SIZE + 1)),
        ]
        funded = [
            (name, self.fund_tapscript_v2(script, amount=50_000_000), witness_elements)
            for name, script, witness_elements in cases
        ]
        assert not self.script_restoration_info()["active"]

        spending_txs = []
        for name, utxo, witness_elements in funded:
            spending_tx = self.spending_tx(utxo, witness_elements=witness_elements)
            spending_txs.append(spending_tx)

            result = node.testmempoolaccept([spending_tx.serialize().hex()], maxfeerate=0)[0]
            assert not result["allowed"], f"{name}: {result}"
            assert "SCRIPT_RESTORATION" in result.get("reject-reason", ""), f"{name}: {result}"
            assert_raises_rpc_error(-26, None, node.sendrawtransaction, spending_tx.serialize().hex(), 0)

        self.init_blockinfo(node)
        self.block_submit(
            node,
            spending_txs,
            "Tapscript v2 leaves before SCRIPT_RESTORATION activation",
            err_msg=None,
            cb_pubkey=host_pubkey,
            fees=10_000 * len(spending_txs),
            sigops_weight=MAX_BLOCK_SIGOPS_WEIGHT,
            witness=True,
            accept=True,
        )

    def script_restoration_info(self):
        return self.nodes[0].getdeploymentinfo()["deployments"]["script_restoration"]

    def script_restoration_state(self):
        return self.script_restoration_info()["bip9"]

    def advance_script_restoration_to_started(self):
        node = self.nodes[0]

        while self.script_restoration_state()["status"] != "started":
            status = self.script_restoration_state()["status"]
            assert_equal(status, "defined")
            blocks_to_next_period = VERSIONBITS_PERIOD - (node.getblockcount() % VERSIONBITS_PERIOD)
            if blocks_to_next_period == 0:
                blocks_to_next_period = VERSIONBITS_PERIOD
            self.generate(node, blocks_to_next_period)

    def signal_script_restoration_activation(self):
        node = self.nodes[0]
        return self.generate(node, 1)[0]

    def submit_spend_block(self, spending_tx, comment, *, err_msg=None, accept=True, fee=10_000):
        node = self.nodes[0]
        host_pubkey, _host_spk, _host_addr = self.nodesigner.getnewaddress(address_type="bech32")

        self.init_blockinfo(node)
        self.block_submit(
            node,
            [spending_tx],
            comment,
            err_msg,
            host_pubkey,
            fee,
            MAX_BLOCK_SIGOPS_WEIGHT,
            True,
            accept,
        )
        if accept:
            return node.getbestblockhash()
        return None

    def test_script_restoration_activation_rollback_reapply(self):
        node = self.nodes[0]

        original_pre_active_utxo = self.fund_tapscript_v2(CScript([OP_0]), amount=50_000_000)
        active_invalid_utxo = self.fund_tapscript_v2(CScript([OP_0]), amount=50_000_000)
        active_valid_utxo = self.fund_tapscript_v2(CScript([OP_1]), amount=50_000_000)
        alternate_pre_active_utxo = self.fund_tapscript_v2(CScript([OP_0]), amount=50_000_000)
        reapplied_invalid_utxo = self.fund_tapscript_v2(CScript([OP_0]), amount=50_000_000)

        self.advance_script_restoration_to_started()
        assert_equal(self.script_restoration_state()["status"], "started")
        started_height = node.getblockcount()
        period = self.script_restoration_state()["statistics"]["period"]

        self.signal_script_restoration_activation()
        target_parent_height = started_height + 2 * period - 2
        blocks_to_target_parent = target_parent_height - node.getblockcount()
        assert blocks_to_target_parent >= 0
        self.generate(node, blocks_to_target_parent)
        assert_equal(node.getblockcount(), target_parent_height)
        assert_equal(self.script_restoration_state()["status"], "locked_in")
        assert_equal(self.script_restoration_state()["status_next"], "locked_in")

        original_pre_active_tx = self.spending_tx(original_pre_active_utxo)
        original_pre_active_hash = self.submit_spend_block(
            original_pre_active_tx,
            "Tapscript v2 0xc2 OP_0 spend in last pre-active block",
        )
        last_pre_active_height = node.getblockcount()
        assert_equal(last_pre_active_height, started_height + 2 * period - 1)
        assert_equal(self.script_restoration_state()["status"], "locked_in")
        assert_equal(self.script_restoration_state()["status_next"], "active")

        active_invalid_tx = self.spending_tx(active_invalid_utxo)
        self.submit_spend_block(
            active_invalid_tx,
            "Tapscript v2 0xc2 OP_0 spend in first active block",
            err_msg=ERR_EVAL_FALSE["err_msg"],
            accept=False,
        )

        active_valid_tx = self.spending_tx(active_valid_utxo)
        active_hash = self.submit_spend_block(
            active_valid_tx,
            "Tapscript v2 0xc2 OP_1 spend in first active block",
        )
        assert_equal(node.getblockcount(), last_pre_active_height + 1)
        assert_equal(self.script_restoration_state()["status"], "active")

        node.invalidateblock(original_pre_active_hash)
        assert_equal(node.getblockcount(), last_pre_active_height - 1)
        assert_equal(self.script_restoration_state()["status"], "locked_in")
        assert_equal(self.script_restoration_state()["status_next"], "locked_in")
        assert not self.script_restoration_info()["active"]

        alternate_pre_active_tx = self.spending_tx(alternate_pre_active_utxo)
        alternate_pre_active_hash = self.submit_spend_block(
            alternate_pre_active_tx,
            "Tapscript v2 0xc2 OP_0 spend in alternate last pre-active block",
        )
        assert alternate_pre_active_hash != original_pre_active_hash
        assert_equal(node.getblockcount(), last_pre_active_height)
        assert_equal(self.script_restoration_state()["status"], "locked_in")
        assert_equal(self.script_restoration_state()["status_next"], "active")

        node.reconsiderblock(original_pre_active_hash)
        node.reconsiderblock(active_hash)
        self.wait_until(lambda: node.getbestblockhash() == active_hash)
        assert_equal(self.script_restoration_state()["status"], "active")

        reapplied_invalid_tx = self.spending_tx(reapplied_invalid_utxo)
        self.submit_spend_block(
            reapplied_invalid_tx,
            "Tapscript v2 0xc2 OP_0 spend after activation branch reapply",
            err_msg=ERR_EVAL_FALSE["err_msg"],
            accept=False,
        )

    def fund_spenders(self, spenders, amount=10_000_000):
        node = self.nodes[0]
        host_pubkey, host_spk, _host_addr = self.nodesigner.getnewaddress(address_type="bech32")

        fund_tx = CTransaction()
        unspents = self.nodesigner.listunspent()
        unspents.sort(key=lambda x: int(x["amount"] * 100_000_000), reverse=True)
        balance = 0
        for unspent in unspents[:20]:
            balance += int(unspent["amount"] * 100_000_000)
            fund_tx.vin.append(CTxIn(COutPoint(int(unspent["txid"], 16), int(unspent["vout"])), CScript()))

        for spender in spenders:
            fund_tx.vout.append(CTxOut(amount, spender.script))
            balance -= amount

        assert balance > 100_000
        fund_tx.vout.append(CTxOut(balance - 10_000, host_spk))
        fund_tx = self.nodesigner.signrawtransaction(fund_tx.serialize().hex(), unspents)
        fund_tx = tx_from_hex(fund_tx["hex"])
        self.init_blockinfo(node)
        self.block_submit(
            node,
            [fund_tx],
            "Tapscript v2 funding tx",
            None,
            host_pubkey,
            10_000,
            MAX_BLOCK_SIGOPS_WEIGHT,
            True,
            True,
        )

        return [
            (COutPoint(fund_tx.txid_int, i), fund_tx.vout[i], spender)
            for i, spender in enumerate(spenders)
        ], host_spk, host_pubkey

    def fund_tapscript_v2(self, script, *, internal_key=None, amount=10_000_000, leaves=None, leaf_name="script"):
        node = self.nodes[0]
        if internal_key is None:
            internal_key = generate_privkey()
        internal_pubkey = compute_xonly_pubkey(internal_key)[0]

        if leaves is None:
            leaves = [(leaf_name, script, LEAF_VERSION_TAPSCRIPT_V2)]
        tap = taproot_construct(internal_pubkey, leaves)

        unspents = self.nodesigner.listunspent()
        unspents.sort(key=lambda x: int(x["amount"] * COIN), reverse=True)
        selected = unspents[0]
        selected_value = int(selected["amount"] * COIN)
        fee = 10_000
        assert selected_value > amount + fee

        _change_pubkey, change_spk, _change_addr = self.nodesigner.getnewaddress(address_type="bech32")
        funding_tx = CTransaction()
        funding_tx.vin = [CTxIn(COutPoint(int(selected["txid"], 16), int(selected["vout"])))]
        funding_tx.vout = [
            CTxOut(amount, tap.scriptPubKey),
            CTxOut(selected_value - amount - fee, change_spk),
        ]
        signed = self.nodesigner.signrawtransaction(funding_tx.serialize().hex(), [selected])
        funding_tx = tx_from_hex(signed["hex"])
        funding_txid = node.sendrawtransaction(funding_tx.serialize().hex(), 0)
        self.generate(node, 1)
        return {
            "amount": amount,
            "internal_key": internal_key,
            "leaf": leaf_name,
            "script": tap.leaves[leaf_name].script,
            "tap": tap,
            "txid": funding_txid,
            "vout": 0,
        }

    def control_block(self, utxo):
        tap = utxo["tap"]
        leaf_info = tap.leaves[utxo["leaf"]]
        return bytes([leaf_info.version + tap.negflag]) + tap.internal_pubkey + leaf_info.merklebranch

    def spending_tx(self, utxo, *, witness_elements=(), fee=10_000, nlocktime=0, nsequence=SEQUENCE_FINAL):
        _output_pubkey, output_spk, _output_addr = self.nodesigner.getnewaddress(address_type="bech32")

        spending_tx = CTransaction()
        spending_tx.version = 2
        spending_tx.nLockTime = nlocktime
        spending_tx.vin = [CTxIn(COutPoint(int(utxo["txid"], 16), utxo["vout"]), CScript(), nsequence)]
        spending_tx.vout = [CTxOut(utxo["amount"] - fee, output_spk)]
        spending_tx.wit.vtxinwit = [CTxInWitness()]
        spending_tx.wit.vtxinwit[0].scriptWitness.stack = [
            *witness_elements,
            bytes(utxo["script"]),
            self.control_block(utxo),
        ]
        return spending_tx

    def submit_and_mine(self, spending_tx, comment):
        node = self.nodes[0]
        result = node.testmempoolaccept([spending_tx.serialize().hex()], maxfeerate=0)[0]
        assert result["allowed"], f"{comment}: {result.get('reject-reason', 'unknown reject reason')}"
        node.sendrawtransaction(spending_tx.serialize().hex(), 0)
        self.generate(node, 1)

    def submit_nonstandard_and_mine(self, spending_tx, comment, fee=10_000):
        node = self.nodes[0]
        host_pubkey, _host_spk, _host_addr = self.nodesigner.getnewaddress(address_type="bech32")

        result = node.testmempoolaccept([spending_tx.serialize().hex()], maxfeerate=0)[0]
        assert not result["allowed"], f"{comment}: unexpectedly accepted into mempool"
        assert "OP_SUCCESS" in result.get("reject-reason", ""), result

        self.init_blockinfo(node)
        self.block_submit(
            node,
            [spending_tx],
            comment,
            None,
            host_pubkey,
            fee,
            MAX_BLOCK_SIGOPS_WEIGHT,
            True,
            True,
        )

    def test_standard_tx_weight_policy(self):
        node = self.nodes[0]
        fee = 200_000
        large_witness_script = CScript([OP_DROP, OP_1])

        def tx_with_padding(utxo, padding_len):
            return self.spending_tx(utxo, witness_elements=[b"\x00" * padding_len], fee=fee)

        def tx_at_weight_boundary(utxo, weight_limit, *, over):
            def weight_at(padding_len):
                return tx_with_padding(utxo, padding_len).get_weight()

            high = weight_limit
            while weight_at(high) <= weight_limit:
                high *= 2

            low = 0
            selected_padding_len = high if over else 0
            while low <= high:
                mid = (low + high) // 2
                weight = weight_at(mid)
                if weight > weight_limit:
                    if over:
                        selected_padding_len = mid
                    high = mid - 1
                else:
                    if not over:
                        selected_padding_len = mid
                    low = mid + 1

            tx = tx_with_padding(utxo, selected_padding_len)
            padding = tx.wit.vtxinwit[0].scriptWitness.stack[0]
            assert_equal(len(padding), selected_padding_len)
            assert_greater_than(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, len(padding))

            if over:
                assert_greater_than(tx.get_weight(), weight_limit)
                assert weight_at(selected_padding_len - 1) <= weight_limit
            else:
                assert tx.get_weight() <= weight_limit
                assert_greater_than(weight_at(selected_padding_len + 1), weight_limit)
            return tx

        standard_utxo = self.fund_tapscript_v2(large_witness_script)
        standard_tx = tx_at_weight_boundary(standard_utxo, MAX_STANDARD_TX_WEIGHT, over=False)
        assert standard_tx.get_weight() <= MAX_STANDARD_TX_WEIGHT
        self.submit_and_mine(standard_tx, "v2 large witness item at standard tx weight")

        oversized_utxo = self.fund_tapscript_v2(large_witness_script)
        oversized_tx = tx_at_weight_boundary(oversized_utxo, MAX_STANDARD_TX_WEIGHT, over=True)
        assert_greater_than(oversized_tx.get_weight(), MAX_STANDARD_TX_WEIGHT)
        assert_greater_than(MAX_BLOCK_WEIGHT, oversized_tx.get_weight())

        result = node.testmempoolaccept([oversized_tx.serialize().hex()], maxfeerate=0)[0]
        assert not result["allowed"], result
        assert_equal(result["reject-reason"], "tx-size")

        self.submit_spend_block(
            oversized_tx,
            "v2 large witness item above standard tx weight",
            fee=fee,
        )

    def test_upgrade_semantics_policy(self):
        node = self.nodes[0]

        # Future pubkey encodings remain policy-discouraged but consensus-valid
        # through BIP342-style unknown-pubkey semantics.
        future_pubkey = b"\x01" + compute_xonly_pubkey(generate_privkey())[0]
        future_pubkey_script = CScript([future_pubkey, OP_CHECKSIG])
        utxo = self.fund_tapscript_v2(future_pubkey_script)
        spending_tx = self.spending_tx(utxo)
        spending_tx.wit.vtxinwit[0].scriptWitness.stack.insert(0, b"\x01" * 64)
        result = node.testmempoolaccept([spending_tx.serialize().hex()], maxfeerate=0)[0]
        assert not result["allowed"], result
        assert "Public key version reserved for soft-fork upgrades" in result.get("reject-reason", ""), result
        self.submit_spend_block(
            spending_tx,
            "v2 future pubkey encoding remains upgradable",
        )

        # Inquisition assigns semantics to 0xcb and 0xcc. On Core master they
        # remain OP_SUCCESS code points, including in tapscript v2.
        for name, success_op in (("0xcb", CScriptOp(0xcb)), ("0xcc", CScriptOp(0xcc))):
            utxo = self.fund_tapscript_v2(CScript([success_op, OP_RETURN]))
            spending_tx = self.spending_tx(utxo)
            self.submit_nonstandard_and_mine(spending_tx, f"{name} as v2 OP_SUCCESS leaf")

    def test_locktime_sequence_val64(self):
        node = self.nodes[0]
        sec = generate_privkey()
        pub = compute_xonly_pubkey(sec)[0]

        def make_lock_spender(name, script, inputs):
            tap = taproot_construct(pub, [(name, script, LEAF_VERSION_TAPSCRIPT_V2)])
            return make_spender(name, tap=tap, leaf=name, inputs=inputs)

        spenders = [
            make_lock_spender(
                "v2/cltv_five_byte_zero",
                CScript([OP_CHECKLOCKTIMEVERIFY, OP_DROP, OP_1]),
                [b"\x00" * 5],
            ),
            make_lock_spender(
                "v2/cltv_too_large",
                CScript([OP_CHECKLOCKTIMEVERIFY, OP_DROP, OP_1]),
                [b"\x00\x00\x00\x00\x01"],
            ),
            make_lock_spender("v2/csv_five_byte_zero", CScript([OP_CHECKSEQUENCEVERIFY, OP_DROP, OP_1]), [b"\x00" * 5]),
            make_lock_spender(
                "v2/csv_unsatisfied_wide",
                CScript([OP_CHECKSEQUENCEVERIFY, OP_DROP, OP_1]),
                [b"\x02\x00\x00\x00\x00"],
            ),
            make_lock_spender(
                "v2/csv_uint32_max_disable",
                CScript([OP_CHECKSEQUENCEVERIFY, OP_DROP, OP_1]),
                [v2_num((1 << 32) - 1)],
            ),
            make_lock_spender(
                "v2/csv_overflow_disable",
                CScript([OP_CHECKSEQUENCEVERIFY, OP_DROP, OP_1]),
                [v2_num((1 << 32) | (1 << 31))],
            ),
        ]
        funded, host_spk, host_pubkey = self.fund_spenders(spenders)

        def spend_one(index, *, nlocktime, nsequence, accept, err_msg=None):
            outpoint, output, spender = funded[index]
            fee = 10_000
            spend_tx = CTransaction()
            spend_tx.version = 2
            spend_tx.nLockTime = nlocktime
            spend_tx.vin = [CTxIn(outpoint, CScript(), nsequence)]
            spend_tx.vout = [CTxOut(output.nValue - fee, host_spk)]
            spend_tx.wit.vtxinwit = [CTxInWitness()]
            script_sig, witness_stack = spender.sat_function(spend_tx, 0, [output], True)
            spend_tx.vin[0].scriptSig = script_sig
            spend_tx.wit.vtxinwit[0].scriptWitness.stack = witness_stack
            if accept:
                node.sendrawtransaction(spend_tx.serialize().hex(), 0)
                assert node.getmempoolentry(spend_tx.txid_hex) is not None
            else:
                assert_raises_rpc_error(-26, None, node.sendrawtransaction, spend_tx.serialize().hex(), 0)

            self.block_submit(
                node,
                [spend_tx],
                spender.comment,
                witness=True,
                accept=accept,
                cb_pubkey=host_pubkey,
                fees=fee,
                sigops_weight=MAX_BLOCK_SIGOPS_WEIGHT,
                err_msg=err_msg,
            )

        spend_one(0, nlocktime=0, nsequence=0, accept=True)
        spend_one(1, nlocktime=0, nsequence=0, accept=False, **ERR_LOCKTIME)
        spend_one(2, nlocktime=0, nsequence=0, accept=True)
        spend_one(3, nlocktime=0, nsequence=1, accept=False, **ERR_LOCKTIME)
        spend_one(4, nlocktime=0, nsequence=0, accept=True)
        spend_one(5, nlocktime=0, nsequence=0, accept=False, **ERR_LOCKTIME)

    def test_transaction_wide_varops_budget(self):
        node = self.nodes[0]
        sec = generate_privkey()
        pub = compute_xonly_pubkey(sec)[0]

        operand_size = 12_000
        padding_size = 10
        operand = b"\xff" * operand_size
        padding = b"\x00" * padding_size
        expensive_script = CScript([OP_MUL, OP_DROP, OP_DROP, OP_1])
        cheap_script = CScript([OP_DROP, OP_DROP, OP_DROP, OP_1])
        threshold_script = CScript([OP_DROP, OP_CAT, OP_DROP, OP_1])
        assert_equal(len(expensive_script), len(cheap_script))
        assert_equal(len(expensive_script), len(threshold_script))

        def make_budget_spender(name, script):
            tap = taproot_construct(pub, [(name, script, LEAF_VERSION_TAPSCRIPT_V2)])
            return make_spender(name, tap=tap, leaf=name, inputs=[padding, operand, operand])

        spenders = [
            make_budget_spender("v2/shared_budget_accepted_expensive", expensive_script),
            make_budget_spender("v2/shared_budget_accepted_cheap", cheap_script),
            make_budget_spender("v2/shared_budget_rejected_expensive", expensive_script),
            make_budget_spender("v2/shared_budget_rejected_threshold", threshold_script),
        ]
        funded, host_spk, host_pubkey = self.fund_spenders(spenders)

        def make_spend_tx(funded_inputs):
            spend_tx = CTransaction()
            spend_tx.version = 2
            spend_tx.vin = [CTxIn(outpoint) for outpoint, _output, _spender in funded_inputs]
            output_value = sum(output.nValue for _outpoint, output, _spender in funded_inputs) - 50_000
            spend_tx.vout = [CTxOut(output_value, host_spk)]
            spend_tx.wit.vtxinwit = [CTxInWitness() for _ in funded_inputs]

            spent_outputs = [output for _outpoint, output, _spender in funded_inputs]
            for index, (_outpoint, _output, spender) in enumerate(funded_inputs):
                script_sig, witness_stack = spender.sat_function(spend_tx, index, spent_outputs, True)
                spend_tx.vin[index].scriptSig = script_sig
                spend_tx.wit.vtxinwit[index].scriptWitness.stack = witness_stack
            return spend_tx

        accepted_funded = funded[:2]
        rejected_funded = funded[2:]
        accepted_tx = make_spend_tx(accepted_funded)
        rejected_tx = make_spend_tx(rejected_funded)
        assert_equal(accepted_tx.get_weight(), rejected_tx.get_weight())

        final_check_cost = comparingzero_cost(1)
        expensive_input_cost = mul_cost(operand_size, operand_size) + final_check_cost
        cheap_input_cost = final_check_cost
        threshold_input_cost = (padding_size + operand_size) * VAROPS_COST_COPYING + final_check_cost
        accepted_cost = expensive_input_cost + cheap_input_cost
        rejected_cost = expensive_input_cost + threshold_input_cost
        tx_weight = accepted_tx.get_weight()
        tx_budget = tx_weight * VAROPS_BUDGET_PER_WEIGHT

        assert expensive_input_cost < tx_budget
        assert expensive_input_cost > tx_budget // 2
        assert accepted_cost <= tx_budget < rejected_cost
        assert accepted_cost > tx_weight * (VAROPS_BUDGET_PER_WEIGHT - 1)
        assert rejected_cost <= tx_weight * (VAROPS_BUDGET_PER_WEIGHT + 1)

        result = node.testmempoolaccept([accepted_tx.serialize().hex()], maxfeerate=0)[0]
        assert result["allowed"], result
        node.sendrawtransaction(accepted_tx.serialize().hex(), 0)
        assert node.getmempoolentry(accepted_tx.txid_hex) is not None
        self.block_submit(
            node,
            [accepted_tx],
            "two v2 inputs share the exact transaction-wide varops budget",
            err_msg=None,
            witness=True,
            accept=True,
            cb_pubkey=host_pubkey,
            fees=50_000,
            sigops_weight=MAX_BLOCK_SIGOPS_WEIGHT,
        )

        finalized_psbt = PSBT(
            g=PSBTMap({PSBT_GLOBAL_UNSIGNED_TX: rejected_tx.serialize_without_witness()}),
            i=[
                PSBTMap({
                    PSBT_IN_WITNESS_UTXO: output.serialize(),
                    PSBT_IN_FINAL_SCRIPTWITNESS: rejected_tx.wit.vtxinwit[index].serialize(),
                })
                for index, (_outpoint, output, _spender) in enumerate(rejected_funded)
            ],
            o=[PSBTMap() for _ in rejected_tx.vout],
        ).to_base64()

        analysis = node.analyzepsbt(finalized_psbt)
        assert_equal(analysis["next"], "creator")
        assert_equal(analysis["error"], "PSBT is not valid. Finalized transaction exceeds the varops budget")

        processed = node.descriptorprocesspsbt(finalized_psbt, [])
        assert_equal(processed["complete"], False)
        assert "hex" not in processed

        assert_raises_rpc_error(-26, None, node.sendrawtransaction, rejected_tx.serialize().hex(), 0)
        self.block_submit(
            node,
            [rejected_tx],
            "two v2 inputs exceed the exact transaction-wide varops budget",
            witness=True,
            accept=False,
            cb_pubkey=host_pubkey,
            fees=50_000,
            sigops_weight=MAX_BLOCK_SIGOPS_WEIGHT,
            err_msg=ERR_VAROP_COUNT["err_msg"],
        )

    def test_final_success_varops_budget(self):
        node = self.nodes[0]
        sec = generate_privkey()
        pub = compute_xonly_pubkey(sec)[0]

        final_size = MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE
        final_shift_bits = (final_size - 1) * 8
        final_shift = v2_num(final_shift_bits)
        final_check_cost = comparingzero_cost(final_size)
        final_value = b"\x01"
        costly_script = CScript([OP_MUL, OP_DROP, OP_LSHIFT])
        _host_pubkey, host_spk, _host_addr = self.nodesigner.getnewaddress(address_type="bech32")

        def make_costly_spender(operand_size):
            operand = b"\xff" * operand_size
            tap = taproot_construct(pub, [("costly", costly_script, LEAF_VERSION_TAPSCRIPT_V2)])
            return make_spender(
                f"v2/final_success_budget_{operand_size}",
                tap=tap,
                leaf="costly",
                inputs=[final_value, final_shift, operand, operand],
            )

        def make_spend_tx(outpoint, output, spender, fee):
            spend_tx = CTransaction()
            spend_tx.version = 2
            spend_tx.vin = [CTxIn(outpoint)]
            spend_tx.vout = [CTxOut(output.nValue - fee, host_spk)]
            spend_tx.wit.vtxinwit = [CTxInWitness()]
            script_sig, witness_stack = spender.sat_function(spend_tx, 0, [output], True)
            spend_tx.vin[0].scriptSig = script_sig
            spend_tx.wit.vtxinwit[0].scriptWitness.stack = witness_stack
            return spend_tx

        dummy_output = CTxOut(10_000_000, host_spk)
        selected_operand_size = None
        for operand_size in range(4_500, 6_500):
            spender = make_costly_spender(operand_size)
            spend_tx = make_spend_tx(COutPoint(0, 0), dummy_output, spender, fee=50_000)
            script_cost = mul_cost(operand_size, operand_size) + upshift_cost(len(final_value), final_shift_bits)
            tx_budget = spend_tx.get_weight() * VAROPS_BUDGET_PER_WEIGHT
            if script_cost < tx_budget < script_cost + final_check_cost:
                selected_operand_size = operand_size
                break
        assert selected_operand_size is not None

        spender = make_costly_spender(selected_operand_size)
        funded, host_spk, host_pubkey = self.fund_spenders([spender])
        outpoint, output, funded_spender = funded[0]
        spend_tx = make_spend_tx(outpoint, output, funded_spender, fee=50_000)
        script_cost = mul_cost(selected_operand_size, selected_operand_size) + upshift_cost(
            len(final_value),
            final_shift_bits,
        )
        tx_budget = spend_tx.get_weight() * VAROPS_BUDGET_PER_WEIGHT
        assert script_cost < tx_budget < script_cost + final_check_cost

        result = node.testmempoolaccept([spend_tx.serialize().hex()], maxfeerate=0)[0]
        assert not result["allowed"], result
        assert ERR_VAROP_COUNT["err_msg"] in result.get("reject-reason", ""), result
        assert_raises_rpc_error(-26, None, node.sendrawtransaction, spend_tx.serialize().hex(), 0)

        self.block_submit(
            node,
            [spend_tx],
            "v2 final success scan overspends varops budget",
            witness=True,
            accept=False,
            cb_pubkey=host_pubkey,
            fees=50_000,
            sigops_weight=MAX_BLOCK_SIGOPS_WEIGHT,
            err_msg=ERR_VAROP_COUNT["err_msg"],
        )


if __name__ == "__main__":
    TapScriptV2Test(__file__).main()
