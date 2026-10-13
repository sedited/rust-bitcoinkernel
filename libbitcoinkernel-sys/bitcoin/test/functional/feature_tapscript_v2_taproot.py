#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Replay Taproot script-path coverage with Tapscript v2 leaves."""

import random

import feature_taproot as taproot

from test_framework.blocktools import COINBASE_MATURITY
from test_framework.script import (
    CScript,
    LEAF_VERSION_TAPSCRIPT,
    LEAF_VERSION_TAPSCRIPT_V2,
    OP_1,
    OP_CHECKSIG,
    OP_CHECKSIGVERIFY,
)
from test_framework.util import assert_equal
from test_framework.wallet import NodeSigner


_ORIGINAL_TAPROOT_CONSTRUCT = taproot.taproot_construct
VERSIONBITS_PERIOD = 144


def _script_tree_to_v2(scripts):
    if scripts is None or callable(scripts):
        return scripts

    if isinstance(scripts, tuple):
        if len(scripts) == 2:
            return (scripts[0], scripts[1], LEAF_VERSION_TAPSCRIPT_V2)
        if len(scripts) == 3 and scripts[2] == LEAF_VERSION_TAPSCRIPT:
            return (scripts[0], scripts[1], LEAF_VERSION_TAPSCRIPT_V2)
        return scripts

    if isinstance(scripts, list):
        return [_script_tree_to_v2(script) for script in scripts]

    return scripts


def taproot_construct_v2(pubkey, scripts=None, **kwargs):
    return _ORIGINAL_TAPROOT_CONSTRUCT(pubkey, _script_tree_to_v2(scripts), **kwargs)


def random_checksig_style_v2(pubkey):
    opcode = random.choice([OP_CHECKSIG, OP_CHECKSIGVERIFY])
    if opcode == OP_CHECKSIGVERIFY:
        return bytes(CScript([pubkey, opcode, OP_1]))
    return bytes(CScript([pubkey, opcode]))


def is_tapscript_v2_replay_spender(spender):
    comment = spender.comment

    # Replay only cases that exercise a script path converted to 0xc2. Key-path,
    # legacy, witness-v0, sighash-cache, and unrelated unknown-leaf cases are
    # already covered by feature_taproot.py without involving Tapscript v2.
    if comment.startswith(("sig/", "legacy/", "compat/", "sighashcache/", "unkver/")):
        return False
    if "keypath" in comment or comment == "sighash/purepk":
        return False

    # These are not v2 leaf replay coverage: they validate future leaf versions
    # and OP_SUCCESSx behavior, whose opcode set is deliberately different in v2.
    if comment.startswith(("opsuccess/", "alwaysvalid/")):
        return False

    # The v2 semantic test covers the changed element, stack, numeric, and
    # signature-budget rules directly. This file keeps the inherited Taproot
    # matrix focused on behavior that should remain equivalent under 0xc2.
    changed_v2_semantics = {
        "sighash/leafver",
        "tapscript/inputmaxlimit",
        "tapscript/input81limit",
        "tapscript/checksigaddresults",
        "tapscript/checksigaddoversize",
        "tapscript/1000stack",
        "tapscript/1000inputs",
        "tapscript/pushmaxlimit",
        "tapscript/bigmulti",
    }
    if comment in changed_v2_semantics:
        return False
    if comment.startswith("tapscript/sigopsratio_"):
        return False
    if comment.startswith("tapscript/oldpk/"):
        return False
    if comment.startswith("apo/"):
        return False

    return True


def tapscript_v2_taproot_spenders():
    original_taproot_construct = taproot.taproot_construct
    original_random_checksig_style = taproot.random_checksig_style
    try:
        taproot.taproot_construct = taproot_construct_v2
        taproot.random_checksig_style = random_checksig_style_v2
        return [
            spender
            for spender in taproot.spenders_taproot_active()
            if is_tapscript_v2_replay_spender(spender)
        ]
    finally:
        taproot.taproot_construct = original_taproot_construct
        taproot.random_checksig_style = original_random_checksig_style


class TapScriptV2TaprootTest(taproot.TaprootTest):
    def set_test_params(self):
        super().set_test_params()
        self.extra_args = [["-vbparams=script_restoration:0:3999999999"]]

    def run_test(self):
        random.seed(442)
        self.nodesigner = NodeSigner(self.nodes[0])

        self.generatetoaddress(
            self.nodes[0],
            COINBASE_MATURITY + 1,
            self.nodesigner.getnewaddress(address_type="bech32")[2],
        )

        self.log.info("Activating SCRIPT_RESTORATION")
        self.activate_script_restoration()

        self.log.info("Tapscript v2 Taproot replay tests")
        self.test_spenders(self.nodes[0], tapscript_v2_taproot_spenders(), input_counts=[1, 2, 2, 2, 2, 3])

    def activate_script_restoration(self):
        node = self.nodes[0]

        deployment = node.getdeploymentinfo()["deployments"]["script_restoration"]["bip9"]
        while deployment["status"] != "started":
            assert_equal(deployment["status"], "defined")
            blocks_to_next_period = VERSIONBITS_PERIOD - (node.getblockcount() % VERSIONBITS_PERIOD)
            if blocks_to_next_period == 0:
                blocks_to_next_period = VERSIONBITS_PERIOD
            self.generate(node, blocks_to_next_period)
            deployment = node.getdeploymentinfo()["deployments"]["script_restoration"]["bip9"]

        period = deployment["statistics"]["period"]
        self.generate(node, 2 * period)
        assert_equal(node.getdeploymentinfo()["deployments"]["script_restoration"]["bip9"]["status"], "active")


if __name__ == "__main__":
    TapScriptV2TaprootTest(__file__).main()
