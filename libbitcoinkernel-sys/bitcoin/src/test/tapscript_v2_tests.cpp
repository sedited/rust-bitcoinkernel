// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <coins.h>
#include <consensus/validation.h>
#include <key.h>
#include <policy/policy.h>
#include <psbt.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/sign.h>
#include <script/signingprovider.h>
#include <script/solver.h>
#include <script/val64.h>
#include <script/valtype_stack.h>
#include <script/varops.h>
#include <test/util/tapscript_v2_test_utils.h>
#include <test/util/setup_common.h>
#include <util/translation.h>

#include <boost/test/unit_test.hpp>

#include <array>
#include <cstdint>
#include <map>
#include <optional>
#include <ranges>
#include <string>
#include <utility>
#include <vector>

using valtype = std::vector<unsigned char>;
using namespace test::tapscript_v2;

static valtype Bytes(std::string_view text)
{
    return valtype{text.begin(), text.end()};
}

static valtype Bytes(std::initializer_list<unsigned char> bytes)
{
    return valtype{bytes};
}

static valtype Num(uint64_t value)
{
    Val64 num{value};
    return num.MoveToValtype();
}

static valtype LargerThanU64()
{
    return Bytes({0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01});
}

static uint64_t FinalSuccessCost(size_t size)
{
    return varops::CompareZeroCost(size);
}

class RecordingSignatureCreator final : public BaseSignatureCreator
{
public:
    mutable std::vector<SigVersion> schnorr_sigversions;

    const BaseSignatureChecker& Checker() const override { return DUMMY_CHECKER; }

    bool CreateSig(const SigningProvider&, std::vector<unsigned char>&, const CKeyID&, const CScript&, SigVersion) const override
    {
        return false;
    }

    bool CreateSchnorrSig(const SigningProvider&, std::vector<unsigned char>& sig, const XOnlyPubKey&, const uint256* leaf_hash, const uint256*, SigVersion sigversion) const override
    {
        if (leaf_hash == nullptr) return false;
        schnorr_sigversions.push_back(sigversion);
        sig.assign(64, 0x01);
        return true;
    }

    std::vector<uint8_t> CreateMuSig2Nonce(const SigningProvider&, const CPubKey&, const CPubKey&, const CPubKey&, const uint256*, const uint256*, SigVersion, const SignatureData&) const override
    {
        return {};
    }

    bool CreateMuSig2PartialSig(const SigningProvider&, uint256&, const CPubKey&, const CPubKey&, const CPubKey&, const uint256*, const std::vector<std::pair<uint256, bool>>&, SigVersion, const SignatureData&) const override
    {
        return false;
    }

    bool CreateMuSig2AggregateSig(const std::vector<CPubKey>&, std::vector<uint8_t>&, const CPubKey&, const CPubKey&, const uint256*, const std::vector<std::pair<uint256, bool>>&, SigVersion, const SignatureData&) const override
    {
        return false;
    }
};

static void CheckEval(const CScript& script, const Stack& initial_stack, const Stack& expected_stack, uint64_t budget)
{
    const EvalOutcome outcome{EvalTapscriptV2(script, initial_stack, budget)};
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
    BOOST_CHECK(outcome.ok);
    if (!outcome.ok) return;
    BOOST_CHECK_EQUAL(outcome.remaining_budget, 0);
    BOOST_CHECK_EQUAL(outcome.stack.size(), expected_stack.size());
    if (outcome.stack.size() != expected_stack.size()) return;
    for (size_t i{0}; i < expected_stack.size(); ++i) {
        BOOST_TEST_CONTEXT("stack index " << i) {
            BOOST_CHECK(outcome.stack[i] == expected_stack[i]);
        }
    }
}

static void CheckError(const CScript& script, const Stack& initial_stack, uint64_t budget, ScriptError expected_error)
{
    const EvalOutcome outcome{EvalTapscriptV2(script, initial_stack, budget)};
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, expected_error);
}

struct FinalizedTapscriptV2Spend {
    CTxOut spent_output;
    CMutableTransaction tx;
};

static FinalizedTapscriptV2Spend BuildFinalizedTapscriptV2Spend(const CScript& leaf_script, const Stack& initial_stack)
{
    CScript script_pub_key;
    CScriptWitness witness{BuildTapscriptV2Witness(leaf_script, initial_stack, script_pub_key)};

    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    tx.vin[0].scriptWitness = std::move(witness);
    tx.vout.emplace_back(500, CScript{} << OP_TRUE);

    return {CTxOut{1000, script_pub_key}, std::move(tx)};
}

static EvalOutcome VerifyTaprootLeafWithFlags(const CScript& leaf_script, const Stack& initial_stack, uint8_t leaf_version, script_verify_flags flags, uint64_t budget)
{
    TaprootBuilder builder;
    builder.Add(0, leaf_script, leaf_version, /*track=*/true);
    builder.Finalize(XOnlyPubKey::NUMS_H);

    CScriptWitness witness;
    witness.stack = initial_stack;
    const std::vector<unsigned char> serialized_script{leaf_script.begin(), leaf_script.end()};
    witness.stack.push_back(serialized_script);
    const auto control_blocks{builder.GetSpendData().scripts.at({serialized_script, leaf_version})};
    witness.stack.push_back(*control_blocks.begin());
    const CScript script_pub_key{GetScriptForDestination(builder.GetOutput())};

    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    varops::Budget varops_budget{budget};
    const bool ok{VerifyScript(CScript{}, script_pub_key, &witness, flags, BaseSignatureChecker{}, &error, varops_budget)};
    return EvalOutcome{ok, error, *varops_budget.Remaining(), {}};
}

static EvalOutcome VerifyTapscriptV2WithFlags(const CScript& leaf_script, const Stack& initial_stack, script_verify_flags flags, uint64_t budget)
{
    return VerifyTaprootLeafWithFlags(leaf_script, initial_stack, TAPROOT_LEAF_TAPSCRIPT_V2, flags, budget);
}

static EvalOutcome VerifyTapscriptV2(const CScript& leaf_script, const Stack& initial_stack, uint64_t budget)
{
    return VerifyTapscriptV2WithFlags(leaf_script, initial_stack, TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS, budget);
}

BOOST_FIXTURE_TEST_SUITE(tapscript_v2_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(op_success_classification)
{
    constexpr auto tapscript_op_success = std::to_array<uint8_t>({
        80, 98,
        126, 127, 128, 129,
        131, 132, 133, 134,
        137, 138,
        141, 142,
        149, 150, 151, 152, 153,
        187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199,
        200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212,
        213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225,
        226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238,
        239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251,
        252, 253, 254,
    });
    constexpr auto tapscript_v2_op_success = std::to_array<uint8_t>({
        79, 80, 98, 137, 138, 143, 144,
        187, 188, 189, 190, 191, 192, 193, 194, 195, 196, 197, 198, 199,
        200, 201, 202, 203, 204, 205, 206, 207, 208, 209, 210, 211, 212,
        213, 214, 215, 216, 217, 218, 219, 220, 221, 222, 223, 224, 225,
        226, 227, 228, 229, 230, 231, 232, 233, 234, 235, 236, 237, 238,
        239, 240, 241, 242, 243, 244, 245, 246, 247, 248, 249, 250, 251,
        252, 253, 254,
    });

    const auto check_all_opcodes = [](SigVersion sigversion, const auto& expected_op_success) {
        for (unsigned int opcode_value{0}; opcode_value <= 0xff; ++opcode_value) {
            const opcodetype opcode{static_cast<opcodetype>(opcode_value)};
            const bool expected{std::ranges::find(expected_op_success, static_cast<uint8_t>(opcode_value)) != expected_op_success.end()};
            BOOST_TEST_CONTEXT("opcode " << opcode_value) {
                BOOST_CHECK_EQUAL(IsOpSuccess(opcode, sigversion), expected);
            }
        }
    };

    check_all_opcodes(SigVersion::TAPSCRIPT, tapscript_op_success);
    check_all_opcodes(SigVersion::TAPSCRIPT_V2, tapscript_v2_op_success);
}

BOOST_AUTO_TEST_CASE(base_evalscript_rejects_tapscript_v2)
{
    Stack stack;
    CScript script;
    script << OP_TRUE;
    ScriptExecutionData execdata;
    ScriptError error{SCRIPT_ERR_OK};

    BOOST_CHECK(!::EvalScript(stack, script, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, SigVersion::TAPSCRIPT_V2, execdata, &error));
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_UNKNOWN_ERROR);
    BOOST_CHECK(stack.empty());
}

BOOST_AUTO_TEST_CASE(tapscript_v2_leaf_requires_script_restoration_flag)
{
    CScript false_script;
    false_script << OP_0;

    EvalOutcome outcome{VerifyTapscriptV2WithFlags(false_script, {}, TAPROOT_SCRIPT_VERIFY_FLAGS, 0)};
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);

    outcome = VerifyTapscriptV2WithFlags(false_script, {},
                                         TAPROOT_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION,
                                         0);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_TAPROOT_VERSION);

    outcome = VerifyTapscriptV2WithFlags(false_script, {},
                                         TAPROOT_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_DISCOURAGE_SCRIPT_RESTORATION,
                                         0);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_DISCOURAGE_SCRIPT_RESTORATION);

    outcome = VerifyTapscriptV2WithFlags(false_script, {},
                                         TAPROOT_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_SCRIPT_RESTORATION,
                                         0);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_EVAL_FALSE);

    CScript true_script;
    true_script << OP_1;
    outcome = VerifyTapscriptV2WithFlags(true_script, {}, TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS, FinalSuccessCost(1));
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(tapleaf_versions_isolate_restored_opcodes)
{
    const CScript restored_script{OneOp(OP_MUL)};

    EvalOutcome outcome{VerifyTaprootLeafWithFlags(restored_script, {}, TAPROOT_LEAF_TAPSCRIPT,
                                            TAPROOT_SCRIPT_VERIFY_FLAGS, 0)};
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);

    outcome = VerifyTaprootLeafWithFlags(restored_script, {}, TAPROOT_LEAF_TAPSCRIPT_V2,
                                         TAPROOT_SCRIPT_VERIFY_FLAGS, 0);
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);

    outcome = VerifyTaprootLeafWithFlags(restored_script, {}, TAPROOT_LEAF_TAPSCRIPT_V2,
                                         TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS, 0);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_INVALID_STACK_OPERATION);

    const CScript cat_script{OneOp(OP_CAT)};
    outcome = VerifyTaprootLeafWithFlags(cat_script, {}, TAPROOT_LEAF_TAPSCRIPT,
                                         TAPROOT_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS, 0);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_DISCOURAGE_OP_SUCCESS);

    outcome = VerifyTaprootLeafWithFlags(cat_script, {}, TAPROOT_LEAF_TAPSCRIPT,
                                         TAPROOT_SCRIPT_VERIFY_FLAGS, 0);
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(splice_opcodes_follow_bip441_byte_ranges)
{
    CheckEval(OneOp(OP_CAT), {Bytes("ab"), Bytes("cde")}, {Bytes("abcde")}, (2 + 3) * varops::COST_COPYING);

    CScript substr;
    substr << OP_SUBSTR;
    CheckEval(substr, {Bytes("abcdef"), Num(2), Num(3)}, {Bytes("cde")},
              varops::LengthConversionCost(1) + varops::LengthConversionCost(1) + 3 * varops::COST_COPYING);
    CheckError(substr, {Bytes("abcdef"), Num(2), Num(3)},
               varops::LengthConversionCost(1) + varops::LengthConversionCost(1) + 3 * varops::COST_COPYING - 1,
               SCRIPT_ERR_VAROP_COUNT);
    CheckEval(substr, {Bytes("abcdef"), Num(9), Num(3)}, {Bytes({})},
              varops::LengthConversionCost(1) + varops::LengthConversionCost(1));
    CheckEval(substr, {Bytes("abcdef"), Num(6), Num(3)}, {Bytes({})},
              varops::LengthConversionCost(1) + varops::LengthConversionCost(1));
    CheckEval(substr, {Bytes("abcdef"), Num(4), Num(9)}, {Bytes("ef")},
              varops::LengthConversionCost(1) + varops::LengthConversionCost(1) + 2 * varops::COST_COPYING);
    CheckEval(substr, {Bytes("abcdef"), Num(2), LargerThanU64()}, {Bytes("cdef")},
              varops::LengthConversionCost(1) + varops::LengthConversionCost(9) + 4 * varops::COST_COPYING);
    CheckEval(substr, {Bytes("abcdef"), LargerThanU64(), LargerThanU64()}, {Bytes({})},
              varops::LengthConversionCost(9) + varops::LengthConversionCost(9));

    CheckEval(OneOp(OP_LEFT), {Bytes("abcdef"), Num(0)}, {Bytes({})}, 0);
    CheckEval(OneOp(OP_LEFT), {Bytes("abcdef"), Num(2)}, {Bytes("ab")}, varops::LengthConversionCost(1));
    CheckError(OneOp(OP_LEFT), {Bytes("abcdef"), Num(2)}, varops::LengthConversionCost(1) - 1,
               SCRIPT_ERR_VAROP_COUNT);
    CheckEval(OneOp(OP_LEFT), {Bytes("abcdef"), Num(9)}, {Bytes("abcdef")}, varops::LengthConversionCost(1));
    CheckEval(OneOp(OP_LEFT), {Bytes("abcdef"), LargerThanU64()}, {Bytes("abcdef")}, varops::LengthConversionCost(9));
    CheckEval(OneOp(OP_LEFT), {Bytes("abcdef"), Bytes({0x02, 0x00, 0x00})}, {Bytes("ab")},
              varops::LengthConversionCost(3));

    CheckEval(OneOp(OP_RIGHT), {Bytes("abcdef"), Num(0)}, {Bytes({})}, 0);
    CheckEval(OneOp(OP_RIGHT), {Bytes("abcdef"), Num(2)}, {Bytes("ef")},
              varops::LengthConversionCost(1) + 2 * varops::COST_COPYING);
    CheckError(OneOp(OP_RIGHT), {Bytes("abcdef"), Num(2)},
               varops::LengthConversionCost(1) + 2 * varops::COST_COPYING - 1,
               SCRIPT_ERR_VAROP_COUNT);
    CheckEval(OneOp(OP_RIGHT), {Bytes("abcdef"), Num(9)}, {Bytes("abcdef")},
              varops::LengthConversionCost(1) + 6 * varops::COST_COPYING);
    CheckEval(OneOp(OP_RIGHT), {Bytes("abcdef"), LargerThanU64()}, {Bytes("abcdef")},
              varops::LengthConversionCost(9) + 6 * varops::COST_COPYING);
    CheckEval(OneOp(OP_RIGHT), {Bytes("abcdef"), Bytes({0x02, 0x00, 0x00})}, {Bytes("ef")},
              varops::LengthConversionCost(3) + 2 * varops::COST_COPYING);
}

BOOST_AUTO_TEST_CASE(length_operands_charge_encoded_width_even_when_value_is_zero)
{
    const valtype padded_zero{Bytes({0x00, 0x00, 0x00})};
    const uint64_t padded_zero_cost{varops::LengthConversionCost(padded_zero.size())};

    CheckEval(OneOp(OP_SUBSTR), {Bytes("abcdef"), padded_zero, padded_zero}, {Bytes({})},
              padded_zero_cost + padded_zero_cost);
    CheckError(OneOp(OP_SUBSTR), {Bytes("abcdef"), padded_zero, padded_zero},
               padded_zero_cost + padded_zero_cost - 1, SCRIPT_ERR_VAROP_COUNT);

    CheckEval(OneOp(OP_LEFT), {Bytes("abcdef"), padded_zero}, {Bytes({})}, padded_zero_cost);
    CheckError(OneOp(OP_LEFT), {Bytes("abcdef"), padded_zero}, padded_zero_cost - 1,
               SCRIPT_ERR_VAROP_COUNT);

    CheckEval(OneOp(OP_RIGHT), {Bytes("abcdef"), padded_zero}, {Bytes({})}, padded_zero_cost);
    CheckError(OneOp(OP_RIGHT), {Bytes("abcdef"), padded_zero}, padded_zero_cost - 1,
               SCRIPT_ERR_VAROP_COUNT);

    CheckEval(OneOp(OP_LSHIFT), {Bytes({0x12, 0x34}), padded_zero}, {Bytes({0x12, 0x34})},
              padded_zero_cost + 2 * varops::COST_COPYING);
    CheckError(OneOp(OP_LSHIFT), {Bytes({0x12, 0x34}), padded_zero},
               padded_zero_cost + 2 * varops::COST_COPYING - 1, SCRIPT_ERR_VAROP_COUNT);

    CheckEval(OneOp(OP_RSHIFT), {Bytes({0x12, 0x34}), padded_zero}, {Bytes({0x12, 0x34})},
              padded_zero_cost + 2 * varops::COST_COPYING);
    CheckError(OneOp(OP_RSHIFT), {Bytes({0x12, 0x34}), padded_zero},
               padded_zero_cost + 2 * varops::COST_COPYING - 1, SCRIPT_ERR_VAROP_COUNT);
}

BOOST_AUTO_TEST_CASE(restored_bit_opcodes_preserve_non_arithmetic_width)
{
    CheckEval(OneOp(OP_INVERT), {Bytes({0x00, 0xff})}, {Bytes({0xff, 0x00})}, varops::InvertCost(2));
    CheckEval(OneOp(OP_AND), {Bytes({0xff, 0xff}), Bytes({0x0f})}, {Bytes({0x0f, 0x00})}, varops::AndCost(2, 1));
    CheckEval(OneOp(OP_OR), {Bytes({0x00, 0x00}), Bytes({0x00})}, {Bytes({0x00, 0x00})}, varops::OrCost(2, 1));
    CheckEval(OneOp(OP_XOR), {Bytes({0x01, 0x00}), Bytes({0x01})}, {Bytes({0x00, 0x00})}, varops::XorCost(2, 1));

    CScript invert_then_add;
    invert_then_add << OP_INVERT << OP_1ADD;
    CheckEval(invert_then_add, {Bytes({0x00})}, {Bytes({0x00, 0x01})},
              varops::InvertCost(1) + varops::AddCost(1, 1));
}

BOOST_AUTO_TEST_CASE(restored_shift_opcodes_are_raw_bitshifts)
{
    CheckEval(OneOp(OP_LSHIFT), {Bytes({0x12, 0x34}), Num(0)}, {Bytes({0x12, 0x34})},
              2 * varops::COST_COPYING);
    CheckEval(OneOp(OP_LSHIFT), {Bytes({0x01}), Num(1)}, {Bytes({0x02, 0x00})},
              varops::LengthConversionCost(1) + 1 * varops::COST_COPYING + varops::UnalignedUpShiftCost(1, 0));
    CheckError(OneOp(OP_LSHIFT), {Bytes({0x01}), Num(1)},
               varops::LengthConversionCost(1) + 1 * varops::COST_COPYING + varops::UnalignedUpShiftCost(1, 0) - 1,
               SCRIPT_ERR_VAROP_COUNT);
    CheckEval(OneOp(OP_LSHIFT), {Bytes({}), Num(1)}, {Bytes({0x00})}, varops::LengthConversionCost(1));
    CheckEval(OneOp(OP_LSHIFT), {Bytes({0x01}), Num(8)}, {Bytes({0x00, 0x01})},
              varops::LengthConversionCost(1) + 1 * varops::COST_FAST + 1 * varops::COST_COPYING);
    CheckError(OneOp(OP_LSHIFT), {Bytes({0x01}), Num(8)},
               varops::LengthConversionCost(1) + 1 * varops::COST_FAST + 1 * varops::COST_COPYING - 1,
               SCRIPT_ERR_VAROP_COUNT);
    CheckEval(OneOp(OP_RSHIFT), {Bytes({0x12, 0x34}), Num(0)}, {Bytes({0x12, 0x34})},
              2 * varops::COST_COPYING);
    CheckEval(OneOp(OP_RSHIFT), {Bytes({0x02, 0x00}), Num(1)}, {Bytes({0x01, 0x00})},
              varops::LengthConversionCost(1) + 2 * varops::COST_COPYING);
    CheckError(OneOp(OP_RSHIFT), {Bytes({0x02, 0x00}), Num(1)},
               varops::LengthConversionCost(1) + 2 * varops::COST_COPYING - 1,
               SCRIPT_ERR_VAROP_COUNT);
    CheckEval(OneOp(OP_RSHIFT), {Bytes({}), Num(1)}, {Bytes({})}, varops::LengthConversionCost(1));
    CheckEval(OneOp(OP_RSHIFT), {Bytes({0xff}), Num(8)}, {Bytes({})}, varops::LengthConversionCost(1));
    CheckEval(OneOp(OP_RSHIFT), {Bytes({0x12, 0x34}), LargerThanU64()}, {Bytes({})},
              varops::LengthConversionCost(9));
    CheckError(OneOp(OP_LSHIFT), {Bytes({0x01}), LargerThanU64()}, 0, SCRIPT_ERR_STACK_ELEMENT_SIZE);
}

BOOST_AUTO_TEST_CASE(tapscript_v2_costed_opcodes_reject_missing_stack_elements)
{
    for (const auto& [opcode, stack] : {
             std::pair{OP_VERIFY, Stack{}},
             std::pair{OP_2DUP, Stack{Bytes("a")}},
             std::pair{OP_3DUP, Stack{Bytes("a"), Bytes("b")}},
             std::pair{OP_2OVER, Stack{Bytes("a"), Bytes("b"), Bytes("c")}},
             std::pair{OP_IFDUP, Stack{}},
             std::pair{OP_DUP, Stack{}},
             std::pair{OP_OVER, Stack{Bytes("a")}},
             std::pair{OP_PICK, Stack{Num(0)}},
             std::pair{OP_ROLL, Stack{Num(0)}},
             std::pair{OP_ROT, Stack{Bytes("a"), Bytes("b")}},
             std::pair{OP_SWAP, Stack{Bytes("a")}},
             std::pair{OP_TUCK, Stack{Bytes("a")}},
             std::pair{OP_SIZE, Stack{}},
             std::pair{OP_EQUAL, Stack{Bytes("a")}},
             std::pair{OP_EQUALVERIFY, Stack{Bytes("a")}},
             std::pair{OP_NOT, Stack{}},
             std::pair{OP_0NOTEQUAL, Stack{}},
             std::pair{OP_BOOLAND, Stack{Bytes("a")}},
             std::pair{OP_BOOLOR, Stack{Bytes("a")}},
             std::pair{OP_NUMEQUAL, Stack{Bytes("a")}},
             std::pair{OP_NUMEQUALVERIFY, Stack{Bytes("a")}},
             std::pair{OP_NUMNOTEQUAL, Stack{Bytes("a")}},
             std::pair{OP_LESSTHAN, Stack{Bytes("a")}},
             std::pair{OP_GREATERTHAN, Stack{Bytes("a")}},
             std::pair{OP_LESSTHANOREQUAL, Stack{Bytes("a")}},
             std::pair{OP_GREATERTHANOREQUAL, Stack{Bytes("a")}},
             std::pair{OP_WITHIN, Stack{Bytes("a"), Bytes("b")}},
             std::pair{OP_RIPEMD160, Stack{}},
             std::pair{OP_SHA1, Stack{}},
             std::pair{OP_SHA256, Stack{}},
             std::pair{OP_HASH160, Stack{}},
             std::pair{OP_HASH256, Stack{}},
             std::pair{OP_CAT, Stack{Bytes("a")}},
             std::pair{OP_SUBSTR, Stack{Bytes("a"), Num(0)}},
             std::pair{OP_LEFT, Stack{Bytes("a")}},
             std::pair{OP_RIGHT, Stack{Bytes("a")}},
             std::pair{OP_INVERT, Stack{}},
             std::pair{OP_AND, Stack{Bytes("a")}},
             std::pair{OP_OR, Stack{Bytes("a")}},
             std::pair{OP_XOR, Stack{Bytes("a")}},
             std::pair{OP_1ADD, Stack{}},
             std::pair{OP_1SUB, Stack{}},
             std::pair{OP_2MUL, Stack{}},
             std::pair{OP_2DIV, Stack{}},
             std::pair{OP_ADD, Stack{Bytes("a")}},
             std::pair{OP_SUB, Stack{Bytes("a")}},
             std::pair{OP_MUL, Stack{Bytes("a")}},
             std::pair{OP_DIV, Stack{Bytes("a")}},
             std::pair{OP_MOD, Stack{Bytes("a")}},
             std::pair{OP_MIN, Stack{Bytes("a")}},
             std::pair{OP_MAX, Stack{Bytes("a")}},
             std::pair{OP_LSHIFT, Stack{Bytes("a")}},
             std::pair{OP_RSHIFT, Stack{Bytes("a")}},
         }) {
        BOOST_TEST_CONTEXT("opcode " << static_cast<int>(opcode)) {
            CheckError(OneOp(opcode), stack, 0, SCRIPT_ERR_INVALID_STACK_OPERATION);
        }
    }
}

BOOST_AUTO_TEST_CASE(bip342_restricted_opcodes_remain_restricted_in_tapscript_v2)
{
    CheckError(OneOp(OP_RETURN), {}, 0, SCRIPT_ERR_OP_RETURN);
    CheckError(OneOp(OP_CHECKMULTISIG), {}, 0, SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG);
    CheckError(OneOp(OP_CHECKMULTISIGVERIFY), {}, 0, SCRIPT_ERR_TAPSCRIPT_CHECKMULTISIG);
}

BOOST_AUTO_TEST_CASE(restored_multiply_divide_and_modulo_opcodes)
{
    CheckEval(OneOp(OP_2MUL), {Bytes({0x80})}, {Bytes({0x00, 0x01})}, varops::TwoMulCost(1));
    CheckEval(OneOp(OP_2DIV), {Bytes({0x01})}, {Bytes({})}, varops::TwoDivCost(1));

    CheckEval(OneOp(OP_MUL), {Bytes({0xff, 0xff}), Bytes({0x02})}, {Bytes({0xfe, 0xff, 0x01})}, varops::MulCost(2, 1));
    CheckEval(OneOp(OP_DIV), {Bytes({0x39, 0x30}), Bytes({0x64})}, {Bytes({0x7b})}, varops::DivCost(2, 1));
    CheckEval(OneOp(OP_MOD), {Bytes({0x39, 0x30}), Bytes({0x64})}, {Bytes({0x2d})}, varops::ModCost(2, 1));

    for (const valtype& divisor : {Bytes({}), Bytes({0x00, 0x00})}) {
        CheckError(OneOp(OP_DIV), {Bytes({0x01}), divisor}, varops::DivCost(1, divisor.size()), SCRIPT_ERR_DIVIDE_BY_ZERO);
        CheckError(OneOp(OP_MOD), {Bytes({0x01}), divisor}, varops::ModCost(1, divisor.size()), SCRIPT_ERR_DIVIDE_BY_ZERO);
    }
}

BOOST_AUTO_TEST_CASE(extended_arithmetic_is_unsigned_and_normalized)
{
    CheckEval(OneOp(OP_1ADD), {Bytes({0xff})}, {Bytes({0x00, 0x01})}, varops::AddCost(1, 1));
    CheckEval(OneOp(OP_1SUB), {Bytes({0x01})}, {Bytes({})}, varops::SubCost(1, 1));
    CheckEval(OneOp(OP_ADD), {Bytes({0x01, 0x00, 0x00}), Bytes({})}, {Bytes({0x01})}, varops::AddCost(3, 0));
    CheckEval(OneOp(OP_SUB), {Bytes({0x00, 0x01}), Bytes({0x01})}, {Bytes({0xff})}, varops::SubCost(2, 1));

    CheckError(OneOp(OP_1SUB), {Bytes({})}, varops::SubCost(0, 1), SCRIPT_ERR_SUB_UNDERFLOW);
    CheckError(OneOp(OP_1SUB), {Bytes({0x00})}, varops::SubCost(1, 1), SCRIPT_ERR_SUB_UNDERFLOW);
    CheckError(OneOp(OP_SUB), {Bytes({0x01}), Bytes({0x02})}, varops::SubCost(1, 1), SCRIPT_ERR_SUB_UNDERFLOW);
    CheckError(OneOp(OP_SUB), {Bytes({0x00}), Bytes({0x01})}, varops::SubCost(1, 1), SCRIPT_ERR_SUB_UNDERFLOW);

    CheckEval(OneOp(OP_MIN), {Bytes({0x01, 0x00}), Bytes({0x02})}, {Bytes({0x01})}, varops::MinMaxCost(2, 1));
    CheckEval(OneOp(OP_MAX), {Bytes({0x01, 0x00}), Bytes({0x02})}, {Bytes({0x02})}, varops::MinMaxCost(2, 1));
}

BOOST_AUTO_TEST_CASE(checksigadd_failure_normalizes_numeric_operand)
{
    const valtype empty_sig{};
    const valtype nonminimal_one{Bytes({0x01, 0x00})};
    const valtype minimal_one{Bytes({0x01})};
    const valtype xonly_pubkey(32, 0x02);

    CScript script;
    script << OP_CHECKSIGADD << minimal_one << OP_EQUAL;

    const uint64_t cost{varops::ChecksigAddIncrementCost(nonminimal_one.size()) +
                        minimal_one.size() * varops::COST_FAST + FinalSuccessCost(1)};
    const EvalOutcome outcome{VerifyTapscriptV2(script, {empty_sig, nonminimal_one, xonly_pubkey}, cost)};
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(checksigadd_enforces_numeric_result_boundaries)
{
    const valtype empty_sig{};
    const valtype nonempty_sig(64, 0x01);
    const valtype xonly_pubkey(32, 0x02);
    const valtype all_zero(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, 0x00);
    const valtype all_ff(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, 0xff);
    const CScript script{OneOp(OP_CHECKSIGADD)};

    {
        RecordingChecker checker;
        const uint64_t cost{varops::COST_PER_SIGOP + varops::ChecksigAddIncrementCost(all_ff.size())};
        const EvalOutcome outcome{EvalTapscriptV2WithFlagsAndChecker(script, {nonempty_sig, all_ff, xonly_pubkey},
                                                              SCRIPT_VERIFY_NONE, checker, cost)};
        BOOST_CHECK(!outcome.ok);
        BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_STACK_ELEMENT_SIZE);
        BOOST_CHECK_EQUAL(outcome.remaining_budget, 0);
        BOOST_CHECK_EQUAL(checker.schnorr_calls, 1);
    }

    {
        RecordingChecker checker;
        const uint64_t cost{varops::COST_PER_SIGOP + varops::ChecksigAddIncrementCost(all_zero.size())};
        const EvalOutcome outcome{EvalTapscriptV2WithFlagsAndChecker(script, {nonempty_sig, all_zero, xonly_pubkey},
                                                              SCRIPT_VERIFY_NONE, checker, cost)};
        BOOST_REQUIRE(outcome.ok);
        BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
        BOOST_CHECK(outcome.stack == Stack{{0x01}});
    }

    {
        RecordingChecker checker;
        const uint64_t cost{varops::ChecksigAddIncrementCost(all_zero.size())};
        const EvalOutcome outcome{EvalTapscriptV2WithFlagsAndChecker(script, {empty_sig, all_zero, xonly_pubkey},
                                                              SCRIPT_VERIFY_NONE, checker, cost)};
        BOOST_REQUIRE(outcome.ok);
        BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
        BOOST_CHECK(outcome.stack == Stack{{}});
        BOOST_CHECK_EQUAL(checker.schnorr_calls, 0);
    }

    {
        RecordingChecker checker;
        const valtype empty_pubkey{};
        const valtype number{0xff};
        const uint64_t cost{varops::COST_PER_SIGOP + varops::ChecksigAddIncrementCost(number.size())};
        const EvalOutcome outcome{EvalTapscriptV2WithFlagsAndChecker(script, {nonempty_sig, number, empty_pubkey},
                                                              SCRIPT_VERIFY_NONE, checker, cost)};
        BOOST_CHECK(!outcome.ok);
        BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY);
        BOOST_CHECK_EQUAL(outcome.remaining_budget, 0);
        BOOST_CHECK_EQUAL(checker.schnorr_calls, 0);
    }
}

BOOST_AUTO_TEST_CASE(bip440_costed_legacy_ops_use_unsigned_values)
{
    CheckEval(OneOp(OP_EQUAL), {Bytes("same"), Bytes("same")}, {Bytes({0x01})}, 4 * varops::COST_FAST);
    CheckEval(OneOp(OP_EQUAL), {Bytes("a"), Bytes("bb")}, {Bytes({})}, 0);
    CheckEval(OneOp(OP_VERIFY), {Bytes({0x00, 0x01})}, {}, varops::LengthConversionCost(2));
    CheckError(OneOp(OP_VERIFY), {Bytes({})}, 0, SCRIPT_ERR_VERIFY);
    CheckError(OneOp(OP_VERIFY), {Bytes({0x00, 0x00})}, varops::CompareZeroCost(2), SCRIPT_ERR_VERIFY);

    CheckEval(OneOp(OP_NOT), {Bytes({0x00, 0x00})}, {Bytes({0x01})}, varops::CompareZeroCost(2));
    CheckEval(OneOp(OP_0NOTEQUAL), {Bytes({0x00, 0x01})}, {Bytes({0x01})}, varops::CompareZeroCost(2));
    CheckEval(OneOp(OP_NUMEQUAL), {Bytes({0x01}), Bytes({0x01, 0x00, 0x00})}, {Bytes({0x01})}, varops::ComparisonCost(1, 3));
    CheckEval(OneOp(OP_BOOLAND), {Bytes({0x01, 0x00}), Bytes({})}, {Bytes({})}, varops::BoolAndCost(2, 0));

    CheckEval(OneOp(OP_PICK), {Bytes("bottom"), Bytes("top"), Bytes({0x01, 0x00, 0x00})}, {Bytes("bottom"), Bytes("top"), Bytes("bottom")},
              varops::LengthConversionCost(3) + 6 * varops::COST_COPYING);
    CheckEval(OneOp(OP_ROLL), {Bytes("bottom"), Bytes("top"), Bytes({0x01, 0x00, 0x00})}, {Bytes("top"), Bytes("bottom")},
              varops::LengthConversionCost(3) + 1 * varops::COST_ROLL);
}

BOOST_AUTO_TEST_CASE(costed_legacy_ops_report_exact_semantic_failures)
{
    CheckError(OneOp(OP_EQUALVERIFY), {Bytes("ab"), Bytes("ac")},
               2 * varops::COST_FAST, SCRIPT_ERR_EQUALVERIFY);
    CheckError(OneOp(OP_NUMEQUALVERIFY), {Bytes({0x01}), Bytes({0x02})},
               varops::ComparisonCost(1, 1), SCRIPT_ERR_NUMEQUALVERIFY);

    CheckError(OneOp(OP_PICK), {Bytes("only"), Num(1)},
               varops::LengthConversionCost(1), SCRIPT_ERR_INVALID_STACK_OPERATION);
    CheckError(OneOp(OP_ROLL), {Bytes("only"), Bytes({0xff})},
               varops::LengthConversionCost(1), SCRIPT_ERR_INVALID_STACK_OPERATION);
}

BOOST_AUTO_TEST_CASE(locktime_sequence_operands_must_fit_transaction_fields)
{
    const CScript cltv_script{OneOp(OP_CHECKLOCKTIMEVERIFY)};
    const CScript csv_script{OneOp(OP_CHECKSEQUENCEVERIFY)};
    const valtype padded_uint32_max{Bytes({0xff, 0xff, 0xff, 0xff, 0x00})};
    const valtype padded_one{Bytes({0x01, 0x00, 0x00, 0x00, 0x00})};
    const valtype uint32_overflow{Bytes({0x00, 0x00, 0x00, 0x00, 0x01})};
    const valtype overflow_with_csv_disable_flag{Bytes({0x00, 0x00, 0x00, 0x80, 0x01})};

    {
        RecordingChecker checker;
        const EvalOutcome outcome{EvalTapscriptV2WithFlagsAndChecker(cltv_script, {padded_uint32_max},
                                                      SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
                                                      checker, varops::LengthConversionCost(padded_uint32_max.size()))};
        BOOST_CHECK(outcome.ok);
        BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(outcome.remaining_budget, 0);
        BOOST_CHECK_EQUAL(checker.locktime_calls, 1);
        BOOST_CHECK_EQUAL(checker.last_locktime, 0xffffffff);
        BOOST_REQUIRE_EQUAL(outcome.stack.size(), 1);
        BOOST_CHECK(outcome.stack.back() == padded_uint32_max);
    }

    {
        RecordingChecker checker;
        const EvalOutcome outcome{EvalTapscriptV2WithFlagsAndChecker(cltv_script, {uint32_overflow},
                                                      SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY,
                                                      checker, varops::LengthConversionCost(uint32_overflow.size()))};
        BOOST_CHECK(!outcome.ok);
        BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
        BOOST_CHECK_EQUAL(checker.locktime_calls, 0);
    }

    {
        RecordingChecker checker;
        const EvalOutcome outcome{EvalTapscriptV2WithFlagsAndChecker(csv_script, {padded_one},
                                                      SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
                                                      checker, varops::LengthConversionCost(padded_one.size()))};
        BOOST_CHECK(outcome.ok);
        BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(outcome.remaining_budget, 0);
        BOOST_CHECK_EQUAL(checker.sequence_calls, 1);
        BOOST_CHECK_EQUAL(checker.last_sequence, 1);
        BOOST_REQUIRE_EQUAL(outcome.stack.size(), 1);
        BOOST_CHECK(outcome.stack.back() == padded_one);
    }

    {
        RecordingChecker checker;
        const EvalOutcome outcome{EvalTapscriptV2WithFlagsAndChecker(csv_script, {uint32_overflow},
                                                      SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
                                                      checker, varops::LengthConversionCost(uint32_overflow.size()))};
        BOOST_CHECK(!outcome.ok);
        BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
        BOOST_CHECK_EQUAL(checker.sequence_calls, 0);
    }

    {
        RecordingChecker checker;
        const EvalOutcome outcome{EvalTapscriptV2WithFlagsAndChecker(csv_script, {overflow_with_csv_disable_flag},
                                                      SCRIPT_VERIFY_CHECKSEQUENCEVERIFY,
                                                      checker, varops::LengthConversionCost(overflow_with_csv_disable_flag.size()))};
        BOOST_CHECK(!outcome.ok);
        BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_UNSATISFIED_LOCKTIME);
        BOOST_CHECK_EQUAL(checker.sequence_calls, 0);
    }
}

BOOST_AUTO_TEST_CASE(hash_opcodes_follow_bip441_limits)
{
    const valtype large(MAX_SCRIPT_ELEMENT_SIZE + 1, 0x42);

    CheckError(OneOp(OP_SHA1), {large}, 0, SCRIPT_ERR_HASH_OPERAND_SIZE);
    CheckError(OneOp(OP_RIPEMD160), {large}, 0, SCRIPT_ERR_HASH_OPERAND_SIZE);

    const EvalOutcome sha256_out{EvalTapscriptV2(OneOp(OP_SHA256), {large}, large.size() * varops::COST_HASH)};
    BOOST_REQUIRE(sha256_out.ok);
    BOOST_CHECK_EQUAL(sha256_out.error, SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(sha256_out.remaining_budget, 0);
    BOOST_REQUIRE_EQUAL(sha256_out.stack.size(), 1);
    BOOST_CHECK_EQUAL(sha256_out.stack[0].size(), 32);
}

BOOST_AUTO_TEST_CASE(tapscript_v2_stack_limits_are_enforced)
{
    Stack max_count_stack(MAX_TAPSCRIPT_V2_STACK_SIZE, Bytes({}));
    CheckEval(OneOp(OP_NOP), max_count_stack, max_count_stack, 0);
    CheckError(OneOp(OP_1), max_count_stack, 0, SCRIPT_ERR_STACK_SIZE);
    CheckError(OneOp(OP_DUP), max_count_stack, 0, SCRIPT_ERR_STACK_SIZE);
    CheckError(OneOp(OP_DEPTH), max_count_stack, 0, SCRIPT_ERR_STACK_SIZE);

    Stack one_below_max_count(MAX_TAPSCRIPT_V2_STACK_SIZE - 1, Bytes({}));
    CheckError(OneOp(OP_2DUP), one_below_max_count, 0, SCRIPT_ERR_STACK_SIZE);
    CheckError(OneOp(OP_2OVER), one_below_max_count, 0, SCRIPT_ERR_STACK_SIZE);

    Stack two_below_max_count(MAX_TAPSCRIPT_V2_STACK_SIZE - 2, Bytes({}));
    CheckError(OneOp(OP_3DUP), two_below_max_count, 0, SCRIPT_ERR_STACK_SIZE);

    const EvalOutcome one_below_depth{EvalTapscriptV2(OneOp(OP_DEPTH), one_below_max_count, 0)};
    BOOST_REQUIRE(one_below_depth.ok);
    BOOST_CHECK_EQUAL(one_below_depth.error, SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(one_below_depth.remaining_budget, 0);
    BOOST_REQUIRE_EQUAL(one_below_depth.stack.size(), MAX_TAPSCRIPT_V2_STACK_SIZE);
    BOOST_CHECK(one_below_depth.stack.back() == Bytes({0xff, 0x7f}));

    Stack max_count_true_top(MAX_TAPSCRIPT_V2_STACK_SIZE, Bytes({}));
    max_count_true_top.back() = Bytes({0x01});
    CheckError(OneOp(OP_IFDUP), max_count_true_top,
               varops::CompareZeroCost(1) + varops::COST_COPYING,
               SCRIPT_ERR_STACK_SIZE);

    const valtype max_element(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, 0x01);
    CheckEval(OneOp(OP_NOP), {max_element}, {max_element}, 0);

    const EvalOutcome max_element_size{EvalTapscriptV2(OneOp(OP_SIZE), {max_element}, 0)};
    BOOST_REQUIRE(max_element_size.ok);
    BOOST_CHECK_EQUAL(max_element_size.error, SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(max_element_size.remaining_budget, 0);
    BOOST_REQUIRE_EQUAL(max_element_size.stack.size(), 2);
    BOOST_CHECK(max_element_size.stack.back() == Bytes({0x00, 0x09, 0x3d}));

    const valtype too_large_element(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE + 1, 0x01);
    CheckError(OneOp(OP_NOP), {too_large_element}, 0, SCRIPT_ERR_STACK_ELEMENT_SIZE);

    const valtype four_mb(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, 0x02);
    CheckEval(OneOp(OP_NOP), {four_mb, four_mb}, {four_mb, four_mb}, 0);
    CheckError(OneOp(OP_NOP), {four_mb, four_mb, Bytes({0x01})}, 0, SCRIPT_ERR_TOTAL_STACK_SIZE);
    CheckEval(OneOp(OP_DUP), {four_mb}, {four_mb, four_mb}, four_mb.size() * varops::COST_COPYING);
    CheckError(OneOp(OP_DUP), {Bytes({0x01}), four_mb}, four_mb.size() * varops::COST_COPYING,
               SCRIPT_ERR_TOTAL_STACK_SIZE);
}

BOOST_AUTO_TEST_CASE(copying_opcodes_enforce_total_stack_size_with_altstack)
{
    constexpr uint64_t budget{250'000'000};
    const valtype one_byte(1, 0x01);
    const valtype almost_max(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE - 1, 0x01);
    const valtype almost_max_minus_one(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE - 2, 0x01);
    const valtype almost_max_minus_two(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE - 3, 0x01);

    const auto check_boundary = [&](opcodetype opcode, const Stack& main_stack,
                                    size_t success_altstack_size, size_t failure_altstack_size) {
        CScript script;
        script << OP_TOALTSTACK << opcode;

        const auto evaluate = [&](size_t altstack_size) {
            Stack initial_stack{main_stack};
            initial_stack.emplace_back(altstack_size, 0x01);
            return EvalTapscriptV2(script, initial_stack, budget);
        };

        BOOST_TEST_CONTEXT("opcode " << static_cast<int>(opcode)) {
            const EvalOutcome success{evaluate(success_altstack_size)};
            BOOST_CHECK(success.ok);
            BOOST_CHECK_EQUAL(success.error, SCRIPT_ERR_OK);

            const EvalOutcome failure{evaluate(failure_altstack_size)};
            BOOST_CHECK(!failure.ok);
            BOOST_CHECK_EQUAL(failure.error, SCRIPT_ERR_TOTAL_STACK_SIZE);
        }
    };

    // Each successful execution ends with exactly 8,000,000 bytes across the
    // main and alt stacks. Increasing only the altstack element by one byte
    // makes the same opcode fail at 8,000,001 bytes.
    check_boundary(OP_2DUP, {one_byte, almost_max_minus_one}, 2, 3);
    check_boundary(OP_3DUP, {one_byte, one_byte, almost_max_minus_two}, 2, 3);
    check_boundary(OP_2OVER, {one_byte, almost_max_minus_one, Bytes({}), Bytes({})}, 2, 3);
    check_boundary(OP_IFDUP, {almost_max}, 2, 3);
    check_boundary(OP_DUP, {almost_max}, 2, 3);
    check_boundary(OP_OVER, {almost_max, one_byte}, 1, 2);
    check_boundary(OP_TUCK, {one_byte, almost_max}, 1, 2);
    check_boundary(OP_PICK, {almost_max, one_byte, Num(1)}, 1, 2);
}

BOOST_AUTO_TEST_CASE(tapscript_v2_witness_initial_stack_limits_are_enforced)
{
    CScript true_script;
    true_script << OP_1;

    Stack too_many_stack(MAX_TAPSCRIPT_V2_STACK_SIZE + 1, valtype{});
    EvalOutcome outcome{VerifyTapscriptV2(true_script, too_many_stack, 1'000)};
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_STACK_SIZE);

    CScript nop_true_script;
    nop_true_script << OP_NOP << OP_1;
    const valtype too_large_element(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE + 1, 0x01);
    outcome = VerifyTapscriptV2(nop_true_script, {too_large_element}, 1'000);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_STACK_ELEMENT_SIZE);

    const valtype four_mb(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, 0x01);
    outcome = VerifyTapscriptV2(nop_true_script, {four_mb, four_mb, Bytes({0x01})}, 1'000);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_TOTAL_STACK_SIZE);
}

BOOST_AUTO_TEST_CASE(tapscript_v2_pushes_use_the_expanded_stack_element_limit)
{
    const valtype max_element(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, 0x01);
    CScript max_push;
    max_push << max_element;
    EvalOutcome outcome{VerifyTapscriptV2(max_push, {}, FinalSuccessCost(max_element.size()))};
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);

    const valtype too_large_element(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE + 1, 0x01);
    CScript too_large_push;
    too_large_push << too_large_element;
    outcome = VerifyTapscriptV2(too_large_push, {}, 0);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_PUSH_SIZE);
}

BOOST_AUTO_TEST_CASE(tapscript_v2_skipped_branches_validate_pushes)
{
    const valtype max_element(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, 0x01);
    CScript max_skipped_push;
    max_skipped_push << OP_0 << OP_IF << max_element << OP_ENDIF;
    CheckEval(max_skipped_push, {}, {}, 0);

    const valtype too_large_element(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE + 1, 0x01);
    CScript oversized_skipped_push;
    oversized_skipped_push << OP_0 << OP_IF << too_large_element << OP_ENDIF;
    CheckError(oversized_skipped_push, {}, 0, SCRIPT_ERR_PUSH_SIZE);

    CScript truncated_skipped_push;
    truncated_skipped_push << OP_0 << OP_IF;
    truncated_skipped_push.push_back(static_cast<unsigned char>(OP_PUSHDATA4));
    CheckError(truncated_skipped_push, {}, 0, SCRIPT_ERR_BAD_OPCODE);
}

BOOST_AUTO_TEST_CASE(restored_ops_enforce_stack_element_limit_edges)
{
    const valtype max_element(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, 0x01);
    const valtype half_element(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE / 2, 0x01);

    CheckEval(OneOp(OP_CAT), {half_element, half_element}, {max_element},
              MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE * varops::COST_COPYING);

    CheckError(OneOp(OP_CAT), {max_element, Bytes({0x01})},
               (max_element.size() + 1) * varops::COST_COPYING,
               SCRIPT_ERR_STACK_ELEMENT_SIZE);

    const valtype one_byte_below_max(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE - 1, 0x01);
    valtype byte_shifted_to_max(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, 0x01);
    byte_shifted_to_max.front() = 0x00;
    CheckEval(OneOp(OP_LSHIFT), {one_byte_below_max, Num(8)}, {byte_shifted_to_max},
              varops::LengthConversionCost(1) + varops::COST_FAST +
                  one_byte_below_max.size() * varops::COST_COPYING);

    CheckError(OneOp(OP_LSHIFT), {max_element, Num(1)}, 0, SCRIPT_ERR_STACK_ELEMENT_SIZE);

    const valtype max_ff_element(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, 0xff);
    CheckError(OneOp(OP_1ADD), {max_ff_element}, varops::AddCost(max_ff_element.size(), 1),
               SCRIPT_ERR_STACK_ELEMENT_SIZE);
    CheckError(OneOp(OP_2MUL), {max_ff_element}, varops::TwoMulCost(max_ff_element.size()),
               SCRIPT_ERR_STACK_ELEMENT_SIZE);
}

BOOST_AUTO_TEST_CASE(varops_budget_must_cover_exact_bip_cost)
{
    CheckEval(OneOp(OP_CAT), {Bytes("a"), Bytes("b")}, {Bytes("ab")}, 2 * varops::COST_COPYING);
    CheckError(OneOp(OP_CAT), {Bytes("a"), Bytes("b")}, 2 * varops::COST_COPYING - 1, SCRIPT_ERR_VAROP_COUNT);

    CheckEval(OneOp(OP_MUL), {Bytes({0xff}), Bytes({0xff})}, {Bytes({0x01, 0xfe})}, varops::MulCost(1, 1));
    CheckError(OneOp(OP_MUL), {Bytes({0xff}), Bytes({0xff})}, varops::MulCost(1, 1) - 1, SCRIPT_ERR_VAROP_COUNT);

    CheckEval(OneOp(OP_DIV), {Bytes({0x39, 0x30}), Bytes({0x64})}, {Bytes({0x7b})}, varops::DivCost(2, 1));
    CheckError(OneOp(OP_DIV), {Bytes({0x39, 0x30}), Bytes({0x64})}, varops::DivCost(2, 1) - 1, SCRIPT_ERR_VAROP_COUNT);

    CheckEval(OneOp(OP_MOD), {Bytes({0x39, 0x30}), Bytes({0x64})}, {Bytes({0x2d})}, varops::ModCost(2, 1));
    CheckError(OneOp(OP_MOD), {Bytes({0x39, 0x30}), Bytes({0x64})}, varops::ModCost(2, 1) - 1, SCRIPT_ERR_VAROP_COUNT);
    CheckError(OneOp(OP_MOD), {Bytes({0x01}), Bytes({})}, varops::ModCost(1, 0) - 1, SCRIPT_ERR_VAROP_COUNT);

    const valtype empty_sig{};
    const valtype nonempty_sig{Bytes({0x01})};
    const valtype nonminimal_one{Bytes({0x01, 0x00})};
    const valtype xonly_pubkey(32, 0x02);
    const valtype unknown_pubkey(33, 0x02);
    const uint64_t empty_checksigadd_cost{varops::ChecksigAddIncrementCost(nonminimal_one.size())};
    CheckEval(OneOp(OP_CHECKSIGADD), {empty_sig, nonminimal_one, xonly_pubkey}, {Bytes({0x01})}, empty_checksigadd_cost);
    CheckError(OneOp(OP_CHECKSIGADD), {empty_sig, nonminimal_one, xonly_pubkey}, empty_checksigadd_cost - 1, SCRIPT_ERR_VAROP_COUNT);

    const uint64_t nonempty_checksigadd_cost{varops::COST_PER_SIGOP + varops::ChecksigAddIncrementCost(nonminimal_one.size())};
    CheckEval(OneOp(OP_CHECKSIGADD), {nonempty_sig, nonminimal_one, unknown_pubkey}, {Bytes({0x02})}, nonempty_checksigadd_cost);
    CheckError(OneOp(OP_CHECKSIGADD), {nonempty_sig, nonminimal_one, unknown_pubkey}, nonempty_checksigadd_cost - 1, SCRIPT_ERR_VAROP_COUNT);
}

BOOST_AUTO_TEST_CASE(signature_varops_charge_depends_on_nonempty_signature)
{
    const valtype empty_sig{};
    const valtype nonempty_sig{Bytes({0x01})};
    const valtype zero{};
    const valtype xonly_pubkey(32, 0x02);
    const valtype unknown_pubkey(33, 0x02);

    CScript empty_checksig_script;
    empty_checksig_script << xonly_pubkey << OP_CHECKSIG << OP_NOT;
    EvalOutcome outcome{VerifyTapscriptV2(empty_checksig_script, {empty_sig}, FinalSuccessCost(1))};
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(outcome.remaining_budget, 0);

    CScript nonempty_checksig_script;
    nonempty_checksig_script << unknown_pubkey << OP_CHECKSIG;
    outcome = VerifyTapscriptV2(nonempty_checksig_script, {nonempty_sig}, varops::COST_PER_SIGOP - 1);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_VAROP_COUNT);

    outcome = VerifyTapscriptV2(nonempty_checksig_script, {nonempty_sig}, varops::COST_PER_SIGOP + FinalSuccessCost(1));
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(outcome.remaining_budget, 0);

    CScript empty_checksigverify_script;
    empty_checksigverify_script << xonly_pubkey << OP_CHECKSIGVERIFY << OP_1;
    outcome = VerifyTapscriptV2(empty_checksigverify_script, {empty_sig}, 0);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_CHECKSIGVERIFY);
    BOOST_CHECK_EQUAL(outcome.remaining_budget, 0);

    CScript nonempty_checksigverify_script;
    nonempty_checksigverify_script << unknown_pubkey << OP_CHECKSIGVERIFY << OP_1;
    outcome = VerifyTapscriptV2(nonempty_checksigverify_script, {nonempty_sig}, varops::COST_PER_SIGOP - 1);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_VAROP_COUNT);

    outcome = VerifyTapscriptV2(nonempty_checksigverify_script, {nonempty_sig}, varops::COST_PER_SIGOP + FinalSuccessCost(1));
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(outcome.remaining_budget, 0);

    CScript empty_checksigadd_script;
    empty_checksigadd_script << xonly_pubkey << OP_CHECKSIGADD << OP_NOT;

    const uint64_t checksigadd_cost{varops::ChecksigAddIncrementCost(zero.size())};
    outcome = VerifyTapscriptV2(empty_checksigadd_script, {empty_sig, zero}, checksigadd_cost - 1);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_VAROP_COUNT);

    outcome = VerifyTapscriptV2(empty_checksigadd_script, {empty_sig, zero}, checksigadd_cost + FinalSuccessCost(1));
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(outcome.remaining_budget, 0);

    CScript nonempty_checksigadd_script;
    nonempty_checksigadd_script << unknown_pubkey << OP_CHECKSIGADD;
    const uint64_t nonempty_checksigadd_cost{varops::COST_PER_SIGOP + varops::ChecksigAddIncrementCost(zero.size())};
    outcome = VerifyTapscriptV2(nonempty_checksigadd_script, {nonempty_sig, zero}, nonempty_checksigadd_cost - 1);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_VAROP_COUNT);

    outcome = VerifyTapscriptV2(nonempty_checksigadd_script, {nonempty_sig, zero}, nonempty_checksigadd_cost + FinalSuccessCost(1));
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
    BOOST_CHECK_EQUAL(outcome.remaining_budget, 0);
}

BOOST_AUTO_TEST_CASE(op_success_redefinitions_are_checked_before_execution)
{
    for (const opcodetype opcode : {OP_1NEGATE, OP_NEGATE, OP_ABS}) {
        CScript script;
        script << opcode << OP_RETURN;
        ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
        const std::optional<bool> result{CheckTapscriptOpSuccess(script, SCRIPT_VERIFY_NONE, SigVersion::TAPSCRIPT_V2, &error)};
        BOOST_REQUIRE(result.has_value());
        BOOST_CHECK(*result);
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);

        error = SCRIPT_ERR_UNKNOWN_ERROR;
        const std::optional<bool> discouraged{CheckTapscriptOpSuccess(script, SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS, SigVersion::TAPSCRIPT_V2, &error)};
        BOOST_REQUIRE(discouraged.has_value());
        BOOST_CHECK(!*discouraged);
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_DISCOURAGE_OP_SUCCESS);

        CScript malformed_after;
        malformed_after << opcode;
        malformed_after.push_back(static_cast<unsigned char>(OP_PUSHDATA4));
        error = SCRIPT_ERR_UNKNOWN_ERROR;
        const std::optional<bool> after_result{CheckTapscriptOpSuccess(malformed_after, SCRIPT_VERIFY_NONE, SigVersion::TAPSCRIPT_V2, &error)};
        BOOST_REQUIRE(after_result.has_value());
        BOOST_CHECK(*after_result);
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);

        CScript malformed_before;
        malformed_before.push_back(static_cast<unsigned char>(OP_PUSHDATA4));
        malformed_before << opcode;
        error = SCRIPT_ERR_UNKNOWN_ERROR;
        const std::optional<bool> before_result{CheckTapscriptOpSuccess(malformed_before, SCRIPT_VERIFY_NONE, SigVersion::TAPSCRIPT_V2, &error)};
        BOOST_REQUIRE(before_result.has_value());
        BOOST_CHECK(!*before_result);
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_BAD_OPCODE);
    }

    // Inquisition assigns these code points to OP_INTERNALKEY and
    // OP_CHECKSIGFROMSTACK. On Core master they remain OP_SUCCESS opcodes, and
    // tapscript v2 must not accidentally give them the Inquisition semantics.
    for (const opcodetype opcode : {static_cast<opcodetype>(0xcb), static_cast<opcodetype>(0xcc)}) {
        CScript script;
        script << opcode << OP_RETURN;
        ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
        const std::optional<bool> result{CheckTapscriptOpSuccess(script, SCRIPT_VERIFY_NONE, SigVersion::TAPSCRIPT_V2, &error)};
        BOOST_REQUIRE(result.has_value());
        BOOST_CHECK(*result);
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);

        error = SCRIPT_ERR_UNKNOWN_ERROR;
        const std::optional<bool> discouraged{CheckTapscriptOpSuccess(script, SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS,
                                                       SigVersion::TAPSCRIPT_V2, &error)};
        BOOST_REQUIRE(discouraged.has_value());
        BOOST_CHECK(!*discouraged);
        BOOST_CHECK_EQUAL(error, SCRIPT_ERR_DISCOURAGE_OP_SUCCESS);

        EvalOutcome outcome{VerifyTapscriptV2WithFlags(script, {}, TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS, 0)};
        BOOST_CHECK(outcome.ok);
        BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
    }

    EvalOutcome discouraged_witness{VerifyTapscriptV2WithFlags(OneOp(OP_1NEGATE), {},
                                                        TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_DISCOURAGE_OP_SUCCESS,
                                                        0)};
    BOOST_CHECK(!discouraged_witness.ok);
    BOOST_CHECK_EQUAL(discouraged_witness.error, SCRIPT_ERR_DISCOURAGE_OP_SUCCESS);

    CScript unexecuted_success;
    unexecuted_success << OP_0 << OP_IF << OP_1NEGATE << OP_ENDIF << OP_RETURN;
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    const std::optional<bool> result{CheckTapscriptOpSuccess(unexecuted_success, SCRIPT_VERIFY_NONE, SigVersion::TAPSCRIPT_V2, &error)};
    BOOST_REQUIRE(result.has_value());
    BOOST_CHECK(*result);
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);

    Stack too_many_stack(MAX_TAPSCRIPT_V2_STACK_SIZE + 1, valtype{});
    EvalOutcome outcome{VerifyTapscriptV2(OneOp(OP_1NEGATE), too_many_stack, 0)};
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);

    const valtype too_large_element(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE + 1, 0x01);
    outcome = VerifyTapscriptV2(OneOp(OP_1NEGATE), {too_large_element}, 0);
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);

    const valtype four_mb(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, 0x01);
    outcome = VerifyTapscriptV2(OneOp(OP_1NEGATE), {four_mb, four_mb, Bytes({0x01})}, 0);
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(nop4_is_upgradable_nop_in_tapscript_v2)
{
    const valtype ctv_hash(32, 0x01);
    CScript script;
    script << ctv_hash << OP_NOP4;

    const script_verify_flags flags{TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS};
    EvalOutcome outcome{VerifyTapscriptV2WithFlags(script, {}, flags, FinalSuccessCost(ctv_hash.size()))};
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);

    outcome = VerifyTapscriptV2WithFlags(script, {}, flags | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_NOPS, 0);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_NOPS);
}

BOOST_AUTO_TEST_CASE(tapscript_v2_treats_future_pubkeys_as_unknown_pubkey_type)
{
    constexpr unsigned char future_pubkey_prefix{0x01};
    valtype future_xonly_pubkey(33, 0x02);
    future_xonly_pubkey.front() = future_pubkey_prefix;
    const valtype invalid_signature(64, 0x01);
    const script_verify_flags flags{TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS};
    const uint64_t cost{varops::COST_PER_SIGOP + FinalSuccessCost(1)};

    for (const valtype& pubkey : {Bytes({future_pubkey_prefix}), future_xonly_pubkey}) {
        CScript script;
        script << pubkey << OP_CHECKSIG;

        EvalOutcome outcome{VerifyTapscriptV2WithFlags(script, {invalid_signature}, flags, cost)};
        BOOST_CHECK(outcome.ok);
        BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);
        BOOST_CHECK_EQUAL(outcome.remaining_budget, 0);

        outcome = VerifyTapscriptV2WithFlags(script, {invalid_signature},
                                             flags | SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE,
                                             cost);
        BOOST_CHECK(!outcome.ok);
        BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE);
    }
}

BOOST_AUTO_TEST_CASE(tapscript_v2_conditionals_require_minimal_inputs)
{
    CScript if_script;
    if_script << OP_IF << OP_2 << OP_ELSE << OP_3 << OP_ENDIF;
    CheckEval(if_script, {Bytes({0x01})}, {Bytes({0x02})}, 0);
    CheckEval(if_script, {Bytes({})}, {Bytes({0x03})}, 0);
    CheckError(if_script, {Bytes({0x02})}, 0, SCRIPT_ERR_TAPSCRIPT_MINIMALIF);
    CheckError(if_script, {Bytes({0x00, 0x00})}, 0, SCRIPT_ERR_TAPSCRIPT_MINIMALIF);

    CScript notif_script;
    notif_script << OP_NOTIF << OP_2 << OP_ELSE << OP_3 << OP_ENDIF;
    CheckEval(notif_script, {Bytes({})}, {Bytes({0x02})}, 0);
    CheckEval(notif_script, {Bytes({0x01})}, {Bytes({0x03})}, 0);
}

BOOST_AUTO_TEST_CASE(unexecuted_branches_do_not_charge_or_execute_costed_ops)
{
    CScript skipped_then_else;
    skipped_then_else << OP_0 << OP_IF << OP_CAT << OP_MUL << OP_SHA256 << OP_ELSE << OP_2 << OP_ENDIF;
    CheckEval(skipped_then_else, {}, {Bytes({0x02})}, 0);
}

BOOST_AUTO_TEST_CASE(tapscript_v2_standard_verify_uses_unmetered_overload)
{
    CScript normal_script;
    normal_script << OP_1;

    CScript script_pub_key;
    const CScriptWitness witness{BuildTapscriptV2Witness(normal_script, {}, script_pub_key)};
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    const bool ok{VerifyScript(CScript{}, script_pub_key, &witness, STANDARD_SCRIPT_VERIFY_FLAGS, BaseSignatureChecker{}, &error)};
    BOOST_CHECK(ok);
    BOOST_CHECK_EQUAL(error, SCRIPT_ERR_OK);
}

BOOST_AUTO_TEST_CASE(taproot_script_signing_propagates_leaf_sigversion)
{
    const CScript leaf_script{CScript{} << ToByteVector(XOnlyPubKey::NUMS_H) << OP_CHECKSIG};

    for (const auto& [leaf_version, expected_sigversion] : {
             std::pair{int{TAPROOT_LEAF_TAPSCRIPT}, SigVersion::TAPSCRIPT},
             std::pair{int{TAPROOT_LEAF_TAPSCRIPT_V2}, SigVersion::TAPSCRIPT_V2},
         }) {
        TaprootBuilder builder;
        builder.Add(0, leaf_script, leaf_version, /*track=*/true);
        builder.Finalize(XOnlyPubKey::NUMS_H);

        const WitnessV1Taproot output{builder.GetOutput()};
        FlatSigningProvider provider;
        provider.tr_trees.emplace(output, builder);

        RecordingSignatureCreator creator;
        SignatureData sigdata;
        BOOST_REQUIRE(ProduceSignature(provider, creator, GetScriptForDestination(output), sigdata));
        BOOST_REQUIRE(!creator.schnorr_sigversions.empty());
        for (const SigVersion sigversion : creator.schnorr_sigversions) {
            BOOST_CHECK(sigversion == expected_sigversion);
        }
    }
}

BOOST_AUTO_TEST_CASE(tapscript_v2_psbt_finalized_witness_is_signed_and_verified)
{
    CScript normal_script;
    normal_script << OP_1;
    FinalizedTapscriptV2Spend spend{BuildFinalizedTapscriptV2Spend(normal_script, {})};

    CMutableTransaction unsigned_tx{spend.tx};
    unsigned_tx.vin[0].scriptWitness.SetNull();
    PartiallySignedTransaction psbt{unsigned_tx};
    psbt.inputs[0].witness_utxo = spend.spent_output;
    psbt.inputs[0].final_script_witness = spend.tx.vin[0].scriptWitness;

    PrecomputedTransactionData txdata;
    txdata.Init(CTransaction{spend.tx}, std::vector<CTxOut>{spend.spent_output});

    BOOST_CHECK(PSBTInputSignedAndVerified(psbt, 0, &txdata));
    BOOST_CHECK(PSBTInputSignedAndVerified(psbt, 0, nullptr));
    BOOST_CHECK(PSBTInputsSignedAndVerified(psbt, txdata));
    BOOST_CHECK(FinalizePSBT(psbt));
}

BOOST_AUTO_TEST_CASE(tapscript_v2_psbt_and_signtransaction_use_transaction_wide_varops_budget)
{
    const size_t operand_size{7'000};
    const valtype operand(operand_size, 0xff);

    CScript costly_script;
    costly_script << OP_MUL << OP_DROP << OP_1;

    CScript script_pub_key;
    const CScriptWitness witness{BuildTapscriptV2Witness(costly_script, {operand, operand}, script_pub_key)};
    const CTxOut spent_output{100'000'000, script_pub_key};

    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 1});
    tx.vin[0].scriptWitness = witness;
    tx.vin[1].scriptWitness = witness;
    tx.vout.emplace_back(50'000, CScript{} << OP_TRUE);

    const CTransaction tx_const{tx};
    const uint64_t per_input_cost{varops::MulCost(operand_size, operand_size)};
    const uint64_t tx_budget{varops::TxBudget(GetTransactionWeight(tx_const))};
    BOOST_REQUIRE_LT(per_input_cost, tx_budget);
    BOOST_REQUIRE_LT(tx_budget, 2 * per_input_cost);

    // Final witnesses are stored in the PSBT inputs, not its unsigned transaction.
    CMutableTransaction unsigned_tx{tx};
    for (CTxIn& in : unsigned_tx.vin) in.scriptWitness.SetNull();
    PartiallySignedTransaction psbt{unsigned_tx};
    for (size_t i{0}; i < psbt.inputs.size(); ++i) {
        psbt.inputs[i].witness_utxo = spent_output;
        psbt.inputs[i].final_script_witness = tx.vin[i].scriptWitness;
    }

    PrecomputedTransactionData txdata;
    txdata.Init(tx_const, std::vector<CTxOut>{spent_output, spent_output});

    BOOST_CHECK(PSBTInputSignedAndVerified(psbt, 0, &txdata));
    BOOST_CHECK(PSBTInputSignedAndVerified(psbt, 1, &txdata));
    BOOST_CHECK(!PSBTInputsSignedAndVerified(psbt, txdata));
    BOOST_CHECK(!FinalizePSBT(psbt));

    std::map<COutPoint, Coin> coins;
    coins.emplace(tx.vin[0].prevout, Coin{spent_output, 1, /*fCoinBaseIn=*/false});
    coins.emplace(tx.vin[1].prevout, Coin{spent_output, 1, /*fCoinBaseIn=*/false});

    std::map<int, bilingual_str> input_errors;
    BOOST_CHECK(!SignTransaction(tx, &DUMMY_SIGNING_PROVIDER, coins, SignOptions{SIGHASH_DEFAULT}, input_errors));
    BOOST_REQUIRE_EQUAL(input_errors.size(), 1);
    BOOST_CHECK_EQUAL(input_errors.begin()->second.original, ScriptErrorString(SCRIPT_ERR_VAROP_COUNT));
}

BOOST_AUTO_TEST_CASE(tapscript_v2_psbt_single_input_over_finalized_budget_is_rejected)
{
    const size_t operand_size{20'000};
    const valtype operand(operand_size, 0xff);

    CScript costly_script;
    costly_script << OP_MUL << OP_DROP << OP_1;

    CScript script_pub_key;
    const CScriptWitness witness{BuildTapscriptV2Witness(costly_script, {operand, operand}, script_pub_key)};
    const CTxOut spent_output{100'000'000, script_pub_key};

    CMutableTransaction tx;
    tx.version = 2;
    tx.vin.emplace_back(COutPoint{Txid::FromUint256(uint256::ONE), 0});
    tx.vin[0].scriptWitness = witness;
    tx.vout.emplace_back(50'000, CScript{} << OP_TRUE);

    const uint64_t input_cost{varops::MulCost(operand_size, operand_size)};
    const uint64_t finalized_budget{varops::TxBudget(GetTransactionWeight(CTransaction{tx}))};
    BOOST_REQUIRE_GT(input_cost, finalized_budget);

    CMutableTransaction unsigned_tx{tx};
    for (CTxIn& in : unsigned_tx.vin) in.scriptWitness.SetNull();
    PartiallySignedTransaction psbt{unsigned_tx};
    psbt.inputs[0].witness_utxo = spent_output;
    psbt.inputs[0].final_script_witness = tx.vin[0].scriptWitness;

    PrecomputedTransactionData txdata;
    txdata.Init(CTransaction{tx}, std::vector<CTxOut>{spent_output});

    BOOST_CHECK(!PSBTInputSignedAndVerified(psbt, 0, &txdata));
    BOOST_CHECK(!PSBTInputSignedAndVerified(psbt, 0, nullptr));
    BOOST_CHECK(!PSBTInputsSignedAndVerified(psbt, txdata));
    BOOST_CHECK(!FinalizePSBT(psbt));
}

BOOST_AUTO_TEST_CASE(tapscript_v2_signtransaction_accepts_finalized_witness)
{
    CScript normal_script;
    normal_script << OP_1;
    FinalizedTapscriptV2Spend spend{BuildFinalizedTapscriptV2Spend(normal_script, {})};

    std::map<COutPoint, Coin> coins;
    coins.emplace(spend.tx.vin[0].prevout, Coin{spend.spent_output, 1, /*fCoinBaseIn=*/false});

    std::map<int, bilingual_str> input_errors;
    BOOST_CHECK(SignTransaction(spend.tx, &DUMMY_SIGNING_PROVIDER, coins, SignOptions{SIGHASH_DEFAULT}, input_errors));
    BOOST_CHECK(input_errors.empty());
}

BOOST_AUTO_TEST_CASE(witness_path_uses_tapscript_v2_final_success_rule)
{
    CScript negative_zero_like;
    negative_zero_like << Bytes({0x80});
    EvalOutcome outcome{VerifyTapscriptV2(negative_zero_like, {}, 1'000)};
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);

    outcome = VerifyTapscriptV2(negative_zero_like, {}, FinalSuccessCost(1) - 1);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_VAROP_COUNT);

    CScript false_result;
    false_result << Bytes({});
    outcome = VerifyTapscriptV2(false_result, {}, 1'000);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_EVAL_FALSE);

    CScript all_zero_result;
    all_zero_result << Bytes({0x00, 0x00});
    outcome = VerifyTapscriptV2(all_zero_result, {}, 1'000);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_EVAL_FALSE);

    CScript high_byte_nonzero_result;
    high_byte_nonzero_result << Bytes({0x00, 0x01});
    outcome = VerifyTapscriptV2(high_byte_nonzero_result, {}, 1'000);
    BOOST_CHECK(outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_OK);

    CScript dirty_stack;
    dirty_stack << OP_1 << OP_1;
    outcome = VerifyTapscriptV2(dirty_stack, {}, 1'000);
    BOOST_CHECK(!outcome.ok);
    BOOST_CHECK_EQUAL(outcome.error, SCRIPT_ERR_CLEANSTACK);
}

BOOST_AUTO_TEST_SUITE_END()
