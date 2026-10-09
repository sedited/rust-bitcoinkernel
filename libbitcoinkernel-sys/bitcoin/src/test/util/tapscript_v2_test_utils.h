// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#ifndef BITCOIN_TEST_UTIL_TAPSCRIPT_V2_TEST_UTILS_H
#define BITCOIN_TEST_UTIL_TAPSCRIPT_V2_TEST_UTILS_H

#include <addresstype.h>
#include <key.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <script/valtype_stack.h>
#include <script/varops.h>
#include <util/check.h>

#include <cstdint>
#include <vector>

namespace test::tapscript_v2 {

using Stack = std::vector<std::vector<unsigned char>>;

inline constexpr script_verify_flags TAPROOT_SCRIPT_VERIFY_FLAGS{SCRIPT_VERIFY_P2SH | SCRIPT_VERIFY_WITNESS | SCRIPT_VERIFY_TAPROOT};
inline constexpr script_verify_flags TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS{TAPROOT_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_SCRIPT_RESTORATION};

struct EvalOutcome {
    bool ok{false};
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    uint64_t remaining_budget{0};
    Stack stack;
};

class RecordingChecker final : public BaseSignatureChecker
{
public:
    bool locktime_result{true};
    bool sequence_result{true};
    mutable int locktime_calls{0};
    mutable int sequence_calls{0};
    mutable int schnorr_calls{0};
    mutable int64_t last_locktime{-1};
    mutable int64_t last_sequence{-1};
    mutable SigVersion last_sigversion{SigVersion::BASE};
    mutable uint32_t last_codeseparator_pos{0};

    RecordingChecker() = default;
    RecordingChecker(bool locktime_result, bool sequence_result)
        : locktime_result{locktime_result}, sequence_result{sequence_result}
    {
    }

    bool CheckSchnorrSignature(std::span<const unsigned char>, std::span<const unsigned char>, SigVersion sigversion, ScriptExecutionData& execdata, ScriptError*) const override
    {
        ++schnorr_calls;
        last_sigversion = sigversion;
        Assert(execdata.m_codeseparator_pos_init);
        last_codeseparator_pos = execdata.m_codeseparator_pos;
        return true;
    }

    bool CheckLockTime(const CScriptNum& locktime) const override
    {
        ++locktime_calls;
        last_locktime = locktime.GetInt64();
        return locktime_result;
    }

    bool CheckSequence(const CScriptNum& sequence) const override
    {
        ++sequence_calls;
        last_sequence = sequence.GetInt64();
        return sequence_result;
    }
};

inline CScript OneOp(opcodetype opcode)
{
    CScript script;
    script << opcode;
    return script;
}

inline CScriptWitness BuildTapscriptV2Witness(const CScript& leaf_script, const Stack& initial_stack, CScript& script_pub_key)
{
    TaprootBuilder builder;
    builder.Add(0, leaf_script, TAPROOT_LEAF_TAPSCRIPT_V2, /*track=*/true);
    builder.Finalize(XOnlyPubKey::NUMS_H);

    CScriptWitness witness;
    witness.stack = initial_stack;
    const std::vector<unsigned char> serialized_script{leaf_script.begin(), leaf_script.end()};
    witness.stack.push_back(serialized_script);
    const auto control_blocks{builder.GetSpendData().scripts.at({serialized_script, TAPROOT_LEAF_TAPSCRIPT_V2})};
    witness.stack.push_back(*control_blocks.begin());

    script_pub_key = GetScriptForDestination(builder.GetOutput());
    return witness;
}

inline EvalOutcome EvalTapscriptV2WithFlagsAndChecker(const CScript& script, const Stack& initial_stack, script_verify_flags flags, const BaseSignatureChecker& checker, uint64_t budget)
{
    ScriptExecutionData execdata;
    execdata.m_annex_present = false;
    execdata.m_annex_init = true;
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    varops::Budget varops_budget{budget};
    ValtypeStack stack{initial_stack};
    const bool ok{::EvalTapscriptV2(stack, script, flags, checker, execdata, varops_budget, &error)};
    return {ok, error, *varops_budget.Remaining(), stack.GetStack()};
}

inline EvalOutcome EvalTapscriptV2(const CScript& script, const Stack& initial_stack, uint64_t budget)
{
    return EvalTapscriptV2WithFlagsAndChecker(script, initial_stack, SCRIPT_VERIFY_NONE, BaseSignatureChecker{}, budget);
}

} // namespace test::tapscript_v2

#endif // BITCOIN_TEST_UTIL_TAPSCRIPT_V2_TEST_UTILS_H
