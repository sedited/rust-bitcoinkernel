// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// Checks Tapscript-v2 budget monotonicity, script-restoration flag gating, and
// successful stack-resource invariants.

#include <script/interpreter.h>
#include <script/script.h>
#include <script/valtype_stack.h>
#include <script/varops.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/tapscript_v2_fuzz_util.h>
#include <test/fuzz/util.h>
#include <util/check.h>

#include <algorithm>
#include <cstdint>
#include <limits>
#include <vector>

namespace {
using namespace test::tapscript_v2;
using namespace test::tapscript_v2::fuzz;

class StableChecker final : public BaseSignatureChecker
{
    bool m_signature_result;
    bool m_locktime_result;
    bool m_sequence_result;

public:
    explicit StableChecker(FuzzedDataProvider& provider) : m_signature_result{provider.ConsumeBool()},
                                                           m_locktime_result{provider.ConsumeBool()},
                                                           m_sequence_result{provider.ConsumeBool()}
    {
    }

    bool CheckSchnorrSignature(std::span<const unsigned char>,
                               std::span<const unsigned char>,
                               SigVersion,
                               ScriptExecutionData&,
                               ScriptError*) const override
    {
        return m_signature_result;
    }

    bool CheckLockTime(const CScriptNum&) const override
    {
        return m_locktime_result;
    }

    bool CheckSequence(const CScriptNum&) const override
    {
        return m_sequence_result;
    }

};

struct RawEvalOutcome {
    bool ok{false};
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    uint64_t remaining_budget{0};
    Stack stack;
    size_t total_stack_size{0};
    size_t max_element_size{0};
};

std::vector<unsigned char> ConsumeStackElement(FuzzedDataProvider& provider)
{
    if (provider.ConsumeIntegralInRange<uint8_t>(0, 31) == 0) {
        const size_t size{provider.ConsumeIntegralInRange<size_t>(0, 64 * 1024)};
        std::vector<unsigned char> elem(size);
        const std::vector<unsigned char> seed{
            provider.ConsumeBytes<unsigned char>(std::min<size_t>(provider.remaining_bytes(), 16))};
        if (seed.empty()) return elem;
        for (size_t i{0}; i < elem.size(); ++i) {
            elem[i] = static_cast<unsigned char>(seed[i % seed.size()] + i);
        }
        return elem;
    }
    return ConsumeRandomLengthByteVector(provider, 128);
}

Stack ConsumeStack(FuzzedDataProvider& provider)
{
    const size_t max_stack_size{provider.ConsumeIntegralInRange<uint8_t>(0, 15) == 0 ? size_t{64} : size_t{16}};
    const size_t stack_size{provider.ConsumeIntegralInRange<size_t>(0, max_stack_size)};
    Stack stack;
    stack.reserve(stack_size);
    for (size_t i{0}; i < stack_size; ++i) {
        stack.push_back(ConsumeStackElement(provider));
    }
    return stack;
}

opcodetype ConsumeUsefulOpcode(FuzzedDataProvider& provider)
{
    return provider.PickValueInArray<opcodetype>({
        OP_0, OP_1, OP_2, OP_3, OP_NOP, OP_IF, OP_NOTIF, OP_ELSE, OP_ENDIF,
        OP_VERIFY, OP_TOALTSTACK, OP_FROMALTSTACK, OP_DROP, OP_DUP, OP_NIP,
        OP_OVER, OP_PICK, OP_ROLL, OP_ROT, OP_SWAP, OP_TUCK, OP_SIZE, OP_EQUAL,
        OP_EQUALVERIFY, OP_1ADD, OP_1SUB, OP_2MUL, OP_2DIV, OP_INVERT, OP_AND,
        OP_OR, OP_XOR, OP_ADD, OP_SUB, OP_BOOLAND, OP_BOOLOR, OP_NUMEQUAL,
        OP_NUMEQUALVERIFY, OP_NUMNOTEQUAL, OP_LESSTHAN, OP_GREATERTHAN,
        OP_LESSTHANOREQUAL, OP_GREATERTHANOREQUAL, OP_MIN, OP_MAX, OP_WITHIN,
        OP_MUL, OP_DIV, OP_MOD, OP_LSHIFT, OP_RSHIFT, OP_CAT, OP_SUBSTR, OP_LEFT,
        OP_RIGHT, OP_RIPEMD160, OP_SHA1, OP_SHA256, OP_HASH160, OP_HASH256,
        OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY, OP_CHECKSIG,
        OP_CHECKSIGVERIFY, OP_CHECKSIGADD, OP_CODESEPARATOR,
        static_cast<opcodetype>(0xcb), static_cast<opcodetype>(0xcc),
        static_cast<opcodetype>(0xce),
    });
}

CScript ConsumeTapscriptV2Script(FuzzedDataProvider& provider)
{
    if (provider.ConsumeBool()) {
        const std::vector<unsigned char> bytes{ConsumeRandomLengthByteVector(provider, 1024)};
        return CScript{bytes.begin(), bytes.end()};
    }

    CScript script;
    const size_t ops{provider.ConsumeIntegralInRange<size_t>(0, 64)};
    for (size_t i{0}; i < ops; ++i) {
        if (provider.ConsumeIntegralInRange<uint8_t>(0, 3) == 0) {
            script << ConsumeRandomLengthByteVector(provider, 128);
        } else {
            script << ConsumeUsefulOpcode(provider);
        }
    }
    return script;
}

uint64_t ConsumeBudget(FuzzedDataProvider& provider)
{
    if (provider.ConsumeIntegralInRange<uint8_t>(0, 15) == 0) {
        return provider.ConsumeIntegralInRange<uint64_t>(0, 500'000'000);
    }
    return provider.ConsumeIntegralInRange<uint64_t>(0, 1'000'000);
}

RawEvalOutcome EvalWithBudget(const CScript& script,
                              const Stack& initial_stack,
                              script_verify_flags flags,
                              const BaseSignatureChecker& checker,
                              uint64_t budget)
{
    ValtypeStack stack{initial_stack};
    ScriptExecutionData execdata;
    execdata.m_annex_present = false;
    execdata.m_annex_init = true;

    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    varops::Budget varops_budget{budget};
    const bool ok{EvalTapscriptV2(stack, script, flags, checker, execdata, varops_budget, &error)};
    return {
        ok,
        error,
        *varops_budget.Remaining(),
        stack.GetStack(),
        stack.GetTotalSize(),
        stack.GetMaxElementSize(),
    };
}

void AssertSuccessfulStackLimits(const RawEvalOutcome& outcome)
{
    if (!outcome.ok) return;
    size_t actual_total_size{0};
    for (const auto& element : outcome.stack) {
        actual_total_size += element.size();
        Assert(element.size() <= MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE);
    }
    Assert(actual_total_size == outcome.total_stack_size);
    Assert(outcome.stack.size() <= MAX_TAPSCRIPT_V2_STACK_SIZE);
    Assert(outcome.total_stack_size <= MAX_TAPSCRIPT_V2_TOTAL_STACK_SIZE);
    Assert(outcome.max_element_size <= MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE);
}

void CheckScriptRestorationFlagGate(const CScript& leaf_script,
                                    const Stack& initial_stack,
                                    const BaseSignatureChecker& checker,
                                    uint64_t budget)
{
    const LeafSpend spend{BuildLeafSpend(leaf_script, initial_stack)};
    const VerifyOutcome loose{VerifySpend(spend, TAPROOT_SCRIPT_VERIFY_FLAGS, checker, budget)};
    Assert(loose.ok);
    Assert(loose.error == SCRIPT_ERR_OK);
    Assert(loose.remaining_budget == budget);

    const VerifyOutcome discouraged{VerifySpend(
        spend,
        TAPROOT_SCRIPT_VERIFY_FLAGS | SCRIPT_VERIFY_DISCOURAGE_SCRIPT_RESTORATION,
        checker, budget)};
    Assert(!discouraged.ok);
    Assert(discouraged.error == SCRIPT_ERR_DISCOURAGE_SCRIPT_RESTORATION);
    Assert(discouraged.remaining_budget == budget);

    const VerifyOutcome strict{VerifySpend(spend, TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS, checker, budget)};
    Assert(strict.error != SCRIPT_ERR_DISCOURAGE_SCRIPT_RESTORATION);
    Assert(strict.remaining_budget <= budget);
}
} // namespace

FUZZ_TARGET(tapscript_v2_eval_invariants)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    const CScript script{ConsumeTapscriptV2Script(provider)};
    const Stack stack{ConsumeStack(provider)};
    const script_verify_flags flags{
        script_verify_flags::from_int(provider.ConsumeIntegral<script_verify_flags::value_type>())};
    const uint64_t budget{ConsumeBudget(provider)};
    const StableChecker checker{provider};

    const RawEvalOutcome outcome{EvalWithBudget(script, stack, flags, checker, budget)};
    AssertSuccessfulStackLimits(outcome);
    Assert(outcome.remaining_budget <= budget);

    if (outcome.ok && budget < std::numeric_limits<uint64_t>::max()) {
        constexpr uint64_t budget_increment{1'000'000};
        const uint64_t higher_budget{budget > std::numeric_limits<uint64_t>::max() - budget_increment ?
                                         std::numeric_limits<uint64_t>::max() :
                                         budget + budget_increment};
        const RawEvalOutcome higher_budget_outcome{EvalWithBudget(script, stack, flags, checker, higher_budget)};
        Assert(higher_budget_outcome.ok);
        Assert(higher_budget_outcome.stack == outcome.stack);
        Assert(higher_budget - higher_budget_outcome.remaining_budget == budget - outcome.remaining_budget);
        AssertSuccessfulStackLimits(higher_budget_outcome);
    }

    CheckScriptRestorationFlagGate(script, stack, checker, budget);
}
