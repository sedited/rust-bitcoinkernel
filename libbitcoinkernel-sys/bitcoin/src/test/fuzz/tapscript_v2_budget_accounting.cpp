// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// Exercises shared varops budgets, conditional charging, partial failures, and
// final stack truthiness at exact and insufficient budget boundaries.

#include <script/script.h>
#include <script/script_error.h>
#include <script/varops.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/tapscript_v2_fuzz_util.h>
#include <util/check.h>

#include <cstdint>

namespace {
using namespace test::tapscript_v2;
using namespace test::tapscript_v2::fuzz;

void VerifyPair(const LeafSpend& first, uint64_t first_cost, const LeafSpend& second, uint64_t second_cost)
{
    const BaseSignatureChecker checker;
    {
        varops::Budget budget{first_cost + second_cost};
        ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
        Assert(VerifySpend(first, TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS, checker, budget, error));
        Assert(error == SCRIPT_ERR_OK);
        Assert(*budget.Remaining() == second_cost);
        Assert(VerifySpend(second, TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS, checker, budget, error));
        Assert(error == SCRIPT_ERR_OK);
        Assert(*budget.Remaining() == 0);
    }
    {
        varops::Budget budget{first_cost + second_cost - 1};
        ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
        Assert(VerifySpend(first, TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS, checker, budget, error));
        Assert(error == SCRIPT_ERR_OK);
        Assert(*budget.Remaining() == second_cost - 1);
        Assert(!VerifySpend(second, TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS, checker, budget, error));
        Assert(error == SCRIPT_ERR_VAROP_COUNT);
    }
}

void CheckSharedBudget(FuzzedDataProvider& provider)
{
    Bytes a{ConsumeElement(provider)};
    Bytes b{ConsumeElement(provider)};
    if (a.empty()) a.push_back(1);
    if (b.empty()) b.push_back(2);

    CScript script;
    script << OP_DUP << OP_EQUAL;
    const LeafSpend spend_a{BuildLeafSpend(script, {a})};
    const LeafSpend spend_b{BuildLeafSpend(script, {b})};
    const uint64_t cost_a{CopyCost(a.size()) + EqualCost(a.size(), a.size()) + CompareZeroCost(1)};
    const uint64_t cost_b{CopyCost(b.size()) + EqualCost(b.size(), b.size()) + CompareZeroCost(1)};
    VerifyPair(spend_a, cost_a, spend_b, cost_b);
    VerifyPair(spend_b, cost_b, spend_a, cost_a);
}

void CheckConditionalBudget(FuzzedDataProvider& provider)
{
    const Bytes element{ConsumeElement(provider)};
    const bool condition{provider.ConsumeBool()};
    const opcodetype conditional{provider.ConsumeBool() ? OP_IF : OP_NOTIF};
    const bool first_branch_executes{condition == (conditional == OP_IF)};
    const bool costed_first{provider.ConsumeBool()};
    const bool nested{provider.ConsumeBool()};

    CScript script;
    script << (condition ? OP_1 : OP_0) << conditional;
    const auto append_branch = [&](bool costed) {
        if (!costed) {
            script << OP_NOP;
        } else if (nested) {
            script << OP_1 << OP_IF << OP_DUP << OP_ENDIF;
        } else {
            script << OP_DUP;
        }
    };
    append_branch(costed_first);
    script << OP_ELSE;
    append_branch(!costed_first);
    script << OP_ENDIF;

    const bool duplicates{first_branch_executes == costed_first};
    const Stack expected{duplicates ? Stack{element, element} : Stack{element}};
    CheckExactEval(script, {element}, expected, duplicates ? CopyCost(element.size()) : 0);
}

void CheckPartialFailure(FuzzedDataProvider& provider)
{
    switch (provider.ConsumeIntegralInRange<uint8_t>(0, 2)) {
    case 0: {
        Bytes element{ConsumeElement(provider)};
        if (element.empty()) element.push_back(1);
        CScript script;
        script << OP_DUP << OP_FROMALTSTACK;
        const uint64_t copy_cost{CopyCost(element.size())};
        const uint64_t extra{provider.ConsumeIntegralInRange<uint64_t>(0, 1'000'000)};
        CheckEvalErrorBudget(script, {element}, copy_cost + extra, SCRIPT_ERR_INVALID_ALTSTACK_OPERATION, extra);
        CheckEvalErrorBudget(script, {element}, copy_cost - 1, SCRIPT_ERR_VAROP_COUNT, copy_cost - 1);
        break;
    }
    case 1: {
        const Bytes a{ConsumeElement(provider)};
        Bytes b{ConsumeElement(provider)};
        if (b.empty()) b.push_back(1);
        CScript script;
        script << OP_DUP << OP_CAT;
        const uint64_t dup_cost{CopyCost(b.size())};
        const uint64_t cat_cost{CopyCost(2 * b.size())};
        CheckEvalErrorBudget(script, {a, b}, dup_cost + cat_cost - 1, SCRIPT_ERR_VAROP_COUNT, cat_cost - 1);
        break;
    }
    case 2: {
        const uint64_t budget{provider.ConsumeIntegralInRange<uint64_t>(0, 1'000'000)};
        const opcodetype opcode{provider.PickValueInArray<opcodetype>({OP_DUP, OP_CAT, OP_FROMALTSTACK})};
        CheckEvalErrorBudget(
            OneOp(opcode),
            {},
            budget,
            opcode == OP_FROMALTSTACK ? SCRIPT_ERR_INVALID_ALTSTACK_OPERATION : SCRIPT_ERR_INVALID_STACK_OPERATION,
            budget);
        break;
    }
    }
}

void CheckFinalSuccess(FuzzedDataProvider& provider)
{
    Stack stack;
    const size_t count{provider.ConsumeIntegralInRange<size_t>(0, 2)};
    for (size_t i{0}; i < count; ++i)
        stack.push_back(ConsumeElement(provider));

    const LeafSpend spend{BuildLeafSpend(CScript{}, stack)};
    const BaseSignatureChecker checker;
    if (stack.size() != 1) {
        const VerifyOutcome outcome{VerifySpend(spend, TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS, checker, 1'000'000)};
        Assert(!outcome.ok);
        Assert(outcome.error == SCRIPT_ERR_CLEANSTACK);
        Assert(outcome.remaining_budget == 1'000'000);
        return;
    }

    const uint64_t cost{CompareZeroCost(stack.back().size())};
    const VerifyOutcome exact{VerifySpend(spend, TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS, checker, cost)};
    Assert(exact.ok == ContainsNonZero(stack.back()));
    Assert(exact.error == (exact.ok ? SCRIPT_ERR_OK : SCRIPT_ERR_EVAL_FALSE));
    Assert(exact.remaining_budget == 0);
    if (cost > 0) {
        const VerifyOutcome low{VerifySpend(spend, TAPSCRIPT_V2_SCRIPT_VERIFY_FLAGS, checker, cost - 1)};
        Assert(!low.ok);
        Assert(low.error == SCRIPT_ERR_VAROP_COUNT);
    }
}
} // namespace

FUZZ_TARGET(tapscript_v2_budget_accounting)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    switch (provider.ConsumeIntegralInRange<uint8_t>(0, 3)) {
    case 0: CheckSharedBudget(provider); break;
    case 1: CheckConditionalBudget(provider); break;
    case 2: CheckPartialFailure(provider); break;
    case 3: CheckFinalSuccess(provider); break;
    }
}
