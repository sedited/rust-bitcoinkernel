// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// Exercises Tapscript-v2 signature, locktime, sequence, internal-key, and
// template-hash behavior across checker results and malformed operands.

#include <primitives/transaction.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/signingprovider.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <test/fuzz/tapscript_v2_fuzz_util.h>
#include <test/util/tapscript_v2_test_utils.h>
#include <util/check.h>

#include <cstdint>

namespace {
using namespace test::tapscript_v2;
using namespace test::tapscript_v2::fuzz;

void CheckSignatureOpcode(FuzzedDataProvider& provider)
{
    const opcodetype opcode{provider.PickValueInArray<opcodetype>({OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKSIGADD})};
    const bool checksigadd{opcode == OP_CHECKSIGADD};
    const bool nonempty_sig{provider.ConsumeBool()};
    const Bytes signature{nonempty_sig ? Bytes(64, 0x01) : Bytes{}};

    Bytes pubkey;
    constexpr unsigned char future_pubkey_prefix{0x01};
    switch (provider.ConsumeIntegralInRange<uint8_t>(0, 5)) {
    case 0: break;
    case 1: pubkey.assign(32, 0x02); break;
    case 2: pubkey = {future_pubkey_prefix}; break;
    case 3:
        pubkey.assign(33, 0x02);
        pubkey.front() = future_pubkey_prefix;
        break;
    case 4: pubkey.assign(33, 0x03); break;
    case 5: pubkey.assign(65, 0x04); break;
    }

    const Bytes number{checksigadd ? ConsumeElement(provider) : Bytes{}};
    const Stack initial{checksigadd ? Stack{signature, number, pubkey} : Stack{signature, pubkey}};
    const uint64_t cost{(nonempty_sig ? COST_PER_SIGOP : 0) + (checksigadd ? ChecksigAddCost(number.size()) : 0)};
    const bool xonly{pubkey.size() == 32};
    const bool upgradable{!pubkey.empty() && !xonly};

    RecordingChecker checker;
    const EvalOutcome exact{
        EvalTapscriptV2WithFlagsAndChecker(OneOp(opcode), initial, SCRIPT_VERIFY_NONE, checker, cost)};
    if (pubkey.empty()) {
        Assert(!exact.ok);
        Assert(exact.error == SCRIPT_ERR_TAPSCRIPT_EMPTY_PUBKEY);
    } else if (opcode == OP_CHECKSIGVERIFY && !nonempty_sig) {
        Assert(!exact.ok);
        Assert(exact.error == SCRIPT_ERR_CHECKSIGVERIFY);
    } else {
        Assert(exact.ok);
        Assert(exact.error == SCRIPT_ERR_OK);
        if (opcode == OP_CHECKSIG) {
            AssertStackEqual(exact.stack, {nonempty_sig ? Bytes{1} : Bytes{}});
        } else if (opcode == OP_CHECKSIGVERIFY) {
            Assert(exact.stack.empty());
        } else {
            AssertStackEqual(exact.stack, {nonempty_sig ? Increment(number) : Normalize(number)});
        }
    }
    Assert(exact.remaining_budget == 0);
    Assert(checker.schnorr_calls == (xonly && nonempty_sig ? 1 : 0));
    if (checker.schnorr_calls == 1) {
        Assert(checker.last_sigversion == SigVersion::TAPSCRIPT_V2);
        Assert(checker.last_codeseparator_pos == 0xFFFFFFFFUL);
    }

    if (cost > 0) {
        RecordingChecker low_checker;
        const EvalOutcome low{
            EvalTapscriptV2WithFlagsAndChecker(OneOp(opcode), initial, SCRIPT_VERIFY_NONE, low_checker, cost - 1)};
        Assert(!low.ok);
        Assert(low.error == SCRIPT_ERR_VAROP_COUNT);
        Assert(low.remaining_budget == cost - 1);
        Assert(low_checker.schnorr_calls == 0);
    }

    if (upgradable) {
        RecordingChecker discouraged_checker;
        const EvalOutcome discouraged{EvalTapscriptV2WithFlagsAndChecker(
            OneOp(opcode), initial, SCRIPT_VERIFY_DISCOURAGE_UPGRADABLE_PUBKEYTYPE, discouraged_checker, cost)};
        Assert(!discouraged.ok);
        Assert(discouraged.error == SCRIPT_ERR_DISCOURAGE_UPGRADABLE_PUBKEYTYPE);
        Assert(discouraged.remaining_budget == 0);
        Assert(discouraged_checker.schnorr_calls == 0);
    }
}

void CheckCodeseparator(FuzzedDataProvider& provider)
{
    const opcodetype opcode{provider.ConsumeBool() ? OP_CHECKSIG : OP_CHECKSIGVERIFY};
    CScript script;
    uint32_t position{0};
    uint32_t expected{0xFFFFFFFFUL};
    const auto append = [&](opcodetype op) {
        script << op;
        return position++;
    };

    const size_t segments{provider.ConsumeIntegralInRange<size_t>(0, 6)};
    for (size_t i{0}; i < segments; ++i) {
        switch (provider.ConsumeIntegralInRange<uint8_t>(0, 3)) {
        case 0: expected = append(OP_CODESEPARATOR); break;
        case 1:
            append(OP_0);
            append(OP_IF);
            append(OP_CODESEPARATOR);
            append(OP_ENDIF);
            break;
        case 2:
            append(OP_1);
            append(OP_IF);
            expected = append(OP_CODESEPARATOR);
            append(OP_ENDIF);
            break;
        case 3: append(OP_NOP); break;
        }
    }
    append(opcode);

    const Stack stack{Bytes(64, 0x01), Bytes(32, 0x02)};
    RecordingChecker checker;
    const EvalOutcome exact{
        EvalTapscriptV2WithFlagsAndChecker(script, stack, SCRIPT_VERIFY_NONE, checker, COST_PER_SIGOP)};
    Assert(exact.ok);
    Assert(exact.error == SCRIPT_ERR_OK);
    Assert(exact.remaining_budget == 0);
    AssertStackEqual(exact.stack, opcode == OP_CHECKSIG ? Stack{Bytes{1}} : Stack{});
    Assert(checker.schnorr_calls == 1);
    Assert(checker.last_codeseparator_pos == expected);

    RecordingChecker low_checker;
    const EvalOutcome low{
        EvalTapscriptV2WithFlagsAndChecker(script, stack, SCRIPT_VERIFY_NONE, low_checker, COST_PER_SIGOP - 1)};
    Assert(!low.ok);
    Assert(low.error == SCRIPT_ERR_VAROP_COUNT);
    Assert(low_checker.schnorr_calls == 0);
}

void CheckRepeatedSigops(FuzzedDataProvider& provider)
{
    const uint8_t checks{provider.ConsumeIntegralInRange<uint8_t>(1, 8)};
    CScript script;
    for (uint8_t i{1}; i < checks; ++i)
        script << OP_CHECKSIGVERIFY;
    script << OP_CHECKSIG;

    Stack stack;
    for (uint8_t i{0}; i < checks; ++i) {
        stack.insert(stack.begin(), Bytes(32, static_cast<unsigned char>(0x02 + i)));
        stack.insert(stack.begin(), Bytes(64, static_cast<unsigned char>(0x11 + i)));
    }

    RecordingChecker checker;
    const uint64_t exact_cost{static_cast<uint64_t>(checks) * COST_PER_SIGOP};
    const EvalOutcome exact{EvalTapscriptV2WithFlagsAndChecker(script, stack, SCRIPT_VERIFY_NONE, checker, exact_cost)};
    Assert(exact.ok);
    AssertStackEqual(exact.stack, {Bytes{1}});
    Assert(checker.schnorr_calls == checks);

    const uint8_t completed{provider.ConsumeIntegralInRange<uint8_t>(0, checks - 1)};
    RecordingChecker low_checker;
    const uint64_t low_budget{static_cast<uint64_t>(completed) * COST_PER_SIGOP + COST_PER_SIGOP - 1};
    const EvalOutcome low{
        EvalTapscriptV2WithFlagsAndChecker(script, stack, SCRIPT_VERIFY_NONE, low_checker, low_budget)};
    Assert(!low.ok);
    Assert(low.error == SCRIPT_ERR_VAROP_COUNT);
    Assert(low.remaining_budget == COST_PER_SIGOP - 1);
    Assert(low_checker.schnorr_calls == completed);
}

Bytes ConsumeTimelockOperand(FuzzedDataProvider& provider)
{
    Bytes operand;
    switch (provider.ConsumeIntegralInRange<uint8_t>(0, 7)) {
    case 0: break;
    case 1: operand = {1}; break;
    case 2: operand = {0xff, 0xff, 0xff, 0xff}; break;
    case 3: operand = {0x00, 0x00, 0x00, 0x00, 0x01}; break;
    case 4: operand = {0x00, 0x00, 0x00, 0x80}; break;
    case 5: operand = {0x00, 0x00, 0x00, 0x80, 0x01}; break;
    case 6: operand = ToLittleEndian(provider.ConsumeIntegral<uint32_t>()); break;
    case 7: operand = ConsumeElement(provider, 32); break;
    }
    if (provider.ConsumeBool()) {
        operand.resize(provider.ConsumeIntegralInRange<size_t>(operand.size(), operand.size() + 8));
    }
    return operand;
}

void CheckTimelock(FuzzedDataProvider& provider)
{
    const bool sequence{provider.ConsumeBool()};
    const Bytes operand{ConsumeTimelockOperand(provider)};
    const uint64_t value{ToU64Ceil(operand, UINT64_C(0x100000000))};
    const uint64_t cost{LengthCost(operand.size())};
    const bool checker_result{provider.ConsumeBool()};
    RecordingChecker checker{checker_result, checker_result};
    const opcodetype opcode{sequence ? OP_CHECKSEQUENCEVERIFY : OP_CHECKLOCKTIMEVERIFY};
    const script_verify_flags flags{sequence ? SCRIPT_VERIFY_CHECKSEQUENCEVERIFY : SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY};
    const EvalOutcome outcome{EvalTapscriptV2WithFlagsAndChecker(OneOp(opcode), {operand}, flags, checker, cost)};

    if (value == UINT64_C(0x100000000)) {
        Assert(!outcome.ok);
        Assert(outcome.error == SCRIPT_ERR_UNSATISFIED_LOCKTIME);
        Assert(outcome.remaining_budget == cost);
        Assert(checker.locktime_calls == 0 && checker.sequence_calls == 0);
        return;
    }

    const bool disabled{sequence && (value & CTxIn::SEQUENCE_LOCKTIME_DISABLE_FLAG) != 0};
    if (disabled || checker_result) {
        Assert(outcome.ok);
        Assert(outcome.error == SCRIPT_ERR_OK);
        Assert(outcome.remaining_budget == 0);
        if (cost > 0) {
            RecordingChecker low_checker;
            const EvalOutcome low{
                EvalTapscriptV2WithFlagsAndChecker(OneOp(opcode), {operand}, flags, low_checker, cost - 1)};
            Assert(!low.ok);
            Assert(low.error == SCRIPT_ERR_VAROP_COUNT);
        }
    } else {
        Assert(!outcome.ok);
        Assert(outcome.error == SCRIPT_ERR_UNSATISFIED_LOCKTIME);
        Assert(outcome.remaining_budget == cost);
    }
    Assert(checker.locktime_calls == (sequence ? 0 : 1));
    Assert(checker.sequence_calls == (sequence && !disabled ? 1 : 0));
}
} // namespace

FUZZ_TARGET(tapscript_v2_signature_timelock)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    switch (provider.ConsumeIntegralInRange<uint8_t>(0, 3)) {
    case 0: CheckSignatureOpcode(provider); break;
    case 1: CheckCodeseparator(provider); break;
    case 2: CheckRepeatedSigops(provider); break;
    case 3: CheckTimelock(provider); break;
    }
}
