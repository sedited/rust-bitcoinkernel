// Copyright (c) 2025-2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <bench/nanobench.h>
#include <consensus/consensus.h>
#include <crypto/sha256.h>
#if defined(__linux__)
#include <features.h> // IWYU pragma: keep
#endif
#include <key.h>
#include <pubkey.h>
#include <script/interpreter.h>
#include <script/script.h>
#include <script/script_error.h>
#include <script/val64.h>
#include <script/valtype_stack.h>
#include <script/varops.h>
#include <script/verify_flags.h>
#include <span.h>
#include <tinyformat.h>
#include <uint256.h>
#include <util/fs.h>
#include <util/strencodings.h>
#include <util/string.h>
#include <util/translation.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cmath> // IWYU pragma: keep
#include <compare>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <fstream>
#include <functional>
#include <initializer_list>
#include <iostream>
#include <limits>
#include <map>
#include <memory>
#include <optional>
#include <random>
#include <ranges>
#include <set>
#include <span>
#include <sstream>
#include <stdexcept>
#include <string>
#include <string_view>
#include <system_error>
#include <tuple>
#include <utility>
#include <variant>
#include <vector>

#if defined(__APPLE__)
#include <malloc/malloc.h>
#elif defined(__GLIBC__)
#include <malloc.h>
#endif

const TranslateFn G_TRANSLATION_FUN{nullptr};

namespace {

constexpr size_t SCRIPT_BYTES{MAX_BLOCK_WEIGHT};
constexpr uint64_t TOTAL_VAROPS_BUDGET{uint64_t{MAX_BLOCK_WEIGHT} * varops::BUDGET_PER_WEIGHT_UNIT};
constexpr uint64_t MAX_FIXTURE_POOL_BYTES{512U * 1024U * 1024U};
constexpr size_t MAX_THREE_WAY_ELEMENT_SIZE{(MAX_TAPSCRIPT_V2_TOTAL_STACK_SIZE - 1) / 6};
constexpr int SIGNATURES_PER_BLOCK{80'000};
constexpr int SCHNORR_BASELINE_SAMPLES{7};
constexpr double PROMOTION_THRESHOLD{0.40};
constexpr uint64_t ROUND_SEED{0x475352};
constexpr script_verify_flags BENCH_SCRIPT_VERIFY_FLAGS{
    SCRIPT_VERIFY_CHECKLOCKTIMEVERIFY | SCRIPT_VERIFY_CHECKSEQUENCEVERIFY};

enum class ExecutionDomain {
    PRE_GSR_TAPSCRIPT,
    GSR_TAPSCRIPT_V2,
    RAW_SCHNORR,
};

enum class HeadlineRole {
    PRE_BASELINE,
    NEW_GSR,
    COMMON_V2,
    DIAGNOSTIC,
};

enum class RepeatMode {
    MAX_SUCCESS,
    VAROP_REJECTION,
    FIXED,
};

enum class SaturationExpectation {
    SCRIPT_BYTES,
    VAROPS_BUDGET,
};

enum class TimingStage {
    SCHNORR_BASELINE,
    DISCOVERY,
    STABLE,
};

using SaturationBoundary = std::pair<size_t, SaturationExpectation>;
using SaturationBoundaries = std::array<SaturationBoundary, 2>;

struct Options {
    std::set<opcodetype> selected_opcodes;
    int stable_rounds{7};
    bool silent{false}, list_opcodes{false};
    std::string output_file;
};

struct CryptoFixture {
    ECC_Context ecc_context{};
    uint256 message{uint256::ONE};
    XOnlyPubKey pubkey;
    valtype pubkey_bytes;
    valtype signature;

    CryptoFixture()
    {
        CKey key;
        std::array<unsigned char, 32> secret{};
        secret.back() = 1;
        key.Set(secret.begin(), secret.end(), false);
        if (!key.IsValid()) {
            throw std::runtime_error("failed to construct benchmark private key");
        }
        pubkey = XOnlyPubKey{key.GetPubKey()};
        pubkey_bytes.assign(pubkey.begin(), pubkey.end());
        signature.resize(64);
        if (!key.SignSchnorr(message, signature, nullptr, message)) {
            throw std::runtime_error("failed to construct benchmark Schnorr signature");
        }
    }
};

class BenchSignatureChecker final : public BaseSignatureChecker
{
public:
    explicit BenchSignatureChecker(const CryptoFixture& fixture) : m_fixture{fixture} {}

    bool CheckSchnorrSignature(std::span<const unsigned char> sig,
                               std::span<const unsigned char> pubkey, SigVersion,
                               ScriptExecutionData&, ScriptError* error) const override
    {
        const bool valid_key{pubkey.size() == m_fixture.pubkey_bytes.size() &&
                             std::equal(pubkey.begin(), pubkey.end(), m_fixture.pubkey_bytes.begin())};
        const bool valid{valid_key && m_fixture.pubkey.VerifySchnorr(m_fixture.message, sig)};
        if (!valid && error) *error = SCRIPT_ERR_SCHNORR_SIG;
        return valid;
    }

    bool CheckLockTime(const CScriptNum&) const override { return true; }
    bool CheckSequence(const CScriptNum&) const override { return true; }

private:
    const CryptoFixture& m_fixture;
};

using StackFactory = std::function<std::vector<valtype>(const CryptoFixture&)>;

struct CaseOptions {
    ScriptError expected_error{SCRIPT_ERR_OK};
    RepeatMode repeat_mode{RepeatMode::MAX_SUCCESS};
    uint64_t fixed_repetitions{0}, max_repetitions{std::numeric_limits<uint64_t>::max()};
    std::optional<size_t> cleanup_items;
    std::string saturation_hint;
    std::optional<uint64_t> expected_varops_per_repeat;
    std::optional<SaturationExpectation> expected_saturation;
};

struct CaseSpec {
    std::string name;
    opcodetype opcode{OP_INVALIDOPCODE};
    std::string opcode_name, sequence_opcodes, operand_shape, operand_pattern;
    HeadlineRole role{HeadlineRole::DIAGNOSTIC};
    ScriptError expected_error{SCRIPT_ERR_OK};
    RepeatMode repeat_mode{RepeatMode::MAX_SUCCESS};
    uint64_t fixed_repetitions{0}, max_repetitions{std::numeric_limits<uint64_t>::max()};
    CScript sequence;
    StackFactory stack_factory;
    std::optional<size_t> cleanup_items;
    std::string saturation_hint;
    std::optional<uint64_t> expected_varops_per_repeat;
    std::optional<SaturationExpectation> expected_saturation;
};

struct MaterializedCase {
    const CaseSpec* spec{nullptr};
    std::vector<valtype> initial_stack;
    CScript script;
    uint64_t repetitions{0}, varops_per_repeat{0};
    std::string saturation;
};

struct EvalOutcome {
    bool success{false};
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    uint64_t varops_consumed{0};
};

struct TimingSample {
    TimingStage stage{TimingStage::DISCOVERY};
    int round{0};
    size_t order{0};
    double wall_sec{0};
};

struct SampleStats {
    double median{0}, minimum{0}, maximum{0}, mdape{0};
};

struct BenchResult {
    std::string name;
    double median_sec{0};
    double mdape{0};
    uint64_t varops_consumed{0};
    ExecutionDomain domain{ExecutionDomain::GSR_TAPSCRIPT_V2};
    HeadlineRole role{HeadlineRole::DIAGNOSTIC};
    std::string opcode_name;
    std::string sequence_opcodes;
    std::string operand_shape;
    std::string operand_pattern;
    uint64_t script_bytes{0};
    uint64_t initial_stack_items{0};
    uint64_t initial_stack_bytes{0};
    ScriptError expected_error{SCRIPT_ERR_OK};
    ScriptError actual_error{SCRIPT_ERR_OK};
    std::string saturation;
    uint64_t repetitions{0};
    uint64_t varops_per_repeat{0};
    std::optional<TimingStage> aggregate_stage;
    std::optional<double> discovery_wall_sec;
    double wall_min_sec{0};
    double wall_max_sec{0};
    bool promoted{false};
    std::vector<std::string> promotion_reasons;
    std::vector<TimingSample> samples;
};

struct CorpusCounts {
    size_t requested_opcodes{0}, generated_cases{0}, completed_cases{0};
};

struct PromotionSummary {
    double promotion_cutoff_seconds{0};
    size_t promoted_cases{0};
};

using ItemFactory = std::function<valtype()>;

static std::string DomainName(ExecutionDomain domain)
{
    switch (domain) {
    case ExecutionDomain::PRE_GSR_TAPSCRIPT: return "pre-gsr-tapscript-v1";
    case ExecutionDomain::GSR_TAPSCRIPT_V2: return "gsr-tapscript-v2";
    case ExecutionDomain::RAW_SCHNORR: return "raw-schnorr";
    }
    return "unknown";
}

static std::string RoleName(HeadlineRole role)
{
    switch (role) {
    case HeadlineRole::PRE_BASELINE: return "pre-baseline";
    case HeadlineRole::NEW_GSR: return "new-gsr";
    case HeadlineRole::COMMON_V2: return "common-v2";
    case HeadlineRole::DIAGNOSTIC: return "diagnostic";
    }
    return "unknown";
}

static ExecutionDomain DomainFor(HeadlineRole role) { return role == HeadlineRole::PRE_BASELINE ? ExecutionDomain::PRE_GSR_TAPSCRIPT : ExecutionDomain::GSR_TAPSCRIPT_V2; }

static std::string FormatBytes(uint64_t bytes)
{
    if (bytes >= 1024 * 1024 && bytes % (1024 * 1024) == 0) {
        return strprintf("%uMB", bytes / (1024 * 1024));
    }
    if (bytes >= 1024 && bytes % 1024 == 0) {
        return strprintf("%uKB", bytes / 1024);
    }
    return strprintf("%uB", bytes);
}

static std::string OpcodeName(opcodetype opcode)
{
    return opcode == OP_0 ? "OP_0" : GetOpName(opcode);
}

static std::string SequenceOpcodeNames(const CScript& sequence)
{
    std::string names;
    CScript::const_iterator pc{sequence.begin()};
    while (pc != sequence.end()) {
        opcodetype opcode;
        valtype pushed_data;
        if (!sequence.GetOp(pc, opcode, pushed_data)) {
            throw std::runtime_error("invalid benchmark sequence");
        }

        if (!names.empty()) names += "+";
        if (opcode == OP_0) {
            names += "OP_0";
        } else if (opcode > OP_0 && opcode < OP_PUSHDATA1) {
            names += strprintf("OP_PUSHBYTES_%u", pushed_data.size());
        } else if (opcode == OP_1NEGATE) {
            names += "OP_1NEGATE";
        } else if (opcode >= OP_1 && opcode <= OP_16) {
            names += strprintf("OP_%u", CScript::DecodeOP_N(opcode));
        } else {
            names += GetOpName(opcode);
        }
    }
    return names;
}

static valtype PaddedNumber(uint64_t value, size_t size)
{
    valtype bytes(std::max<size_t>(size, 1), 0);
    for (size_t i{0}; i < std::min<size_t>(sizeof(value), bytes.size()); ++i) {
        bytes[i] = static_cast<unsigned char>(value & 0xff);
        value >>= 8;
    }
    if (size == 0) bytes.clear();
    return bytes;
}

static valtype PatternBytes(size_t size, std::string_view pattern)
{
    if (pattern == "zero") return valtype(size, 0x00);
    if (pattern == "one-low" || pattern == "padded-low") return PaddedNumber(1, size);
    if (pattern == "late-nonzero") {
        valtype out(size, 0x00);
        if (!out.empty()) out.back() = 0x01;
        return out;
    }
    if (pattern == "alternating") {
        valtype out(size);
        for (size_t i{0}; i < size; ++i)
            out[i] = (i & 1) ? 0x55 : 0xaa;
        return out;
    }
    return valtype(size, 0xff);
}

static uint64_t StackPayloadBytes(const std::vector<valtype>& stack)
{
    uint64_t total{0};
    for (const valtype& item : stack)
        total += item.size();
    return total;
}

static uint64_t StackFixtureBytes(const std::vector<valtype>& stack) { return StackPayloadBytes(stack) + uint64_t{stack.size()} * sizeof(valtype); }

static void ReleaseAllocatorCaches()
{
#if defined(__APPLE__)
    malloc_zone_pressure_relief(nullptr, 0);
#elif defined(__GLIBC__)
    malloc_trim(0);
#endif
}

static bool InitialStackAllowed(ExecutionDomain domain, const std::vector<valtype>& stack)
{
    if (domain == ExecutionDomain::RAW_SCHNORR) return stack.empty();
    if (domain == ExecutionDomain::PRE_GSR_TAPSCRIPT) {
        if (stack.size() > MAX_STACK_SIZE) return false;
        return std::ranges::all_of(stack, [](const valtype& item) {
            return item.size() <= MAX_SCRIPT_ELEMENT_SIZE;
        });
    }

    if (stack.size() > MAX_TAPSCRIPT_V2_STACK_SIZE) return false;
    uint64_t total{0};
    for (const valtype& item : stack) {
        if (item.size() > MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE) return false;
        if (item.size() > MAX_TAPSCRIPT_V2_TOTAL_STACK_SIZE - total) return false;
        total += item.size();
    }
    return true;
}

static bool NumericOperandAllowed(ExecutionDomain domain, size_t size, bool timelock)
{
    if (domain == ExecutionDomain::GSR_TAPSCRIPT_V2) {
        return size <= MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE;
    }
    return size <= (timelock ? 5U : 4U);
}

static SaturationBoundaries FindCrossoverPair(size_t sequence_bytes, size_t cleanup_items, size_t maximum,
                                              const std::function<uint64_t(size_t)>& sequence_cost)
{
    if (sequence_bytes == 0 || cleanup_items + 1 >= SCRIPT_BYTES || maximum < 2) {
        throw std::runtime_error("invalid crossover search bounds");
    }
    const uint64_t script_limit{(SCRIPT_BYTES - cleanup_items - 1) / sequence_bytes};
    const uint64_t available_budget{TOTAL_VAROPS_BUDGET - varops::CompareZeroCost(1)};
    const auto script_limited = [&](size_t size) {
        const uint64_t cost{sequence_cost(size)};
        return cost == 0 || available_budget / cost >= script_limit;
    };
    if (!script_limited(1) || script_limited(maximum)) {
        throw std::runtime_error("crossover search does not bracket a transition");
    }

    size_t low{1};
    size_t high{maximum};
    while (low < high) {
        const size_t mid{low + (high - low) / 2};
        if (script_limited(mid)) {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    return {{{low - 1, SaturationExpectation::SCRIPT_BYTES},
             {low, SaturationExpectation::VAROPS_BUDGET}}};
}

static std::string_view SaturationName(SaturationExpectation expectation) { return expectation == SaturationExpectation::SCRIPT_BYTES ? "script-bytes" : "varops-budget"; }
static void Check(bool condition, std::string_view error)
{
    if (!condition) throw std::runtime_error(std::string{error});
}

static void RunBoundarySelfChecks()
{
    const std::vector<valtype> pre_1000(MAX_STACK_SIZE, valtype{});
    const std::vector<valtype> pre_1001(MAX_STACK_SIZE + 1, valtype{});
    const std::vector<valtype> v2_32768(MAX_TAPSCRIPT_V2_STACK_SIZE, valtype{});
    const std::vector<valtype> v2_32769(MAX_TAPSCRIPT_V2_STACK_SIZE + 1, valtype{});
    Check(InitialStackAllowed(ExecutionDomain::PRE_GSR_TAPSCRIPT, pre_1000) &&
              !InitialStackAllowed(ExecutionDomain::PRE_GSR_TAPSCRIPT, pre_1001) &&
              InitialStackAllowed(ExecutionDomain::GSR_TAPSCRIPT_V2, v2_32768) &&
              !InitialStackAllowed(ExecutionDomain::GSR_TAPSCRIPT_V2, v2_32769) &&
              InitialStackAllowed(ExecutionDomain::PRE_GSR_TAPSCRIPT, {valtype(520)}) &&
              !InitialStackAllowed(ExecutionDomain::PRE_GSR_TAPSCRIPT, {valtype(521)}) &&
              InitialStackAllowed(ExecutionDomain::GSR_TAPSCRIPT_V2, {valtype(521)}),
          "internal initial-stack boundary classification failed");
    Check(NumericOperandAllowed(ExecutionDomain::PRE_GSR_TAPSCRIPT, 4, false) &&
              !NumericOperandAllowed(ExecutionDomain::PRE_GSR_TAPSCRIPT, 5, false) &&
              NumericOperandAllowed(ExecutionDomain::PRE_GSR_TAPSCRIPT, 5, true) &&
              NumericOperandAllowed(ExecutionDomain::GSR_TAPSCRIPT_V2, 521, false),
          "internal numeric boundary classification failed");
    const auto crossover{FindCrossoverPair(1, 1, 10'000, [](size_t size) { return 2 * size; })};
    Check(crossover[0].first == 5'000 && crossover[1].first == 5'001,
          "internal crossover classification failed");
    Check(6 * MAX_THREE_WAY_ELEMENT_SIZE + 1 <= MAX_TAPSCRIPT_V2_TOTAL_STACK_SIZE &&
              6 * (MAX_THREE_WAY_ELEMENT_SIZE + 1) + 1 > MAX_TAPSCRIPT_V2_TOTAL_STACK_SIZE,
          "internal three-way stack boundary classification failed");
}

struct PreparedExecution {
    std::vector<valtype> legacy_stack;
    std::optional<ValtypeStack> v2_stack;
    ScriptExecutionData execdata;
    std::unique_ptr<varops::Budget> budget;
};

static PreparedExecution PrepareExecution(const MaterializedCase& test_case, bool timed = false)
{
    PreparedExecution execution;
    const bool legacy{DomainFor(test_case.spec->role) == ExecutionDomain::PRE_GSR_TAPSCRIPT};
    if (legacy || timed) {
        execution.execdata.m_validation_weight_left = MAX_BLOCK_WEIGHT;
        execution.execdata.m_validation_weight_left_init = true;
    }
    if (legacy) {
        execution.legacy_stack = test_case.initial_stack;
    } else {
        execution.v2_stack.emplace(test_case.initial_stack);
        execution.budget = std::make_unique<varops::Budget>(TOTAL_VAROPS_BUDGET);
    }
    return execution;
}

static EvalOutcome ExecutePrepared(const MaterializedCase& test_case, const BenchSignatureChecker& checker,
                                   PreparedExecution& execution)
{
    EvalOutcome outcome;
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    if (DomainFor(test_case.spec->role) == ExecutionDomain::PRE_GSR_TAPSCRIPT) {
        bool success{EvalScript(execution.legacy_stack, test_case.script, BENCH_SCRIPT_VERIFY_FLAGS,
                                checker, SigVersion::TAPSCRIPT, execution.execdata, &error)};
        if (success && execution.legacy_stack.size() != 1) {
            success = false;
            error = SCRIPT_ERR_CLEANSTACK;
        } else if (success && !CastToBool(execution.legacy_stack.back())) {
            success = false;
            error = SCRIPT_ERR_EVAL_FALSE;
        }
        outcome.success = success;
        outcome.error = success ? SCRIPT_ERR_OK : error;
        return outcome;
    }

    bool success{EvalTapscriptV2(*execution.v2_stack, test_case.script, BENCH_SCRIPT_VERIFY_FLAGS,
                                 checker, execution.execdata, *execution.budget, &error)};
    if (success) success = CheckTapscriptV2ScriptResult(*execution.v2_stack, *execution.budget, &error);
    outcome.success = success;
    outcome.error = error;
    outcome.varops_consumed = TOTAL_VAROPS_BUDGET - *execution.budget->Remaining();
    return outcome;
}

static EvalOutcome Evaluate(const MaterializedCase& test_case, const BenchSignatureChecker& checker)
{
    PreparedExecution execution{PrepareExecution(test_case)};
    return ExecutePrepared(test_case, checker, execution);
}

static CScript BuildScript(const CScript& sequence, uint64_t repetitions, size_t cleanup_items)
{
    if (cleanup_items >= SCRIPT_BYTES) throw std::runtime_error("cleanup suffix exceeds script envelope");
    const size_t suffix_size{cleanup_items + 1};
    if (!sequence.empty() && repetitions > (SCRIPT_BYTES - suffix_size) / sequence.size()) {
        throw std::runtime_error("sequence repetitions exceed script envelope");
    }

    CScript script;
    script.reserve(SCRIPT_BYTES);
    for (uint64_t i{0}; i < repetitions; ++i) {
        script.insert(script.end(), sequence.begin(), sequence.end());
    }
    const size_t padding{SCRIPT_BYTES - script.size() - suffix_size};
    script.insert(script.end(), padding, static_cast<unsigned char>(OP_NOP));
    script.insert(script.end(), cleanup_items, static_cast<unsigned char>(OP_DROP));
    script << OP_1;
    if (script.size() != SCRIPT_BYTES) throw std::runtime_error("script envelope construction failed");
    return script;
}

static uint64_t CalibrateRepeatVarops(const CaseSpec& spec, const std::vector<valtype>& stack,
                                      const BenchSignatureChecker& checker)
{
    if (DomainFor(spec.role) != ExecutionDomain::GSR_TAPSCRIPT_V2 || spec.sequence.empty()) return 0;
    MaterializedCase calibration;
    calibration.spec = &spec;
    calibration.initial_stack = stack;
    calibration.repetitions = 1;
    calibration.script = spec.sequence;
    const size_t cleanup_items{spec.cleanup_items.value_or(stack.size())};
    calibration.script.insert(calibration.script.end(), cleanup_items, static_cast<unsigned char>(OP_DROP));
    calibration.script << OP_1;
    const EvalOutcome outcome{Evaluate(calibration, checker)};
    if (!outcome.success || outcome.error != SCRIPT_ERR_OK) {
        throw std::runtime_error(strprintf("one-sequence calibration failed for %s: %s",
                                           spec.name, ScriptErrorString(outcome.error)));
    }
    const uint64_t final_cost{varops::CompareZeroCost(1)};
    if (outcome.varops_consumed < final_cost) {
        throw std::runtime_error("calibration consumed less than the final-result cost");
    }
    return outcome.varops_consumed - final_cost;
}

static MaterializedCase Materialize(const CaseSpec& spec, const CryptoFixture& fixture)
{
    MaterializedCase materialized;
    materialized.spec = &spec;
    materialized.initial_stack = spec.stack_factory(fixture);
    if (!InitialStackAllowed(DomainFor(spec.role), materialized.initial_stack)) {
        throw std::runtime_error(strprintf("%s has an invalid initial stack for %s",
                                           spec.name, DomainName(DomainFor(spec.role))));
    }

    const size_t cleanup_items{spec.cleanup_items.value_or(materialized.initial_stack.size())};
    const size_t suffix_size{cleanup_items + 1};
    const uint64_t script_limit{spec.sequence.empty() ? 0 : (SCRIPT_BYTES - suffix_size) / spec.sequence.size()};
    BenchSignatureChecker checker{fixture};
    if (spec.expected_error == SCRIPT_ERR_OK || spec.repeat_mode == RepeatMode::VAROP_REJECTION) {
        materialized.varops_per_repeat = CalibrateRepeatVarops(spec, materialized.initial_stack, checker);
    }
    if (spec.expected_varops_per_repeat && materialized.varops_per_repeat != *spec.expected_varops_per_repeat) {
        throw std::runtime_error(strprintf("sequence varops mismatch for %s: expected %u, got %u",
                                           spec.name, *spec.expected_varops_per_repeat,
                                           materialized.varops_per_repeat));
    }

    if (spec.repeat_mode == RepeatMode::FIXED) {
        materialized.repetitions = spec.fixed_repetitions;
        materialized.saturation = spec.saturation_hint;
    } else if (spec.repeat_mode == RepeatMode::VAROP_REJECTION) {
        if (materialized.varops_per_repeat == 0) {
            throw std::runtime_error(strprintf("%s requests varops rejection with a zero-cost sequence", spec.name));
        }
        materialized.repetitions = TOTAL_VAROPS_BUDGET / materialized.varops_per_repeat + 1;
        materialized.saturation = "varops-limit";
    } else {
        uint64_t budget_limit{std::numeric_limits<uint64_t>::max()};
        if (DomainFor(spec.role) == ExecutionDomain::GSR_TAPSCRIPT_V2 && materialized.varops_per_repeat != 0) {
            const uint64_t final_cost{varops::CompareZeroCost(1)};
            budget_limit = (TOTAL_VAROPS_BUDGET - final_cost) / materialized.varops_per_repeat;
        }
        materialized.repetitions = std::min({script_limit, budget_limit, spec.max_repetitions});
        if (materialized.repetitions == budget_limit && budget_limit < script_limit) {
            materialized.saturation = "varops-budget";
        } else if (materialized.repetitions == spec.max_repetitions && spec.max_repetitions < script_limit) {
            materialized.saturation = spec.saturation_hint.empty() ? "explicit-limit" : spec.saturation_hint;
        } else {
            materialized.saturation = "script-bytes";
        }
    }

    if (spec.expected_saturation && materialized.saturation != SaturationName(*spec.expected_saturation)) {
        throw std::runtime_error(strprintf("saturation mismatch for %s: expected %s, got %s",
                                           spec.name, SaturationName(*spec.expected_saturation),
                                           materialized.saturation));
    }

    if (!spec.sequence.empty() && materialized.repetitions == 0) {
        throw std::runtime_error(strprintf("%s cannot execute its target sequence", spec.name));
    }
    if (!spec.sequence.empty() && materialized.repetitions > script_limit) {
        throw std::runtime_error(strprintf("%s cannot reach its requested termination inside 4MB", spec.name));
    }
    materialized.script = BuildScript(spec.sequence, materialized.repetitions, cleanup_items);
    return materialized;
}

static bool IsResourceError(ScriptError error)
{
    switch (error) {
    case SCRIPT_ERR_STACK_SIZE:
    case SCRIPT_ERR_PUSH_SIZE:
    case SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT:
    case SCRIPT_ERR_VAROP_COUNT:
    case SCRIPT_ERR_TOTAL_STACK_SIZE:
    case SCRIPT_ERR_STACK_ELEMENT_SIZE:
    case SCRIPT_ERR_HASH_OPERAND_SIZE:
        return true;
    default:
        return false;
    }
}

static CScript Ops(std::initializer_list<opcodetype> opcodes)
{
    CScript script;
    for (const opcodetype opcode : opcodes)
        script << opcode;
    return script;
}

static void AddCase(std::vector<CaseSpec>& specs, opcodetype opcode, HeadlineRole role,
                    std::string case_label, std::string shape,
                    std::string pattern, CScript sequence, StackFactory stack_factory,
                    CaseOptions options = {})
{
    const std::string opcode_name{OpcodeName(opcode)};
    const std::string sequence_opcodes{SequenceOpcodeNames(sequence)};
    const std::string name{strprintf("%s/%s/%s/%s/%s/%s/%s", DomainName(DomainFor(role)), opcode_name,
                                     sequence_opcodes, case_label, shape, pattern, ScriptErrorString(options.expected_error))};
    specs.push_back({name, opcode, opcode_name, sequence_opcodes, std::move(shape), std::move(pattern),
                     role, options.expected_error, options.repeat_mode,
                     options.fixed_repetitions, options.max_repetitions, std::move(sequence),
                     std::move(stack_factory), options.cleanup_items, std::move(options.saturation_hint),
                     options.expected_varops_per_repeat, options.expected_saturation});
}

static CaseOptions FixedCase(ScriptError error, uint64_t repetitions, std::optional<size_t> cleanup_items,
                             std::string saturation)
{
    CaseOptions options{};
    options.expected_error = error;
    options.repeat_mode = RepeatMode::FIXED;
    options.fixed_repetitions = repetitions;
    options.max_repetitions = repetitions;
    options.cleanup_items = cleanup_items;
    options.saturation_hint = std::move(saturation);
    return options;
}

static CaseOptions VaropsRejection(std::optional<uint64_t> expected_cost = std::nullopt)
{
    CaseOptions options{};
    options.expected_error = SCRIPT_ERR_VAROP_COUNT;
    options.repeat_mode = RepeatMode::VAROP_REJECTION;
    options.expected_varops_per_repeat = expected_cost;
    return options;
}

static ItemFactory CompactItem(valtype item)
{
    const size_t size{item.size()};
    if (item.size() <= 1024) {
        return [item = std::move(item)] { return item; };
    }

    if (std::ranges::all_of(item, [&](unsigned char byte) { return byte == item.front(); })) {
        const unsigned char fill{item.front()};
        return [size, fill] { return valtype(size, fill); };
    }

    if (std::ranges::all_of(item, [index = size_t{0}](unsigned char byte) mutable {
            return byte == ((index++ & 1) ? 0x55 : 0xaa);
        })) {
        return [size] {
            valtype expanded(size);
            for (size_t index{0}; index < size; ++index)
                expanded[index] = (index & 1) ? 0x55 : 0xaa;
            return expanded;
        };
    }

    std::vector<std::pair<size_t, unsigned char>> exceptions;
    for (size_t index{0}; index < size; ++index) {
        if (item[index] != 0) exceptions.emplace_back(index, item[index]);
        if (exceptions.size() > 64) {
            return [item = std::move(item)] { return item; };
        }
    }
    return [size, exceptions = std::move(exceptions)] {
        valtype expanded(size, 0);
        for (const auto& [index, byte] : exceptions) {
            expanded[index] = byte;
        }
        return expanded;
    };
}

static StackFactory FixedStack(std::vector<valtype> stack)
{
    const uint64_t expanded_bytes{StackPayloadBytes(stack)};
    std::vector<ItemFactory> factories;
    factories.reserve(stack.size());
    for (valtype& item : stack)
        factories.push_back(CompactItem(std::move(item)));
    stack.clear();
    stack.shrink_to_fit();
    if (expanded_bytes >= 1024U * 1024U) ReleaseAllocatorCaches();
    return [factories = std::move(factories)](const CryptoFixture&) {
        std::vector<valtype> expanded;
        expanded.reserve(factories.size());
        for (const ItemFactory& factory : factories)
            expanded.push_back(factory());
        return expanded;
    };
}

static void AddPreAndV2Cases(std::vector<CaseSpec>& specs, opcodetype opcode,
                             std::string case_label, std::string shape, std::string pattern,
                             const CScript& sequence, StackFactory factory)
{
    AddCase(specs, opcode, HeadlineRole::PRE_BASELINE,
            case_label, shape, pattern, sequence, factory);
    AddCase(specs, opcode, HeadlineRole::COMMON_V2,
            std::move(case_label), std::move(shape), std::move(pattern), sequence, std::move(factory));
}

static void AddCostCase(std::vector<CaseSpec>& specs, opcodetype opcode, HeadlineRole role,
                        std::string case_label, std::string shape, std::string pattern,
                        const CScript& sequence, StackFactory factory, uint64_t expected_varops_per_repeat,
                        std::optional<SaturationExpectation> expected_saturation = std::nullopt)
{
    CaseOptions options{};
    options.expected_varops_per_repeat = expected_varops_per_repeat;
    options.expected_saturation = expected_saturation;
    AddCase(specs, opcode, role, std::move(case_label), std::move(shape), std::move(pattern),
            sequence, std::move(factory), std::move(options));
}

template <typename Cost, typename Stack, typename Shape>
static void AddCostCrossovers(std::vector<CaseSpec>& specs, opcodetype opcode,
                              std::string_view label, std::string_view pattern,
                              const CScript& sequence, size_t cleanup_items, size_t maximum,
                              Cost cost, Stack stack, Shape shape)
{
    for (const auto& [size, saturation] :
         FindCrossoverPair(sequence.size(), cleanup_items, maximum, cost)) {
        AddCostCase(specs, opcode, HeadlineRole::NEW_GSR, std::string{label}, shape(size),
                    std::string{pattern}, sequence, stack(size), cost(size), saturation);
    }
}

static CScript OneToOneSequence(opcodetype opcode, bool three_way) { return three_way ? Ops({OP_3DUP, opcode, OP_DROP, opcode, OP_DROP, opcode, OP_DROP}) : Ops({OP_DUP, opcode, OP_DROP}); }

static uint64_t OneToOneTargetCost(opcodetype opcode, size_t size)
{
    switch (opcode) {
    case OP_1ADD: return varops::AddCost(size, 1);
    case OP_1SUB: return varops::SubCost(size, 1);
    case OP_NOT:
    case OP_0NOTEQUAL: return varops::CompareZeroCost(size);
    case OP_INVERT: return varops::InvertCost(size);
    case OP_2MUL: return varops::TwoMulCost(size);
    case OP_2DIV: return varops::TwoDivCost(size);
    case OP_RIPEMD160:
    case OP_SHA1: return 0;
    case OP_SHA256:
    case OP_HASH160:
    case OP_HASH256: return size * varops::COST_HASH;
    default: throw std::runtime_error("unsupported one-to-one opcode");
    }
}

static uint64_t OneToOneSequenceCost(opcodetype opcode, size_t size, bool three_way)
{
    const uint64_t transforms{three_way ? 3U : 1U};
    return transforms * size * varops::COST_COPYING +
           transforms * OneToOneTargetCost(opcode, size);
}

static uint64_t TruthCopyCost(size_t size) { return size * varops::COST_COPYING + varops::CompareZeroCost(size); }
static StackFactory OneToOneStack(size_t size, std::string_view pattern, bool three_way) { return FixedStack(std::vector<valtype>(three_way ? 3U : 1U, PatternBytes(size, pattern))); }

static void AddOneToOneSpec(std::vector<CaseSpec>& specs, opcodetype opcode, HeadlineRole role,
                            std::string_view family, size_t size, std::string pattern, bool three_way,
                            std::optional<SaturationExpectation> expected_saturation = std::nullopt)
{
    const CScript sequence{OneToOneSequence(opcode, three_way)};
    const std::string case_label{strprintf("%s-%s", family, three_way ? "3way" : "single")};
    const std::optional<uint64_t> expected_varops_per_repeat{
        DomainFor(role) == ExecutionDomain::GSR_TAPSCRIPT_V2 ? std::optional<uint64_t>{OneToOneSequenceCost(opcode, size, three_way)} : std::nullopt};
    StackFactory factory{OneToOneStack(size, pattern, three_way)};
    CaseOptions options{};
    options.expected_varops_per_repeat = expected_varops_per_repeat;
    options.expected_saturation = expected_saturation;
    AddCase(specs, opcode, role, case_label, FormatBytes(size), std::move(pattern), sequence,
            std::move(factory), std::move(options));
}

static void AddOneToOneCrossovers(std::vector<CaseSpec>& specs, opcodetype opcode,
                                  HeadlineRole role, std::string_view label, std::string_view pattern,
                                  size_t maximum, bool three_way,
                                  std::optional<HeadlineRole> script_role = std::nullopt)
{
    const CScript sequence{OneToOneSequence(opcode, three_way)};
    const auto cost{[=](size_t size) { return OneToOneSequenceCost(opcode, size, three_way); }};
    for (const auto& [size, saturation] :
         FindCrossoverPair(sequence.size(), three_way ? 3 : 1, maximum, cost)) {
        if (script_role) {
            AddOneToOneSpec(specs, opcode, *script_role, label, size, std::string{pattern},
                            three_way, SaturationExpectation::SCRIPT_BYTES);
        }
        AddOneToOneSpec(specs, opcode, role, label, size, std::string{pattern}, three_way, saturation);
    }
}

static std::vector<size_t> SelectSizes(std::initializer_list<size_t> full,
                                       size_t maximum = std::numeric_limits<size_t>::max())
{
    std::vector<size_t> sizes{full};
    std::erase_if(sizes, [maximum](size_t size) { return size > maximum; });
    std::sort(sizes.begin(), sizes.end());
    sizes.erase(std::unique(sizes.begin(), sizes.end()), sizes.end());
    return sizes;
}

static std::vector<size_t> PreDataSizes() { return SelectSizes({0, 1, 3, 4, 5, 7, 8, 9, 15, 16, 17, 519, 520}); }
static std::vector<size_t> PreNumericSizes() { return SelectSizes({1, 3, 4}); }
static std::vector<size_t> PreCompareSizes() { return SelectSizes({0, 1, 3, 4, 5, 7, 8, 9, 16, 17, 519, 520}); }
static std::vector<size_t> V2NumericSizes(size_t maximum) { return SelectSizes({5, 7, 8, 9, 15, 16, 17, 519, 520, 521, 1024, 4096, 65536, 262144, 1048576, 2000000, maximum}, maximum); }
static std::vector<size_t> V2LargeSizes(size_t maximum) { return SelectSizes({521, 1024, 4096, 65536, 262144, 1048576, 2000000, maximum}, maximum); }

static void AddUnaryDataCases(std::vector<CaseSpec>& specs, opcodetype opcode,
                              bool restored, size_t maximum = MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE)
{
    if (!restored) {
        for (size_t size : PreNumericSizes()) {
            const std::string pattern{"padded-low"};
            AddOneToOneSpec(specs, opcode, HeadlineRole::PRE_BASELINE,
                            "unary-preserve", size, pattern, true);
            AddOneToOneSpec(specs, opcode, HeadlineRole::COMMON_V2,
                            "unary-preserve", size, pattern, true);
        }
    }
    for (size_t size : V2NumericSizes(maximum)) {
        const std::string pattern{size == maximum ? "late-nonzero" : "padded-low"};
        AddOneToOneSpec(specs, opcode, HeadlineRole::NEW_GSR, "unary-preserve", size,
                        pattern, size <= MAX_THREE_WAY_ELEMENT_SIZE);
    }
    if ((opcode == OP_2MUL || opcode == OP_2DIV)) {
        AddOneToOneSpec(specs, opcode, HeadlineRole::NEW_GSR, "unary-preserve", maximum,
                        "padded-low", false);
    }
    AddOneToOneCrossovers(specs, opcode, HeadlineRole::NEW_GSR, "unary-crossover",
                          "padded-low", MAX_THREE_WAY_ELEMENT_SIZE, true);
    AddOneToOneCrossovers(specs, opcode, HeadlineRole::NEW_GSR, "unary-crossover-control",
                          "padded-low", MAX_THREE_WAY_ELEMENT_SIZE, false);

    AddOneToOneSpec(specs, opcode, HeadlineRole::NEW_GSR, "unary-batch-boundary",
                    MAX_THREE_WAY_ELEMENT_SIZE, "dense", true);
}

static void AddBinaryDataCases(std::vector<CaseSpec>& specs, opcodetype opcode,
                               bool restored, size_t maximum = 2'000'000)
{
    const bool verify_opcode{opcode == OP_EQUALVERIFY || opcode == OP_NUMEQUALVERIFY};
    const bool byte_compare{opcode == OP_EQUAL || opcode == OP_EQUALVERIFY};
    const CScript sequence{verify_opcode ? Ops({OP_2DUP, opcode}) : Ops({OP_2DUP, opcode, OP_DROP})};
    if (!restored) {
        for (size_t size : byte_compare ? PreCompareSizes() : PreNumericSizes()) {
            const std::string pattern{opcode == OP_EQUAL || opcode == OP_EQUALVERIFY ? "equal" : "padded-low"};
            valtype first{PatternBytes(size, pattern == "equal" ? "alternating" : "padded-low")};
            valtype second{first};
            if (opcode == OP_SUB) first = PaddedNumber(3, size);
            if (opcode == OP_SUB) second = PaddedNumber(1, size);
            AddPreAndV2Cases(specs, opcode, "binary-preserve", FormatBytes(size) + "x" + FormatBytes(size),
                             pattern, sequence, FixedStack({first, second}));
        }
    }
    for (size_t size : byte_compare ? V2LargeSizes(maximum) : V2NumericSizes(maximum)) {
        valtype first{PatternBytes(size, "alternating")};
        valtype second{first};
        if (opcode == OP_SUB) {
            first = PaddedNumber(3, size);
            second = PaddedNumber(1, size);
        }
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "binary-preserve", FormatBytes(size) + "x" + FormatBytes(size), "equal-dense",
                sequence, FixedStack({first, second}));
    }
    if ((opcode == OP_MIN || opcode == OP_MAX)) {
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "binary-preserve", FormatBytes(maximum) + "x" + FormatBytes(maximum), "equal-padded-low",
                sequence, FixedStack({PaddedNumber(1, maximum), PaddedNumber(1, maximum)}));
    }
    if (maximum >= 65536 && opcode != OP_EQUALVERIFY) {
        const bool numeric_verify{opcode == OP_NUMEQUALVERIFY};
        const bool subtraction{opcode == OP_SUB};
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "binary-preserve", "64KBx1B", "asymmetric-long-short", sequence,
                FixedStack({subtraction ? PaddedNumber(3, 65536) : (numeric_verify ? PaddedNumber(1, 65536) : PatternBytes(65536, "alternating")),
                            subtraction ? PaddedNumber(1, 1) : PatternBytes(1, "one-low")}));
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "binary-preserve", "1Bx64KB", "asymmetric-short-long", sequence,
                FixedStack({subtraction ? PaddedNumber(3, 1) : PatternBytes(1, "one-low"),
                            subtraction ? PaddedNumber(1, 65536) : (numeric_verify ? PaddedNumber(1, 65536) : PatternBytes(65536, "alternating"))}));
    }
}

static void AddStackOpcodeCases(std::vector<CaseSpec>& specs, opcodetype opcode)
{
    const auto add_shared_case = [&](std::string case_label, CScript sequence, std::vector<valtype> stack) {
        AddPreAndV2Cases(specs, opcode, std::move(case_label), "32B", "dense", sequence,
                         FixedStack(std::move(stack)));
    };
    switch (opcode) {
    case OP_TOALTSTACK:
    case OP_FROMALTSTACK:
        add_shared_case("altstack-roundtrip", Ops({OP_TOALTSTACK, OP_FROMALTSTACK}), {PatternBytes(32, "dense")});
        break;
    case OP_DROP: add_shared_case("dup-drop", Ops({OP_DUP, OP_DROP}), {PatternBytes(32, "dense")}); break;
    case OP_2DROP: add_shared_case("2dup-2drop", Ops({OP_2DUP, OP_2DROP}), {PatternBytes(32, "dense"), PatternBytes(32, "dense")}); break;
    case OP_DUP: add_shared_case("dup-drop", Ops({OP_DUP, OP_DROP}), {PatternBytes(32, "dense")}); break;
    case OP_2DUP: add_shared_case("2dup-2drop", Ops({OP_2DUP, OP_2DROP}), {PatternBytes(32, "dense"), PatternBytes(32, "dense")}); break;
    case OP_3DUP: add_shared_case("3dup-cleanup", Ops({OP_3DUP, OP_2DROP, OP_DROP}), {PatternBytes(32, "dense"), PatternBytes(32, "dense"), PatternBytes(32, "dense")}); break;
    case OP_OVER: add_shared_case("over-drop", Ops({OP_OVER, OP_DROP}), {PatternBytes(32, "dense"), PatternBytes(32, "dense")}); break;
    case OP_2OVER: add_shared_case("2over-2drop", Ops({OP_2OVER, OP_2DROP}), std::vector<valtype>(4, PatternBytes(32, "dense"))); break;
    case OP_IFDUP: {
        const CScript true_sequence{Ops({OP_IFDUP, OP_DROP})};
        AddPreAndV2Cases(specs, opcode, "ifdup-drop", "1B", "true", true_sequence,
                         FixedStack({valtype{1}}));
        const CScript false_sequence{Ops({OP_IFDUP})};
        AddCase(specs, opcode, HeadlineRole::PRE_BASELINE,
                "ifdup-true", "520B", "late-nonzero", true_sequence,
                FixedStack({PatternBytes(520, "late-nonzero")}));
        AddCostCase(specs, opcode, HeadlineRole::COMMON_V2,
                    "ifdup-true", "520B", "late-nonzero", true_sequence,
                    FixedStack({PatternBytes(520, "late-nonzero")}), TruthCopyCost(520));
        AddCase(specs, opcode, HeadlineRole::PRE_BASELINE,
                "ifdup-false", "520B", "zero", false_sequence,
                FixedStack({PatternBytes(520, "zero")}));
        AddCostCase(specs, opcode, HeadlineRole::COMMON_V2,
                    "ifdup-false", "520B", "zero", false_sequence,
                    FixedStack({PatternBytes(520, "zero")}), TruthCopyCost(520));

        AddCostCrossovers(specs, opcode, "ifdup-true-crossover", "late-nonzero", true_sequence, 1, MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, TruthCopyCost, [](size_t size) { return FixedStack({PatternBytes(size, "late-nonzero")}); }, FormatBytes);
        AddCostCrossovers(specs, opcode, "ifdup-false-crossover", "zero", false_sequence, 1, MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, TruthCopyCost, [](size_t size) { return FixedStack({PatternBytes(size, "zero")}); }, FormatBytes);
        AddCostCase(specs, opcode, HeadlineRole::NEW_GSR,
                    "ifdup-true-scale-tail", "4MB", "late-nonzero", true_sequence,
                    FixedStack({PatternBytes(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, "late-nonzero")}),
                    TruthCopyCost(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE));
        break;
    }
    case OP_NIP: add_shared_case("2dup-nip-drop", Ops({OP_2DUP, OP_NIP, OP_DROP}), {PatternBytes(32, "dense"), PatternBytes(32, "dense")}); break;
    case OP_TUCK: add_shared_case("tuck-drop-swap", Ops({OP_TUCK, OP_DROP, OP_SWAP}), {PatternBytes(32, "dense"), PatternBytes(32, "dense")}); break;
    case OP_SWAP: add_shared_case("swap-twice", Ops({OP_SWAP, OP_SWAP}), {PatternBytes(32, "dense"), PatternBytes(32, "dense")}); break;
    case OP_2SWAP: add_shared_case("2swap-twice", Ops({OP_2SWAP, OP_2SWAP}), std::vector<valtype>(4, PatternBytes(32, "dense"))); break;
    case OP_ROT: add_shared_case("rot-thrice", Ops({OP_ROT, OP_ROT, OP_ROT}), std::vector<valtype>(3, PatternBytes(32, "dense"))); break;
    case OP_2ROT: add_shared_case("2rot-thrice", Ops({OP_2ROT, OP_2ROT, OP_2ROT}), std::vector<valtype>(6, PatternBytes(32, "dense"))); break;
    case OP_DEPTH: add_shared_case("depth-drop", Ops({OP_DEPTH, OP_DROP}), {PatternBytes(32, "dense")}); break;
    case OP_PICK: {
        add_shared_case("pick-depth-1", Ops({OP_DUP, OP_PICK, OP_DROP}),
                        {PatternBytes(32, "dense"), PatternBytes(32, "alternating"), Val64(1).MoveToValtype()});
        AddCase(specs, opcode, HeadlineRole::NEW_GSR, "pick-max-depth-one-shot", "32768-items", "heterogeneous-buried", Ops({OP_PICK}), [](const CryptoFixture&) {
                        std::vector<valtype> stack(MAX_TAPSCRIPT_V2_STACK_SIZE - 1, valtype{0x01});
                        stack.front() = PatternBytes(520, "late-nonzero");
                        stack.push_back(Val64(MAX_TAPSCRIPT_V2_STACK_SIZE - 2).MoveToValtype());
                        return stack; }, FixedCase(SCRIPT_ERR_OK, 1, MAX_TAPSCRIPT_V2_STACK_SIZE, "stack-depth"));
        break;
    }
    case OP_ROLL: {
        CScript roll_one;
        roll_one << OP_1 << OP_ROLL << OP_SWAP;
        add_shared_case("roll-depth-1-neutral", roll_one, {PatternBytes(32, "dense"), PatternBytes(32, "alternating")});
        CaseOptions deep_stack_options{};
        deep_stack_options.expected_saturation = SaturationExpectation::VAROPS_BUDGET;
        AddCase(specs, opcode, HeadlineRole::NEW_GSR, "deep-stack", "1000x4B", "dense",
                Ops({OP_DEPTH, OP_1SUB, OP_ROLL}),
                FixedStack(std::vector<valtype>(1000, PatternBytes(4, "dense"))),
                std::move(deep_stack_options));
        AddCase(specs, opcode, HeadlineRole::NEW_GSR, "roll-max-depth-one-shot", "32768-items", "heterogeneous-buried", Ops({OP_ROLL}), [](const CryptoFixture&) {
                        std::vector<valtype> stack(MAX_TAPSCRIPT_V2_STACK_SIZE - 1, valtype{0x01});
                        stack.front() = PatternBytes(520, "late-nonzero");
                        stack.push_back(Val64(MAX_TAPSCRIPT_V2_STACK_SIZE - 2).MoveToValtype());
                        return stack; }, FixedCase(SCRIPT_ERR_OK, 1, MAX_TAPSCRIPT_V2_STACK_SIZE - 1, "stack-depth"));
        break;
    }
    default: throw std::runtime_error("unhandled stack opcode registry entry");
    }

    if ((opcode == OP_DUP || opcode == OP_2DUP || opcode == OP_OVER)) {
        const CScript sequence{opcode == OP_DUP  ? Ops({OP_DUP, OP_DROP}) :
                               opcode == OP_2DUP ? Ops({OP_2DUP, OP_2DROP}) :
                                                   Ops({OP_OVER, OP_DROP})};
        const size_t count{opcode == OP_DUP ? 1U : 2U};
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "large-copy", opcode == OP_DUP ? "4MB" : "2MBx2", "late-nonzero", sequence,
                [count](const CryptoFixture&) { return std::vector<valtype>(count, PatternBytes(4'000'000 / count, "late-nonzero")); });
        AddCase(specs, opcode, HeadlineRole::NEW_GSR, "large-copy-varops-reject", opcode == OP_DUP ? "4MB" : "2MBx2", "late-nonzero", sequence, [count](const CryptoFixture&) { return std::vector<valtype>(count, PatternBytes(4'000'000 / count, "late-nonzero")); }, VaropsRejection());
    }
}

static void AddHashCases(std::vector<CaseSpec>& specs, opcodetype opcode)
{
    for (size_t size : PreDataSizes()) {
        const std::string pattern{size == 0 ? "zero" : "late-nonzero"};
        AddOneToOneSpec(specs, opcode, HeadlineRole::PRE_BASELINE,
                        "hash-preserve", size, pattern, true);
        AddOneToOneSpec(specs, opcode, HeadlineRole::COMMON_V2,
                        "hash-preserve", size, pattern, true);
    }
    if (opcode == OP_RIPEMD160 || opcode == OP_SHA1) {
        AddCase(specs, opcode, HeadlineRole::DIAGNOSTIC,
                "hash-legacy-limit", "521B", "dense", Ops({opcode}), FixedStack({PatternBytes(521, "dense")}),
                FixedCase(SCRIPT_ERR_HASH_OPERAND_SIZE, 1, 0, "hash-operand-limit"));
        return;
    }
    for (size_t size : V2LargeSizes(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE)) {
        AddOneToOneSpec(specs, opcode, HeadlineRole::NEW_GSR, "hash-preserve", size,
                        "late-nonzero", size <= MAX_THREE_WAY_ELEMENT_SIZE);
    }
    AddOneToOneCrossovers(specs, opcode, HeadlineRole::COMMON_V2, "hash-crossover",
                          "late-nonzero", MAX_SCRIPT_ELEMENT_SIZE, true,
                          HeadlineRole::PRE_BASELINE);
    AddOneToOneCrossovers(specs, opcode, HeadlineRole::NEW_GSR, "hash-crossover-control",
                          "late-nonzero", MAX_THREE_WAY_ELEMENT_SIZE, false);
    AddOneToOneSpec(specs, opcode, HeadlineRole::NEW_GSR, "hash-batch-boundary",
                    MAX_THREE_WAY_ELEMENT_SIZE, "dense", true);

    const CScript sequence{OneToOneSequence(opcode, false)};
    AddCase(specs, opcode, HeadlineRole::NEW_GSR,
            "hash-varops-reject-single", "4MB", "late-nonzero", sequence,
            FixedStack({PatternBytes(4'000'000, "late-nonzero")}),
            VaropsRejection(OneToOneSequenceCost(opcode, 4'000'000, false)));
}

static void AddSpliceCases(std::vector<CaseSpec>& specs, opcodetype opcode)
{
    if (opcode == OP_CAT) {
        const CScript sequence{Ops({OP_2DUP, OP_CAT, OP_DROP})};
        const std::vector<std::pair<size_t, size_t>> shapes{{0, 1}, {1, 1}, {520, 520}, {521, 521}, {65536, 1}, {1, 65536}, {1048576, 1048576}, {2000000, 2000000}};
        for (const auto& [left, right] : shapes) {
            AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                    "cat-preserve", FormatBytes(left) + "+" + FormatBytes(right), "asymmetric-dense", sequence,
                    FixedStack({PatternBytes(left, "alternating"), PatternBytes(right, "late-nonzero")}));
        }
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "cat-element-reject", "2000001B+2000001B", "dense", Ops({OP_CAT}),
                FixedStack({PatternBytes(2'000'001, "dense"), PatternBytes(2'000'001, "dense")}),
                FixedCase(SCRIPT_ERR_STACK_ELEMENT_SIZE, 1, 0, "stack-element-limit"));
        return;
    }

    // Leave room for duplicated, heavily padded offset/length operands while
    // keeping the data operand as close to the 4MB element limit as possible.
    constexpr size_t data_size{3'998'900};
    if (opcode == OP_SUBSTR) {
        const CScript sequence{Ops({OP_3DUP, OP_SUBSTR, OP_DROP})};
        const std::vector<std::tuple<uint64_t, uint64_t, std::string>> params{
            {0, 1, "zero-one"},
            {1, data_size / 2, "one-mid"},
            {data_size / 2, data_size, "mid-past-end"},
        };
        for (const auto& [begin, length, pattern] : params) {
            const size_t numeric_size{pattern == "mid-past-end" ? 521U : 8U};
            AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                    "substr-preserve", FormatBytes(data_size) + ":" + pattern, numeric_size > 8 ? "padded-lengths" : "minimal-lengths",
                    sequence, FixedStack({PatternBytes(data_size, "alternating"), PaddedNumber(begin, numeric_size), PaddedNumber(length, numeric_size)}));
        }
        return;
    }

    const CScript sequence{Ops({OP_2DUP, opcode, OP_DROP})};
    for (const auto& [offset, label] : std::vector<std::pair<uint64_t, std::string>>{
             {0, "zero"}, {1, "one"}, {data_size / 2, "mid"}, {data_size, "end"}, {data_size + 1, "past-end"}}) {
        const size_t numeric_size{label == "past-end" ? 521U : 8U};
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "splice-preserve", FormatBytes(data_size) + ":" + label,
                numeric_size > 8 ? "padded-offset" : "minimal-offset", sequence,
                FixedStack({PatternBytes(data_size, "alternating"), PaddedNumber(offset, numeric_size)}));
    }
}

static size_t LargestAffordable(const std::function<uint64_t(size_t)>& cost, size_t maximum)
{
    size_t low{1};
    size_t high{maximum};
    const uint64_t target{TOTAL_VAROPS_BUDGET * 9 / 10};
    while (low < high) {
        const size_t mid{low + (high - low + 1) / 2};
        if (cost(mid) <= target)
            low = mid;
        else
            high = mid - 1;
    }
    return low;
}

static uint64_t MulSequenceCost(size_t left, size_t right) { return (left + right) * varops::COST_COPYING + varops::MulCost(left, right); }

static void AddMulCases(std::vector<CaseSpec>& specs, opcodetype opcode)
{
    const CScript sequence{Ops({OP_2DUP, opcode, OP_DROP})};
    std::vector<std::pair<size_t, size_t>> shapes{{1, 1}, {109, 109}};
    const size_t largest{LargestAffordable([](size_t size) { return varops::MulCost(size, size); }, 2'000'000)};
    shapes.insert(shapes.end(), {{108, 108}, {110, 110}, {65536, 1}, {1, 65536}, {largest > 1 ? largest - 1 : largest, largest}, {largest, largest}, {largest + 1, largest + 1}});
    for (const auto& [left, right] : shapes) {
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "mul-preserve", FormatBytes(left) + "x" + FormatBytes(right), "dense", sequence,
                FixedStack({PatternBytes(left, "alternating"), PatternBytes(right, "late-nonzero")}));
    }
    for (unsigned int ratio : {1U, 4U, 16U, 0U}) {
        const auto right_size{[ratio](size_t left) {
            return ratio == 0 ? size_t{1} : std::max<size_t>(1, left / ratio);
        }};
        const auto sequence_cost{[&](size_t left) {
            return MulSequenceCost(left, right_size(left));
        }};
        const std::string pattern{ratio == 1 ? "balanced-dense" :
                                  ratio == 0 ? "asymmetric-one-byte" :
                                               strprintf("asymmetric-%u-to-1", ratio)};
        AddCostCrossovers(specs, opcode, "mul-crossover", pattern, sequence, 2, 2'000'000, sequence_cost, [&](size_t left) { return FixedStack({PatternBytes(left, "alternating"),
                                                                                                                                                PatternBytes(right_size(left), "late-nonzero")}); }, [&](size_t left) { return FormatBytes(left) + "x" + FormatBytes(right_size(left)); });
    }
    constexpr size_t tail_left{2'000'000};
    constexpr size_t tail_right{1};
    AddCostCase(specs, opcode, HeadlineRole::NEW_GSR,
                "mul-scale-tail", FormatBytes(tail_left) + "x1B", "asymmetric-long-short",
                sequence, FixedStack({PatternBytes(tail_left, "alternating"), PatternBytes(tail_right, "late-nonzero")}),
                MulSequenceCost(tail_left, tail_right));

    const size_t rejected{LargestAffordable([](size_t size) { return varops::MulCost(size, size); }, 2'000'000)};
    AddCase(specs, opcode, HeadlineRole::NEW_GSR,
            "mul-varops-reject", FormatBytes(rejected), "dense", sequence,
            FixedStack({PatternBytes(rejected, "alternating"), PatternBytes(rejected, "late-nonzero")}),
            VaropsRejection());
}

static valtype DivisorTopClear(size_t size) { return valtype(size, 0x7f); }

static valtype DivisorTopLimbOne(size_t size)
{
    valtype divisor(size, 0);
    if (size == 0) return divisor;
    divisor.front() = 0xff;
    const size_t top_limb_start{(size - 1) / sizeof(uint64_t) * sizeof(uint64_t)};
    divisor[top_limb_start] = 0x01;
    return divisor;
}

static uint64_t DivModSequenceCost(opcodetype opcode, size_t dividend, size_t divisor)
{
    const uint64_t operation_cost{opcode == OP_DIV ? varops::DivCost(dividend, divisor) : varops::ModCost(dividend, divisor)};
    return (dividend + divisor) * varops::COST_COPYING + operation_cost;
}

static void AddDivModCases(std::vector<CaseSpec>& specs, opcodetype opcode)
{
    const CScript sequence{Ops({OP_2DUP, opcode, OP_DROP})};
    const auto add = [&](valtype dividend, valtype divisor, std::string shape, std::string pattern) {
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "divmod-preserve", std::move(shape), std::move(pattern), sequence,
                FixedStack({std::move(dividend), std::move(divisor)}));
    };
    add(valtype{0x0a}, valtype{0x03}, "1Bx1B", "normalization-short");
    add(PatternBytes(17, "dense"), DivisorTopClear(9), "17Bx9B", "normalization-top-clear");
    add(PatternBytes(8, "one-low"), PatternBytes(16, "late-nonzero"), "8Bx16B", "dividend-smaller");
    const valtype addback_dividend{
        0x71, 0x0a, 0x7f, 0x30, 0x34, 0x4d, 0x13, 0x98, 0xb1, 0x15, 0xd5, 0x64, 0xac, 0xc8, 0x9d, 0x56,
        0x5a, 0x64, 0xdc, 0x11, 0x21, 0xf7, 0x22, 0x7c, 0xf9, 0x7f, 0x16, 0xbc, 0xeb, 0xe8, 0x95, 0x85};
    const valtype addback_divisor{
        0xcd, 0x07, 0x2c, 0xd8, 0xbe, 0x6f, 0x9f, 0x62, 0xac, 0x4c, 0x09, 0xc2, 0x82, 0x06, 0xe7, 0xe3,
        0x55, 0x94, 0xaa, 0x6b, 0x34, 0x2f, 0x5d, 0x8a};
    add(addback_dividend, addback_divisor, "32Bx24B", "knuth-d6-add-back");
    const valtype correction_dividend{
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x3b, 0x00};
    const valtype correction_divisor{
        0xe7, 0x26, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x3b, 0x00};
    add(correction_dividend, correction_divisor, "25Bx17B", "knuth-d3-quotient-correction");

    enum class DivisorPattern { DENSE,
                                TOP_CLEAR,
                                TOP_LIMB_ONE };
    struct RectangularCase {
        unsigned int ratio;
        DivisorPattern pattern;
        std::string_view name;
    };
    const std::array rectangular_cases{
        RectangularCase{4, DivisorPattern::DENSE, "asymmetric-quarter-dense"},
        RectangularCase{16, DivisorPattern::DENSE, "asymmetric-sixteenth-dense"},
        RectangularCase{0, DivisorPattern::DENSE, "asymmetric-one-byte"},
        RectangularCase{4, DivisorPattern::TOP_CLEAR, "asymmetric-quarter-top-clear"},
        RectangularCase{16, DivisorPattern::TOP_LIMB_ONE, "asymmetric-sixteenth-top-limb-one"},
    };
    for (const RectangularCase& rectangular : rectangular_cases) {
        const auto divisor_size{[&](size_t dividend) {
            return rectangular.ratio == 0 ? size_t{1} : std::max<size_t>(1, dividend / rectangular.ratio);
        }};
        const auto sequence_cost{[&](size_t dividend) {
            return DivModSequenceCost(opcode, dividend, divisor_size(dividend));
        }};
        AddCostCrossovers(specs, opcode, "divmod-crossover", rectangular.name, sequence, 2, 2'000'000, sequence_cost, [&](size_t dividend) {
                              const size_t size{divisor_size(dividend)};
                              valtype divisor{rectangular.pattern == DivisorPattern::TOP_CLEAR ? DivisorTopClear(size) :
                                              rectangular.pattern == DivisorPattern::TOP_LIMB_ONE ? DivisorTopLimbOne(size) :
                                                                                                   PatternBytes(size, "dense")};
                              return FixedStack({PatternBytes(dividend, "dense"), std::move(divisor)}); }, [&](size_t dividend) { return FormatBytes(dividend) + "x" + FormatBytes(divisor_size(dividend)); });
    }
    constexpr size_t tail_dividend{65536};
    constexpr size_t tail_divisor{16384};
    AddCostCase(specs, opcode, HeadlineRole::NEW_GSR,
                "divmod-scale-tail", "64KBx16KB", "asymmetric-quarter-top-clear", sequence,
                FixedStack({PatternBytes(tail_dividend, "dense"), DivisorTopClear(tail_divisor)}),
                DivModSequenceCost(opcode, tail_dividend, tail_divisor));

    const size_t largest{LargestAffordable([opcode](size_t size) {
        return opcode == OP_DIV ? varops::DivCost(size, size) : varops::ModCost(size, size);
    },
                                           2'000'000)};
    for (size_t size : {largest > 1 ? largest - 1 : largest, largest, largest + 1}) {
        add(PatternBytes(size, "dense"), DivisorTopLimbOne(size),
            FormatBytes(size) + "x" + FormatBytes(size), "largest-normalized");
    }
    AddCase(specs, opcode, HeadlineRole::NEW_GSR,
            "divmod-varops-reject", FormatBytes(largest), "largest-normalized", sequence,
            FixedStack({PatternBytes(largest, "dense"), DivisorTopLimbOne(largest)}),
            VaropsRejection());
}

static uint64_t ShiftSequenceCost(opcodetype opcode, size_t size, uint64_t shift)
{
    const size_t shift_size{Val64(shift).MoveToValtype().size()};
    const uint64_t copy_cost{(size + shift_size) * varops::COST_COPYING};
    const uint64_t prebytes{shift / 8};
    if (opcode == OP_RSHIFT) {
        return copy_cost + varops::LengthConversionCost(shift_size) +
               (prebytes < size ? size - prebytes : 0) * varops::COST_COPYING;
    }
    if (opcode != OP_LSHIFT) throw std::runtime_error("unsupported shift opcode");
    return copy_cost + varops::LengthConversionCost(shift_size) + prebytes * varops::COST_FAST +
           size * varops::COST_COPYING +
           (shift % 8 == 0 ? 0 : varops::UnalignedUpShiftCost(size, prebytes));
}

static void AddShiftCases(std::vector<CaseSpec>& specs, opcodetype opcode)
{
    const CScript sequence{Ops({OP_2DUP, opcode, OP_DROP})};
    std::vector<std::pair<size_t, uint64_t>> shapes{{1, 1}, {17, 9}, {17, 56}, {17, 65}};
    shapes.insert(shapes.end(), {{1024, 8}, {1024, 1032}, {1024, 1033}, {65536, 524288}, {1, uint64_t{MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE - 1} * 8}});
    for (const auto& [size, shift] : shapes) {
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "shift-preserve", FormatBytes(size) + ":" + strprintf("%ubits", shift),
                shift % 8 == 0 ? "byte-aligned" : "unaligned", sequence,
                FixedStack({PatternBytes(size, "late-nonzero"), Val64(shift).MoveToValtype()}));
    }
    for (uint64_t shift : {8U, 65U}) {
        const auto sequence_cost{[opcode, shift](size_t size) {
            return ShiftSequenceCost(opcode, size, shift);
        }};
        AddCostCrossovers(specs, opcode, "shift-crossover", shift % 8 == 0 ? "byte-aligned" : "unaligned", sequence, 2, 2'000'000, sequence_cost, [=](size_t size) { return FixedStack({PatternBytes(size, "late-nonzero"),
                                                                                                                                                                                        Val64(shift).MoveToValtype()}); }, [=](size_t size) { return FormatBytes(size) + ":" + strprintf("%ubits", shift); });
    }
    constexpr size_t tail_size{2'000'000};
    constexpr uint64_t tail_shift{1};
    AddCostCase(specs, opcode, HeadlineRole::NEW_GSR,
                "shift-scale-tail", FormatBytes(tail_size) + ":1bit", "unaligned", sequence,
                FixedStack({PatternBytes(tail_size, "late-nonzero"),
                            Val64(tail_shift).MoveToValtype()}),
                ShiftSequenceCost(opcode, tail_size, tail_shift));
    if (opcode == OP_LSHIFT) {
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "shift-element-reject", "1B:past-4MB", "past-end", Ops({OP_LSHIFT}),
                FixedStack({valtype{1}, Val64(uint64_t{MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE} * 8).MoveToValtype()}),
                FixedCase(SCRIPT_ERR_STACK_ELEMENT_SIZE, 1, 0, "stack-element-limit"));
    }
}

static void AddSignatureCases(std::vector<CaseSpec>& specs, opcodetype opcode)
{
    const CScript sequence{opcode == OP_CHECKSIG       ? Ops({OP_2DUP, OP_CHECKSIG, OP_DROP}) :
                           opcode == OP_CHECKSIGVERIFY ? Ops({OP_2DUP, OP_CHECKSIGVERIFY}) :
                                                         Ops({OP_3DUP, OP_CHECKSIGADD, OP_DROP})};
    const auto valid_factory = [opcode](const CryptoFixture& fixture) {
        if (opcode == OP_CHECKSIGADD) return std::vector<valtype>{fixture.signature, valtype{}, fixture.pubkey_bytes};
        return std::vector<valtype>{fixture.signature, fixture.pubkey_bytes};
    };
    CaseOptions pre_baseline_options{};
    pre_baseline_options.max_repetitions = SIGNATURES_PER_BLOCK;
    pre_baseline_options.saturation_hint = "validation-weight";
    AddCase(specs, opcode, HeadlineRole::PRE_BASELINE,
            "signature-preserve", opcode == OP_CHECKSIGADD ? "64B+0B+32B" : "64B+32B",
            "valid-fixed-message", sequence, valid_factory,
            std::move(pre_baseline_options));
    AddCase(specs, opcode, HeadlineRole::COMMON_V2,
            "signature-preserve", opcode == OP_CHECKSIGADD ? "64B+0B+32B" : "64B+32B",
            "valid-fixed-message", sequence, valid_factory);

    AddCase(specs, opcode, HeadlineRole::PRE_BASELINE,
            "signature-validation-weight-reject", opcode == OP_CHECKSIGADD ? "64B+0B+32B" : "64B+32B",
            "valid-fixed-message", sequence, valid_factory,
            FixedCase(SCRIPT_ERR_TAPSCRIPT_VALIDATION_WEIGHT, SIGNATURES_PER_BLOCK + 1,
                      std::nullopt, "validation-weight-limit"));

    const auto empty_factory = [opcode](const CryptoFixture& fixture) {
        if (opcode == OP_CHECKSIGADD) return std::vector<valtype>{valtype{}, PaddedNumber(1, 521), fixture.pubkey_bytes};
        return std::vector<valtype>{valtype{}, fixture.pubkey_bytes};
    };
    const bool empty_verify_failure{opcode == OP_CHECKSIGVERIFY};
    CaseOptions empty_options{empty_verify_failure ? FixedCase(SCRIPT_ERR_CHECKSIGVERIFY, 1, 0, "semantic-failure") : CaseOptions{}};
    AddCase(specs, opcode,
            empty_verify_failure ? HeadlineRole::DIAGNOSTIC : (opcode == OP_CHECKSIGADD ? HeadlineRole::NEW_GSR : HeadlineRole::COMMON_V2),
            "signature-empty", opcode == OP_CHECKSIGADD ? "0B+521B+32B" : "0B+32B",
            "empty-signature", sequence, empty_factory, std::move(empty_options));

    const auto invalid_factory = [opcode](const CryptoFixture& fixture) {
        valtype invalid{fixture.signature};
        invalid.front() ^= 1;
        if (opcode == OP_CHECKSIGADD) return std::vector<valtype>{invalid, valtype{}, fixture.pubkey_bytes};
        return std::vector<valtype>{invalid, fixture.pubkey_bytes};
    };
    AddCase(specs, opcode, HeadlineRole::DIAGNOSTIC,
            "signature-invalid", opcode == OP_CHECKSIGADD ? "64B+0B+32B" : "64B+32B",
            "invalid-fixed-message", sequence, invalid_factory,
            FixedCase(SCRIPT_ERR_SCHNORR_SIG, 1, 0, "semantic-failure"));
}

static uint64_t TimelockSequenceCost(size_t size) { return varops::LengthConversionCost(size); }

static void AddTimelockCases(std::vector<CaseSpec>& specs, opcodetype opcode)
{
    const CScript sequence{Ops({opcode})};
    for (size_t size : std::array{4U, 5U}) {
        AddPreAndV2Cases(specs, opcode, "timelock-preserve", FormatBytes(size), "padded-one", sequence,
                         FixedStack({PaddedNumber(1, size)}));
    }
    for (size_t size : V2LargeSizes(65536)) {
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "timelock-preserve", FormatBytes(size), "padded-one", sequence,
                FixedStack({PaddedNumber(1, size)}));
    }
    AddCostCrossovers(specs, opcode, "timelock-crossover", "padded-one", sequence, 1, MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, TimelockSequenceCost, [](size_t size) { return FixedStack({PaddedNumber(1, size)}); }, FormatBytes);
    AddCostCase(specs, opcode, HeadlineRole::NEW_GSR,
                "timelock-scale-tail", "4MB", "padded-one", sequence,
                FixedStack({PaddedNumber(1, MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE)}),
                TimelockSequenceCost(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE));
}

static void AddControlAndFloorCases(std::vector<CaseSpec>& specs, opcodetype opcode)
{
    const auto forced_push = [](opcodetype push_opcode, size_t size) {
        CScript sequence;
        sequence.push_back(static_cast<unsigned char>(push_opcode));
        if (push_opcode == OP_PUSHDATA1) {
            sequence.push_back(static_cast<unsigned char>(size));
        } else if (push_opcode == OP_PUSHDATA2) {
            sequence.push_back(static_cast<unsigned char>(size & 0xff));
            sequence.push_back(static_cast<unsigned char>((size >> 8) & 0xff));
        } else {
            for (unsigned int shift : {0U, 8U, 16U, 24U}) {
                sequence.push_back(static_cast<unsigned char>((size >> shift) & 0xff));
            }
        }
        sequence.insert(sequence.end(), size, 0x42);
        sequence << OP_DROP;
        return sequence;
    };

    switch (opcode) {
    case OP_NOP:
    case OP_CODESEPARATOR:
        AddPreAndV2Cases(specs, opcode, "interpreter-floor", "no-operands", "executed", Ops({opcode}), FixedStack({}));
        if (opcode == OP_NOP) {
            AddCase(specs, opcode, HeadlineRole::PRE_BASELINE,
                    "max-initial-stack", "1000-items", "empty-items", Ops({OP_NOP}),
                    FixedStack(std::vector<valtype>(MAX_STACK_SIZE, valtype{})));
            AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                    "max-initial-stack", "32768-items", "empty-items", Ops({OP_NOP}),
                    FixedStack(std::vector<valtype>(MAX_TAPSCRIPT_V2_STACK_SIZE, valtype{})));
        }
        break;
    case OP_0:
        AddPreAndV2Cases(specs, opcode, "push-drop", "0B", "push-parse", Ops({OP_0, OP_DROP}), FixedStack({}));
        AddCase(specs, opcode, HeadlineRole::PRE_BASELINE,
                "push-stack-reject", "1001-pushes", "empty-items", Ops({OP_0}), FixedStack({}),
                FixedCase(SCRIPT_ERR_STACK_SIZE, MAX_STACK_SIZE + 1, 0, "stack-count-limit"));
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "push-stack-reject", "32769-pushes", "empty-items", Ops({OP_0}), FixedStack({}),
                FixedCase(SCRIPT_ERR_STACK_SIZE, MAX_TAPSCRIPT_V2_STACK_SIZE + 1, 0, "stack-count-limit"));
        break;
    case OP_PUSHDATA1:
        AddPreAndV2Cases(specs, opcode, "pushdata1-drop", "76B", "forced-push-encoding",
                         forced_push(OP_PUSHDATA1, 76), FixedStack({}));
        break;
    case OP_PUSHDATA2:
        AddPreAndV2Cases(specs, opcode, "pushdata2-drop", "520B", "forced-push-encoding",
                         forced_push(OP_PUSHDATA2, 520), FixedStack({}));
        AddCase(specs, opcode, HeadlineRole::PRE_BASELINE,
                "pushdata2-element-reject", "521B", "forced-push-encoding",
                forced_push(OP_PUSHDATA2, 521), FixedStack({}),
                FixedCase(SCRIPT_ERR_PUSH_SIZE, 1, 0, "push-element-limit"));
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "pushdata2-drop", "521B", "forced-push-encoding",
                forced_push(OP_PUSHDATA2, 521), FixedStack({}));
        break;
    case OP_PUSHDATA4:
        AddPreAndV2Cases(specs, opcode, "pushdata4-drop", "1B", "forced-nonminimal-encoding",
                         forced_push(OP_PUSHDATA4, 1), FixedStack({}));
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "pushdata4-drop", "64KB", "forced-push-encoding",
                forced_push(OP_PUSHDATA4, 65536), FixedStack({}));
        break;
    case OP_VERIFY: {
        AddPreAndV2Cases(specs, opcode, "true-verify", "1B", "true", Ops({OP_1, OP_VERIFY}), FixedStack({}));
        const CScript sequence{Ops({OP_DUP, OP_VERIFY})};
        AddCase(specs, opcode, HeadlineRole::PRE_BASELINE,
                "verify-preserve", "520B", "late-nonzero", sequence,
                FixedStack({PatternBytes(520, "late-nonzero")}));
        AddCostCase(specs, opcode, HeadlineRole::COMMON_V2,
                    "verify-preserve", "520B", "late-nonzero", sequence,
                    FixedStack({PatternBytes(520, "late-nonzero")}), TruthCopyCost(520));
        AddCostCrossovers(specs, opcode, "verify-crossover", "late-nonzero", sequence, 1, MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, TruthCopyCost, [](size_t size) { return FixedStack({PatternBytes(size, "late-nonzero")}); }, FormatBytes);
        AddCostCase(specs, opcode, HeadlineRole::NEW_GSR,
                    "verify-scale-tail", "4MB", "late-nonzero", sequence,
                    FixedStack({PatternBytes(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, "late-nonzero")}),
                    TruthCopyCost(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE));
        break;
    }
    case OP_IF:
        AddPreAndV2Cases(specs, opcode, "executed-if", "1B", "true-branch", Ops({OP_1, OP_IF, OP_NOP, OP_ENDIF}), FixedStack({}));
        AddPreAndV2Cases(specs, opcode, "skipped-if", "0B", "false-branch", Ops({OP_0, OP_IF, OP_NOP, OP_ENDIF}), FixedStack({}));
        break;
    default: throw std::runtime_error("unhandled control opcode registry entry");
    }
}

static void AddSizeCases(std::vector<CaseSpec>& specs, opcodetype opcode)
{
    const CScript sequence{Ops({OP_SIZE, OP_DROP})};
    for (size_t size : PreDataSizes()) {
        AddPreAndV2Cases(specs, opcode, "size-preserve", FormatBytes(size), "late-nonzero", sequence,
                         FixedStack({PatternBytes(size, "late-nonzero")}));
    }
    for (size_t size : V2LargeSizes(MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE)) {
        AddCase(specs, opcode, HeadlineRole::NEW_GSR,
                "size-preserve", FormatBytes(size), "late-nonzero", sequence,
                FixedStack({PatternBytes(size, "late-nonzero")}));
    }
}

static uint64_t WithinSequenceCost(size_t size) { return 3 * size * varops::COST_COPYING + varops::WithinCost(size, size, size); }

static void AddWithinCases(std::vector<CaseSpec>& specs, opcodetype opcode)
{
    const CScript sequence{Ops({OP_3DUP, OP_WITHIN, OP_DROP})};
    AddPreAndV2Cases(specs, opcode, "within-preserve", "4Bx4Bx4B", "inside-range", sequence,
                     FixedStack({PaddedNumber(2, 4), PaddedNumber(1, 4), PaddedNumber(3, 4)}));
    AddCase(specs, opcode, HeadlineRole::NEW_GSR,
            "within-preserve", "521Bx521Bx521B", "inside-range-padded", sequence,
            FixedStack({PaddedNumber(2, 521), PaddedNumber(1, 521), PaddedNumber(3, 521)}));
    AddCostCrossovers(specs, opcode, "within-crossover", "inside-range-padded", sequence, 3, MAX_THREE_WAY_ELEMENT_SIZE, WithinSequenceCost, [](size_t size) { return FixedStack({PaddedNumber(2, size), PaddedNumber(1, size),
                                                                                                                                                                                  PaddedNumber(3, size)}); }, [](size_t size) { return FormatBytes(size) + "x" + FormatBytes(size) + "x" + FormatBytes(size); });
    AddCostCase(specs, opcode, HeadlineRole::NEW_GSR,
                "within-scale-tail",
                FormatBytes(MAX_THREE_WAY_ELEMENT_SIZE) + "x" +
                    FormatBytes(MAX_THREE_WAY_ELEMENT_SIZE) + "x" +
                    FormatBytes(MAX_THREE_WAY_ELEMENT_SIZE),
                "inside-range-padded", sequence,
                FixedStack({PaddedNumber(2, MAX_THREE_WAY_ELEMENT_SIZE),
                            PaddedNumber(1, MAX_THREE_WAY_ELEMENT_SIZE),
                            PaddedNumber(3, MAX_THREE_WAY_ELEMENT_SIZE)}),
                WithinSequenceCost(MAX_THREE_WAY_ELEMENT_SIZE));
}

using CaseGenerator = void (*)(std::vector<CaseSpec>&, opcodetype);

struct OpcodeEntry {
    opcodetype opcode;
    CaseGenerator generate;
};

static const std::vector<OpcodeEntry>& OpcodeRegistry()
{
    static const std::vector<OpcodeEntry> registry{[] {
        std::vector<OpcodeEntry> entries;
        const auto add = [&](CaseGenerator generate, std::initializer_list<opcodetype> opcodes) {
            for (opcodetype opcode : opcodes)
                entries.push_back({opcode, generate});
        };
        const CaseGenerator unary_common{[](auto& out, auto op) { AddUnaryDataCases(out, op, false); }};
        const CaseGenerator unary_restored{[](auto& out, auto op) { AddUnaryDataCases(out, op, true); }};
        const CaseGenerator binary_common{[](auto& out, auto op) { AddBinaryDataCases(out, op, false); }};
        const CaseGenerator binary_restored{[](auto& out, auto op) { AddBinaryDataCases(out, op, true); }};

        add(AddControlAndFloorCases, {OP_0, OP_PUSHDATA1, OP_PUSHDATA2, OP_PUSHDATA4, OP_IF, OP_VERIFY, OP_NOP, OP_CODESEPARATOR});
        add(AddStackOpcodeCases, {OP_TOALTSTACK, OP_FROMALTSTACK, OP_2DROP, OP_2DUP, OP_3DUP, OP_2OVER, OP_2ROT, OP_2SWAP,
                                  OP_IFDUP, OP_DEPTH, OP_DROP, OP_DUP, OP_NIP, OP_OVER, OP_PICK, OP_ROLL, OP_ROT, OP_SWAP, OP_TUCK});
        add(unary_common, {OP_1ADD, OP_1SUB, OP_NOT, OP_0NOTEQUAL});
        add(unary_restored, {OP_INVERT, OP_2MUL, OP_2DIV});
        add(binary_common, {OP_EQUAL, OP_EQUALVERIFY, OP_ADD, OP_SUB, OP_BOOLAND, OP_BOOLOR, OP_NUMEQUAL,
                            OP_NUMEQUALVERIFY, OP_NUMNOTEQUAL, OP_LESSTHAN, OP_GREATERTHAN,
                            OP_LESSTHANOREQUAL, OP_GREATERTHANOREQUAL, OP_MIN, OP_MAX});
        add(binary_restored, {OP_AND, OP_OR, OP_XOR});
        add(AddHashCases, {OP_RIPEMD160, OP_SHA1, OP_SHA256, OP_HASH160, OP_HASH256});
        add(AddSpliceCases, {OP_CAT, OP_SUBSTR, OP_LEFT, OP_RIGHT});
        add(AddMulCases, {OP_MUL});
        add(AddDivModCases, {OP_DIV, OP_MOD});
        add(AddShiftCases, {OP_LSHIFT, OP_RSHIFT});
        add(AddSizeCases, {OP_SIZE});
        add(AddWithinCases, {OP_WITHIN});
        add(AddSignatureCases, {OP_CHECKSIG, OP_CHECKSIGVERIFY, OP_CHECKSIGADD});
        add(AddTimelockCases, {OP_CHECKLOCKTIMEVERIFY, OP_CHECKSEQUENCEVERIFY});
        return entries;
    }()};
    return registry;
}

static std::map<std::string, opcodetype> SupportedOpcodeMap()
{
    std::map<std::string, opcodetype> out;
    for (const OpcodeEntry& entry : OpcodeRegistry())
        out.emplace(OpcodeName(entry.opcode), entry.opcode);
    return out;
}

static std::vector<CaseSpec> GenerateCaseSpecs(const Options& options)
{
    std::vector<CaseSpec> specs;
    for (const OpcodeEntry& entry : OpcodeRegistry()) {
        const opcodetype opcode{entry.opcode};
        if (!options.selected_opcodes.empty() && !options.selected_opcodes.contains(opcode)) continue;
        entry.generate(specs, opcode);
    }

    if (options.selected_opcodes.empty() || options.selected_opcodes.contains(OP_DUP)) {
        AddCase(specs, OP_DUP, HeadlineRole::PRE_BASELINE,
                "empty-dup-stack-reject", "1001-items", "empty-items", Ops({OP_DUP}),
                FixedStack({valtype{}}), FixedCase(SCRIPT_ERR_STACK_SIZE, MAX_STACK_SIZE, 0, "stack-count-limit"));
        AddCase(specs, OP_DUP, HeadlineRole::NEW_GSR,
                "empty-dup-stack-reject", "32769-items", "empty-items", Ops({OP_DUP}),
                FixedStack({valtype{}}),
                FixedCase(SCRIPT_ERR_STACK_SIZE, MAX_TAPSCRIPT_V2_STACK_SIZE, 0, "stack-count-limit"));
        AddCase(specs, OP_DUP, HeadlineRole::NEW_GSR,
                "total-stack-reject", "4MB-item", "dense", Ops({OP_DUP, OP_DUP}),
                FixedStack({PatternBytes(4'000'000, "dense")}),
                FixedCase(SCRIPT_ERR_TOTAL_STACK_SIZE, 1, 0, "total-stack-limit"));
    }

    std::sort(specs.begin(), specs.end(), [](const CaseSpec& left, const CaseSpec& right) { return left.name < right.name; });
    const std::vector<CaseSpec>::iterator duplicate{std::adjacent_find(specs.begin(), specs.end(), [](const CaseSpec& left, const CaseSpec& right) {
        return left.name == right.name;
    })};
    if (duplicate != specs.end()) throw std::runtime_error("duplicate generated case name: " + duplicate->name);
    return specs;
}

static ankerl::nanobench::Bench SetupBenchmark()
{
    ankerl::nanobench::Bench bench;
    bench.output(nullptr).epochs(1).epochIterations(1);
    return bench;
}

static std::string_view TimingStageName(TimingStage stage)
{
    switch (stage) {
    case TimingStage::SCHNORR_BASELINE: return "schnorr-baseline";
    case TimingStage::DISCOVERY: return "discovery";
    case TimingStage::STABLE: return "stable";
    }
    return "unknown";
}

static SampleStats CalculateStats(std::vector<double> values)
{
    if (values.empty()) throw std::runtime_error("cannot aggregate an empty sample set");
    std::sort(values.begin(), values.end());
    const size_t middle{values.size() / 2};
    const double median{values.size() % 2 == 0 ? (values[middle - 1] + values[middle]) / 2 : values[middle]};
    std::vector<double> errors;
    errors.reserve(values.size());
    for (double value : values) {
        if (value == 0) {
            errors.push_back(median == 0 ? 0 : std::numeric_limits<double>::infinity());
        } else {
            errors.push_back(std::abs((value - median) / value));
        }
    }
    std::sort(errors.begin(), errors.end());
    const size_t error_middle{errors.size() / 2};
    const double mdape{errors.size() % 2 == 0 ? (errors[error_middle - 1] + errors[error_middle]) / 2 : errors[error_middle]};
    return {median, values.front(), values.back(), mdape};
}

static void AggregateSamples(BenchResult& result, TimingStage stage)
{
    std::vector<double> values;
    for (const TimingSample& sample : result.samples) {
        if (sample.stage == stage) values.push_back(sample.wall_sec);
    }
    const SampleStats stats{CalculateStats(std::move(values))};
    result.median_sec = stats.median;
    result.wall_min_sec = stats.minimum;
    result.wall_max_sec = stats.maximum;
    result.mdape = stats.mdape;
    result.aggregate_stage = stage;
}

static void RunGlobalWarmup(const CryptoFixture& fixture)
{
    const CScript warmup_script{BuildScript(Ops({OP_NOP}), 1, 0)};
    ValtypeStack warmup_stack;
    BenchSignatureChecker checker{fixture};
    ScriptExecutionData execdata;
    varops::Budget budget{TOTAL_VAROPS_BUDGET};
    ScriptError error{SCRIPT_ERR_UNKNOWN_ERROR};
    if (!EvalTapscriptV2(warmup_stack, warmup_script, BENCH_SCRIPT_VERIFY_FLAGS,
                         checker, execdata, budget, &error)) {
        throw std::runtime_error("global benchmark warmup failed: " + ScriptErrorString(error));
    }
}

static BenchResult ResultMetadata(const MaterializedCase& test_case)
{
    const CaseSpec& spec{*test_case.spec};
    BenchResult result;
    result.name = spec.name;
    result.domain = DomainFor(spec.role);
    result.role = spec.role;
    result.opcode_name = spec.opcode_name;
    result.sequence_opcodes = spec.sequence_opcodes;
    result.operand_shape = spec.operand_shape;
    result.operand_pattern = spec.operand_pattern;
    result.script_bytes = test_case.script.size();
    result.initial_stack_items = test_case.initial_stack.size();
    result.initial_stack_bytes = StackPayloadBytes(test_case.initial_stack);
    result.expected_error = spec.expected_error;
    result.actual_error = SCRIPT_ERR_UNKNOWN_ERROR;
    result.saturation = test_case.saturation;
    result.repetitions = test_case.repetitions;
    result.varops_per_repeat = test_case.varops_per_repeat;
    return result;
}

static void CheckDeclaredOutcome(const MaterializedCase& test_case, const EvalOutcome& outcome,
                                 std::string_view stage)
{
    if (outcome.error != test_case.spec->expected_error || outcome.success != (test_case.spec->expected_error == SCRIPT_ERR_OK)) {
        throw std::runtime_error(strprintf("%s mismatch for %s: expected %s, got %s",
                                           stage, test_case.spec->name,
                                           ScriptErrorString(test_case.spec->expected_error),
                                           ScriptErrorString(outcome.error)));
    }
}

static void CheckScriptEnvelope(const MaterializedCase& test_case)
{
    if (test_case.script.size() != SCRIPT_BYTES) {
        throw std::runtime_error(test_case.spec->name + " is not exactly 4,000,000 script bytes");
    }
}

static void CheckMeasuredOutcome(const MaterializedCase& test_case, const EvalOutcome& expected,
                                 const EvalOutcome& actual, std::string_view stage)
{
    if (actual.error != expected.error || actual.success != expected.success ||
        actual.varops_consumed != expected.varops_consumed) {
        throw std::runtime_error(strprintf("%s changed outcome during %s", test_case.spec->name, stage));
    }
}

static TimingSample MeasurePrepared(const MaterializedCase& test_case, const CryptoFixture& fixture,
                                    PreparedExecution& execution, const EvalOutcome& expected,
                                    TimingStage stage, int round, size_t order)
{
    BenchSignatureChecker checker{fixture};
    ankerl::nanobench::Bench bench{SetupBenchmark()};
    EvalOutcome outcome;
    size_t executions{0};
    bench.run(test_case.spec->name, [&] {
        ++executions;
        outcome = ExecutePrepared(test_case, checker, execution);
    });
    if (executions != 1 || bench.results().size() != 1 || bench.results().front().size() != 1) {
        throw std::runtime_error("nanobench did not execute exactly one case sample");
    }
    CheckMeasuredOutcome(test_case, expected, outcome, TimingStageName(stage));
    return {stage, round, order,
            bench.results().front().get(0, ankerl::nanobench::Result::Measure::elapsed)};
}

static TimingSample RunTimedCaseSample(const MaterializedCase& test_case, const CryptoFixture& fixture,
                                       const EvalOutcome& expected, TimingStage stage, int round,
                                       size_t order, bool warmup)
{
    const uint64_t fixture_bytes{StackFixtureBytes(test_case.initial_stack)};
    const uint64_t copies{warmup ? 2U : 1U};
    if (fixture_bytes > MAX_FIXTURE_POOL_BYTES / copies) {
        throw std::runtime_error(strprintf("%s sample fixtures would require %u bytes (limit %u)",
                                           test_case.spec->name, fixture_bytes * copies,
                                           MAX_FIXTURE_POOL_BYTES));
    }

    if (warmup) ReleaseAllocatorCaches();
    TimingSample sample;
    {
        std::optional<PreparedExecution> warmup_execution;
        if (warmup) warmup_execution.emplace(PrepareExecution(test_case, true));
        PreparedExecution measured_execution{PrepareExecution(test_case, true)};
        BenchSignatureChecker checker{fixture};
        if (warmup_execution) {
            const EvalOutcome warmup_outcome{ExecutePrepared(test_case, checker, *warmup_execution)};
            CheckMeasuredOutcome(test_case, expected, warmup_outcome, "warmup");
        }
        sample = MeasurePrepared(test_case, fixture, measured_execution, expected, stage, round, order);
    }
    if (warmup) ReleaseAllocatorCaches();
    return sample;
}

static TimingSample MeasureSchnorrBatch(const CryptoFixture& fixture, TimingStage stage,
                                        int round, size_t order, uint64_t iterations)
{
    ankerl::nanobench::Bench bench{SetupBenchmark()};
    uint64_t valid{0};
    size_t executions{0};
    bench.run("Schnorr signature validation", [&] {
        ++executions;
        for (uint64_t i{0}; i < iterations; ++i) {
            valid += fixture.pubkey.VerifySchnorr(fixture.message, fixture.signature);
        }
        ankerl::nanobench::doNotOptimizeAway(valid);
    });
    if (executions != 1 || valid != iterations || bench.results().size() != 1 ||
        bench.results().front().size() != 1) {
        throw std::runtime_error("raw Schnorr anchor failed");
    }
    const double scale{static_cast<double>(SIGNATURES_PER_BLOCK) / iterations};
    return {stage, round, order,
            bench.results().front().get(0, ankerl::nanobench::Result::Measure::elapsed) * scale};
}

static BenchResult RunRawSchnorr(const CryptoFixture& fixture)
{
    BenchResult result;
    result.name = "Schnorr signature validation";
    result.domain = ExecutionDomain::RAW_SCHNORR;
    result.role = HeadlineRole::PRE_BASELINE;
    result.opcode_name = "RAW_SCHNORR_80000";
    result.sequence_opcodes = "RAW_SCHNORR_VERIFY";
    result.operand_shape = "64B+32B";
    result.operand_pattern = "valid-fixed-message";
    result.expected_error = SCRIPT_ERR_OK;
    result.actual_error = SCRIPT_ERR_OK;
    result.saturation = "80000-signature-anchor";
    constexpr uint64_t iterations{1000};
    MeasureSchnorrBatch(fixture, TimingStage::SCHNORR_BASELINE, 0, 0, iterations);
    for (int sample{1}; sample <= SCHNORR_BASELINE_SAMPLES; ++sample) {
        result.samples.push_back(MeasureSchnorrBatch(fixture, TimingStage::SCHNORR_BASELINE,
                                                     sample, sample - 1, iterations));
    }
    AggregateSamples(result, TimingStage::SCHNORR_BASELINE);
    result.repetitions = SIGNATURES_PER_BLOCK;
    return result;
}

static BenchResult RunDiscoveryCase(const MaterializedCase& test_case, const CryptoFixture& fixture,
                                    size_t order)
{
    CheckScriptEnvelope(test_case);
    const uint64_t fixture_bytes{StackFixtureBytes(test_case.initial_stack)};
    if (fixture_bytes > MAX_FIXTURE_POOL_BYTES / 2) {
        throw std::runtime_error(strprintf("%s discovery fixtures would require %u bytes (limit %u)",
                                           test_case.spec->name, fixture_bytes * 2,
                                           MAX_FIXTURE_POOL_BYTES));
    }

    ReleaseAllocatorCaches();
    PreparedExecution preflight_execution{PrepareExecution(test_case, true)};
    PreparedExecution measured_execution{PrepareExecution(test_case, true)};
    BenchSignatureChecker checker{fixture};
    const EvalOutcome preflight{ExecutePrepared(test_case, checker, preflight_execution)};
    CheckDeclaredOutcome(test_case, preflight, "discovery preflight/warmup");
    TimingSample sample{MeasurePrepared(test_case, fixture, measured_execution, preflight,
                                        TimingStage::DISCOVERY, 0, order)};
    ReleaseAllocatorCaches();

    BenchResult result{ResultMetadata(test_case)};
    result.actual_error = preflight.error;
    result.varops_consumed = preflight.varops_consumed;
    result.discovery_wall_sec = sample.wall_sec;
    result.samples.push_back(std::move(sample));
    AggregateSamples(result, TimingStage::DISCOVERY);
    return result;
}

static void AddPromotionReason(BenchResult& result, std::string reason)
{
    if (std::ranges::find(result.promotion_reasons, reason) == result.promotion_reasons.end()) {
        result.promotion_reasons.push_back(std::move(reason));
    }
    result.promoted = true;
}

static void PromoteLeader(std::vector<BenchResult>& results,
                          const std::function<bool(const BenchResult&)>& predicate)
{
    BenchResult* leader{nullptr};
    for (BenchResult& result : results) {
        if (result.domain == ExecutionDomain::RAW_SCHNORR || !predicate(result)) continue;
        if (!leader || *result.discovery_wall_sec > *leader->discovery_wall_sec) leader = &result;
    }
    if (leader) AddPromotionReason(*leader, "category-leader");
}

static PromotionSummary PromoteDiscoveryResults(std::vector<BenchResult>& results,
                                                const BenchResult& schnorr)
{
    PromotionSummary summary{schnorr.median_sec * PROMOTION_THRESHOLD, 0};
    for (BenchResult& result : results) {
        if (result.domain != ExecutionDomain::RAW_SCHNORR &&
            *result.discovery_wall_sec >= summary.promotion_cutoff_seconds) {
            AddPromotionReason(result, "wall-cutoff");
        }
    }

    const std::array<std::function<bool(const BenchResult&)>, 7> categories{
        [](const BenchResult& result) { return result.domain == ExecutionDomain::PRE_GSR_TAPSCRIPT; },
        [](const BenchResult& result) { return result.role == HeadlineRole::NEW_GSR; },
        [](const BenchResult& result) { return result.role == HeadlineRole::NEW_GSR && result.actual_error == SCRIPT_ERR_OK; },
        [](const BenchResult& result) { return result.role == HeadlineRole::NEW_GSR && IsResourceError(result.actual_error); },
        [](const BenchResult& result) { return result.domain == ExecutionDomain::GSR_TAPSCRIPT_V2; },
        [](const BenchResult& result) {
            return result.domain == ExecutionDomain::PRE_GSR_TAPSCRIPT ||
                   result.domain == ExecutionDomain::GSR_TAPSCRIPT_V2;
        },
        [](const BenchResult& result) { return result.role == HeadlineRole::COMMON_V2; },
    };
    for (const auto& category : categories)
        PromoteLeader(results, category);
    summary.promoted_cases = std::ranges::count_if(results, [](const BenchResult& result) {
        return result.promoted;
    });
    return summary;
}

static std::vector<std::vector<size_t>> BuildRoundSchedules(const std::vector<size_t>& indices,
                                                            int rounds)
{
    std::mt19937_64 generator{ROUND_SEED};
    std::vector<std::vector<size_t>> schedules;
    schedules.reserve(rounds);
    for (int round{0}; round < rounds; ++round) {
        schedules.push_back(indices);
        std::shuffle(schedules.back().begin(), schedules.back().end(), generator);
    }
    return schedules;
}

static void RunTimingSelfChecks()
{
    const SampleStats stats{CalculateStats({1, 2, 3, 4})};
    Check(stats.median == 2.5 && stats.minimum == 1 && stats.maximum == 4 &&
              std::abs(stats.mdape - 0.3125) <= 1e-12,
          "internal timing aggregation failed");

    const std::vector<size_t> indices{0, 1, 2, 3};
    const auto first{BuildRoundSchedules(indices, 7)};
    Check(first == BuildRoundSchedules(indices, 7) && first.size() == 7,
          "internal round schedule determinism failed");
    for (const auto& round : first) {
        std::vector<size_t> sorted{round};
        std::sort(sorted.begin(), sorted.end());
        Check(sorted == indices, "internal round schedule coverage failed");
    }

    BenchResult lower;
    lower.domain = ExecutionDomain::PRE_GSR_TAPSCRIPT;
    lower.discovery_wall_sec = 1;
    BenchResult higher;
    higher.domain = ExecutionDomain::PRE_GSR_TAPSCRIPT;
    higher.discovery_wall_sec = 2;
    std::vector<BenchResult> category_results{lower, higher};
    PromoteLeader(category_results, [](const BenchResult&) { return true; });
    Check(!category_results[0].promoted && category_results[1].promoted,
          "internal category leader promotion failed");
}

static const BenchResult* Slowest(const std::vector<BenchResult>& results,
                                  const std::function<bool(const BenchResult&)>& predicate)
{
    const BenchResult* slowest{nullptr};
    for (const BenchResult& result : results) {
        if (predicate(result) && (!slowest || result.median_sec > slowest->median_sec)) slowest = &result;
    }
    return slowest;
}

static bool IsRankable(const BenchResult& result)
{
    return result.domain == ExecutionDomain::RAW_SCHNORR || result.promoted;
}

static std::optional<SampleStats> PairedRatioStats(const BenchResult& numerator,
                                                   const BenchResult& denominator)
{
    std::map<int, double> denominator_by_round;
    for (const TimingSample& sample : denominator.samples) {
        if (sample.stage == TimingStage::STABLE) denominator_by_round.emplace(sample.round, sample.wall_sec);
    }
    std::vector<double> ratios;
    for (const TimingSample& sample : numerator.samples) {
        if (sample.stage != TimingStage::STABLE) continue;
        const auto denominator_value{denominator_by_round.find(sample.round)};
        if (denominator_value != denominator_by_round.end() && denominator_value->second > 0) {
            ratios.push_back(sample.wall_sec / denominator_value->second);
        }
    }
    return ratios.empty() ? std::nullopt : std::optional<SampleStats>{CalculateStats(std::move(ratios))};
}

static void PrintReport(const std::vector<BenchResult>& results, const CorpusCounts& counts,
                        const Options& options, const PromotionSummary& promotion)
{
    const BenchResult* denominator{Slowest(results, [](const BenchResult& result) {
        return IsRankable(result) && result.domain == ExecutionDomain::PRE_GSR_TAPSCRIPT;
    })};
    const BenchResult* numerator{Slowest(results, [](const BenchResult& result) {
        return IsRankable(result) && result.role == HeadlineRole::NEW_GSR;
    })};
    const BenchResult* schnorr{Slowest(results, [](const BenchResult& result) {
        return result.domain == ExecutionDomain::RAW_SCHNORR;
    })};

    std::cout << "\n================================================================================\n";
    std::cout << "MAXIMUM OBSERVED IN THE GENERATED CORPUS\n";
    std::cout << "================================================================================\n";
    std::cout << strprintf("Corpus: %u requested opcodes, %u generated rows, %u completed rows\n",
                           counts.requested_opcodes, counts.generated_cases, counts.completed_cases);
    std::cout << strprintf("Promotion: %u/%u rows at wall >= %.3f sec (threshold %.0f%%)\n",
                           promotion.promoted_cases, counts.generated_cases,
                           promotion.promotion_cutoff_seconds, 100 * PROMOTION_THRESHOLD);
    std::cout << strprintf("Stable measurement: %u rounds (seed 0x%x)\n",
                           options.stable_rounds, static_cast<unsigned int>(ROUND_SEED));
    if (denominator) {
        std::cout << strprintf("Pre-GSR denominator: %s  %.3f sec (%.2f%% MdAPE)\n",
                               denominator->name, denominator->median_sec, 100 * denominator->mdape);
    }
    if (numerator) {
        std::cout << strprintf("New-GSR numerator:   %s  %.3f sec (%.2f%% MdAPE)\n",
                               numerator->name, numerator->median_sec, 100 * numerator->mdape);
    }
    if (denominator && numerator && denominator->median_sec > 0) {
        std::cout << strprintf("Headline quotient:   %.3f\n",
                               numerator->median_sec / denominator->median_sec);
        if (const auto paired{PairedRatioStats(*numerator, *denominator)}) {
            std::cout << strprintf("Paired quotient:     %.3f median (%.2f%% MdAPE)\n",
                                   paired->median, 100 * paired->mdape);
        }
    }
    if (schnorr) {
        std::cout << strprintf("Raw Schnorr (80,000): %.3f sec (%.2f%% MdAPE)\n",
                               schnorr->median_sec, 100 * schnorr->mdape);
    }
    std::cout << "================================================================================\n";
}

static std::string GetBenchmarkSystemInfo()
{
    std::ostringstream info;
    std::string cpu_name{"Unknown"};
#if defined(__APPLE__)
    if (FILE * fp{popen("sysctl -n machdep.cpu.brand_string", "r")}) {
        char buffer[256];
        if (fgets(buffer, sizeof(buffer), fp)) {
            cpu_name = buffer;
            if (!cpu_name.empty() && cpu_name.back() == '\n') cpu_name.pop_back();
        }
        pclose(fp);
    }
#elif defined(__linux__)
    if (FILE * cpuinfo{fopen("/proc/cpuinfo", "r")}) {
        char line[256];
        while (fgets(line, sizeof(line), cpuinfo)) {
            if (strncmp(line, "model name", 10) != 0) continue;
            if (const char* separator{strchr(line, ':')}) {
                cpu_name = separator + 2;
                if (!cpu_name.empty() && cpu_name.back() == '\n') cpu_name.pop_back();
                break;
            }
        }
        fclose(cpuinfo);
    }
#endif

    std::string architecture{"Unknown"};
#if defined(__x86_64__) || defined(__amd64__) || defined(_M_X64)
    architecture = "x86_64";
#elif defined(__aarch64__) || defined(_M_ARM64)
    architecture = "ARM64";
#elif defined(__i386__) || defined(_M_IX86)
    architecture = "x86";
#elif defined(__arm__) || defined(_M_ARM)
    architecture = "ARM";
#endif

    std::string compiler{"Unknown"};
#if defined(__clang__)
    compiler = strprintf("Clang %d.%d.%d", __clang_major__, __clang_minor__, __clang_patchlevel__);
#elif defined(__GNUC__)
    compiler = strprintf("GCC %d.%d.%d", __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#elif defined(_MSC_VER)
    compiler = strprintf("MSVC %d", _MSC_VER);
#endif

    info << "# CPU: " << cpu_name << "\n";
    info << "# Architecture: " << architecture << "\n";
    info << "# Compiler: " << compiler << "\n";
    info << "# SHA256 Implementation: " << SHA256AutoDetect() << "\n";
    return info.str();
}

static std::string CsvEscape(std::string_view value)
{
    if (value.find_first_of(",\"\n\r") == std::string_view::npos) return std::string{value};
    std::string escaped{"\""};
    for (char ch : value) {
        if (ch == '"') escaped += '"';
        escaped += ch;
    }
    return escaped + '"';
}

static std::string JoinPromotionReasons(const std::vector<std::string>& reasons)
{
    std::string joined;
    for (const std::string& reason : reasons) {
        if (!joined.empty()) joined += ';';
        joined += reason;
    }
    return joined;
}

static std::string CsvNumber(double value)
{
    return strprintf("%.17g", value);
}

template <typename T>
static std::string CsvNumber(const T& value)
{
    std::ostringstream output;
    output << value;
    return output.str();
}

enum class CsvColumn : size_t {
    RECORD_TYPE,
    RANK,
    NAME,
    EXECUTION_DOMAIN,
    HEADLINE_ROLE,
    OPCODE,
    SEQUENCE_OPCODES,
    OPERAND_SHAPE,
    OPERAND_PATTERN,
    SCRIPT_BYTES,
    INITIAL_STACK_ITEMS,
    INITIAL_STACK_BYTES,
    VAROPS_CONSUMED,
    EXPECTED_TERMINATION,
    ACTUAL_TERMINATION,
    SATURATION,
    REPETITIONS,
    SEQUENCE_VAROPS,
    PROMOTED,
    PROMOTION_REASONS,
    STAGE,
    ROUND,
    ORDER,
    SAMPLES,
    WALL_SECONDS,
    WALL_MIN_SECONDS,
    WALL_MAX_SECONDS,
    MDAPE,
    SCHNORR_EQUIVALENTS,
    VAROPS_PERCENTAGE,
    COUNT,
};

static constexpr size_t CsvIndex(CsvColumn column) { return static_cast<size_t>(column); }

using CsvRow = std::array<std::string, CsvIndex(CsvColumn::COUNT)>;

static constexpr std::string_view CSV_HEADER{
    "Record_Type,Rank,Name,Domain,Headline_Role,Opcode,Sequence_Opcodes,Operand_Shape,"
    "Operand_Pattern,Script_Bytes,Initial_Stack_Items,Initial_Stack_Bytes,Varops_Consumed,"
    "Expected_Termination,Actual_Termination,Saturation,Repetitions,Sequence_Varops,Promoted,"
    "Promotion_Reasons,Stage,Round,Order,Samples,Wall_Seconds,Wall_Min_Seconds,Wall_Max_Seconds,"
    "MdAPE,Schnorr_Equivalents,Varops_Percentage"};
static_assert(std::ranges::count(CSV_HEADER, ',') + 1 == CsvIndex(CsvColumn::COUNT));

static std::string& CsvField(CsvRow& row, CsvColumn column) { return row[CsvIndex(column)]; }

template <typename Fields>
static void WriteCsvRow(std::ostream& output, const Fields& fields)
{
    for (size_t index{0}; index < fields.size(); ++index) {
        if (index != 0) output << ',';
        output << CsvEscape(fields[index]);
    }
    output << '\n';
}

static void SetResultIdentity(CsvRow& row, const BenchResult& result)
{
    CsvField(row, CsvColumn::NAME) = result.name;
    CsvField(row, CsvColumn::EXECUTION_DOMAIN) = DomainName(result.domain);
    CsvField(row, CsvColumn::HEADLINE_ROLE) = RoleName(result.role);
    CsvField(row, CsvColumn::OPCODE) = result.opcode_name;
    CsvField(row, CsvColumn::SEQUENCE_OPCODES) = result.sequence_opcodes;
    CsvField(row, CsvColumn::OPERAND_SHAPE) = result.operand_shape;
    CsvField(row, CsvColumn::OPERAND_PATTERN) = result.operand_pattern;
    CsvField(row, CsvColumn::SCRIPT_BYTES) = CsvNumber(result.script_bytes);
    CsvField(row, CsvColumn::INITIAL_STACK_ITEMS) = CsvNumber(result.initial_stack_items);
    CsvField(row, CsvColumn::INITIAL_STACK_BYTES) = CsvNumber(result.initial_stack_bytes);
    CsvField(row, CsvColumn::VAROPS_CONSUMED) = CsvNumber(result.varops_consumed);
    CsvField(row, CsvColumn::EXPECTED_TERMINATION) = ScriptErrorString(result.expected_error);
    CsvField(row, CsvColumn::ACTUAL_TERMINATION) = ScriptErrorString(result.actual_error);
    CsvField(row, CsvColumn::SATURATION) = result.saturation;
    CsvField(row, CsvColumn::REPETITIONS) = CsvNumber(result.repetitions);
    CsvField(row, CsvColumn::SEQUENCE_VAROPS) = CsvNumber(result.varops_per_repeat);
}

static bool FlushAndClose(std::ofstream& file, const fs::path& path)
{
    file.flush();
    if (!file.good()) {
        std::cerr << "Error: failed while writing " << path << "\n";
        file.close();
        return false;
    }
    file.close();
    if (file.fail()) {
        std::cerr << "Error: failed while closing " << path << "\n";
        return false;
    }
    return true;
}

static bool SaveResultsToFile(const std::vector<BenchResult>& results, const std::string& filepath,
                              const CorpusCounts& counts, const Options& options,
                              const PromotionSummary& promotion)
{
    const fs::path output_target{fs::PathFromString(filepath)};
    fs::path output_temporary{output_target};
    output_temporary += ".tmp." + util::ToString(std::chrono::steady_clock::now().time_since_epoch().count());
    std::ofstream output_file(output_temporary.std_path(), std::ios::out | std::ios::trunc);
    if (!output_file.is_open()) {
        std::cerr << "Error: could not open temporary output file " << output_temporary << "\n";
        return false;
    }

    size_t raw_sample_count{0};
    for (const BenchResult& result : results)
        raw_sample_count += result.samples.size();

    output_file << "# Schema: bench_varops-v2\n";
    output_file << GetBenchmarkSystemInfo();
    output_file << "# Record types: summary=aggregated row; sample=normalized wall-clock measurement.\n";
    output_file << "# Wall_Seconds: summary median or sample value; Schnorr samples are normalized to 80,000 validations.\n";
    output_file << strprintf("# Records: summary=%u sample=%u\n", results.size(), raw_sample_count);
    output_file << "# Synthetic envelope: every script is exactly 4,000,000 bytes; initial stack preparation is untimed.\n";
    output_file << "# Sequence opcodes exclude OP_NOP envelope padding and the final cleanup/result suffix.\n";
    output_file << strprintf("# Corpus: requested_opcodes=%u generated=%u completed=%u profile=full\n",
                             counts.requested_opcodes, counts.generated_cases, counts.completed_cases);
    output_file << strprintf("# Protocol: schnorr_samples=%u threshold=%.2f round_seed=0x%x stable_rounds=%u promoted=%u wall_cutoff=%.9f\n",
                             SCHNORR_BASELINE_SAMPLES, PROMOTION_THRESHOLD,
                             static_cast<unsigned int>(ROUND_SEED),
                             options.stable_rounds, promotion.promoted_cases, promotion.promotion_cutoff_seconds);
    output_file << "#\n";
    output_file << CSV_HEADER << '\n';

    const BenchResult* schnorr{Slowest(results, [](const BenchResult& result) {
        return result.domain == ExecutionDomain::RAW_SCHNORR;
    })};
    const double one_schnorr{!schnorr || schnorr->median_sec == 0 ? 0 : schnorr->median_sec / SIGNATURES_PER_BLOCK};
    for (size_t index{0}; index < results.size(); ++index) {
        const BenchResult& result{results[index]};
        CsvRow row;
        SetResultIdentity(row, result);
        CsvField(row, CsvColumn::RECORD_TYPE) = "summary";
        CsvField(row, CsvColumn::RANK) = CsvNumber(index + 1);
        CsvField(row, CsvColumn::PROMOTED) = result.promoted ? "true" : "false";
        CsvField(row, CsvColumn::PROMOTION_REASONS) = JoinPromotionReasons(result.promotion_reasons);
        CsvField(row, CsvColumn::STAGE) =
            result.aggregate_stage ? TimingStageName(*result.aggregate_stage) : "unmeasured";
        CsvField(row, CsvColumn::SAMPLES) = CsvNumber(result.aggregate_stage ? std::ranges::count_if(
                                                                                   result.samples, [&](const TimingSample& sample) { return sample.stage == *result.aggregate_stage; }) :
                                                                               0);
        CsvField(row, CsvColumn::WALL_SECONDS) = CsvNumber(result.median_sec);
        CsvField(row, CsvColumn::WALL_MIN_SECONDS) = CsvNumber(result.wall_min_sec);
        CsvField(row, CsvColumn::WALL_MAX_SECONDS) = CsvNumber(result.wall_max_sec);
        CsvField(row, CsvColumn::MDAPE) = CsvNumber(result.mdape);
        CsvField(row, CsvColumn::SCHNORR_EQUIVALENTS) =
            CsvNumber(one_schnorr == 0 ? 0 : result.median_sec / one_schnorr);
        CsvField(row, CsvColumn::VAROPS_PERCENTAGE) =
            CsvNumber(100.0 * result.varops_consumed / TOTAL_VAROPS_BUDGET);
        WriteCsvRow(output_file, row);
    }

    for (const BenchResult& result : results) {
        for (const TimingSample& sample : result.samples) {
            CsvRow row;
            CsvField(row, CsvColumn::RECORD_TYPE) = "sample";
            CsvField(row, CsvColumn::NAME) = result.name;
            CsvField(row, CsvColumn::PROMOTED) = result.promoted ? "true" : "false";
            CsvField(row, CsvColumn::PROMOTION_REASONS) = JoinPromotionReasons(result.promotion_reasons);
            CsvField(row, CsvColumn::STAGE) = TimingStageName(sample.stage);
            CsvField(row, CsvColumn::ROUND) = CsvNumber(sample.round);
            CsvField(row, CsvColumn::ORDER) = CsvNumber(sample.order);
            CsvField(row, CsvColumn::WALL_SECONDS) = CsvNumber(sample.wall_sec);
            WriteCsvRow(output_file, row);
        }
    }

    if (!FlushAndClose(output_file, output_temporary)) {
        std::error_code ignored;
        fs::remove(output_temporary, ignored);
        return false;
    }
    std::error_code rename_error;
    fs::rename(output_temporary, output_target, rename_error);
    if (rename_error) {
        std::cerr << "Error: could not atomically replace " << output_target << ": " << rename_error.message() << "\n";
        std::error_code ignored;
        fs::remove(output_temporary, ignored);
        return false;
    }
    return true;
}

static void PrintUsage(const char* program)
{
    std::cout << "Usage: " << program << " [OPTIONS]\n\n"
              << "Options:\n"
              << "  --opcodes OP_NAME...    Benchmark only explicitly supported opcodes\n"
              << "  --epochs N              Stable measurement rounds (default: 7)\n"
              << "  --list-opcodes          List the declarative opcode inventory\n"
              << "  --silent                Suppress per-row progress\n"
              << "  --file PATH             Atomically write a v2 summary-and-sample CSV\n"
              << "  --help, -h              Show this help\n\n"
              << "Protocol constants: promotion threshold 0.40, round seed 0x475352.\n\n"
              << "Examples:\n"
              << "  " << program << " --opcodes OP_ROLL OP_SHA256\n"
              << "  " << program << " --opcodes OP_NOP --epochs 1 --file results.csv\n";
}

static Options ParseArguments(int argc, char* argv[])
{
    Options options;
    const std::map<std::string, opcodetype> supported{SupportedOpcodeMap()};
    for (int i{1}; i < argc; ++i) {
        const std::string arg{argv[i]};
        if (arg == "--opcodes") {
            const int first{i + 1};
            while (i + 1 < argc && !std::string_view{argv[i + 1]}.starts_with("--")) {
                const std::string requested{argv[++i]};
                std::string name{ToUpper(requested)};
                if (!name.starts_with("OP_")) name = "OP_" + name;
                const auto found{supported.find(name)};
                if (found == supported.end()) {
                    throw std::runtime_error("unknown or unsupported opcode '" + requested + "'");
                }
                options.selected_opcodes.insert(found->second);
            }
            if (i + 1 == first) throw std::runtime_error("--opcodes requires at least one opcode");
        } else if (arg == "--epochs") {
            if (++i >= argc) throw std::runtime_error("--epochs requires a positive integer");
            const std::optional<int> stable_rounds{ToIntegral<int>(argv[i])};
            if (!stable_rounds || *stable_rounds <= 0) {
                throw std::runtime_error("invalid --epochs value '" + std::string{argv[i]} + "'");
            }
            options.stable_rounds = *stable_rounds;
        } else if (arg == "--list-opcodes") {
            options.list_opcodes = true;
        } else if (arg == "--silent") {
            options.silent = true;
        } else if (arg == "--file") {
            if (++i >= argc) throw std::runtime_error("--file requires a path");
            options.output_file = argv[i];
        } else if (arg == "--help" || arg == "-h") {
            PrintUsage(argv[0]);
            std::exit(0);
        } else {
            throw std::runtime_error("unknown option '" + arg + "'");
        }
    }
    return options;
}

} // namespace

int main(int argc, char* argv[])
{
    try {
        const Options options{ParseArguments(argc, argv)};
        if (options.list_opcodes) {
            for (const auto& [name, opcode] : SupportedOpcodeMap()) {
                std::cout << strprintf("%s (0x%02x)\n", name, static_cast<unsigned int>(opcode));
            }
            return 0;
        }

        RunBoundarySelfChecks();
        RunTimingSelfChecks();
        SHA256AutoDetect();
        const CryptoFixture fixture;
        const std::vector<CaseSpec> specs{GenerateCaseSpecs(options)};
        if (specs.empty()) throw std::runtime_error("the requested opcode set generated no cases");
        ReleaseAllocatorCaches();

        std::set<opcodetype> completed_opcodes;
        std::vector<BenchResult> results;
        results.reserve(specs.size() + 1);
        CorpusCounts counts{
            options.selected_opcodes.empty() ? OpcodeRegistry().size() : options.selected_opcodes.size(),
            specs.size(),
            0,
        };
        PromotionSummary promotion;

        RunGlobalWarmup(fixture);
        results.push_back(RunRawSchnorr(fixture));
        promotion.promotion_cutoff_seconds = results.front().median_sec * PROMOTION_THRESHOLD;

        if (!options.silent) {
            std::cout << strprintf("\nDISCOVERY: %u rows, one sample each; Schnorr %.3f sec; cutoff %.3f sec\n",
                                   specs.size(), results.front().median_sec,
                                   promotion.promotion_cutoff_seconds);
        }

        for (size_t index{0}; index < specs.size(); ++index) {
            MaterializedCase test_case{Materialize(specs[index], fixture)};
            BenchResult result{RunDiscoveryCase(test_case, fixture, index)};
            completed_opcodes.insert(specs[index].opcode);
            results.push_back(std::move(result));
            ++counts.completed_cases;
            if (!options.silent) {
                const BenchResult& completed{results.back()};
                std::cout << strprintf("discover %u/%u %s  %.3f sec  %s\n",
                                       index + 1, specs.size(), completed.name,
                                       completed.median_sec,
                                       ScriptErrorString(completed.actual_error));
            }
            ReleaseAllocatorCaches();
        }

        promotion = PromoteDiscoveryResults(results, results.front());
        std::vector<size_t> promoted_indices;
        promoted_indices.reserve(promotion.promoted_cases);
        for (size_t index{1}; index < results.size(); ++index) {
            if (results[index].promoted) promoted_indices.push_back(index);
        }
        const auto schedules{BuildRoundSchedules(promoted_indices, options.stable_rounds)};
        if (!options.silent) {
            std::cout << strprintf("\nSTABLE: %u/%u promoted rows, %u rounds, seed 0x%x\n",
                                   promotion.promoted_cases, specs.size(), options.stable_rounds,
                                   static_cast<unsigned int>(ROUND_SEED));
        }
        for (size_t round{0}; round < schedules.size(); ++round) {
            for (size_t order{0}; order < schedules[round].size(); ++order) {
                const size_t result_index{schedules[round][order]};
                MaterializedCase test_case{Materialize(specs[result_index - 1], fixture)};
                const BenchResult& metadata{results[result_index]};
                const EvalOutcome expected{metadata.actual_error == SCRIPT_ERR_OK,
                                           metadata.actual_error, metadata.varops_consumed};
                TimingSample sample{RunTimedCaseSample(test_case, fixture, expected,
                                                       TimingStage::STABLE, round + 1,
                                                       order, true)};
                if (!options.silent) {
                    std::cout << strprintf("stable %u/%u %u/%u %s  %.3f sec  %s\n",
                                           round + 1, schedules.size(), order + 1,
                                           schedules[round].size(), metadata.name,
                                           sample.wall_sec,
                                           ScriptErrorString(metadata.actual_error));
                }
                results[result_index].samples.push_back(std::move(sample));
            }
        }
        for (size_t index : promoted_indices)
            AggregateSamples(results[index], TimingStage::STABLE);

        for (opcodetype requested : options.selected_opcodes) {
            if (!completed_opcodes.contains(requested)) {
                throw std::runtime_error("requested opcode produced no completed row: " + OpcodeName(requested));
            }
        }
        std::sort(results.begin(), results.end(), [](const BenchResult& left, const BenchResult& right) {
            return left.median_sec > right.median_sec;
        });
        PrintReport(results, counts, options, promotion);
        if (!options.output_file.empty() &&
            !SaveResultsToFile(results, options.output_file, counts, options, promotion)) {
            return 1;
        }
        return 0;
    } catch (const std::exception& exception) {
        std::cerr << "bench_varops: " << exception.what() << "\n";
        return 1;
    }
}
