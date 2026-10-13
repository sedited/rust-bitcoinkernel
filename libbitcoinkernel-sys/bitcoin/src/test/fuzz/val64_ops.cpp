// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

// Checks Val64 arithmetic, bitwise shifts, predicates, and large multiply,
// divide, and modulo operations against independent integer properties.

#include <script/script.h>
#include <script/val64.h>
#include <test/fuzz/FuzzedDataProvider.h>
#include <test/fuzz/fuzz.h>
#include <util/check.h>

#include <boost/multiprecision/cpp_int.hpp>

#include <algorithm>
#include <array>
#include <cstdint>
#include <iterator>
#include <limits>
#include <optional>
#include <utility>
#include <vector>

namespace {
using boost::multiprecision::cpp_int;
using Bytes = std::vector<unsigned char>;
using OptionalBytes = std::optional<Bytes>;

constexpr size_t MAX_NORMAL_OPERAND_SIZE{256};
constexpr size_t MIN_LARGE_OPERAND_SIZE{257};
constexpr size_t MAX_LARGE_OPERAND_SIZE{4 * 1024};

// BIP 440 cost coefficients. These intentionally do not use the production
// varops helpers so the fuzz target remains an independent cost oracle.
constexpr uint64_t COST_FAST{2};
constexpr uint64_t COST_COPYING{3};
constexpr uint64_t COST_OTHER{4};
constexpr uint64_t COST_ARITH{6};

enum class ArithmeticOp : uint8_t {
    ADD,
    SUB,
    ONE_ADD,
    ONE_SUB,
    TWO_MUL,
    TWO_DIV,
    MIN,
    MAX,
    MUL,
    DIV,
    MOD,
};

enum class BitwiseShiftOp : uint8_t {
    INVERT,
    AND,
    OR,
    XOR,
    UPSHIFT,
    DOWNSHIFT,
};

class Val64Fuzz final : public Val64
{
public:
    explicit Val64Fuzz(Bytes bytes) : Val64(std::move(bytes)) {}

    static void SetForcePortableMath(bool value) { Val64::m_force_portable_math = value; }
};

class ScopedPortableMath final
{
public:
    explicit ScopedPortableMath(bool portable) { Val64Fuzz::SetForcePortableMath(portable); }
    ~ScopedPortableMath() { Val64Fuzz::SetForcePortableMath(false); }

    ScopedPortableMath(const ScopedPortableMath&) = delete;
    ScopedPortableMath& operator=(const ScopedPortableMath&) = delete;
};

struct ActualResult {
    OptionalBytes value;
    std::optional<uint64_t> cost;
};

cpp_int FromLittleEndian(const Bytes& bytes)
{
    if (bytes.empty()) return 0;

    cpp_int value{0};
    boost::multiprecision::import_bits(value, bytes.begin(), bytes.end(), 8, /*msv_first=*/false);
    return value;
}

Bytes ToMinimalLittleEndian(cpp_int value)
{
    Assert(value >= 0);
    if (value == 0) return {};

    Bytes bytes;
    boost::multiprecision::export_bits(value, std::back_inserter(bytes), 8, /*msv_first=*/false);
    return bytes;
}

uint64_t ToU64Ceil(const Bytes& bytes, uint64_t max)
{
    const cpp_int value{FromLittleEndian(bytes)};
    if (value > max) return max;
    return value.convert_to<uint64_t>();
}

uint64_t W(size_t size)
{
    const uint64_t bytes{static_cast<uint64_t>(size)};
    return (bytes + 7) / 8 * 8;
}

uint64_t LengthConversionCost(size_t size)
{
    return W(size) * COST_FAST;
}

OptionalBytes ReferenceArithmetic(ArithmeticOp op, const Bytes& a, const Bytes& b)
{
    const cpp_int av{FromLittleEndian(a)};

    switch (op) {
    case ArithmeticOp::ADD:
        return ToMinimalLittleEndian(av + FromLittleEndian(b));
    case ArithmeticOp::SUB: {
        const cpp_int bv{FromLittleEndian(b)};
        if (av < bv) return std::nullopt;
        return ToMinimalLittleEndian(av - bv);
    }
    case ArithmeticOp::ONE_ADD:
        return ToMinimalLittleEndian(av + 1);
    case ArithmeticOp::ONE_SUB:
        if (av == 0) return std::nullopt;
        return ToMinimalLittleEndian(av - 1);
    case ArithmeticOp::TWO_MUL:
        return ToMinimalLittleEndian(av * 2);
    case ArithmeticOp::TWO_DIV:
        return ToMinimalLittleEndian(av / 2);
    case ArithmeticOp::MIN: {
        const cpp_int bv{FromLittleEndian(b)};
        return ToMinimalLittleEndian(std::min(av, bv));
    }
    case ArithmeticOp::MAX: {
        const cpp_int bv{FromLittleEndian(b)};
        return ToMinimalLittleEndian(std::max(av, bv));
    }
    case ArithmeticOp::MUL:
        return ToMinimalLittleEndian(av * FromLittleEndian(b));
    case ArithmeticOp::DIV: {
        const cpp_int bv{FromLittleEndian(b)};
        if (bv == 0) return std::nullopt;
        return ToMinimalLittleEndian(av / bv);
    }
    case ArithmeticOp::MOD: {
        const cpp_int bv{FromLittleEndian(b)};
        if (bv == 0) return std::nullopt;
        return ToMinimalLittleEndian(av % bv);
    }
    }
    Assert(false);
    return std::nullopt;
}

std::optional<uint64_t> ReferenceArithmeticCost(ArithmeticOp op, size_t a_size, size_t b_size)
{
    const uint64_t max_word_size{std::max(W(a_size), W(b_size))};

    switch (op) {
    case ArithmeticOp::ADD:
        return max_word_size * (COST_ARITH + COST_COPYING);
    case ArithmeticOp::SUB:
        return max_word_size * COST_ARITH;
    case ArithmeticOp::ONE_ADD:
        return std::max(W(a_size), W(1)) * (COST_ARITH + COST_COPYING);
    case ArithmeticOp::ONE_SUB:
        return std::max(W(a_size), W(1)) * COST_ARITH;
    case ArithmeticOp::TWO_MUL:
        return W(a_size) * (COST_COPYING + COST_OTHER);
    case ArithmeticOp::TWO_DIV:
        return W(a_size) * COST_OTHER;
    case ArithmeticOp::MIN:
    case ArithmeticOp::MAX:
        return max_word_size * COST_OTHER;
    case ArithmeticOp::MUL:
    case ArithmeticOp::DIV:
    case ArithmeticOp::MOD:
        return std::nullopt;
    }
    Assert(false);
    return std::nullopt;
}

ActualResult ExecuteArithmetic(ArithmeticOp op, const Bytes& a, const Bytes& b, bool portable_math)
{
    const ScopedPortableMath scoped_portable_math{portable_math};
    Val64Fuzz va{a};
    Val64Fuzz vb{b};
    uint64_t cost{0};

    switch (op) {
    case ArithmeticOp::ADD:
        Val64::OpAdd(va, vb, cost);
        return {va.MoveToValtype(), cost};
    case ArithmeticOp::SUB:
        if (!Val64::OpSub(va, vb, cost)) return {std::nullopt, cost};
        return {va.MoveToValtype(), cost};
    case ArithmeticOp::ONE_ADD:
        Val64::Op1Add(va, cost);
        return {va.MoveToValtype(), cost};
    case ArithmeticOp::ONE_SUB:
        if (!Val64::Op1Sub(va, cost)) return {std::nullopt, cost};
        return {va.MoveToValtype(), cost};
    case ArithmeticOp::TWO_MUL:
        Val64::Op2Mul(va, cost);
        return {va.MoveToValtype(), cost};
    case ArithmeticOp::TWO_DIV:
        Val64::Op2Div(va, cost);
        return {va.MoveToValtype(), cost};
    case ArithmeticOp::MIN:
        Val64::OpMin(va, vb, cost);
        return {va.MoveToValtype(), cost};
    case ArithmeticOp::MAX:
        Val64::OpMax(va, vb, cost);
        return {va.MoveToValtype(), cost};
    case ArithmeticOp::MUL: {
        Val64 result{Val64::OpMul(va, vb)};
        return {result.MoveToValtype(), std::nullopt};
    }
    case ArithmeticOp::DIV:
        if (!Val64::OpDiv(va, vb)) return {std::nullopt, std::nullopt};
        return {va.MoveToValtype(), std::nullopt};
    case ArithmeticOp::MOD:
        if (!Val64::OpMod(va, vb)) return {std::nullopt, std::nullopt};
        return {va.MoveToValtype(), std::nullopt};
    }
    Assert(false);
    return {};
}

bool UsesPortableMath(ArithmeticOp op)
{
    return op == ArithmeticOp::MUL || op == ArithmeticOp::DIV || op == ArithmeticOp::MOD;
}

bool IsUnary(ArithmeticOp op)
{
    return op == ArithmeticOp::ONE_ADD || op == ArithmeticOp::ONE_SUB ||
           op == ArithmeticOp::TWO_MUL || op == ArithmeticOp::TWO_DIV;
}

void CheckArithmeticBackend(ArithmeticOp op,
                            const Bytes& a,
                            const Bytes& b,
                            bool portable_math,
                            const OptionalBytes& expected,
                            std::optional<uint64_t> expected_cost)
{
    const ActualResult actual{ExecuteArithmetic(op, a, b, portable_math)};
    Assert(actual.value == expected);
    Assert(actual.cost == expected_cost);
}

void CheckArithmetic(ArithmeticOp op, const Bytes& a, const Bytes& b)
{
    const OptionalBytes expected{ReferenceArithmetic(op, a, b)};
    const std::optional<uint64_t> expected_cost{ReferenceArithmeticCost(op, a.size(), b.size())};

    CheckArithmeticBackend(op, a, b, /*portable_math=*/false, expected, expected_cost);
    if (UsesPortableMath(op)) {
        CheckArithmeticBackend(op, a, b, /*portable_math=*/true, expected, expected_cost);
    }
}

Bytes ReferenceBitwise(BitwiseShiftOp op, const Bytes& a, const Bytes& b)
{
    Assert(op == BitwiseShiftOp::AND || op == BitwiseShiftOp::OR || op == BitwiseShiftOp::XOR);
    Bytes result(std::max(a.size(), b.size()));
    for (size_t i{0}; i < result.size(); ++i) {
        const unsigned char av{i < a.size() ? a[i] : static_cast<unsigned char>(0)};
        const unsigned char bv{i < b.size() ? b[i] : static_cast<unsigned char>(0)};
        if (op == BitwiseShiftOp::AND) result[i] = av & bv;
        if (op == BitwiseShiftOp::OR) result[i] = av | bv;
        if (op == BitwiseShiftOp::XOR) result[i] = av ^ bv;
    }
    return result;
}

Bytes ShiftLeftFixed(const Bytes& value, uint64_t bits, size_t result_size)
{
    Bytes result(result_size, 0);
    const size_t byte_shift{static_cast<size_t>(bits / 8)};
    const unsigned int bit_shift{static_cast<unsigned int>(bits % 8)};
    for (size_t i{0}; i < value.size() && i + byte_shift < result.size(); ++i) {
        const uint16_t shifted{static_cast<uint16_t>(static_cast<uint16_t>(value[i]) << bit_shift)};
        result[i + byte_shift] |= static_cast<unsigned char>(shifted);
        if (bit_shift != 0 && i + byte_shift + 1 < result.size()) {
            result[i + byte_shift + 1] |= static_cast<unsigned char>(shifted >> 8);
        }
    }
    return result;
}

Bytes ShiftRightFixed(const Bytes& value, uint64_t bits, size_t result_size)
{
    Bytes result(result_size, 0);
    const size_t byte_shift{static_cast<size_t>(bits / 8)};
    const unsigned int bit_shift{static_cast<unsigned int>(bits % 8)};
    for (size_t i{0}; i < result.size(); ++i) {
        const size_t source{i + byte_shift};
        uint16_t shifted{static_cast<uint16_t>(static_cast<uint16_t>(value[source]) >> bit_shift)};
        if (bit_shift != 0 && source + 1 < value.size()) {
            shifted |= static_cast<uint16_t>(value[source + 1]) << (8 - bit_shift);
        }
        result[i] = static_cast<unsigned char>(shifted);
    }
    return result;
}

OptionalBytes ReferenceBitwiseShift(BitwiseShiftOp op, const Bytes& a, const Bytes& b)
{
    switch (op) {
    case BitwiseShiftOp::INVERT: {
        Bytes result{a};
        for (unsigned char& byte : result)
            byte ^= 0xff;
        return result;
    }
    case BitwiseShiftOp::AND:
    case BitwiseShiftOp::OR:
    case BitwiseShiftOp::XOR:
        return ReferenceBitwise(op, a, b);
    case BitwiseShiftOp::UPSHIFT: {
        constexpr uint64_t max_bits{uint64_t{MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE} * 8};
        const uint64_t bits{ToU64Ceil(b, max_bits + 1)};
        const uint64_t a_bits{static_cast<uint64_t>(a.size()) * 8};
        if (bits > max_bits - a_bits) return std::nullopt;

        const size_t prebytes{static_cast<size_t>(bits / 8)};
        const size_t result_size{a.size() + prebytes + (bits % 8 == 0 ? 0 : 1)};
        return ShiftLeftFixed(a, bits, result_size);
    }
    case BitwiseShiftOp::DOWNSHIFT: {
        const uint64_t a_bits{static_cast<uint64_t>(a.size()) * 8};
        const uint64_t bits{ToU64Ceil(b, a_bits)};
        const size_t bytes{static_cast<size_t>(bits / 8)};
        if (bytes >= a.size()) return Bytes{};
        return ShiftRightFixed(a, bits, a.size() - bytes);
    }
    }
    Assert(false);
    return std::nullopt;
}

uint64_t ReferenceBitwiseShiftCost(BitwiseShiftOp op, const Bytes& a, const Bytes& b)
{
    switch (op) {
    case BitwiseShiftOp::INVERT:
        return W(a.size()) * COST_OTHER;
    case BitwiseShiftOp::AND:
        return (W(a.size()) + W(b.size())) * COST_FAST;
    case BitwiseShiftOp::OR:
    case BitwiseShiftOp::XOR:
        return std::min(W(a.size()), W(b.size())) * COST_OTHER;
    case BitwiseShiftOp::UPSHIFT: {
        constexpr uint64_t max_bits{uint64_t{MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE} * 8};
        const uint64_t bits{ToU64Ceil(b, max_bits + 1)};
        const uint64_t a_bits{static_cast<uint64_t>(a.size()) * 8};
        uint64_t cost{LengthConversionCost(b.size())};
        if (bits > max_bits - a_bits) return cost;

        const size_t prebytes{static_cast<size_t>(bits / 8)};
        cost += prebytes * COST_FAST + a.size() * COST_COPYING;
        if (bits % 8 != 0) cost += W(a.size() + prebytes) * COST_OTHER;
        return cost;
    }
    case BitwiseShiftOp::DOWNSHIFT: {
        const uint64_t bits{ToU64Ceil(b, static_cast<uint64_t>(a.size()) * 8)};
        const size_t bytes{static_cast<size_t>(bits / 8)};
        uint64_t cost{LengthConversionCost(b.size())};
        if (bytes < a.size()) cost += (a.size() - bytes) * COST_COPYING;
        return cost;
    }
    }
    Assert(false);
    return 0;
}

ActualResult ExecuteBitwiseShift(BitwiseShiftOp op, const Bytes& a, const Bytes& b)
{
    Val64Fuzz va{a};
    Val64Fuzz vb{b};
    uint64_t cost{0};

    switch (op) {
    case BitwiseShiftOp::INVERT:
        Val64::OpInvert(va, cost);
        break;
    case BitwiseShiftOp::AND:
        Val64::OpAnd(va, vb, cost);
        break;
    case BitwiseShiftOp::OR:
        Val64::OpOr(va, vb, cost);
        break;
    case BitwiseShiftOp::XOR:
        Val64::OpXor(va, vb, cost);
        break;
    case BitwiseShiftOp::UPSHIFT:
        if (!Val64::OpUpShift(va, vb, MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE, cost)) {
            return {std::nullopt, cost};
        }
        break;
    case BitwiseShiftOp::DOWNSHIFT:
        Val64::OpDownShift(va, vb, cost);
        break;
    }
    return {va.MoveToValtype(), cost};
}

void CheckBitwiseShift(BitwiseShiftOp op, const Bytes& a, const Bytes& b)
{
    const OptionalBytes expected{ReferenceBitwiseShift(op, a, b)};
    const uint64_t expected_cost{ReferenceBitwiseShiftCost(op, a, b)};
    const ActualResult actual{ExecuteBitwiseShift(op, a, b)};
    Assert(actual.value == expected);
    Assert(actual.cost == expected_cost);
}

template <size_t N>
size_t ConsumeSize(FuzzedDataProvider& provider,
                   const std::array<size_t, N>& boundaries,
                   size_t min,
                   size_t max)
{
    if (provider.ConsumeBool()) return provider.PickValueInArray(boundaries);
    return provider.ConsumeIntegralInRange<size_t>(min, max);
}

Bytes ConsumeBytesWithSize(FuzzedDataProvider& provider, size_t size)
{
    const uint8_t mode{provider.ConsumeIntegralInRange<uint8_t>(0, 3)};
    if (mode == 1) return Bytes(size, 0x00);
    if (mode == 2) return Bytes(size, 0xff);

    const unsigned char fill{provider.ConsumeIntegral<unsigned char>()};
    Bytes bytes{provider.ConsumeBytes<unsigned char>(size)};
    bytes.resize(size, fill);
    if (mode == 3 && !bytes.empty()) {
        const size_t zero_tail{provider.ConsumeIntegralInRange<size_t>(1, std::min<size_t>(8, bytes.size()))};
        std::fill(bytes.end() - zero_tail, bytes.end(), 0x00);
    }
    return bytes;
}

Bytes ConsumeNormalOperand(FuzzedDataProvider& provider)
{
    static constexpr std::array<size_t, 20> boundaries{
        0,
        1,
        2,
        7,
        8,
        9,
        15,
        16,
        17,
        31,
        32,
        33,
        63,
        64,
        65,
        127,
        128,
        129,
        255,
        256,
    };
    return ConsumeBytesWithSize(provider, ConsumeSize(provider, boundaries, 0, MAX_NORMAL_OPERAND_SIZE));
}

Bytes ConsumeLargeOperand(FuzzedDataProvider& provider)
{
    static constexpr std::array<size_t, 12> boundaries{
        257,
        511,
        512,
        513,
        1023,
        1024,
        1025,
        2047,
        2048,
        2049,
        4095,
        4096,
    };
    return ConsumeBytesWithSize(
        provider,
        ConsumeSize(provider, boundaries, MIN_LARGE_OPERAND_SIZE, MAX_LARGE_OPERAND_SIZE));
}

void AddNear(std::vector<uint64_t>& values, uint64_t value)
{
    if (value > 0) values.push_back(value - 1);
    values.push_back(value);
    if (value < std::numeric_limits<uint64_t>::max()) values.push_back(value + 1);
}

Bytes PadNumericOperand(FuzzedDataProvider& provider, Bytes bytes)
{
    if (provider.ConsumeBool()) {
        bytes.resize(bytes.size() + provider.ConsumeIntegralInRange<size_t>(0, 8), 0x00);
    }
    return bytes;
}

Bytes ConsumeShiftOperand(FuzzedDataProvider& provider, BitwiseShiftOp op, size_t a_size)
{
    constexpr uint64_t max_bits{uint64_t{MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE} * 8};
    const uint64_t a_bits{static_cast<uint64_t>(a_size) * 8};
    std::vector<uint64_t> candidates{0, 1, 7, 8, 9, 15, 16, 63, 64, 65};
    AddNear(candidates, a_bits);
    AddNear(candidates, (a_bits / 64) * 64);

    if (op == BitwiseShiftOp::UPSHIFT) {
        candidates.push_back(max_bits + 1);
        candidates.push_back(provider.ConsumeIntegralInRange<uint64_t>(0, a_bits + 1024));
    } else {
        AddNear(candidates, a_bits + 64);
        candidates.push_back(provider.ConsumeIntegralInRange<uint64_t>(0, a_bits + 128));
    }

    const uint64_t value{candidates.at(provider.ConsumeIntegralInRange<size_t>(0, candidates.size() - 1))};
    return PadNumericOperand(provider, ToMinimalLittleEndian(cpp_int{value}));
}

int ReferenceCompare(const Bytes& a, const Bytes& b)
{
    const cpp_int av{FromLittleEndian(a)};
    const cpp_int bv{FromLittleEndian(b)};
    if (av < bv) return -1;
    if (av > bv) return 1;
    return 0;
}

void CheckPredicates(FuzzedDataProvider& provider, const Bytes& a, const Bytes& b)
{
    uint64_t max;
    if (provider.ConsumeBool()) {
        max = provider.ConsumeIntegral<uint64_t>();
    } else {
        max = provider.PickValueInArray<uint64_t>({0, 1, 255, 256, 4096,
                                                   std::numeric_limits<uint32_t>::max(),
                                                   std::numeric_limits<uint64_t>::max()});
    }
    const uint64_t expected_ceil{ToU64Ceil(a, max)};
    const bool expected_zero{FromLittleEndian(a) == 0};
    const int expected_cmp{ReferenceCompare(a, b)};

    {
        Val64Fuzz va{a};
        uint64_t cost{0};
        Assert(va.ToU64Ceil(max, cost) == expected_ceil);
        Assert(cost == LengthConversionCost(a.size()));
    }
    {
        Val64Fuzz va{a};
        uint64_t cost{0};
        Assert(va.IsZero() == expected_zero);
        Assert(va.IsZero(cost) == expected_zero);
        Assert(cost == W(a.size()) * COST_FAST);
    }
    {
        Val64Fuzz va{a};
        Val64Fuzz vb{b};
        uint64_t cost{0};
        Assert(va.Compare(vb) == expected_cmp);
        Assert(va.Compare(vb, cost) == expected_cmp);
        Assert(cost == std::max(W(a.size()), W(b.size())) * COST_FAST);
    }
}
} // namespace

FUZZ_TARGET(val64_arithmetic)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    const ArithmeticOp op{static_cast<ArithmeticOp>(provider.ConsumeIntegralInRange<int>(
        0, static_cast<int>(ArithmeticOp::MOD)))};
    const Bytes a{ConsumeNormalOperand(provider)};
    const Bytes b{IsUnary(op) ? Bytes{} : ConsumeNormalOperand(provider)};
    CheckArithmetic(op, a, b);
}

FUZZ_TARGET(val64_bitwise_shift)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    const BitwiseShiftOp op{static_cast<BitwiseShiftOp>(provider.ConsumeIntegralInRange<int>(
        0, static_cast<int>(BitwiseShiftOp::DOWNSHIFT)))};
    const Bytes a{ConsumeNormalOperand(provider)};
    Bytes b;
    if (op == BitwiseShiftOp::UPSHIFT || op == BitwiseShiftOp::DOWNSHIFT) {
        b = ConsumeShiftOperand(provider, op, a.size());
    } else if (op != BitwiseShiftOp::INVERT) {
        b = ConsumeNormalOperand(provider);
    }
    CheckBitwiseShift(op, a, b);
}

FUZZ_TARGET(val64_predicates)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    const Bytes a{ConsumeNormalOperand(provider)};
    const Bytes b{ConsumeNormalOperand(provider)};
    CheckPredicates(provider, a, b);
}

FUZZ_TARGET(val64_large_mul_divmod)
{
    FuzzedDataProvider provider{buffer.data(), buffer.size()};
    const ArithmeticOp op{provider.PickValueInArray<ArithmeticOp>({
        ArithmeticOp::MUL,
        ArithmeticOp::DIV,
        ArithmeticOp::MOD,
    })};
    const Bytes a{ConsumeLargeOperand(provider)};
    const Bytes b{ConsumeLargeOperand(provider)};
    const OptionalBytes expected{ReferenceArithmetic(op, a, b)};
    CheckArithmeticBackend(op, a, b, provider.ConsumeBool(), expected, std::nullopt);
}
