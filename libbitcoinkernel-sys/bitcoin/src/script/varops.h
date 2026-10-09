// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_SCRIPT_VAROPS_H
#define BITCOIN_SCRIPT_VAROPS_H

#include <script/script.h>
#include <util/check.h>

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <optional>

namespace varops {

/** Thread-safe varops budget shared by script checks for one transaction. */
class Budget final
{
private:
    /** std::nullopt represents evaluation without varops metering. */
    std::optional<std::atomic<uint64_t>> m_remaining;

    Budget() = default;

public:
    explicit Budget(uint64_t remaining) : m_remaining{std::in_place, remaining} {}

    /** Use when standalone evaluation lacks transaction-wide budget context. */
    static Budget Unmetered() { return {}; }

    /** Return true if cost was charged; false if the bounded budget was exhausted. */
    [[nodiscard]] bool Spend(uint64_t cost)
    {
        if (!m_remaining || cost == 0) return true;
        // Only the counter value is synchronized; it does not publish other state.
        uint64_t remaining{m_remaining->load(std::memory_order_relaxed)};
        while (true) {
            if (cost > remaining) return false;
            if (m_remaining->compare_exchange_weak(remaining, remaining - cost,
                                                   std::memory_order_relaxed,
                                                   std::memory_order_relaxed)) {
                return true;
            }
        }
    }

    std::optional<uint64_t> Remaining() const
    {
        if (!m_remaining) return std::nullopt;
        return m_remaining->load(std::memory_order_relaxed);
    }
};

// Varops cost categories per byte:
// Fast operations: comparing bytes, comparing bytes against zero, and zeroing bytes
static constexpr uint64_t COST_FAST = 2;
// Copying bytes: slightly more expensive than fast operations due to memory allocation overhead
static constexpr uint64_t COST_COPYING = 3;
// Everything else
static constexpr uint64_t COST_OTHER = 4;
// Arithmetic operations (add/subtract inner loop)
static constexpr uint64_t COST_ARITH = 6;
// Multiplication quadratic term: inner loop cost with overhead multiplier
static constexpr uint64_t COST_MUL_QUAD = 27;
// OP_ROLL: per stack element moved (24 bytes per std::vector * COST_FAST)
static constexpr uint64_t COST_ROLL = 48;
// Hashing operations
static constexpr uint64_t COST_HASH = 50;

// A per-transaction budget is determined by multiplying the
// total transaction weight by the fixed factor 10,000.
static constexpr uint64_t BUDGET_PER_WEIGHT_UNIT = 10'000;

inline constexpr uint64_t TxBudget(int64_t weight)
{
    Assume(weight >= 0);
    return static_cast<uint64_t>(weight) * BUDGET_PER_WEIGHT_UNIT;
}

// BIP 440: Signature operations cost BUDGET_PER_WEIGHT_UNIT * VALIDATION_WEIGHT_PER_SIGOP_PASSED
// (10,000 * 50 = 500,000 varops units).
static constexpr uint64_t COST_PER_SIGOP = BUDGET_PER_WEIGHT_UNIT * VALIDATION_WEIGHT_PER_SIGOP_PASSED;

namespace detail {

constexpr uint64_t ToCostSize(size_t size)
{
    return static_cast<uint64_t>(size);
}

constexpr uint64_t WordSize(size_t size)
{
    const uint64_t s{ToCostSize(size)};
    return (s + 7) / 8 * 8;
}

constexpr uint64_t MaxWordSize(size_t size1, size_t size2)
{
    return std::max(WordSize(size1), WordSize(size2));
}

constexpr uint64_t MinWordSize(size_t size1, size_t size2)
{
    return std::min(WordSize(size1), WordSize(size2));
}

// BIP 441 costs are maximal when every operand has the maximum permitted size.
constexpr uint64_t MAX_COST_SIZE{MAX_TAPSCRIPT_V2_STACK_ELEMENT_SIZE};
constexpr uint64_t MAX_U64{std::numeric_limits<uint64_t>::max()};
constexpr uint64_t MAX_COST_WORD_SIZE{WordSize(MAX_COST_SIZE)};
constexpr uint64_t MAX_MUL_COPY_COST{2 * MAX_COST_SIZE * COST_COPYING};
constexpr uint64_t MAX_DIV_SQUARE{MAX_COST_WORD_SIZE * MAX_COST_WORD_SIZE};
constexpr uint64_t MAX_DIV_QUADRATIC{MAX_DIV_SQUARE * 2 / 3};

// These bounds prove that every intermediate in the maximum-size BIP 441 cost
// expressions fits in uint64_t, not merely each final result.
static_assert(MAX_COST_SIZE <= MAX_U64 - 7);
static_assert(MAX_COST_SIZE <= MAX_U64 / (2 * COST_COPYING));
static_assert(MAX_COST_WORD_SIZE / 8 <=
                  (MAX_U64 - MAX_MUL_COPY_COST) / COST_MUL_QUAD / MAX_COST_WORD_SIZE,
              "maximum OP_MUL cost must fit in uint64_t");
static_assert(MAX_COST_WORD_SIZE <= MAX_U64 / MAX_COST_WORD_SIZE);
static_assert(MAX_DIV_SQUARE <= MAX_U64 / 2);
static_assert(MAX_COST_WORD_SIZE <=
                  (MAX_U64 - MAX_DIV_QUADRATIC) / (3 * COST_ARITH + COST_OTHER),
              "maximum OP_DIV and OP_MOD cost must fit in uint64_t");

} // namespace detail

/** Pure cost calculations taking operand sizes in bytes. */
constexpr uint64_t LengthConversionCost(size_t size)
{
    return detail::WordSize(size) * COST_FAST;
}

constexpr uint64_t CompareZeroCost(size_t size)
{
    return detail::WordSize(size) * COST_FAST;
}

constexpr uint64_t ComparisonCost(size_t size1, size_t size2)
{
    return detail::MaxWordSize(size1, size2) * COST_FAST;
}

constexpr uint64_t AddCost(size_t size1, size_t size2)
{
    return detail::MaxWordSize(size1, size2) * (COST_ARITH + COST_COPYING);
}

constexpr uint64_t SubCost(size_t size1, size_t size2)
{
    return detail::MaxWordSize(size1, size2) * COST_ARITH;
}

constexpr uint64_t MulCost(size_t size1, size_t size2)
{
    const uint64_t copy_cost{(detail::ToCostSize(size1) + detail::ToCostSize(size2)) * COST_COPYING};
    const uint64_t quadratic_cost{detail::WordSize(size1) / 8 * detail::WordSize(size2) * COST_MUL_QUAD};
    return copy_cost + quadratic_cost;
}

constexpr uint64_t DivCost(size_t size1, size_t size2)
{
    const uint64_t s1{detail::WordSize(size1)};
    const uint64_t s2{detail::WordSize(size2)};
    const uint64_t linear_cost{s1 * (3 * COST_ARITH) + s2 * COST_OTHER};
    const uint64_t quadratic_cost{s1 * s1 * 2 / 3};
    return linear_cost + quadratic_cost;
}

constexpr uint64_t ModCost(size_t size1, size_t size2)
{
    // OP_MOD uses the same division algorithm and cost model as OP_DIV.
    return DivCost(size1, size2);
}

constexpr uint64_t BoolAndCost(size_t size1, size_t size2)
{
    return (detail::WordSize(size1) + detail::WordSize(size2)) * COST_FAST; // COMPARINGZERO both operands
}

constexpr uint64_t BoolOrCost(size_t size1, size_t size2)
{
    return (detail::WordSize(size1) + detail::WordSize(size2)) * COST_FAST; // COMPARINGZERO both operands
}

constexpr uint64_t WithinCost(size_t size1, size_t size2, size_t size3)
{
    // Two comparisons: v1 vs v2, v1 vs v3
    return detail::MaxWordSize(size1, size2) * COST_FAST + detail::MaxWordSize(size1, size3) * COST_FAST;
}

constexpr uint64_t InvertCost(size_t size)
{
    return detail::WordSize(size) * COST_OTHER;
}

constexpr uint64_t AndCost(size_t size1, size_t size2)
{
    // min * COST_OTHER + (max - min) * COST_FAST simplifies to this expression.
    return (detail::WordSize(size1) + detail::WordSize(size2)) * COST_FAST;
}

constexpr uint64_t OrCost(size_t size1, size_t size2)
{
    return detail::MinWordSize(size1, size2) * COST_OTHER;
}

constexpr uint64_t XorCost(size_t size1, size_t size2)
{
    return detail::MinWordSize(size1, size2) * COST_OTHER;
}

constexpr uint64_t MinMaxCost(size_t size1, size_t size2)
{
    return detail::MaxWordSize(size1, size2) * COST_OTHER;
}

constexpr uint64_t TwoMulCost(size_t size)
{
    return detail::WordSize(size) * (COST_COPYING + COST_OTHER);
}

constexpr uint64_t TwoDivCost(size_t size)
{
    return detail::WordSize(size) * COST_OTHER;
}

constexpr uint64_t UnalignedUpShiftCost(size_t size, size_t prepended_bytes)
{
    return detail::WordSize(detail::ToCostSize(size) + detail::ToCostSize(prepended_bytes)) * COST_OTHER;
}

constexpr uint64_t ChecksigAddIncrementCost(size_t number_size)
{
    return std::max(detail::WordSize(1), detail::WordSize(number_size)) * (COST_ARITH + COST_COPYING);
}

} // namespace varops

#endif // BITCOIN_SCRIPT_VAROPS_H
