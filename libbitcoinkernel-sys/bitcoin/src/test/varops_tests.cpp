// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <script/varops.h>

#include <boost/test/unit_test.hpp>

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <thread>
#include <type_traits>
#include <utility>
#include <vector>

BOOST_AUTO_TEST_SUITE(varops_tests)

BOOST_AUTO_TEST_CASE(bip440_cost_constants)
{
    BOOST_CHECK_EQUAL(varops::BUDGET_PER_WEIGHT_UNIT, 10'000);
    BOOST_CHECK_EQUAL(varops::TxBudget(4), 40'000);
    BOOST_CHECK_EQUAL(varops::COST_PER_SIGOP, 500'000);
    BOOST_CHECK_EQUAL(varops::COST_HASH, 50);
    BOOST_CHECK_EQUAL(varops::COST_ROLL, 48);
    BOOST_CHECK_EQUAL(varops::COST_FAST, 2);
    BOOST_CHECK_EQUAL(varops::COST_COPYING, 3);
    BOOST_CHECK_EQUAL(varops::COST_OTHER, 4);
    BOOST_CHECK_EQUAL(varops::COST_ARITH, 6);
    BOOST_CHECK_EQUAL(varops::COST_MUL_QUAD, 27);
}

static uint64_t ExpectedMulCost(size_t size_a, size_t size_b)
{
    const uint64_t a{static_cast<uint64_t>(size_a)};
    const uint64_t b{static_cast<uint64_t>(size_b)};
    const uint64_t wa{(a + 7) / 8 * 8};
    const uint64_t wb{(b + 7) / 8 * 8};
    return (a + b) * 3 + wa / 8 * wb * 27;
}

static uint64_t ExpectedDivModCost(size_t size_a, size_t size_b)
{
    const uint64_t a{(static_cast<uint64_t>(size_a) + 7) / 8 * 8};
    const uint64_t b{(static_cast<uint64_t>(size_b) + 7) / 8 * 8};
    return a * 18 + b * 4 + a * a * 2 / 3;
}

BOOST_AUTO_TEST_CASE(bip441_multiply_and_divide_costs_are_64_bit)
{
    static_assert(std::is_same_v<decltype(varops::MulCost(size_t{0}, size_t{0})), uint64_t>);

    BOOST_CHECK_EQUAL(varops::detail::WordSize(0), 0);
    BOOST_CHECK_EQUAL(varops::detail::WordSize(1), 8);
    BOOST_CHECK_EQUAL(varops::detail::WordSize(8), 8);
    BOOST_CHECK_EQUAL(varops::detail::WordSize(9), 16);

    for (const auto& [size_a, size_b] : {
             std::pair<size_t, size_t>{0, 0},
             std::pair<size_t, size_t>{1, 1},
             std::pair<size_t, size_t>{7, 1},
             std::pair<size_t, size_t>{8, 8},
             std::pair<size_t, size_t>{9, 9},
             std::pair<size_t, size_t>{4'000'000, 4'000'000},
         }) {
        BOOST_TEST_CONTEXT("sizes " << size_a << ", " << size_b)
        {
            BOOST_CHECK_EQUAL(varops::MulCost(size_a, size_b), ExpectedMulCost(size_a, size_b));
            BOOST_CHECK_EQUAL(varops::DivCost(size_a, size_b), ExpectedDivModCost(size_a, size_b));
            BOOST_CHECK_EQUAL(varops::ModCost(size_a, size_b), ExpectedDivModCost(size_a, size_b));
        }
    }

    BOOST_CHECK_GT(varops::MulCost(4'000'000, 4'000'000), uint64_t{std::numeric_limits<uint32_t>::max()});
    BOOST_CHECK_GT(varops::DivCost(4'000'000, 4'000'000), uint64_t{std::numeric_limits<uint32_t>::max()});
}

BOOST_AUTO_TEST_CASE(bip440_and_bip441_word_granular_cost_helpers)
{
    BOOST_CHECK_EQUAL(varops::LengthConversionCost(1), 8 * varops::COST_FAST);
    BOOST_CHECK_EQUAL(varops::LengthConversionCost(8), 8 * varops::COST_FAST);
    BOOST_CHECK_EQUAL(varops::LengthConversionCost(9), 16 * varops::COST_FAST);

    BOOST_CHECK_EQUAL(varops::CompareZeroCost(3), 8 * varops::COST_FAST);
    BOOST_CHECK_EQUAL(varops::ComparisonCost(1, 9), 16 * varops::COST_FAST);
    BOOST_CHECK_EQUAL(varops::BoolAndCost(1, 9), (8 + 16) * varops::COST_FAST);
    BOOST_CHECK_EQUAL(varops::BoolOrCost(9, 1), (16 + 8) * varops::COST_FAST);
    BOOST_CHECK_EQUAL(varops::WithinCost(1, 9, 17), (16 + 24) * varops::COST_FAST);

    BOOST_CHECK_EQUAL(varops::AddCost(1, 9), 16 * (varops::COST_ARITH + varops::COST_COPYING));
    BOOST_CHECK_EQUAL(varops::SubCost(9, 1), 16 * varops::COST_ARITH);
    BOOST_CHECK_EQUAL(varops::MinMaxCost(1, 9), 16 * varops::COST_OTHER);

    BOOST_CHECK_EQUAL(varops::InvertCost(9), 16 * varops::COST_OTHER);
    BOOST_CHECK_EQUAL(varops::AndCost(1, 9), (8 + 16) * varops::COST_FAST);
    BOOST_CHECK_EQUAL(varops::OrCost(1, 9), 8 * varops::COST_OTHER);
    BOOST_CHECK_EQUAL(varops::XorCost(9, 1), 8 * varops::COST_OTHER);

    BOOST_CHECK_EQUAL(varops::TwoMulCost(9), 16 * (varops::COST_COPYING + varops::COST_OTHER));
    BOOST_CHECK_EQUAL(varops::TwoDivCost(9), 16 * varops::COST_OTHER);
    BOOST_CHECK_EQUAL(varops::UnalignedUpShiftCost(9, 0), 16 * varops::COST_OTHER);
    BOOST_CHECK_EQUAL(varops::UnalignedUpShiftCost(1, 9), 16 * varops::COST_OTHER);
    BOOST_CHECK_EQUAL(varops::ChecksigAddIncrementCost(0), 8 * (varops::COST_ARITH + varops::COST_COPYING));
    BOOST_CHECK_EQUAL(varops::ChecksigAddIncrementCost(9), 16 * (varops::COST_ARITH + varops::COST_COPYING));
}

BOOST_AUTO_TEST_CASE(budget_does_not_overspend)
{
    varops::Budget budget{10};

    BOOST_CHECK(budget.Spend(0));
    BOOST_CHECK_EQUAL(*budget.Remaining(), 10);

    BOOST_CHECK(budget.Spend(4));
    BOOST_CHECK_EQUAL(*budget.Remaining(), 6);

    BOOST_CHECK(!budget.Spend(7));
    BOOST_CHECK_EQUAL(*budget.Remaining(), 6);

    BOOST_CHECK(budget.Spend(6));
    BOOST_CHECK_EQUAL(*budget.Remaining(), 0);

    BOOST_CHECK(!budget.Spend(1));
    BOOST_CHECK_EQUAL(*budget.Remaining(), 0);

    BOOST_CHECK(budget.Spend(0));
    BOOST_CHECK_EQUAL(*budget.Remaining(), 0);
}

BOOST_AUTO_TEST_CASE(budget_can_be_unmetered)
{
    auto budget{varops::Budget::Unmetered()};

    BOOST_CHECK(!budget.Remaining());
    BOOST_CHECK(budget.Spend(std::numeric_limits<uint64_t>::max()));
    BOOST_CHECK(!budget.Remaining());
}

BOOST_AUTO_TEST_CASE(budget_is_transaction_wide_and_thread_safe)
{
    static constexpr int thread_count{32};
    static constexpr int spends_per_thread{4096};
    static constexpr uint64_t budget_amount{thread_count * spends_per_thread / 2};

    varops::Budget budget{budget_amount};
    std::atomic<uint64_t> successful_spends{0};
    std::atomic<int> ready_threads{0};
    std::atomic<bool> start{false};
    std::vector<std::thread> threads;

    threads.reserve(thread_count);
    for (int i{0}; i < thread_count; ++i) {
        threads.emplace_back([&] {
            ready_threads.fetch_add(1, std::memory_order_acq_rel);
            while (!start.load(std::memory_order_acquire)) {
                std::this_thread::yield();
            }

            for (int spend{0}; spend < spends_per_thread; ++spend) {
                if (budget.Spend(1)) {
                    successful_spends.fetch_add(1, std::memory_order_relaxed);
                }
            }
        });
    }

    while (ready_threads.load(std::memory_order_acquire) != thread_count) {
        std::this_thread::yield();
    }
    start.store(true, std::memory_order_release);

    for (std::thread& thread : threads) {
        thread.join();
    }

    BOOST_CHECK_EQUAL(successful_spends.load(std::memory_order_relaxed), budget_amount);
    BOOST_CHECK(!budget.Spend(1));
}

BOOST_AUTO_TEST_SUITE_END()
