// Copyright (c) 2026 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or https://opensource.org/license/mit/.

#include <script/val64.h>
#include <script/varops.h>
#include <test/util/setup_common.h>

#include <boost/test/unit_test.hpp>

#include <cstdint>
#include <utility>
#include <vector>

using valtype = std::vector<unsigned char>;

static valtype Bytes(std::initializer_list<unsigned char> bytes)
{
    return valtype{bytes};
}

static Val64 ValFromBytes(const valtype& bytes)
{
    valtype copy{bytes};
    return Val64{std::move(copy)};
}

static valtype Num(uint64_t value)
{
    Val64 num{value};
    return num.MoveToValtype();
}

static valtype MoveOut(Val64& value)
{
    return value.MoveToValtype();
}

BOOST_FIXTURE_TEST_SUITE(val64_semantics_tests, BasicTestingSetup)

BOOST_AUTO_TEST_CASE(unsigned_minimal_encoding)
{
    BOOST_CHECK(Num(0) == Bytes({}));
    BOOST_CHECK(Num(1) == Bytes({0x01}));
    BOOST_CHECK(Num(0xff) == Bytes({0xff}));
    BOOST_CHECK(Num(0x100) == Bytes({0x00, 0x01}));
    BOOST_CHECK(Num(0x8000000000000000ULL) == Bytes({0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80}));
}

BOOST_AUTO_TEST_CASE(length_conversion_reads_full_little_endian_value)
{
    uint64_t cost{0};

    Val64 with_trailing_zeroes{ValFromBytes(Bytes({0xff, 0x00, 0x00}))};
    BOOST_CHECK_EQUAL(with_trailing_zeroes.ToU64Ceil(300, cost), 255);
    BOOST_CHECK_EQUAL(cost, varops::LengthConversionCost(3));

    cost = 0;
    Val64 capped_by_max{ValFromBytes(Bytes({0x05}))};
    BOOST_CHECK_EQUAL(capped_by_max.ToU64Ceil(4, cost), 4);
    BOOST_CHECK_EQUAL(cost, varops::LengthConversionCost(1));

    cost = 0;
    Val64 larger_than_u64{ValFromBytes(Bytes({0, 0, 0, 0, 0, 0, 0, 0, 1}))};
    BOOST_CHECK_EQUAL(larger_than_u64.ToU64Ceil(1000, cost), 1000);
    BOOST_CHECK_EQUAL(cost, varops::LengthConversionCost(9));

    cost = 0;
    Val64 padded_u64_max{ValFromBytes(Bytes({0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x00}))};
    BOOST_CHECK_EQUAL(padded_u64_max.ToU64Ceil(UINT64_MAX, cost), UINT64_MAX);
    BOOST_CHECK_EQUAL(cost, varops::LengthConversionCost(9));
}

BOOST_AUTO_TEST_CASE(arithmetic_operations_normalize_results)
{
    uint64_t cost{0};

    Val64 add_a{ValFromBytes(Bytes({0xff}))};
    Val64 add_b{ValFromBytes(Bytes({0x01}))};
    Val64::OpAdd(add_a, add_b, cost);
    BOOST_CHECK(MoveOut(add_a) == Bytes({0x00, 0x01}));
    BOOST_CHECK_EQUAL(cost, varops::AddCost(1, 1));

    cost = 0;
    Val64 add_with_zeroes{ValFromBytes(Bytes({0x01, 0x00, 0x00}))};
    Val64 zero{ValFromBytes(Bytes({}))};
    Val64::OpAdd(add_with_zeroes, zero, cost);
    BOOST_CHECK(MoveOut(add_with_zeroes) == Bytes({0x01}));
    BOOST_CHECK_EQUAL(cost, varops::AddCost(3, 0));

    cost = 0;
    Val64 sub_a{ValFromBytes(Bytes({0x00, 0x01}))};
    Val64 sub_b{ValFromBytes(Bytes({0x01}))};
    BOOST_CHECK(Val64::OpSub(sub_a, sub_b, cost));
    BOOST_CHECK(MoveOut(sub_a) == Bytes({0xff}));
    BOOST_CHECK_EQUAL(cost, varops::SubCost(2, 1));

    cost = 0;
    Val64 sub_to_zero{ValFromBytes(Bytes({0x01}))};
    Val64 one{ValFromBytes(Bytes({0x01}))};
    BOOST_CHECK(Val64::OpSub(sub_to_zero, one, cost));
    BOOST_CHECK(MoveOut(sub_to_zero) == Bytes({}));

    cost = 0;
    Val64 underflow{ValFromBytes(Bytes({}))};
    BOOST_CHECK(!Val64::Op1Sub(underflow, cost));
    BOOST_CHECK_EQUAL(cost, varops::SubCost(0, 1));
}

BOOST_AUTO_TEST_CASE(one_add_and_one_sub_cross_word_boundaries)
{
    uint64_t cost{0};

    Val64 carry_from_full_word{ValFromBytes(Bytes({0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}))};
    Val64::Op1Add(carry_from_full_word, cost);
    BOOST_CHECK(MoveOut(carry_from_full_word) == Bytes({0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}));
    BOOST_CHECK_EQUAL(cost, varops::AddCost(8, 1));

    cost = 0;
    Val64 borrow_from_next_word{ValFromBytes(Bytes({0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01}))};
    BOOST_CHECK(Val64::Op1Sub(borrow_from_next_word, cost));
    BOOST_CHECK(MoveOut(borrow_from_next_word) == Bytes({0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}));
    BOOST_CHECK_EQUAL(cost, varops::SubCost(9, 1));
}

BOOST_AUTO_TEST_CASE(bit_operations_preserve_operand_width)
{
    uint64_t cost{0};

    Val64 inverted{ValFromBytes(Bytes({0x00, 0xff}))};
    Val64::OpInvert(inverted, cost);
    BOOST_CHECK(MoveOut(inverted) == Bytes({0xff, 0x00}));
    BOOST_CHECK_EQUAL(cost, varops::InvertCost(2));

    cost = 0;
    Val64 and_a{ValFromBytes(Bytes({0xff, 0xff}))};
    Val64 and_b{ValFromBytes(Bytes({0x0f}))};
    Val64::OpAnd(and_a, and_b, cost);
    BOOST_CHECK(MoveOut(and_a) == Bytes({0x0f, 0x00}));
    BOOST_CHECK_EQUAL(cost, varops::AndCost(2, 1));

    cost = 0;
    Val64 or_a{ValFromBytes(Bytes({0x00, 0x00}))};
    Val64 or_b{ValFromBytes(Bytes({0x00}))};
    Val64::OpOr(or_a, or_b, cost);
    BOOST_CHECK(MoveOut(or_a) == Bytes({0x00, 0x00}));
    BOOST_CHECK_EQUAL(cost, varops::OrCost(2, 1));

    cost = 0;
    Val64 xor_a{ValFromBytes(Bytes({0x01, 0x00}))};
    Val64 xor_b{ValFromBytes(Bytes({0x01}))};
    Val64::OpXor(xor_a, xor_b, cost);
    BOOST_CHECK(MoveOut(xor_a) == Bytes({0x00, 0x00}));
    BOOST_CHECK_EQUAL(cost, varops::XorCost(2, 1));
}

BOOST_AUTO_TEST_CASE(bitshift_operations_preserve_width)
{
    uint64_t cost{0};

    Val64 upshift_one_bit{ValFromBytes(Bytes({0x01}))};
    Val64 one_bit{ValFromBytes(Bytes({0x01}))};
    BOOST_CHECK(Val64::OpUpShift(upshift_one_bit, one_bit, 10, cost));
    BOOST_CHECK(MoveOut(upshift_one_bit) == Bytes({0x02, 0x00}));
    BOOST_CHECK_EQUAL(cost, varops::LengthConversionCost(1) + 1 * varops::COST_COPYING + varops::UnalignedUpShiftCost(1, 0));

    cost = 0;
    Val64 upshift_one_byte{ValFromBytes(Bytes({0x01}))};
    Val64 eight_bits{ValFromBytes(Bytes({0x08}))};
    BOOST_CHECK(Val64::OpUpShift(upshift_one_byte, eight_bits, 10, cost));
    BOOST_CHECK(MoveOut(upshift_one_byte) == Bytes({0x00, 0x01}));
    BOOST_CHECK_EQUAL(cost, varops::LengthConversionCost(1) + 1 * varops::COST_FAST + 1 * varops::COST_COPYING);

    cost = 0;
    Val64 downshift_one_bit{ValFromBytes(Bytes({0x02, 0x00}))};
    Val64 one_bit_down{ValFromBytes(Bytes({0x01}))};
    Val64::OpDownShift(downshift_one_bit, one_bit_down, cost);
    BOOST_CHECK(MoveOut(downshift_one_bit) == Bytes({0x01, 0x00}));
    BOOST_CHECK_EQUAL(cost, varops::LengthConversionCost(1) + 2 * varops::COST_COPYING);

    cost = 0;
    Val64 downshift_past_end{ValFromBytes(Bytes({0xff}))};
    Val64 many_bits{ValFromBytes(Bytes({0x08}))};
    Val64::OpDownShift(downshift_past_end, many_bits, cost);
    BOOST_CHECK(MoveOut(downshift_past_end) == Bytes({}));
    BOOST_CHECK_EQUAL(cost, varops::LengthConversionCost(1));
}

BOOST_AUTO_TEST_CASE(multiply_divide_and_modulo_are_unsigned_and_normalized)
{
    Val64 mul_a{ValFromBytes(Bytes({0xff, 0xff}))};
    Val64 mul_b{ValFromBytes(Bytes({0x02}))};
    Val64 product{Val64::OpMul(mul_a, mul_b)};
    BOOST_CHECK(MoveOut(product) == Bytes({0xfe, 0xff, 0x01}));

    Val64 zero_a{ValFromBytes(Bytes({0x00, 0x00}))};
    Val64 zero_b{ValFromBytes(Bytes({0x42}))};
    Val64 zero_product{Val64::OpMul(zero_a, zero_b)};
    BOOST_CHECK(MoveOut(zero_product) == Bytes({}));

    Val64 div_a{ValFromBytes(Bytes({0x39, 0x30}))}; // 12345
    Val64 div_b{ValFromBytes(Bytes({0x64}))};       // 100
    BOOST_CHECK(Val64::OpDiv(div_a, div_b));
    BOOST_CHECK(MoveOut(div_a) == Bytes({0x7b}));  // 123

    Val64 mod_a{ValFromBytes(Bytes({0x39, 0x30}))};
    Val64 mod_b{ValFromBytes(Bytes({0x64}))};
    BOOST_CHECK(Val64::OpMod(mod_a, mod_b));
    BOOST_CHECK(MoveOut(mod_a) == Bytes({0x2d}));  // 45

    Val64 divide_by_zero_a{ValFromBytes(Bytes({0x01}))};
    Val64 divide_by_zero_b{ValFromBytes(Bytes({0x00, 0x00}))};
    BOOST_CHECK(!Val64::OpDiv(divide_by_zero_a, divide_by_zero_b));
}

BOOST_AUTO_TEST_CASE(numeric_comparison_treats_trailing_zeroes_as_equal)
{
    uint64_t cost{0};
    Val64 one_minimal{ValFromBytes(Bytes({0x01}))};
    Val64 one_wide{ValFromBytes(Bytes({0x01, 0x00, 0x00}))};
    BOOST_CHECK_EQUAL(one_minimal.Compare(one_wide, cost), 0);
    BOOST_CHECK_EQUAL(cost, varops::ComparisonCost(1, 3));

    cost = 0;
    Val64 high_bit{ValFromBytes(Bytes({0x00, 0x80}))};
    Val64 smaller{ValFromBytes(Bytes({0xff, 0x7f}))};
    BOOST_CHECK_EQUAL(high_bit.Compare(smaller, cost), 1);
    BOOST_CHECK_EQUAL(cost, varops::ComparisonCost(2, 2));
}

BOOST_AUTO_TEST_CASE(min_and_max_normalize_equal_numeric_values)
{
    uint64_t cost{0};

    Val64 min_a{ValFromBytes(Bytes({0x01, 0x00, 0x00}))};
    Val64 min_b{ValFromBytes(Bytes({0x01}))};
    Val64::OpMin(min_a, min_b, cost);
    BOOST_CHECK(MoveOut(min_a) == Bytes({0x01}));
    BOOST_CHECK_EQUAL(cost, varops::MinMaxCost(3, 1));

    cost = 0;
    Val64 max_a{ValFromBytes(Bytes({0x01, 0x00, 0x00}))};
    Val64 max_b{ValFromBytes(Bytes({0x01}))};
    Val64::OpMax(max_a, max_b, cost);
    BOOST_CHECK(MoveOut(max_a) == Bytes({0x01}));
    BOOST_CHECK_EQUAL(cost, varops::MinMaxCost(3, 1));

    cost = 0;
    Val64 min_selects_second{ValFromBytes(Bytes({0x05}))};
    Val64 smaller_second{ValFromBytes(Bytes({0x03, 0x00}))};
    Val64::OpMin(min_selects_second, smaller_second, cost);
    BOOST_CHECK(MoveOut(min_selects_second) == Bytes({0x03}));
    BOOST_CHECK_EQUAL(cost, varops::MinMaxCost(1, 2));

    cost = 0;
    Val64 max_selects_second{ValFromBytes(Bytes({0x03}))};
    Val64 larger_second{ValFromBytes(Bytes({0x05, 0x00}))};
    Val64::OpMax(max_selects_second, larger_second, cost);
    BOOST_CHECK(MoveOut(max_selects_second) == Bytes({0x05}));
    BOOST_CHECK_EQUAL(cost, varops::MinMaxCost(1, 2));
}

BOOST_AUTO_TEST_SUITE_END()
