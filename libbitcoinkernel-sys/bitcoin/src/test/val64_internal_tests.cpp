// Copyright (c) 2011-2022 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/val64.h>
#include <script/varops.h>
#include <test/data/val64_conversion.json.h>
#include <test/util/json.h>
#include <test/util/random.h>
#include <test/util/setup_common.h>
#include <util/vector.h>

#include <univalue.h>

#include <boost/multiprecision/cpp_int.hpp>
#include <boost/test/unit_test.hpp>

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <span>
#include <utility>
#include <vector>

BOOST_FIXTURE_TEST_SUITE(val64_internal_tests, BasicTestingSetup)

using boost::multiprecision::cpp_int;

// Resize/create vector so this bit will fit
static std::vector<unsigned char> vec_sized_for_bit(size_t bit,
                                                    const std::vector<unsigned char> in = std::vector<unsigned char>())
{
    std::vector<unsigned char> v = in;
    if (v.size() < (bit + 8) / 8)
        v.resize((bit + 8) / 8);
    return v;
}

// Set bit or create vector with this bit set.
static std::vector<unsigned char> vec_setbit(size_t bit,
                                             const std::vector<unsigned char> in = std::vector<unsigned char>())
{
    std::vector<unsigned char> v = vec_sized_for_bit(bit, in);
    v[bit / 8] |= (1 << (bit % 8));
    return v;
}

// Expose Val64 internals for focused unit tests.
class Val64Test : public Val64
{
public:
    // Unlike Val64, this makes a copy.
    explicit Val64Test(std::vector<unsigned char> bytes) : Val64(std::move(bytes)) {}
    Val64Test(const Val64Test&) = default;
    Val64Test(Val64Test&&) noexcept = default;
    explicit Val64Test(uint64_t value) : Val64(value) {}
    Val64Test() = default;

    std::span<le64_t> Limbs() const { return Val64::m_limbs; }
    size_t LimbCount() const { return Val64::m_limbs.size(); }
    uint64_t Get(size_t index) const { return Val64::Get(index); }
    static void SetForceOffsetSpan(bool value) { Val64::m_force_offset_span = value; }
    static void SetForcePortableMath(bool value) { Val64::m_force_portable_math = value; }

    void Set(size_t index, uint64_t value) { Val64::Set(index, value); }
    static void MultiplySpan(std::span<le64_t> result, std::span<const le64_t> source, uint64_t multiplier)
    {
        Val64::MultiplySpan(result, source, multiplier);
    }
    static bool AddSpans(std::span<le64_t> v1, std::span<const le64_t> v2, size_t& nonzero_len)
    {
        return Val64::AddSpans(v1, v2, nonzero_len);
    }
    static bool SubtractSpans(std::span<le64_t> v1, std::span<const le64_t> v2, size_t& nonzero_len)
    {
        return Val64::SubtractSpans(v1, v2, nonzero_len);
    }
    std::vector<uint64_t> CopyVector()
    {
        std::vector<uint64_t> v;
        v.reserve(LimbCount());
        for (size_t i = 0; i < LimbCount(); ++i) {
            v.push_back(Get(i));
        }
        return v;
    }
};

static Val64Test val64_singleton(uint64_t val)
{
    std::vector<unsigned char> bitvec(8);
    Val64Test v(bitvec);
    v.Set(0, val);

    return v;
}

static cpp_int vector_to_cpp_int(const std::vector<unsigned char>& vec)
{
    cpp_int num{0};
    for (auto it = vec.rbegin(); it != vec.rend(); ++it) {
        num *= 256;
        num += *it;
    }
    return num;
}

static std::vector<unsigned char> cpp_int_to_vector(cpp_int num)
{
    BOOST_REQUIRE(num >= 0);

    std::vector<unsigned char> vec;
    while (num != 0) {
        vec.push_back(static_cast<unsigned char>((num % 256).convert_to<unsigned int>()));
        num /= 256;
    }
    return vec;
}

static std::vector<unsigned char> cpp_int_to_fixed_vector(cpp_int num, size_t len)
{
    std::vector<unsigned char> vec = cpp_int_to_vector(num);
    BOOST_REQUIRE_LE(vec.size(), len);
    vec.resize(len);
    return vec;
}

static std::vector<unsigned char> shift_left_fixed(const std::vector<unsigned char>& value, size_t bits, size_t result_size)
{
    std::vector<unsigned char> result(result_size, 0);
    const size_t byte_shift{bits / 8};
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

static std::vector<unsigned char> shift_right_fixed(const std::vector<unsigned char>& value, size_t bits, size_t result_size)
{
    std::vector<unsigned char> result(result_size, 0);
    const size_t byte_shift{bits / 8};
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

static std::vector<unsigned char> TrimTrailingZeros(std::vector<unsigned char> value)
{
    while (!value.empty() && value.back() == 0) value.pop_back();
    return value;
}

template <typename T>
static std::vector<T> ParseVec(const UniValue& arr)
{
    std::vector<T> values;
    values.reserve(arr.size());
    for (size_t i = 0; i < arr.size(); i++) {
        values.push_back(arr[i].getInt<T>());
    }
    return values;
}

BOOST_AUTO_TEST_CASE(val64_valtype_conversion)
{
    UniValue tests = read_json(json_tests::val64_conversion);

    for (unsigned int idx = 0; idx < tests.size(); idx++) {
        const UniValue& test = tests[idx];

        for (bool offset_span: {false, true}) {
            Val64Test::SetForceOffsetSpan(offset_span);

            // JSON: COMMENT, u8-arr, u64-arr
            const std::vector<unsigned char> v_in = ParseVec<unsigned char>(test[1].get_array());
            std::vector<uint64_t> v_out = ParseVec<uint64_t>(test[2].get_array());

            // Check that we get expected u64 vector (make a copy, we mangle it!)
            Val64Test test_v64(v_in);
            std::vector<uint64_t> v64 = test_v64.CopyVector();
            BOOST_CHECK(v64 == v_out);

            // We should get vector back!
            std::vector<unsigned char> v_ret = test_v64.MoveToValtype();
            BOOST_CHECK(v_ret == v_in);
        }
    }
    Val64Test::SetForceOffsetSpan(false);
}

BOOST_AUTO_TEST_CASE(val64_offset_span)
{
    Val64Test::SetForceOffsetSpan(true);

    std::vector<unsigned char> v_in_empty;
    std::vector<unsigned char> v_in_small = {1,2,3};
    std::vector<unsigned char> v_in_word = {1,2,3,4,5,6,7,8};
    std::vector<unsigned char> v_in_large = {1,2,3,4,5,6,7,8,9};

    // We don't mess with empty vectors (they're always "aligned")
    Val64Test v1(v_in_empty);
    BOOST_CHECK(v1.LimbCount() == 0);

    Val64Test v2(v_in_small);
    BOOST_CHECK(v2.LimbCount() == 1);

    BOOST_CHECK(v2.Get(0) == 0x0000000000030201);

    Val64Test v3(v_in_word);
    BOOST_CHECK(v3.LimbCount() == 1);

    BOOST_CHECK(v3.Get(0) == 0x0807060504030201);

    Val64Test v4(v_in_large);
    BOOST_CHECK(v4.LimbCount() == 2);

    BOOST_CHECK(v4.Get(0) == 0x0807060504030201);
    BOOST_CHECK(v4.Get(1) == 0x0000000000000009);

    Val64Test::SetForceOffsetSpan(false);
}

BOOST_AUTO_TEST_CASE(val64_offset_span_copy_constructor_preserves_valtype)
{
    Val64Test::SetForceOffsetSpan(true);

    const std::vector<unsigned char> v_in = {1,2,3,4,5,6,7,8,9};
    Val64Test v(v_in);
    Val64Test copy(v);

    BOOST_CHECK(copy.MoveToValtype() == v_in);

    Val64Test::SetForceOffsetSpan(false);
}

BOOST_AUTO_TEST_CASE(val64_offset_span_move_constructor_preserves_valtype)
{
    Val64Test::SetForceOffsetSpan(true);

    const std::vector<unsigned char> v_in = {1,2,3,4,5,6,7,8,9};
    Val64Test v(v_in);
    Val64Test moved(std::move(v));

    BOOST_CHECK(moved.MoveToValtype() == v_in);

    Val64Test::SetForceOffsetSpan(false);
}

BOOST_AUTO_TEST_CASE(val64_and_or_xor)
{
    uint64_t varcost = 0;
    for (bool offset_span: {false, true}) {
        Val64Test::SetForceOffsetSpan(offset_span);

        for (size_t i = 0; i < 128; i++) {
            for (size_t j = 0; j < 128; j++) {
                std::vector<unsigned char> expected_and, expected_or, expected_xor;

                expected_or = vec_setbit(j, vec_setbit(i, expected_or));
                if (i != j) {
                    expected_and = vec_sized_for_bit(i, vec_sized_for_bit(j));
                    expected_xor = expected_or;
                } else {
                    expected_and = vec_setbit(i);
                    expected_xor = vec_sized_for_bit(i);
                }

                // AND test
                {
                    Val64Test v64a(vec_setbit(i));
                    Val64Test v64b(vec_setbit(j));
                    Val64::OpAnd(v64a, v64b, varcost);
                    BOOST_CHECK(v64a.MoveToValtype() == expected_and);
                }

                // OR test
                {
                    Val64Test v64a(vec_setbit(i));
                    Val64Test v64b(vec_setbit(j));
                    Val64::OpOr(v64a, v64b, varcost);
                    BOOST_CHECK(v64a.MoveToValtype() == expected_or);
                }

                // XOR test
                {
                    Val64Test v64a(vec_setbit(i));
                    Val64Test v64b(vec_setbit(j));
                    Val64::OpXor(v64a, v64b, varcost);
                    BOOST_CHECK(v64a.MoveToValtype() == expected_xor);
                }
            }
        }

        for (size_t i = 0; i < 1000; i++) {
            size_t len1 = m_rng.randrange(50);
            size_t len2 = m_rng.randrange(50);

            std::vector<unsigned char> v1 =    m_rng.randbytes(len1);
            std::vector<unsigned char> v2 =    m_rng.randbytes(len2);

            const cpp_int cpp1 = vector_to_cpp_int(v1);
            const cpp_int cpp2 = vector_to_cpp_int(v2);

            // We preserve length.
            const size_t expected_len = std::max(len1, len2);
            std::vector<unsigned char> expect_and = cpp_int_to_fixed_vector(cpp1 & cpp2, expected_len);
            std::vector<unsigned char> expect_or = cpp_int_to_fixed_vector(cpp1 | cpp2, expected_len);
            std::vector<unsigned char> expect_xor = cpp_int_to_fixed_vector(cpp1 ^ cpp2, expected_len);

            // AND
            {
                Val64Test v64a(v1);
                Val64Test v64b(v2);
                Val64::OpAnd(v64a, v64b, varcost);
                BOOST_CHECK(v64a.MoveToValtype() == expect_and);
            }

            // OR
            {
                Val64Test v64a(v1);
                Val64Test v64b(v2);
                Val64::OpOr(v64a, v64b, varcost);
                BOOST_CHECK(v64a.MoveToValtype() == expect_or);
            }

            // XOR
            {
                Val64Test v64a(v1);
                Val64Test v64b(v2);
                Val64::OpXor(v64a, v64b, varcost);
                BOOST_CHECK(v64a.MoveToValtype() == expect_xor);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(val64_invert_clears_word_padding)
{
    for (bool offset_span : {false, true}) {
        Val64Test::SetForceOffsetSpan(offset_span);

        for (size_t width{1}; width < sizeof(uint64_t); ++width) {
            std::vector<unsigned char> input(width);
            std::vector<unsigned char> expected(width);
            for (size_t i{0}; i < width; ++i) {
                input[i] = static_cast<unsigned char>(width * 17 + i);
                expected[i] = static_cast<unsigned char>(~input[i]);
            }

            Val64Test value(input);
            uint64_t varcost{0};
            Val64::OpInvert(value, varcost);

            BOOST_CHECK_EQUAL(varcost, varops::InvertCost(width));
            BOOST_CHECK_EQUAL(value.size(), width);
            const Val64 expected_value{std::move(expected)};
            BOOST_CHECK_EQUAL(value.Compare(expected_value), 0);

            const std::span<const uint64_t> words{value.Limbs()};
            const auto* bytes{reinterpret_cast<const unsigned char*>(words.data())};
            for (size_t i{width}; i < words.size_bytes(); ++i) {
                BOOST_CHECK_EQUAL(bytes[i], 0);
            }
        }
    }
    Val64Test::SetForceOffsetSpan(false);
}

BOOST_AUTO_TEST_CASE(val64_add)
{
    uint64_t varcost = 0;
    for (bool offset_span: {false, true}) {
        Val64Test::SetForceOffsetSpan(offset_span);

        // Add two bits, check result.
        for (size_t i = 0; i < 128; i++) {
            for (size_t j = 0; j < 128; j++) {
                Val64Test v64a(vec_setbit(i));
                Val64Test v64b(vec_setbit(j));
                Val64::OpAdd(v64a, v64b, varcost);

                // Check against expected vector.
                std::vector<unsigned char> expected;
                if (i != j) {
                    expected = vec_setbit(i);
                    expected = vec_setbit(j, expected);
                } else {
                    expected = vec_setbit(i + 1);
                }
                BOOST_CHECK(v64a.MoveToValtype() == expected);
            }
        }

        // Overflow tests.
        for (size_t i = 1; i < 24; i++) {
            std::vector<unsigned char> almost(i, 0xff);
            std::vector<unsigned char> one{1};

            Val64 v64a(std::move(almost));
            Val64 v64b(std::move(one));
            Val64::OpAdd(v64a, v64b, varcost);
            std::vector<unsigned char> res = v64a.MoveToValtype();

            std::vector<unsigned char> expect(i, 0);
            expect.push_back(1);

            BOOST_CHECK(res == expect);
        }
        for (size_t i = 0; i < 1000; i++) {
            size_t len1 = m_rng.randrange(50);
            size_t len2 = m_rng.randrange(50);

            std::vector<unsigned char> v1 =    m_rng.randbytes(len1);
            std::vector<unsigned char> v2 =    m_rng.randbytes(len2);

            const std::vector<unsigned char> expect = cpp_int_to_vector(vector_to_cpp_int(v1) + vector_to_cpp_int(v2));

            // Val64 version
            Val64 v64_1(std::move(v1)), v64_2(std::move(v2));

            Val64::OpAdd(v64_1, v64_2, varcost);
            std::vector<unsigned char> res = v64_1.MoveToValtype();

            BOOST_CHECK(res == expect);
        }
    }
}

BOOST_AUTO_TEST_CASE(val64_sub)
{
    uint64_t varcost = 0;
    for (bool offset_span: {false, true}) {
        Val64Test::SetForceOffsetSpan(offset_span);

        // Underflow must not leave nonzero bytes in Val64's word padding.
        {
            Val64Test smaller{{0xb2, 0x89}};
            const Val64Test larger{{0x16, 0xaa, 0x73, 0x3d}};
            BOOST_CHECK(!Val64::OpSub(smaller, larger, varcost));
            BOOST_CHECK_EQUAL(smaller.Get(0) >> 16, 0U);
        }

        // Sub zero (unchanged).
        for (size_t i = 0; i < 128; i++) {
            const std::vector<unsigned char> zero;

            // Subtract 0, should not change.
            Val64Test v64a(vec_setbit(i));
            Val64Test v64zero(zero);

            bool res = Val64::OpSub(v64a, v64zero, varcost);
            BOOST_CHECK(res);

            BOOST_CHECK(v64a.MoveToValtype() == vec_setbit(i));
        }

        // Sub one.
        for (size_t i = 63; i < 128; i++) {
            const std::vector<unsigned char> one{1};

            Val64Test v64a(vec_setbit(i));
            Val64Test v64one(one);

            bool res = Val64::OpSub(v64a, v64one, varcost);
            BOOST_CHECK(res);

            std::vector<unsigned char> expected;
            for (size_t j = 0; j < i; j++)
                expected = vec_setbit(j, expected);

            std::vector<unsigned char> va = v64a.MoveToValtype();
            BOOST_CHECK(va == expected);
        }
        for (size_t i = 0; i < 1000; i++) {
            size_t len1 = m_rng.randrange(50);
            size_t len2 = m_rng.randrange(50);

            std::vector<unsigned char> v1 =    m_rng.randbytes(len1);
            std::vector<unsigned char> v2 =    m_rng.randbytes(len2);

            const cpp_int cpp1 = vector_to_cpp_int(v1);
            const cpp_int cpp2 = vector_to_cpp_int(v2);
            const bool expect_neg = cpp1 < cpp2;
            std::vector<unsigned char> expect;
            if (!expect_neg) {
                expect = cpp_int_to_vector(cpp1 - cpp2);
            }

            // Val64 version
            Val64 v64_1(std::move(v1)), v64_2(std::move(v2));

            bool neg = !Val64::OpSub(v64_1, v64_2, varcost);
            std::vector<unsigned char> res = v64_1.MoveToValtype();

            if (expect_neg) {
                BOOST_CHECK(neg == true);
            } else {
                BOOST_CHECK(neg == false);
                BOOST_CHECK(res == expect);
            }
        }
    }
}

BOOST_AUTO_TEST_CASE(val64_cmp)
{
    uint64_t varcost = 0;
    for (bool offset_span: {false, true}) {
        Val64Test::SetForceOffsetSpan(offset_span);

        for (size_t i = 0; i < 128; i++) {
            for (size_t j = 0; j < 128; j++) {
                std::vector<unsigned char> va = vec_setbit(i);
                std::vector<unsigned char> vb = vec_setbit(j);
                Val64 v64a(std::move(va));
                Val64 v64b(std::move(vb));
                int res = v64a.Compare(v64b, varcost);

                int expected;
                if (i == j)
                    expected = 0;
                else if (i > j)
                    expected = 1;
                else
                    expected = -1;

                BOOST_CHECK(res == expected);
            }
        }

        for (size_t i = 0; i < 1000; i++) {
            size_t len1 = m_rng.randrange(50);
            size_t len2 = m_rng.randrange(50);

            std::vector<unsigned char> v1 =    m_rng.randbytes(len1);
            std::vector<unsigned char> v2 =    m_rng.randbytes(len2);

            const cpp_int cpp1 = vector_to_cpp_int(v1);
            const cpp_int cpp2 = vector_to_cpp_int(v2);
            int expected;
            if (cpp1 == cpp2)
                expected = 0;
            else if (cpp1 > cpp2)
                expected = 1;
            else
                expected = -1;

            // Val64 version
            Val64Test v64_1(v1), v64_2(v2);

            int res = v64_1.Compare(v64_2, varcost);

            BOOST_CHECK(res == expected);
        }
    }
}

BOOST_AUTO_TEST_CASE(val64_upshift)
{
    uint64_t varcost = 0;
    for (bool offset_span: {false, true}) {
        Val64Test::SetForceOffsetSpan(offset_span);

        for (size_t i = 0; i < 128; i++) {
            for (size_t j = 0; j < 128; j++) {
                std::vector<unsigned char> va = vec_setbit(i);
                Val64 v64a(std::move(va));
                bool ok = Val64::OpUpShift(v64a, val64_singleton(j), 1000, varcost);
                BOOST_CHECK(ok);
                va = v64a.MoveToValtype();

                std::vector<unsigned char> expected = vec_setbit(i + j);
                // Definitionally, upshift inserts an extra (j + 7) / 8 bytes.
                expected.resize(1 + i / 8 + (j + 7) / 8);

                BOOST_CHECK(va == expected);
            }
        }

        for (size_t i = 0; i < 1000; i++) {
            size_t len1 = m_rng.randrange(500);
            size_t sbits = m_rng.randrange(500 * 8);

            std::vector<unsigned char> v1 =    m_rng.randbytes(len1);

            // Always leaves trailing zeroes
            const size_t expected_len = len1 + sbits / 8 + (sbits % 8 ? 1 : 0);
            const std::vector<unsigned char> expect = shift_left_fixed(v1, sbits, expected_len);

            // Val64 version
            Val64 v64(std::move(v1));
            bool ok = Val64::OpUpShift(v64, val64_singleton(sbits), 5000, varcost);
            BOOST_CHECK(ok);
            v1 = v64.MoveToValtype();

            BOOST_CHECK(v1 == expect);
        }
    }
}

BOOST_AUTO_TEST_CASE(val64_downshift)
{
    uint64_t varcost = 0;
    for (bool offset_span: {false, true}) {
        Val64Test::SetForceOffsetSpan(offset_span);

        for (size_t i = 0; i < 128; i++) {
            for (size_t j = 0; j < 128; j++) {
                std::vector<unsigned char> va = vec_setbit(i);
                BOOST_CHECK(va.size() == (i + 8) / 8);
                Val64 v64a(std::move(va));
                Val64::OpDownShift(v64a, val64_singleton(j), varcost);
                va = v64a.MoveToValtype();

                std::vector<unsigned char> expected;
                if (j <= i)
                    expected = vec_setbit(i - j);

                // Definitionally, downshift only removes one byte for every 8 bits shifted.
                if (j / 8 <= (i + 8) / 8)
                    expected.resize((i + 8) / 8 - j / 8);

                BOOST_CHECK(va == expected);
            }
        }

        for (size_t i = 0; i < 1000; i++) {
            size_t len1 = m_rng.randrange(500);
            size_t sbits = m_rng.randrange(500 * 8);

            std::vector<unsigned char> v1 =    m_rng.randbytes(len1);

            // We subtract only whole bytes from length.
            const size_t expected_len = v1.size() > sbits / 8 ? v1.size() - sbits / 8 : 0;
            const std::vector<unsigned char> expect = shift_right_fixed(v1, sbits, expected_len);

            // Val64 version
            Val64 v64(std::move(v1));
            Val64::OpDownShift(v64, val64_singleton(sbits), varcost);
            v1 = v64.MoveToValtype();

            BOOST_CHECK(v1 == expect);
        }
    }
}

BOOST_AUTO_TEST_CASE(val64_add_span)
{
    Val64Test res(std::vector<unsigned char>(sizeof(uint64_t) * 2));

    // 0xFFFFFFFFFFFFFFFF
    const Val64Test u64_max(std::vector<unsigned char>(sizeof(uint64_t), 0xff));
    const Val64Test u64_zero(std::vector<unsigned char>(sizeof(uint64_t), 0));
    bool carry;
    size_t nonzero_len;

    // Add empty at offset 0.
    carry = Val64Test::AddSpans(res.Limbs(), u64_zero.Limbs(), nonzero_len);
    BOOST_CHECK(res.Get(0) == 0);
    BOOST_CHECK(res.Get(1) == 0);
    BOOST_CHECK(nonzero_len == 0);
    BOOST_CHECK(!carry);

    // Add at offset 0.
    carry = Val64Test::AddSpans(res.Limbs(), u64_max.Limbs(), nonzero_len);
    BOOST_CHECK(res.Get(0) == 0xFFFFFFFFFFFFFFFFULL);
    BOOST_CHECK(res.Get(1) == 0);
    BOOST_CHECK(nonzero_len == 1);
    BOOST_CHECK(!carry);

    // Add at offset 1.
    carry = Val64Test::AddSpans(res.Limbs().subspan(1), u64_max.Limbs(), nonzero_len);
    BOOST_CHECK(res.Get(0) == 0xFFFFFFFFFFFFFFFFULL);
    BOOST_CHECK(res.Get(1) == 0xFFFFFFFFFFFFFFFFULL);
    // Relative to subspan!
    BOOST_CHECK(nonzero_len == 1);
    BOOST_CHECK(!carry);

    // Add one more, should carry.
    carry = Val64Test::AddSpans(res.Limbs().subspan(1), Val64Test(1).Limbs(), nonzero_len);
    BOOST_CHECK(res.Get(0) == 0xFFFFFFFFFFFFFFFFULL);
    BOOST_CHECK(res.Get(1) == 0);
    BOOST_CHECK(carry);
}

BOOST_AUTO_TEST_CASE(val64_sub_span)
{
    Val64Test res(std::vector<unsigned char>(sizeof(uint64_t) * 2, 0xFF));

    // 0xFFFFFFFFFFFFFFFF
    const Val64Test u64_max(std::vector<unsigned char>(sizeof(uint64_t), 0xff));
    const Val64Test u64_zero(std::vector<unsigned char>(sizeof(uint64_t), 0));
    bool underflow;
    size_t nonzero_len;

    // Sub empty at offset 0.
    underflow = Val64Test::SubtractSpans(res.Limbs(), u64_zero.Limbs(),
                                    nonzero_len);
    BOOST_CHECK(res.Get(0) == 0xFFFFFFFFFFFFFFFFULL);
    BOOST_CHECK(res.Get(1) == 0xFFFFFFFFFFFFFFFFULL);
    BOOST_CHECK(nonzero_len == 2);
    BOOST_CHECK(!underflow);

    // Sub at offset 1.
    underflow = Val64Test::SubtractSpans(res.Limbs().subspan(1), u64_max.Limbs(),
                                    nonzero_len);
    BOOST_CHECK(res.Get(0) == 0xFFFFFFFFFFFFFFFFULL);
    BOOST_CHECK(res.Get(1) == 0);
    BOOST_CHECK(nonzero_len == 0);
    BOOST_CHECK(!underflow);

    // Sub at offset 0.
    underflow = Val64Test::SubtractSpans(res.Limbs(), u64_max.Limbs(), nonzero_len);
    BOOST_CHECK(res.Get(0) == 0);
    BOOST_CHECK(res.Get(1) == 0);
    BOOST_CHECK(nonzero_len == 0);
    BOOST_CHECK(!underflow);

    // Sub one more, should underflow.
    underflow = Val64Test::SubtractSpans(res.Limbs().subspan(1), Val64Test(1).Limbs(),
                                    nonzero_len);
    BOOST_CHECK(res.Get(0) == 0);
    BOOST_CHECK(res.Get(1) == 0xFFFFFFFFFFFFFFFFULL);
    BOOST_CHECK(underflow);
}

BOOST_AUTO_TEST_CASE(val64_mul_span)
{
    Val64Test::SetForceOffsetSpan(false);

    for (bool portable_math : {false, true}) {
        Val64Test::SetForcePortableMath(portable_math);

    // Multiply this by mul, place into res.
    for (size_t i = 0; i < 128; i++) {
        for (size_t j = 0; j < 65; j++) {
            Val64Test v64a(vec_setbit(i));

            // Initial contents shouldn't matter, but size needs to match.
            size_t vecsize = (v64a.LimbCount() + 1) * sizeof(uint64_t);
            std::vector<unsigned char> dummy(vecsize, 1|j);
            Val64Test res64(dummy);

            if (j == 64) {
                // Test multiply by 0
                Val64Test::MultiplySpan(res64.Limbs(), v64a.Limbs(), 0);
            } else {
                Val64Test::MultiplySpan(res64.Limbs(), v64a.Limbs(), (uint64_t)1 << j);
            }

            // mul_vector does not trim zeros.
            std::vector<unsigned char> expected(vecsize);
            if (j != 64)
                expected = vec_setbit(i + j, expected);
            BOOST_CHECK(res64.MoveToValtype() == expected);
        }
    }

    } // end for portable_math
    Val64Test::SetForcePortableMath(false);
}

BOOST_AUTO_TEST_CASE(val64_mul)
{
    constexpr size_t POWER_OF_TWO_BITS{128};
    constexpr size_t RHS_BOUNDARY_BITS{129};
    constexpr size_t RANDOM_CASES{1000};
    constexpr size_t RANDOM_OPERAND_BYTES{50};

    for (bool portable_math : {false, true}) {
        Val64Test::SetForcePortableMath(portable_math);
    for (bool offset_span: {false, true}) {
        Val64Test::SetForceOffsetSpan(offset_span);

        // Test 2^lhs_bit * 2^rhs_bit = 2^(lhs_bit + rhs_bit).
        for (size_t lhs_bit = 0; lhs_bit < POWER_OF_TWO_BITS; lhs_bit++) {
            for (size_t rhs_bit = 0; rhs_bit < RHS_BOUNDARY_BITS; rhs_bit++) {
                std::vector<unsigned char> va = vec_setbit(lhs_bit), vb = vec_setbit(rhs_bit);

                Val64 v64a(std::move(va));
                Val64 v64b(std::move(vb));
                Val64 ret = Val64::OpMul(v64a, v64b);
                std::vector<unsigned char> retvec = ret.MoveToValtype();

                std::vector<unsigned char> expected = vec_setbit(lhs_bit + rhs_bit);
                BOOST_CHECK(retvec == expected);
            }

            {
                std::vector<unsigned char> va = vec_setbit(lhs_bit);
                std::vector<unsigned char> vb;

                Val64 v64a(std::move(va));
                Val64 v64b(std::move(vb));
                Val64 ret = Val64::OpMul(v64a, v64b);
                std::vector<unsigned char> retvec = ret.MoveToValtype();

                BOOST_CHECK(retvec == std::vector<unsigned char>{});
            }
        }

        // Test (2^bits - 1) * 2^shift.
        for (size_t bits = 1; bits < POWER_OF_TWO_BITS; bits++) {
            for (size_t shift = 0; shift < POWER_OF_TWO_BITS; shift++) {
                std::vector<unsigned char> va((bits + 7) / 8, 0xff);
                const size_t high_byte_bits = bits % 8;
                if (high_byte_bits != 0) {
                    va.back() = static_cast<unsigned char>((1U << high_byte_bits) - 1);
                }
                std::vector<unsigned char> vb = vec_setbit(shift);
                const std::vector<unsigned char> expected{
                    TrimTrailingZeros(shift_left_fixed(va, shift, (bits + shift + 7) / 8))};

                Val64 v64a(std::move(va));
                Val64 v64b(std::move(vb));
                Val64 ret = Val64::OpMul(v64a, v64b);
                std::vector<unsigned char> retvec = ret.MoveToValtype();

                BOOST_CHECK(retvec == expected);
            }
        }
        for (size_t case_idx = 0; case_idx < RANDOM_CASES; case_idx++) {
            size_t lhs_len = m_rng.randrange(RANDOM_OPERAND_BYTES);
            size_t rhs_len = m_rng.randrange(RANDOM_OPERAND_BYTES);

            std::vector<unsigned char> lhs = m_rng.randbytes(lhs_len);
            std::vector<unsigned char> rhs = m_rng.randbytes(rhs_len);

            const std::vector<unsigned char> expect = cpp_int_to_vector(vector_to_cpp_int(lhs) * vector_to_cpp_int(rhs));

            // Val64 version
            Val64 v64a(std::move(lhs));
            Val64 v64b(std::move(rhs));
            Val64 ret64 = Val64::OpMul(v64a, v64b);
            std::vector<unsigned char> ret = ret64.MoveToValtype();

            BOOST_CHECK(ret == expect);
        }
    }
    } // end for portable_math
    Val64Test::SetForcePortableMath(false);
}

BOOST_AUTO_TEST_CASE(val64_2mul)
{
    uint64_t varcost = 0;
    for (bool offset_span: {false, true}) {
        Val64Test::SetForceOffsetSpan(offset_span);

        for (size_t i = 0; i < 129; i++) {
            for (size_t j = 0; j < 16; j++) {
                std::vector<unsigned char> va;

                // Test zero case
                if (i != 128)
                    va = vec_setbit(i);

                // Append empty bytes (shouldn't make a difference)
                va.insert(va.end(), j, 0);

                Val64 v64a(std::move(va));
                Val64::Op2Mul(v64a, varcost);
                va = v64a.MoveToValtype();

                std::vector<unsigned char> expected;

                if (i != 128)
                    expected = vec_setbit(i + 1);
                BOOST_CHECK(va == expected);
            }
        }

        for (size_t i = 0; i < 1000; i++) {
            size_t len1 = m_rng.randrange(500);
            std::vector<unsigned char> v1 =    m_rng.randbytes(len1);

            const std::vector<unsigned char> expect{
                TrimTrailingZeros(shift_left_fixed(v1, 1, v1.size() + 1))};

            // Val64 version
            Val64 v64(std::move(v1));
            Val64::Op2Mul(v64, varcost);
            v1 = v64.MoveToValtype();

            BOOST_CHECK(v1 == expect);
        }
    }
}

BOOST_AUTO_TEST_CASE(val64_2div)
{
    uint64_t varcost = 0;
    for (bool offset_span: {false, true}) {
        Val64Test::SetForceOffsetSpan(offset_span);

        {
            constexpr size_t padded_size{64 * 1024};
            std::vector<unsigned char> padded_one(padded_size, 0);
            padded_one.front() = 1;
            uint64_t padded_cost{0};
            Val64 padded_value(std::move(padded_one));
            Val64::Op2Div(padded_value, padded_cost);
            BOOST_CHECK(padded_value.MoveToValtype().empty());
            BOOST_CHECK_EQUAL(padded_cost, varops::TwoDivCost(padded_size));
        }

        for (size_t i = 0; i < 129; i++) {
            for (size_t j = 0; j < 16; j++) {
                std::vector<unsigned char> va;

                // Test zero case
                if (i != 128)
                    va = vec_setbit(i);

                // Append empty bytes (shouldn't make a difference)
                va.insert(va.end(), j, 0);

                Val64 v64a(std::move(va));
                Val64::Op2Div(v64a, varcost);
                va = v64a.MoveToValtype();

                std::vector<unsigned char> expected;
                if (i > 0 && i != 128)
                    expected = vec_setbit(i - 1);
                BOOST_CHECK(va == expected);
            }
        }

        for (size_t i = 0; i < 1000; i++) {
            size_t len1 = m_rng.randrange(500);
            std::vector<unsigned char> v1 =    m_rng.randbytes(len1);

            const std::vector<unsigned char> expect{
                TrimTrailingZeros(shift_right_fixed(v1, 1, v1.size()))};

            // Val64 version
            Val64 v64(std::move(v1));
            Val64::Op2Div(v64, varcost);
            v1 = v64.MoveToValtype();

            BOOST_CHECK(v1 == expect);
        }
    }
}

BOOST_AUTO_TEST_CASE(val64_trim_tail_word_padding)
{
    for (bool offset_span : {false, true}) {
        Val64Test::SetForceOffsetSpan(offset_span);

        for (size_t size : {size_t{8}, size_t{9}, size_t{16}, size_t{17}, size_t{4096}}) {
            std::vector<unsigned char> zeroes(size, 0);
            Val64 zero_value(std::move(zeroes));
            zero_value.TrimTrailingZeros();
            BOOST_CHECK(zero_value.MoveToValtype().empty());

            std::vector<unsigned char> padded_one(size, 0);
            padded_one.front() = 1;
            Val64 one_value(std::move(padded_one));
            one_value.TrimTrailingZeros();
            BOOST_CHECK(one_value.MoveToValtype() == std::vector<unsigned char>{1});
        }

        std::vector<unsigned char> later_limb(4096, 0);
        later_limb[8] = 1;
        Val64 later_limb_value(std::move(later_limb));
        later_limb_value.TrimTrailingZeros();
        std::vector<unsigned char> expected(9, 0);
        expected.back() = 1;
        BOOST_CHECK(later_limb_value.MoveToValtype() == expected);
    }
    Val64Test::SetForceOffsetSpan(false);
}

BOOST_AUTO_TEST_CASE(val64_div_mod)
{
    for (bool portable_math : {false, true}) {
        Val64Test::SetForcePortableMath(portable_math);
    for (bool offset_span: {false, true}) {
        Val64Test::SetForceOffsetSpan(offset_span);

        for (size_t i = 0; i < 128; i++) {
            for (size_t j = 0; j < 129; j++) {
                std::vector<unsigned char> va = vec_setbit(i), vb = vec_setbit(j);

                Val64Test v64a_div(va), v64a_mod(va);
                Val64Test v64b_div(vb), v64b_mod(vb);
                bool div_ret = Val64Test::OpDiv(v64a_div, v64b_div);
                bool mod_ret = Val64Test::OpMod(v64a_mod, v64b_mod);
                std::vector<unsigned char> div_vec = v64a_div.MoveToValtype();
                std::vector<unsigned char> mod_vec = v64a_mod.MoveToValtype();

                std::vector<unsigned char> expected_div, expected_remainder;
                BOOST_CHECK(div_ret == true);
                BOOST_CHECK(mod_ret == true);
                if (i >= j)
                    expected_div = vec_setbit(i - j);
                else
                    expected_remainder = vec_setbit(i);


                BOOST_CHECK(div_vec == expected_div);
                BOOST_CHECK(mod_vec == expected_remainder);
            }

            {
                const std::vector<unsigned char> va = vec_setbit(i);
                const std::vector<unsigned char> vb;

                Val64Test v64a_div(va), v64a_mod(va);
                Val64Test v64b_div(vb), v64b_mod(vb);
                BOOST_CHECK(Val64Test::OpDiv(v64a_div, v64b_div) == false);
                BOOST_CHECK(Val64Test::OpMod(v64a_mod, v64b_mod) == false);
            }
        }

        for (size_t i = 0; i < 1000; i++) {
            size_t len1 = m_rng.randrange(50);
            size_t len2 = m_rng.randrange(50);

            std::vector<unsigned char> v1 =    m_rng.randbytes(len1);
            std::vector<unsigned char> v2 =    m_rng.randbytes(len2);

            const cpp_int cpp1 = vector_to_cpp_int(v1);
            const cpp_int cpp2 = vector_to_cpp_int(v2);
            const bool expect_success = cpp2 != 0;
            std::vector<unsigned char> expect_res;
            std::vector<unsigned char> expect_rem;
            if (expect_success) {
                expect_res = cpp_int_to_vector(cpp1 / cpp2);
                expect_rem = cpp_int_to_vector(cpp1 % cpp2);
            }

            // Val64 version
            Val64Test v64a_div(v1), v64a_mod(v1);
            Val64Test v64b_div(v2), v64b_mod(v2);
            bool div_ret = Val64Test::OpDiv(v64a_div, v64b_div);
            bool mod_ret = Val64Test::OpMod(v64a_mod, v64b_mod);
            std::vector<unsigned char> div_vec = v64a_div.MoveToValtype();
            std::vector<unsigned char> mod_vec = v64a_mod.MoveToValtype();

            BOOST_CHECK(div_ret == expect_success);
            BOOST_CHECK(mod_ret == expect_success);
            if (expect_success) {
                BOOST_CHECK(div_vec == expect_res);
                BOOST_CHECK(mod_vec == expect_rem);
            }
        }

        for (uint16_t a = 0; a <= 255; ++a) {
            for (uint16_t b = 0; b <= 255; ++b) {
                const std::vector<unsigned char> va{static_cast<unsigned char>(a)};
                const std::vector<unsigned char> vb{static_cast<unsigned char>(b)};

                Val64Test v64a_div(va), v64a_mod(va);
                Val64Test v64b_div(vb), v64b_mod(vb);
                const bool div_ret = Val64Test::OpDiv(v64a_div, v64b_div);
                const bool mod_ret = Val64Test::OpMod(v64a_mod, v64b_mod);

                if (b == 0) {
                    BOOST_CHECK(div_ret == false);
                    BOOST_CHECK(mod_ret == false);
                    continue;
                }

                BOOST_CHECK(div_ret == true);
                BOOST_CHECK(mod_ret == true);
                BOOST_CHECK(v64a_div.MoveToValtype() == cpp_int_to_vector(cpp_int{a} / b));
                BOOST_CHECK(v64a_mod.MoveToValtype() == cpp_int_to_vector(cpp_int{a} % b));
            }
        }
    }
    } // end for portable_math
    Val64Test::SetForcePortableMath(false);
}

BOOST_AUTO_TEST_CASE(val64_div_mod_normalizes_clear_top_bit_divisor)
{
    for (bool portable_math : {false, true}) {
        Val64Test::SetForcePortableMath(portable_math);
        for (bool offset_span : {false, true}) {
            Val64Test::SetForceOffsetSpan(offset_span);

            // The divisor's top bit is clear, so DivMod() normalizes through OpUpShift().
            const std::vector<unsigned char> dividend{0x0a};
            const std::vector<unsigned char> divisor{0x03};

            Val64Test quotient{dividend};
            Val64Test quotient_divisor{divisor};
            BOOST_CHECK(Val64Test::OpDiv(quotient, quotient_divisor));
            BOOST_CHECK(quotient.MoveToValtype() == std::vector<unsigned char>{0x03});

            Val64Test remainder{dividend};
            Val64Test remainder_divisor{divisor};
            BOOST_CHECK(Val64Test::OpMod(remainder, remainder_divisor));
            BOOST_CHECK(remainder.MoveToValtype() == std::vector<unsigned char>{0x01});
        }
    }

    Val64Test::SetForcePortableMath(false);
    Val64Test::SetForceOffsetSpan(false);
}

BOOST_AUTO_TEST_CASE(val64_div_mod_knuth_d6_add_back)
{
    const std::vector<unsigned char> dividend = {
        0x71, 0x0a, 0x7f, 0x30, 0x34, 0x4d, 0x13, 0x98,
        0xb1, 0x15, 0xd5, 0x64, 0xac, 0xc8, 0x9d, 0x56,
        0x5a, 0x64, 0xdc, 0x11, 0x21, 0xf7, 0x22, 0x7c,
        0xf9, 0x7f, 0x16, 0xbc, 0xeb, 0xe8, 0x95, 0x85,
    };
    const std::vector<unsigned char> divisor = {
        0xcd, 0x07, 0x2c, 0xd8, 0xbe, 0x6f, 0x9f, 0x62,
        0xac, 0x4c, 0x09, 0xc2, 0x82, 0x06, 0xe7, 0xe3,
        0x55, 0x94, 0xaa, 0x6b, 0x34, 0x2f, 0x5d, 0x8a,
    };
    const std::vector<unsigned char> expected_quotient = {
        0x39, 0x5e, 0x48, 0x42, 0xfa, 0xb4, 0x28, 0xf7,
    };
    const std::vector<unsigned char> expected_remainder = {
        0xcc, 0x07, 0x2c, 0xd8, 0xbe, 0x6f, 0x9f, 0x62,
        0xac, 0x4c, 0x09, 0xc2, 0x82, 0x06, 0xe7, 0xe3,
        0x55, 0x94, 0xaa, 0x6b, 0x34, 0x2f, 0x5d, 0x8a,
    };

    for (bool portable_math : {false, true}) {
        Val64Test::SetForcePortableMath(portable_math);
        for (bool offset_span : {false, true}) {
            Val64Test::SetForceOffsetSpan(offset_span);

            Val64Test quotient{dividend};
            Val64Test quotient_divisor{divisor};
            BOOST_CHECK(Val64Test::OpDiv(quotient, quotient_divisor));
            BOOST_CHECK(quotient.MoveToValtype() == expected_quotient);

            Val64Test remainder{dividend};
            Val64Test remainder_divisor{divisor};
            BOOST_CHECK(Val64Test::OpMod(remainder, remainder_divisor));
            BOOST_CHECK(remainder.MoveToValtype() == expected_remainder);
        }
    }

    Val64Test::SetForcePortableMath(false);
    Val64Test::SetForceOffsetSpan(false);
}

BOOST_AUTO_TEST_CASE(val64_div_mod_fuzz_regression_normalized_divisor)
{
    const std::vector<unsigned char> dividend = {
        0x2b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xf6, 0x88,
    };
    const std::vector<unsigned char> divisor = {
        0x2a, 0x01, 0x48, 0x2f, 0xff, 0xff, 0xff, 0x4e, 0x01, 0x00, 0x00,
    };
    const std::vector<unsigned char> expected_quotient = {
        0x68,
    };
    const std::vector<unsigned char> expected_remainder = {
        0x1b, 0x86, 0xbf, 0xca, 0x54, 0x00, 0x00, 0xdf,
    };

    for (bool portable_math : {false, true}) {
        Val64Test::SetForcePortableMath(portable_math);
        for (bool offset_span : {false, true}) {
            Val64Test::SetForceOffsetSpan(offset_span);

            Val64Test quotient{dividend};
            Val64Test quotient_divisor{divisor};
            BOOST_CHECK(Val64Test::OpDiv(quotient, quotient_divisor));
            BOOST_CHECK(quotient.MoveToValtype() == expected_quotient);

            Val64Test remainder{dividend};
            Val64Test remainder_divisor{divisor};
            BOOST_CHECK(Val64Test::OpMod(remainder, remainder_divisor));
            BOOST_CHECK(remainder.MoveToValtype() == expected_remainder);
        }
    }

    Val64Test::SetForcePortableMath(false);
    Val64Test::SetForceOffsetSpan(false);
}

BOOST_AUTO_TEST_CASE(val64_div_mod_trial_quotient_beta)
{
    // The high dividend word equals the high divisor word after normalization.
    // Knuth D3 first estimates qhat as β, then corrects it to β - 1.
    const std::vector<unsigned char> dividend = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x01,
        0x00, 0x01, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x3b,
        0x00,
    };
    const std::vector<unsigned char> divisor = {
        0xe7, 0x26, 0xff, 0xff, 0xff, 0xff, 0x01, 0x00,
        0x01, 0x00, 0x00, 0x00, 0x1d, 0x00, 0x00, 0x3b,
        0x00,
    };
    const std::vector<unsigned char> expected_quotient = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    const std::vector<unsigned char> expected_remainder = {
        0xe6, 0x26, 0xff, 0xff, 0xff, 0xff, 0x01, 0x02,
        0x1a, 0xda, 0x00, 0x00, 0x1d, 0x1d, 0xfe, 0x3a,
    };

    for (bool portable_math : {false, true}) {
        Val64Test::SetForcePortableMath(portable_math);
        for (bool offset_span : {false, true}) {
            Val64Test::SetForceOffsetSpan(offset_span);

            Val64Test quotient{dividend};
            Val64Test quotient_divisor{divisor};
            BOOST_CHECK(Val64Test::OpDiv(quotient, quotient_divisor));
            BOOST_CHECK(quotient.MoveToValtype() == expected_quotient);

            Val64Test remainder{dividend};
            Val64Test remainder_divisor{divisor};
            BOOST_CHECK(Val64Test::OpMod(remainder, remainder_divisor));
            BOOST_CHECK(remainder.MoveToValtype() == expected_remainder);
        }
    }

    Val64Test::SetForcePortableMath(false);
    Val64Test::SetForceOffsetSpan(false);
}

BOOST_AUTO_TEST_CASE(val64_div_mod_trial_quotient_beta_raw_division_overflow)
{
    // Same qhat == β boundary as above, but the raw 128-bit division would
    // compute β + 1 if it were not capped to Algorithm D's trial quotient.
    const std::vector<unsigned char> dividend = {
        0x50, 0x00, 0x30, 0x9d, 0x2c, 0x3f, 0xfe, 0xff,
        0x00, 0x00, 0x00, 0x00, 0x27, 0xb1, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xcf, 0xf3, 0x3b,
    };
    const std::vector<unsigned char> divisor = {
        0x3e, 0x03, 0x00, 0x00, 0x27, 0xb1, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xcf, 0xf3, 0x3b,
    };
    const std::vector<unsigned char> expected_quotient = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    };
    const std::vector<unsigned char> expected_remainder = {
        0x8e, 0x03, 0x30, 0x9d, 0x53, 0xf0, 0xfd, 0xff,
        0xc2, 0xfc, 0xff, 0xff, 0xcf, 0xf3, 0x3b,
    };

    for (bool portable_math : {false, true}) {
        Val64Test::SetForcePortableMath(portable_math);
        for (bool offset_span : {false, true}) {
            Val64Test::SetForceOffsetSpan(offset_span);

            Val64Test quotient{dividend};
            Val64Test quotient_divisor{divisor};
            BOOST_CHECK(Val64Test::OpDiv(quotient, quotient_divisor));
            BOOST_CHECK(quotient.MoveToValtype() == expected_quotient);

            Val64Test remainder{dividend};
            Val64Test remainder_divisor{divisor};
            BOOST_CHECK(Val64Test::OpMod(remainder, remainder_divisor));
            BOOST_CHECK(remainder.MoveToValtype() == expected_remainder);
        }
    }

    Val64Test::SetForcePortableMath(false);
    Val64Test::SetForceOffsetSpan(false);
}

// Test edge cases for the portable 64-bit math implementation (used on Windows/MSVC).
// These tests specifically target edge cases that could trigger overflow bugs in
// the 128-bit arithmetic emulation.
BOOST_AUTO_TEST_CASE(val64_portable_math_edge_cases)
{
    for (bool portable_math : {false, true}) {
        Val64Test::SetForcePortableMath(portable_math);

    // Test multiplication edge case: (2^64-1) * (2^64-1)
    // This tests the MultiplySpan portable implementation
    {
        std::vector<unsigned char> max_u64(8, 0xFF);
        Val64Test v64a(max_u64);
        Val64Test v64b(max_u64);
        Val64 ret = Val64::OpMul(v64a, v64b);
        std::vector<unsigned char> retvec = ret.MoveToValtype();

        // (2^64-1)^2 = 2^128 - 2^65 + 1
        // In little-endian bytes: 0x01, 0x00, ..., 0x00, 0xFE, 0xFF, ..., 0xFF
        std::vector<unsigned char> expected = {
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  // low word
            0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF   // high word
        };
        BOOST_CHECK(retvec == expected);
    }

    // Test division edge case that exercises the Knuth refinement loop
    // We need a dividend and divisor that produce a large qstar estimate
    // and where v2[n-2] is also large, triggering the cross overflow.
    {
        // Dividend: a large number with multiple 64-bit words
        // 0xFFFFFFFFFFFFFFFF_FFFFFFFFFFFFFFFF (two words of all 1s)
        std::vector<unsigned char> dividend(16, 0xFF);

        // Divisor: 0x8000000000000001 (normalized, with second word considerations)
        // This divisor has the top bit set (normalized) and will produce
        // a quotient estimate that exercises the refinement.
        std::vector<unsigned char> divisor = {
            0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80
        };

        Val64Test v64a_div(dividend);
        Val64Test v64b_div(divisor);
        bool div_ret = Val64Test::OpDiv(v64a_div, v64b_div);
        BOOST_CHECK(div_ret == true);

        std::vector<unsigned char> div_vec = v64a_div.MoveToValtype();
        std::vector<unsigned char> expected_div = {
            0xFC, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x01
        };
        BOOST_CHECK(div_vec == expected_div);
    }

    // Test another division edge case: dividend that produces qstar close to 2^64
    {
        std::vector<unsigned char> dividend = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        };
        std::vector<unsigned char> divisor(8, 0xFF);

        Val64Test v64a_div(dividend);
        Val64Test v64b_div(divisor);
        bool div_ret = Val64Test::OpDiv(v64a_div, v64b_div);
        BOOST_CHECK(div_ret == true);

        std::vector<unsigned char> div_vec = v64a_div.MoveToValtype();
        std::vector<unsigned char> expected_div(8, 0xFF);
        expected_div[0] = 0xFE;
        BOOST_CHECK(div_vec == expected_div);
    }

    // Test mod with the same edge case
    {
        std::vector<unsigned char> dividend = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        };
        std::vector<unsigned char> divisor(8, 0xFF);

        Val64Test v64a_mod(dividend);
        Val64Test v64b_mod(divisor);
        bool mod_ret = Val64Test::OpMod(v64a_mod, v64b_mod);
        BOOST_CHECK(mod_ret == true);

        std::vector<unsigned char> mod_vec = v64a_mod.MoveToValtype();
        std::vector<unsigned char> expected_mod = {
            0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
        };
        BOOST_CHECK(mod_vec == expected_mod);
    }

    // Test case specifically designed to trigger cross overflow in Knuth refinement.
    // We need: qstar close to 2^64 and v2[n-2] close to 2^64.
    // This happens when the dividend's top two words form a value just under
    // (divisor[n-1] * 2^64), and divisor[n-2] is large.
    {
        // Create a 3-word dividend and 2-word divisor to exercise the refinement.
        // Dividend: 0x7FFFFFFFFFFFFFFF_FFFFFFFFFFFFFFFF_FFFFFFFFFFFFFFFF
        std::vector<unsigned char> dividend = {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x7F
        };

        // Divisor: 0x8000000000000000_FFFFFFFFFFFFFFFF
        // This has a normalized high word and a large second word.
        std::vector<unsigned char> divisor = {
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80
        };

        Val64Test v64a_div(dividend);
        Val64Test v64b_div(divisor);
        bool div_ret = Val64Test::OpDiv(v64a_div, v64b_div);
        BOOST_CHECK(div_ret == true);

        const cpp_int dividend_int = vector_to_cpp_int(dividend);
        const cpp_int divisor_int = vector_to_cpp_int(divisor);
        BOOST_CHECK(v64a_div.MoveToValtype() == cpp_int_to_vector(dividend_int / divisor_int));

        Val64Test v64a_mod(dividend);
        Val64Test v64b_mod(divisor);
        bool mod_ret = Val64Test::OpMod(v64a_mod, v64b_mod);
        BOOST_CHECK(mod_ret == true);
        BOOST_CHECK(v64a_mod.MoveToValtype() == cpp_int_to_vector(dividend_int % divisor_int));
    }

    }

    Val64Test::SetForcePortableMath(false);
}

BOOST_AUTO_TEST_SUITE_END()
