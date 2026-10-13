// Copyright (c) 2024 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/val64.h>

#include <compat/endian.h>
#include <script/varops.h>

#include <algorithm>
#include <bit>
#include <cassert>
#include <cstring>
#include <memory>
#include <utility>

// MSVC compatibility: use compiler intrinsics where __int128 is not available.
#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_ARM64))
#include <intrin.h>
#if defined(_M_X64)
#include <immintrin.h>
#define VAL64_HAVE_MSVC_UMUL128 1
#if _MSC_VER >= 1920
#define VAL64_HAVE_MSVC_UDIV128 1
#endif
#elif defined(_M_ARM64)
#define VAL64_HAVE_MSVC_UMULH 1
#endif
#endif


// For testing.
bool Val64::m_force_offset_span = false;
bool Val64::m_force_portable_math = false;

namespace {

#ifdef __has_builtin
#if __has_builtin(__builtin_add_overflow) && __has_builtin(__builtin_sub_overflow)
#define VAL64_HAVE_BUILTIN_OVERFLOW 1
#endif
#endif

bool AddOverflow(uint64_t lhs, uint64_t rhs, uint64_t& result)
{
#ifdef VAL64_HAVE_BUILTIN_OVERFLOW
    return __builtin_add_overflow(lhs, rhs, &result);
#else
    const bool overflow{rhs > UINT64_MAX - lhs};
    result = overflow ? rhs - (UINT64_MAX - lhs) - 1 : lhs + rhs;
    return overflow;
#endif
}

bool SubUnderflow(uint64_t lhs, uint64_t rhs, uint64_t& result)
{
#ifdef VAL64_HAVE_BUILTIN_OVERFLOW
    return __builtin_sub_overflow(lhs, rhs, &result);
#else
    const bool underflow{lhs < rhs};
    result = underflow ? UINT64_MAX - (rhs - lhs) + 1 : lhs - rhs;
    return underflow;
#endif
}

uint64_t ShiftLeftLow64(uint64_t value, size_t shift)
{
    assert(shift < 64);
    if (shift == 0) return value;
    return (value & (UINT64_MAX >> shift)) << shift;
}

struct Div64Result {
    uint64_t quotient;
    uint64_t remainder;
    bool quotient_is_beta;
};

struct Uint128 {
    uint64_t hi;
    uint64_t lo;

    static Uint128 Mul(uint64_t a, uint64_t b, bool force_portable_math)
    {
#if defined(__SIZEOF_INT128__)
        if (!force_portable_math) {
            const unsigned __int128 product{static_cast<unsigned __int128>(a) * b};
            return {static_cast<uint64_t>(product >> 64), static_cast<uint64_t>(product)};
        }
#elif defined(VAL64_HAVE_MSVC_UMUL128)
        if (!force_portable_math) {
            uint64_t hi;
            const uint64_t lo{_umul128(a, b, &hi)};
            return {hi, lo};
        }
#elif defined(VAL64_HAVE_MSVC_UMULH)
        if (!force_portable_math) {
            return {__umulh(a, b), a * b};
        }
#endif

        // Reconstruct a 64x64-to-128-bit product from four 32x32-bit
        // partial products, carrying the middle terms into the high word.
        const uint64_t a_lo{a & 0xFFFFFFFFULL};
        const uint64_t a_hi{a >> 32};
        const uint64_t b_lo{b & 0xFFFFFFFFULL};
        const uint64_t b_hi{b >> 32};

        const uint64_t p0{a_lo * b_lo};
        const uint64_t p1{a_lo * b_hi};
        const uint64_t p2{a_hi * b_lo};
        const uint64_t p3{a_hi * b_hi};

        const uint64_t carry{((p0 >> 32) + (p1 & 0xFFFFFFFFULL) + (p2 & 0xFFFFFFFFULL)) >> 32};
        uint64_t lo;
        AddOverflow(p0, ShiftLeftLow64(p1, 32), lo);
        AddOverflow(lo, ShiftLeftLow64(p2, 32), lo);
        const uint64_t hi{p3 + (p1 >> 32) + (p2 >> 32) + carry};
        return {hi, lo};
    }

    Div64Result DivMod64(uint64_t divisor, bool force_portable_math) const
    {
        assert(divisor != 0);

        if (hi >= divisor) {
            // The trial quotient is beta. D3 represents the corrected beta - 1.
            assert(hi == divisor);
            return {UINT64_MAX, lo, true};
        }

#if defined(__SIZEOF_INT128__)
        if (!force_portable_math) {
            const unsigned __int128 dividend{(static_cast<unsigned __int128>(hi) << 64) | lo};
            const unsigned __int128 quotient{dividend / divisor};
            const unsigned __int128 remainder{dividend % divisor};

            assert((quotient >> 64) == 0);
            return {static_cast<uint64_t>(quotient), static_cast<uint64_t>(remainder), false};
        }
#elif defined(VAL64_HAVE_MSVC_UDIV128)
        if (!force_portable_math) {
            uint64_t remainder;
            const uint64_t quotient{_udiv128(hi, lo, divisor, &remainder)};
            return {quotient, remainder, false};
        }
#endif

        // Portable 128-bit by 64-bit division using 32-bit digits.
        // Based on Hacker's Delight divlu() and Knuth's Algorithm D.
        // Computes (hi:lo) / divisor. When hi == divisor, Knuth's trial
        // quotient is beta and gets corrected by D3 in the caller.
        if (hi == 0) {
            return {lo / divisor, lo % divisor, false};
        }

        // The divisor has its top bit set (normalized), so we can safely use
        // 32-bit chunks without overflow in intermediate calculations.
        constexpr uint64_t B = 1ULL << 32; // Base (2^32)

        // Split divisor into two 32-bit digits.
        const uint64_t d1{divisor >> 32};
        const uint64_t d0{divisor & 0xFFFFFFFF};

        // The dividend is (hi : lo), treated as four 32-bit digits:
        // hi = (u3 : u2), lo = (u1 : u0). Compute one quotient digit at a time.
        const uint64_t u32{hi};
        const uint64_t u1{lo >> 32};
        const uint64_t u0{lo & 0xFFFFFFFF};

        // Estimate q1 = floor(u32 / d1). Since divisor is normalized and
        // hi < divisor, the result fits in 32 bits.
        uint64_t q1{u32 / d1};
        uint64_t r1{u32 % d1};

        // Refine: while q1 >= B or q1 * d0 > B * r1 + u1.
        while (q1 >= B || q1 * d0 > ShiftLeftLow64(r1, 32) + u1) {
            --q1;
            r1 += d1;
            if (r1 >= B) break;
        }

        // Update partial remainder for next digit:
        // u21 = (u32 * B + u1) - q1 * divisor
        //     = (r1 * B + u1) - q1 * d0.
        uint64_t u21;
        SubUnderflow(ShiftLeftLow64(r1, 32) + u1, q1 * d0, u21);

        uint64_t q0{u21 / d1};
        uint64_t r0{u21 % d1};

        while (q0 >= B || q0 * d0 > ShiftLeftLow64(r0, 32) + u0) {
            --q0;
            r0 += d1;
            if (r0 >= B) break;
        }

        assert(q1 < B);
        assert(q0 < B);
        const uint64_t quotient{(q1 << 32) + q0};
        uint64_t remainder;
        SubUnderflow(ShiftLeftLow64(r0, 32) + u0, q0 * d0, remainder);
        return {quotient, remainder, false};
    }
};

// Make the byte-backed words accessible as uint64_t objects before exposing
// them through m_limbs.
uint64_t* StartLimbLifetimes(void* aligned_ptr, size_t limb_count)
{
    uint64_t* limbs = static_cast<uint64_t*>(aligned_ptr);
    unsigned char* bytes = static_cast<unsigned char*>(aligned_ptr);

    for (size_t i = 0; i < limb_count; ++i) {
        uint64_t value;
        std::memcpy(&value, bytes + i * sizeof(uint64_t), sizeof(value));
        std::construct_at(limbs + i, value);
    }

    return limbs;
}

#undef VAL64_HAVE_BUILTIN_OVERFLOW

} // namespace

Val64::Val64(std::vector<unsigned char>&& bytes) : m_bytes(std::move(bytes))
{
    SetSpan();
}

size_t Val64::LimbOffset() const
{
    if (m_size == 0) return 0;

    const unsigned char* p{reinterpret_cast<const unsigned char*>(m_limbs.data())};

    // Sanity check that the limb view is in bounds.
    assert(p >= m_bytes.data());
    assert(p + m_size <= m_bytes.data() + m_bytes.size());

    return p - m_bytes.data();
}

#ifdef DEBUG
void Val64::CheckInvariants() const
{
    assert(m_size <= m_bytes.size());

    if (m_limbs.empty()) {
        assert(m_size == 0);
        return;
    }

    const unsigned char* const data{m_bytes.data()};
    const unsigned char* const span_bytes{reinterpret_cast<const unsigned char*>(m_limbs.data())};
    const size_t span_bytes_size{m_limbs.size_bytes()};

    assert(span_bytes >= data);
    assert(span_bytes + span_bytes_size <= data + m_bytes.size());

    const size_t span_offset{static_cast<size_t>(span_bytes - data)};
    assert(span_offset + m_size <= m_bytes.size());
    assert(std::all_of(m_bytes.begin(), m_bytes.begin() + span_offset, [](unsigned char c) { return c == 0; }));
    assert(std::all_of(m_bytes.begin() + span_offset + m_size, m_bytes.end(), [](unsigned char c) { return c == 0; }));
}
#endif

// Only m_bytes is set: initialize other fields.
void Val64::SetSpan()
{
    m_size = m_bytes.size();

    // Round up to get number of u64s
    const size_t limb_count{(m_size + sizeof(uint64_t) - 1) / sizeof(uint64_t)};
    if (limb_count == 0) {
        m_limbs = {};
#ifdef DEBUG
        CheckInvariants();
#endif
        return;
    }

    // Enlarge if necessary (trailing zeroes are harmless in little-endian)
    if (m_bytes.size() < limb_count * sizeof(uint64_t)) {
        m_bytes.insert(m_bytes.end(), limb_count * sizeof(uint64_t) - m_bytes.size(), 0);
    }

    // Val64 stores script values as bytes and creates live 64-bit limb objects
    // in aligned byte storage so arithmetic can use word-sized spans.
    size_t available_space = m_bytes.size();
    void* aligned_ptr{m_bytes.data()};
    if (std::align(alignof(uint64_t), limb_count * sizeof(uint64_t), aligned_ptr, available_space) == m_bytes.data() && aligned_ptr == m_bytes.data() && !m_force_offset_span) {
        m_limbs = std::span<le64_t>(StartLimbLifetimes(m_bytes.data(), limb_count), limb_count);
#ifdef DEBUG
        CheckInvariants();
#endif
        return;
    }

    // Append zeroes so we can move values.  This might change alignment.
    m_bytes.insert(m_bytes.end(), sizeof(uint64_t), 0);
    available_space = m_bytes.size();
    aligned_ptr = m_bytes.data();
    std::align(alignof(uint64_t), limb_count * sizeof(uint64_t), aligned_ptr, available_space);

    // Force an offset span in tests even when the vector is already aligned.
    if (m_force_offset_span && aligned_ptr == m_bytes.data()) {
        aligned_ptr = m_bytes.data() + sizeof(uint64_t);
    }

    // Figure out how much the offset now is, so we can move data.
    const size_t span_offset{static_cast<size_t>(static_cast<unsigned char*>(aligned_ptr) - m_bytes.data())};
    std::memmove(m_bytes.data() + span_offset, m_bytes.data(), limb_count * sizeof(uint64_t));
    std::fill(m_bytes.begin(), m_bytes.begin() + span_offset, 0);
    m_limbs = std::span<le64_t>(StartLimbLifetimes(aligned_ptr, limb_count), limb_count);
#ifdef DEBUG
    CheckInvariants();
#endif
}

// Remove offset because we're changing m_bytes.
void Val64::PrepareForByteMutation()
{
#ifdef DEBUG
    CheckInvariants();
#endif
    const size_t span_offset{LimbOffset()};
    if (span_offset != 0) {
        m_bytes.erase(m_bytes.begin(), m_bytes.begin() + span_offset);
    }

    // Trim any added bytes.
    assert(m_size <= m_bytes.size());
    m_bytes.resize(m_size);
}

void Val64::RemoveFront(size_t bytes)
{
    assert(bytes <= m_size);

    PrepareForByteMutation();
    m_bytes.erase(m_bytes.begin(), m_bytes.begin() + bytes);
    SetSpan();
}

void Val64::PrependZeros(size_t prebytes)
{
    PrepareForByteMutation();
    m_bytes.insert(m_bytes.begin(), prebytes, 0);
    SetSpan();
}

void Val64::Truncate(size_t new_size)
{
    assert(new_size <= m_bytes.size());

    PrepareForByteMutation();
    m_bytes.resize(new_size);
    SetSpan();
}

void Val64::MoveFromValtype(std::vector<unsigned char>&& bytes)
{
    m_bytes = std::move(bytes);
    SetSpan();
}

std::vector<unsigned char> Val64::MoveToValtype()
{
    std::vector<unsigned char> ret;

    PrepareForByteMutation();
    ret = std::move(m_bytes);
    SetSpan();

    return ret;
}

void Val64::TrimTrailingZeros()
{
    TrimTail();
}

Val64::Val64(const Val64& other)
{
    const size_t span_offset{other.LimbOffset()};
    m_bytes.assign(other.m_bytes.begin() + span_offset, other.m_bytes.begin() + span_offset + other.m_size);
    SetSpan();
}

// Faster "trim zeroes from end" function
void Val64::TrimTail(size_t nonzero_len)
{
#ifdef DEBUG
    // Check that the words after nonzero len are indeed all zero.
    for (size_t i = nonzero_len; i < m_limbs.size(); ++i) {
        assert(m_limbs[i] == 0);
    }
#endif

    if (nonzero_len < m_limbs.size()) {
        m_limbs = m_limbs.first(nonzero_len);
    }

    TrimTail();
}

void Val64::TrimTail()
{
    // Discard complete zero limbs before examining the remaining bytes.
    size_t nonzero_words{m_limbs.size()};
    while (nonzero_words > 0 && m_limbs[nonzero_words - 1] == 0) {
        --nonzero_words;
    }
    if (nonzero_words < m_limbs.size()) {
        m_limbs = m_limbs.first(nonzero_words);
    }

    m_size = m_limbs.size_bytes();

    PrepareForByteMutation();
    // At most the seven high zero bytes in the final non-zero limb remain.
    while (!m_bytes.empty() && m_bytes.back() == 0) {
        m_bytes.pop_back();
    }
    SetSpan();
}

Val64::Val64(uint64_t value) : m_bytes(sizeof(uint64_t))
{
    SetSpan();
    Set(0, value);
    TrimTail();
}

Val64::Val64(Val64&& other) noexcept
{
    other.PrepareForByteMutation();
    m_bytes = std::move(other.m_bytes);
    other.SetSpan();
    SetSpan();
}

Val64& Val64::operator=(Val64&& other) noexcept
{
    if (this != &other) {
        other.PrepareForByteMutation();
        m_bytes = std::move(other.m_bytes);
        other.SetSpan();
        SetSpan();
    }
    return *this;
}

void Val64::Swap(Val64& other) noexcept
{
    std::swap(m_bytes, other.m_bytes);
    std::swap(m_size, other.m_size);
    std::swap(m_limbs, other.m_limbs);
}

uint64_t Val64::GetOrZero(size_t index) const
{
    if (index >= m_limbs.size()) return 0;
    return Get(index);
}

// Append a 1 byte to the limb array.
void Val64::AppendOne()
{
    PrepareForByteMutation();

    // Make sure we have room to append.
    m_bytes.resize(m_limbs.size() * sizeof(uint64_t) + 1);
    m_bytes[m_limbs.size() * sizeof(uint64_t)] = 1;

    // Re-evaluate with new m_bytes.
    SetSpan();
}

uint64_t Val64::ToU64Ceil(uint64_t max, uint64_t& varcost) const
{
    // Worst case, we have to examine the padded word span (LENGTHCONV).
    varcost += varops::LengthConversionCost(m_size);

    // Little endian: get first word (zero-fills).
    const uint64_t value{GetOrZero(0)};
    if (value > max) return max;

    // If any other bytes are non-zero, it's > UINT64_MAX.
    if (m_limbs.size() > 1 && !SpanIsAllZero(m_limbs.last(m_limbs.size() - 1))) {
        return max;
    }

    return value;
}

bool Val64::IsZero() const
{
    return SpanIsAllZero(m_limbs);
}

bool Val64::IsZero(uint64_t& varcost) const
{
    varcost += varops::CompareZeroCost(m_size);
    return SpanIsAllZero(m_limbs);
}

bool Val64::SpanIsAllZero(std::span<const le64_t> span)
{
    if (span.empty()) return true;
    if (span.front() != 0) return false;

    // memcmp-with-self trick: see https://rusty.ozlabs.org/2015/10/20/ccanmems-memeqzero-iteration.html
    return std::memcmp(span.data(), span.data() + 1, (span.size() - 1) * sizeof(le64_t)) == 0;
}

// If v1 > v2: 1. If v1 < v2: -1. Otherwise 0.
int Val64::CompareSpans(std::span<const le64_t> v1, std::span<const le64_t> v2)
{
    const size_t max_length{std::max(v1.size(), v2.size())};
    if (max_length == 0) return 0;

    for (size_t i = max_length; i > 0;) {
        --i;
        const uint64_t value1{i < v1.size() ? le64toh_internal(v1[i]) : 0};
        const uint64_t value2{i < v2.size() ? le64toh_internal(v2[i]) : 0};
        if (value1 < value2) return -1;
        if (value1 > value2) return 1;
    }
    return 0;
}

int Val64::Compare(const Val64& other) const
{
    return CompareSpans(m_limbs, other.m_limbs);
}

int Val64::Compare(const Val64& other, uint64_t& varcost) const
{
    varcost += varops::ComparisonCost(m_size, other.m_size);

    return CompareSpans(m_limbs, other.m_limbs);
}

// v1 += v2 (size v2 <= v1).  Return true if carry overflowed.
bool Val64::AddSpans(std::span<le64_t> v1, std::span<const le64_t> v2, size_t& nonzero_len)
{
    assert(v1.size() >= v2.size());

    // Little endian, overflow forward.
    bool carry = false;

    size_t i;
    nonzero_len = 0;
    for (i = 0; i < v2.size(); ++i) {
        uint64_t u1, u2, res;

        u1 = le64toh_internal(v1[i]);
        u2 = le64toh_internal(v2[i]);

        const bool add_carry{AddOverflow(u1, u2, res)};
        const bool carry_carry{AddOverflow(res, uint64_t{carry}, res)};
        carry = add_carry || carry_carry;
        if (res != 0) nonzero_len = i + 1;
        v1[i] = htole64_internal(res);
    }

    /* Carry forwards if required (continue even if not overflowing,
     * to set nonzero_len) */
    while (i < v1.size()) {
        uint64_t u1;
        carry = AddOverflow(le64toh_internal(v1[i]), uint64_t{carry}, u1);
        v1[i] = htole64_internal(u1);
        if (u1 != 0) nonzero_len = i + 1;
        ++i;
    }

    return carry;
}

void Val64::OpAdd(Val64& v1, Val64& v2, uint64_t& varcost)
{
    PutLongerFirst(v1, v2);

    varcost += varops::AddCost(v1.m_size, v2.m_size);

    size_t nonzero_len;
    bool carry = AddSpans(v1.m_limbs, v2.m_limbs, nonzero_len);

    if (carry) {
        v1.AppendOne();
        return;
    }

    v1.TrimTail(nonzero_len);
}

void Val64::Op1Add(Val64& v1, uint64_t& varcost)
{
    // Charge as ADD with a minimal one-byte operand.
    varcost += varops::AddCost(v1.m_size, 1);
    if (v1.m_limbs.empty()) {
        v1.AppendOne();
        return;
    }

    le64_t one{htole64_internal(1)};
    size_t nonzero_len;
    if (AddSpans(v1.m_limbs, std::span<le64_t>{&one, 1}, nonzero_len)) {
        v1.AppendOne();
    } else {
        v1.TrimTail(nonzero_len);
    }
}

// v1 -= v2
bool Val64::SubtractSpans(std::span<le64_t> v1, std::span<const le64_t> v2, size_t& nonzero_len)
{
    const size_t common_len{std::min(v1.size(), v2.size())};

    // Little endian, underflow forward.
    bool underflow = false;

    size_t i;
    nonzero_len = 0;
    for (i = 0; i < common_len; ++i) {
        uint64_t u1, u2, res;

        u1 = le64toh_internal(v1[i]);
        u2 = le64toh_internal(v2[i]);

        const bool sub_underflow{SubUnderflow(u1, u2, res)};
        const bool borrow_underflow{SubUnderflow(res, uint64_t{underflow}, res)};
        underflow = sub_underflow || borrow_underflow;
        v1[i] = htole64_internal(res);
        if (res != 0) nonzero_len = i + 1;
    }

    /* We have exhausted v1? */
    if (i < v2.size()) {
        if (underflow) return true;
        while (i < v2.size()) {
            if (v2[i] != 0) return true;
            ++i;
        }
        return false;
    }

    /* We have exhausted v2.  Underflow forwards if required: we keep
     * going even if we don't need to, to update nonzero_len. */
    while (i < v1.size()) {
        const uint64_t u1{le64toh_internal(v1[i])};
        uint64_t res;
        underflow = SubUnderflow(u1, uint64_t{underflow}, res);
        v1[i] = htole64_internal(res);
        if (res != 0) nonzero_len = i + 1;
        ++i;
    }

    return underflow;
}


bool Val64::OpSub(Val64& v1, const Val64& v2, uint64_t& varcost)
{
    varcost += varops::SubCost(v1.m_size, v2.m_size);
    size_t nonzero_len;

    const bool underflow{SubtractSpans(v1.m_limbs, v2.m_limbs, nonzero_len)};
    if (underflow) {
        // SubtractSpans writes whole words, but padding bytes outside the logical value
        // must remain zero even when the result is discarded for underflow.
        if (v1.m_size < v1.m_limbs.size_bytes()) {
            unsigned char* bytes{reinterpret_cast<unsigned char*>(v1.m_limbs.data())};
            std::fill(bytes + v1.m_size, bytes + v1.m_limbs.size_bytes(), 0);
        }
        return false;
    }

    v1.TrimTail(nonzero_len);
    return true;
}

bool Val64::Op1Sub(Val64& v1, uint64_t& varcost)
{
    varcost += varops::SubCost(v1.m_size, 1);
    if (v1.m_limbs.empty()) return false;

    le64_t one{htole64_internal(1)};
    size_t nonzero_len;
    if (SubtractSpans(v1.m_limbs, std::span<le64_t>{&one, 1}, nonzero_len)) return false;

    v1.TrimTail(nonzero_len);
    return true;
}

void Val64::ShiftDown(size_t words, size_t bits)
{
    assert(!m_limbs.empty());
    assert(bits > 0);
    assert(bits < 64);

    // [B, A] rshift 1 => [B>>1 | A>>63, A << 1]
    uint64_t previous_bits{Get(words) >> bits};
    for (size_t i = words; i < m_limbs.size() - 1; ++i) {
        const uint64_t next{Get(i + 1)};
        Set(i - words, previous_bits | ShiftLeftLow64(next, 64 - bits));
        previous_bits = next >> bits;
    }
    // Shift the last word.
    Set(m_limbs.size() - 1 - words, previous_bits);
}

void Val64::OpDownShift(Val64& v1, const Val64& v2, uint64_t& varcost)
{
    const uint64_t bits{v2.ToU64Ceil(v1.m_size * 8, varcost)};
    const size_t bytes{static_cast<size_t>(bits / 8)};

    // ToU64Ceil charged conversion of BITS; charge copying below once the
    // surviving operand length is known.

    // Shift past end?  Empty.  Also covers empty array.
    if (bytes >= v1.m_size) {
        v1 = Val64{0};
        return;
    }

    varcost += (v1.m_size - bytes) * varops::COST_COPYING;

    // Bitwise shifts can't do 0 anyway, as << 64 undefined.
    if (bits % 8 == 0) {
        // Remove least-significant words.
        v1.RemoveFront(bytes);
        return;
    }

    // Size after this is at least 1!
    assert(!v1.m_limbs.empty());

    // We shift and move at the same time.
    v1.ShiftDown(bits / 64, bits % 64);

    // Truncate.
    v1.Truncate(v1.m_size - bytes);
}

// Shift bits toward more-significant positions, increasing the value.
bool Val64::OpUpShift(Val64& v1, const Val64& v2, size_t max_size, uint64_t& varcost)
{
    const uint64_t bits{v2.ToU64Ceil(max_size * 8 + 1, varcost)};

    // Cannot overflow: m_size is (far) less than 32 bits, so is max_size.
    if (bits + v1.m_size * 8 > max_size * 8) return false;

    // How many whole bytes should we prepend?
    const size_t prebytes{static_cast<size_t>(bits / 8)};

    // Charge against the pre-mutation operand size.
    varcost += prebytes * varops::COST_FAST + v1.m_size * varops::COST_COPYING;

    if (bits % 8 == 0) {
        // Simply insert bytes at the beginning.
        v1.PrependZeros(prebytes);
    } else {
        varcost += varops::UnalignedUpShiftCost(v1.m_size, prebytes);
        // There's no nice C++ "add this many bytes at the beginning,
        // and one at the end" so it is better to prepend too many bytes
        // (fast!) and shift backwards.
        v1.PrependZeros(prebytes + 1);
        v1.ShiftDown(0, 8 - (bits % 8));
    }

    return true;
}

bool Val64::ShiftLeftLessThanWord(size_t bits)
{
    assert(bits > 0);
    assert(bits < 64);

    uint64_t previous_bits{0};

    // [B, A] lshift 1 => [B<<1, A<<1 | B >> 63]
    for (size_t i = 0; i < m_limbs.size(); ++i) {
        const uint64_t old_value{Get(i)};
        const uint64_t new_value{ShiftLeftLow64(old_value, bits) | previous_bits};

        Set(i, new_value);
        previous_bits = old_value >> (64 - bits);
    }
    return previous_bits != 0;
}

void Val64::Op2Mul(Val64& v1, uint64_t& varcost)
{
    // Charge before trimming the operand.
    varcost += varops::TwoMulCost(v1.m_size);

    // Trim first: any bytes we trim here, we avoid shifting.
    v1.TrimTail();

    if (v1.ShiftLeftLessThanWord(1)) {
        v1.AppendOne();
    } else {
        v1.TrimTail();
    }
}

void Val64::Op2Div(Val64& v1, uint64_t& varcost)
{
    // Charge before trimming the operand.
    varcost += varops::TwoDivCost(v1.m_size);

    // Trim first: any bytes we trim here, we avoid shifting.
    v1.TrimTail();

    // ShiftDown assumes non-zero size.
    if (v1.m_size == 0) return;

    v1.ShiftDown(0, 1);
    v1.TrimTail();
}

void Val64::OpInvert(Val64& v1, uint64_t& varcost)
{
    varcost += varops::InvertCost(v1.m_size);

    // Endian doesn't matter, so access raw.
    for (le64_t& v : v1.m_limbs) {
        v ^= UINT64_MAX;
    }

    // Zero out padding bytes beyond m_size in the last u64 word,
    // so subsequent Val64 operations don't see contaminated padding.
    const size_t padding{v1.m_limbs.size() * sizeof(uint64_t) - v1.m_size};
    if (padding > 0) {
        unsigned char* bytes{reinterpret_cast<unsigned char*>(v1.m_limbs.data())};
        std::memset(bytes + v1.m_size, 0, padding);
    }
}

// Makes sure v1 is at least as long as v2.
void Val64::PutLongerFirst(Val64& v1, Val64& v2)
{
    // Make sure v1 is the longer one.
    if (v1.m_size < v2.m_size) v1.Swap(v2);
}

void Val64::OpAnd(Val64& v1, Val64& v2, uint64_t& varcost)
{
    PutLongerFirst(v1, v2);

    varcost += varops::AndCost(v1.m_size, v2.m_size);

    // Endian doesn't matter, so access raw.
    for (size_t i = 0; i < v2.m_limbs.size(); ++i) {
        v1.m_limbs[i] &= v2.m_limbs[i];
    }

    // Rest is 0.
    std::fill(v1.m_limbs.begin() + v2.m_limbs.size(), v1.m_limbs.end(), 0);
}

void Val64::OpOr(Val64& v1, Val64& v2, uint64_t& varcost)
{
    PutLongerFirst(v1, v2);

    varcost += varops::OrCost(v1.m_size, v2.m_size);

    // Endian doesn't matter, so access raw.
    for (size_t i = 0; i < v2.m_limbs.size(); ++i) {
        v1.m_limbs[i] |= v2.m_limbs[i];
    }
}

void Val64::OpXor(Val64& v1, Val64& v2, uint64_t& varcost)
{
    PutLongerFirst(v1, v2);

    varcost += varops::XorCost(v1.m_size, v2.m_size);

    // Endian doesn't matter, so access raw.
    for (size_t i = 0; i < v2.m_limbs.size(); ++i) {
        v1.m_limbs[i] ^= v2.m_limbs[i];
    }
}

void Val64::OpMin(Val64& v1, Val64& v2, uint64_t& varcost)
{
    PutLongerFirst(v1, v2);

    varcost += varops::MinMaxCost(v1.m_size, v2.m_size);

    if (CompareSpans(v1.m_limbs, v2.m_limbs) > 0) {
        v1 = std::move(v2);
    }
    v1.TrimTail();
}

void Val64::OpMax(Val64& v1, Val64& v2, uint64_t& varcost)
{
    PutLongerFirst(v1, v2);

    varcost += varops::MinMaxCost(v1.m_size, v2.m_size);

    if (CompareSpans(v1.m_limbs, v2.m_limbs) < 0) {
        v1 = std::move(v2);
    }
    v1.TrimTail();
}

void Val64::MultiplySpan(std::span<le64_t> res,
                         std::span<const le64_t> src,
                         uint64_t mul)
{
    // Result must be (at least) 1 word larger, for carry.
    assert(res.size() >= src.size() + 1);

    // Calculate this * mul, into res.
    res[0] = htole64_internal(0);
    for (size_t i = 0; i < src.size(); ++i) {
        const Uint128 product{Uint128::Mul(le64toh_internal(src[i]), mul, m_force_portable_math)};
        uint64_t hi{product.hi};
        uint64_t lo{product.lo};
        const uint64_t oldhi{le64toh_internal(res[i])};
        /* Note: hi cannot overflow since UINT64MAX * UINT64MAX
         * gives an upper u64 which is < UINT64MAX. */
        if (AddOverflow(lo, oldhi, lo)) ++hi;
        res[i] = htole64_internal(lo);
        res[i + 1] = htole64_internal(hi);
    }
}

Val64 Val64::OpMul(Val64& v1, Val64& v2)
{
    // Slightly more optimal if v1 is the larger operand.
    PutLongerFirst(v1, v2);

    // Result (worst case is sum of operand lengths)
    std::vector<unsigned char> retvec((v1.m_limbs.size() + v2.m_limbs.size()) * sizeof(uint64_t));
    Val64 ret(std::move(retvec));

    // Result of each v1[] * v2.
    std::vector<le64_t> scratch(v2.m_limbs.size() + 1);

    size_t ret_nonzero_len = 0;

    for (size_t i = 0; i < v1.m_limbs.size(); ++i) {
        size_t nonzero_len;
        // Multiply v2 by v1[i] into scratch.
        MultiplySpan(scratch, v2.m_limbs, v1.Get(i));

        // Now add into result at offset i.
        // Cannot overflow.  Worst case ret effectively adds 1 to v1[i],
        // which *still* doesn't quite overflow.
        const bool carry{AddSpans(ret.m_limbs.subspan(i, v2.m_limbs.size() + 1),
                                  scratch, nonzero_len)};
        assert(!carry);
        if (nonzero_len != 0) ret_nonzero_len = i + nonzero_len;
    }

    ret.TrimTail(ret_nonzero_len);
    return ret;
}

// False iff v2 is 0.
bool Val64::DivMod(Val64& v1, Val64& v2, DivModOp op)
{
    // This is BasecaseDivRem from "Modern Computer Arithmetic" by Richard
    // Brent and Paul Zimmerman.  I discovered later that this is the same as
    // Knuth's TAOCP v2 (of course!) page 272, Algorithm D "Division of
    // non-negative integers".

    // For efficiency, the divisor (v2) needs to be *normalized*, i.e.
    // the top bit is set.  We trim and shift both to ensure this is true.

    // This does not add cost because any
    // bytes trimmed here (cost == number of bytes trimmed + 1) saves
    // costs below.
    v1.TrimTail();
    v2.TrimTail();

    // Now there's only one canonical zero.
    if (v2.m_size == 0) return false;

    // How many bits do we have to shift to get top bit set?
    const size_t k{static_cast<size_t>(std::countl_zero(v2.Get(v2.m_limbs.size() - 1)))};

    if (v1.m_size < v2.m_size) {
        // v2 > v1: v1 is remainder, quotient is 0.
        if (op == DivModOp::DIV) v1 = Val64{0};
        return true;
    }

    // These might have to reallocate, but by no more than 8 bytes.
    // In theory, we could save this cost by doing shifting as we go.
    // But this shift isn't really the main overhead, so keep it simple.
    if (k != 0) {
        uint64_t varcost{0};
        // Val64(k) makes a one-limb temporary and varcost is discarded; both
        // are fine: this runs once per division and OP_DIV/OP_MOD pre-charge
        // their full cost.
        // k is at most 63, and max_size reserves one extra limb for normalization.
        const bool shifted{OpUpShift(v1, Val64(k), v1.m_size + sizeof(uint64_t), varcost)};
        assert(shifted);
        const bool overflow{v2.ShiftLeftLessThanWord(k)};
        assert(!overflow);
    }

    // Shift can add a few zero bytes, re-normalize.
    v1.TrimTail();
    v2.TrimTail();

    // v1 has n+m words, v2 has n words.  β is the base (2^64 here).
    assert(v1.m_limbs.size() >= v2.m_limbs.size());
    const size_t n{v2.m_limbs.size()};
    const size_t m{v1.m_limbs.size() - n};

    // If we need quotient, create empty q vec, worst-case len.
    Val64 q;
    if (op == DivModOp::DIV) {
        std::vector<unsigned char> qvec((m + 1) * sizeof(uint64_t));
        q.MoveFromValtype(std::move(qvec));
    }

    // 1: if v1 >= β^m x v2, then q_m = 1, v1 = v1 - β^m x v2 else q_m = 0
    if (CompareSpans(v1.m_limbs.subspan(m), v2.m_limbs) > -1) {
        size_t last_nonzero;
        if (op == DivModOp::DIV) q.Set(m, 1);
        const bool carry{SubtractSpans(v1.m_limbs.subspan(m), v2.m_limbs, last_nonzero)};
        assert(!carry);
    } else {
        if (op == DivModOp::DIV) q.Set(m, 0);
    }

    // We need a temporary, but we overwrite it all, so create outside loop.
    std::vector<le64_t> scratch(v2.m_limbs.size() + 1);

    // 2: for j from m-1 downto 0 do:
    for (size_t j = m; j > 0;) {
        --j;

        // 3: q* = floor((v1_n+j_ x β + v1_n+j-1_) / v2_n-1_)
        const uint64_t v_hi{v1.Get(n + j)};
        const uint64_t v_lo{v1.Get(n + j - 1)};
        const uint64_t divisor{v2.Get(n - 1)};
        const Div64Result div64{Uint128{v_hi, v_lo}.DivMod64(divisor, m_force_portable_math)};
        uint64_t qstar{div64.quotient};
        uint64_t rstar{div64.remainder};
        bool qstar_is_beta{div64.quotient_is_beta};
        bool rstar_overflow{false};
        if (qstar_is_beta) assert(n > 1);

        // Knuth suggests: test if q* == β, or
        // q* x v2_n-2_ > βr* + v1_n+j-2_.  If so, decrease q* by 1,
        // increase r* by v2_n-1_, and repeat if r* did not overflow β.
        if (n > 1) {
            const uint64_t v2_n2{v2.Get(n - 2)};
            const uint64_t v1_nj2{v1.Get(n + j - 2)};
            const uint64_t divisor{v2.Get(n - 1)};

            auto product_greater_than_remainder = [&]() {
                const Uint128 product{Uint128::Mul(qstar, v2_n2, m_force_portable_math)};
                return product.hi > rstar || (product.hi == rstar && product.lo > v1_nj2);
            };

            while (qstar_is_beta || (!rstar_overflow && product_greater_than_remainder())) {
                if (qstar_is_beta) {
                    qstar_is_beta = false;
                } else {
                    --qstar;
                }

                rstar_overflow = AddOverflow(rstar, divisor, rstar);
            }
        }

        // This is our (64-bit) guess.
        uint64_t qj = qstar;

        // D4: v1 = v1 - q_j_ x β^j x v2

        // Assign scratch = q_j_ x v2
        // Note: v2 doesn't change in this loop, so scratch gets fully
        // overwritten each time, meaning we don't need to zero it.
        MultiplySpan(scratch, v2.m_limbs, qj);

        bool underflow;
        size_t last_nonzero;
        underflow = SubtractSpans(v1.m_limbs.subspan(j), scratch, last_nonzero);
        // D5: Set q_j_ = q*.  If the result of D4 was negative, go to D6.
        if (underflow) {
            // D6: Decrease q_j_ by 1, and add β^j x v2 to v1

            // Intuitively: we've got an estimate on v1/v2, using division on
            // the high words, plus a compensation from the next-highest.  It
            // could be an overestimate by one, however!  This path is covered
            // by the val64_div_mod_knuth_d6_add_back regression test.
            --qj;
            size_t nonzero_len;
            const bool carry{AddSpans(v1.m_limbs.subspan(j), v2.m_limbs, nonzero_len)};
            assert(carry);
        }

        // Keep shrinking v1.  Note: we could use the sub/add_with_offset
        // return to trim a bit faster if we wanted.
        if (!v1.m_limbs.empty()) {
            assert(v1.Get(v1.m_limbs.size() - 1) == 0);
            v1.Truncate((v1.m_limbs.size() - 1) * sizeof(uint64_t));
        }

        if (op == DivModOp::DIV) q.Set(j, qj);
    }

    switch (op) {
    case DivModOp::MOD:
        // Remainder needs shifting back (quotient is unaffected, since
        // (A * N) / (B * N) == A / B).
        if (k != 0 && v1.m_size != 0) v1.ShiftDown(0, k);
        v1.TrimTail();
        return true;
    case DivModOp::DIV:
        v1 = std::move(q);
        v1.TrimTail();
        return true;
    }
    assert(!"Invalid op");
}

bool Val64::OpDiv(Val64& v1, Val64& v2)
{
    return DivMod(v1, v2, DivModOp::DIV);
}

bool Val64::OpMod(Val64& v1, Val64& v2)
{
    return DivMod(v1, v2, DivModOp::MOD);
}
