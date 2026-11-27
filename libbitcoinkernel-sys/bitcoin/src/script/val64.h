// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_SCRIPT_VAL64_H
#define BITCOIN_SCRIPT_VAL64_H

#include <compat/endian.h>

#include <cstddef>
#include <cstdint>
#include <span>
#include <vector>

/**
 * Arbitrary-length unsigned Script value for BIP 441 arithmetic and bit
 * operations, backed by little-endian 64-bit limbs.
 *
 * Logical bytes start at LimbOffset() inside m_bytes. Bytes outside the
 * logical range are representation padding and must remain zero.
 */
class Val64
{
protected:
    // Convenience typedef for clarity, where dealing with little-endian.
    typedef uint64_t le64_t;

    // Byte storage for the value plus possible alignment padding.
    std::vector<unsigned char> m_bytes;

    // Number of logical value bytes starting at LimbOffset().
    size_t m_size{0};

    // Little-endian uint64_t span over the logical bytes and zero padding.
    std::span<le64_t> m_limbs{};

    // Rebuild the limb view after m_bytes changes.
    void SetSpan();

    // Remove alignment and trailing padding before changing m_bytes.
    void PrepareForByteMutation();

    // Byte offset of the first logical limb within m_bytes.
    size_t LimbOffset() const;

#ifdef DEBUG
    void CheckInvariants() const;
#endif

    // Append a 1 byte to the value for carry.
    void AppendOne();

    // Remove this many bytes from the front.
    void RemoveFront(size_t bytes);

    // Prepend this many zero bytes to the front.
    void PrependZeros(size_t prebytes);

    // Trim to this length.
    void Truncate(size_t new_size);

public:
    Val64() = default;
    explicit Val64(std::vector<unsigned char>&& bytes);

    // Make a minimal Val64 from a uint64_t.
    explicit Val64(uint64_t value);

    Val64(Val64&& other) noexcept;
    Val64& operator=(Val64&& other) noexcept;

    void MoveFromValtype(std::vector<unsigned char>&& bytes);

    // Convert to a valtype and clear this value.
    std::vector<unsigned char> MoveToValtype();

    // Trim trailing zero bytes so serialization is minimal.
    void TrimTrailingZeros();

    // Byte size of the value.
    size_t size() const { return m_size; }

    // Unmetered helpers; consensus callers must charge separately.
    bool IsZero() const;
    int Compare(const Val64& other) const;

    // Convert to uint64_t, returning max if the value is larger.
    uint64_t ToU64Ceil(uint64_t max, uint64_t& varcost) const;

    // Return whether this value is zero.
    bool IsZero(uint64_t& varcost) const;

    // Return -1 if this < other, 0 if equal, and 1 if this > other.
    int Compare(const Val64& other, uint64_t& varcost) const;

    // Explicit opcode names distinguish these consensus-constrained operations
    // from generic arithmetic.
    static void OpAdd(Val64& v1, Val64& v2, uint64_t& varcost);
    static void Op1Add(Val64& v1, uint64_t& varcost);

    // Return false and leave v1 unspecified if v1 < v2.
    // Otherwise set v1 to v1 - v2 and return true.
    static bool OpSub(Val64& v1, const Val64& v2, uint64_t& varcost);
    static bool Op1Sub(Val64& v1, uint64_t& varcost);

    // Returns false if v1 would exceed max_size.
    static bool OpUpShift(Val64& v1, const Val64& v2, size_t max_size, uint64_t& varcost);
    static void OpDownShift(Val64& v1, const Val64& v2, uint64_t& varcost);

    // Shift by one bit and normalize the result.
    static void Op2Mul(Val64& v1, uint64_t& varcost);
    static void Op2Div(Val64& v1, uint64_t& varcost);

    static void OpInvert(Val64& v1, uint64_t& varcost);

    static void OpAnd(Val64& v1, Val64& v2, uint64_t& varcost);
    static void OpOr(Val64& v1, Val64& v2, uint64_t& varcost);
    static void OpXor(Val64& v1, Val64& v2, uint64_t& varcost);

    static void OpMin(Val64& v1, Val64& v2, uint64_t& varcost);
    static void OpMax(Val64& v1, Val64& v2, uint64_t& varcost);

    // Operands may be swapped for efficiency.
    static Val64 OpMul(Val64& v1, Val64& v2);

    // Returns false if v2 is 0.
    static bool OpDiv(Val64& v1, Val64& v2);
    static bool OpMod(Val64& v1, Val64& v2);

protected:
    // Copy constructor, useful for tests.
    Val64(const Val64&);

    // Swap with the other value.
    void Swap(Val64& other) noexcept;

    // Endian conversion helpers.
    void Set(size_t index, uint64_t value)
    {
        m_limbs[index] = htole64_internal(value);
    }

    uint64_t Get(size_t index) const
    {
        return le64toh_internal(m_limbs[index]);
    }

    // If it's past the end, return 0.
    uint64_t GetOrZero(size_t index) const;

    // We've treated this as a u64 array, now trim trailing zero bytes.
    void TrimTail();

    // Fast version, if we know some zeros already.
    void TrimTail(size_t nonzero_len);

    // Swap v1 and v2 so v1 is always longer or same size than v2.
    static void PutLongerFirst(Val64& v1, Val64& v2);

    // Right shift by this many words, and this many bits (1-63 incl).
    void ShiftDown(size_t words, size_t bits);

    // Left shift in place by less than one word (1-63 bits inclusive).
    // Return true iff we had overflow.
    bool ShiftLeftLessThanWord(size_t bits);

    // False if any non-zero bytes in span.
    static bool SpanIsAllZero(std::span<const le64_t> span);

    static int CompareSpans(std::span<const le64_t> v1, std::span<const le64_t> v2);

    // v1 += v2, return carry.  v1.size() >= v2.size().
    // If returns false, nonzero_len is one past the last non-zero u64 in v1
    // (which helps optimize TrimTail)
    static bool AddSpans(std::span<le64_t> v1, std::span<const le64_t> v2, size_t& nonzero_len);

    // v1 -= v2, returns underflow.
    // If returns false, nonzero_len is one past the last non-zero u64 in v1
    // (which helps optimize TrimTail)
    static bool SubtractSpans(std::span<le64_t> v1, std::span<const le64_t> v2, size_t& nonzero_len);

    // res = src * mul
    static void MultiplySpan(std::span<le64_t> res,
                             std::span<const le64_t> src,
                             uint64_t mul);

    enum class DivModOp {
        DIV,
        MOD,
    };

    // Div: v1 = v1 / v2.  Mod: v1 = v1 % v2.  False if v2 is zero.
    static bool DivMod(Val64& v1, Val64& v2, DivModOp op);

    // Test helpers
    static bool m_force_offset_span;
    static bool m_force_portable_math;
};

#endif // BITCOIN_SCRIPT_VAL64_H
