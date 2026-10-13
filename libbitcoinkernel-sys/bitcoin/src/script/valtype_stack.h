// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
#ifndef BITCOIN_SCRIPT_VALTYPE_STACK_H
#define BITCOIN_SCRIPT_VALTYPE_STACK_H

#include <cstddef>
#include <span>
#include <vector>

class Val64;

using valtype = std::vector<unsigned char>;

/**
 * Script stack wrapper that tracks the current total element size and the
 * largest element size seen during execution.
 */
class ValtypeStack
{
public:
    ValtypeStack() = default;
    explicit ValtypeStack(std::span<const valtype> plain_stack);

    ValtypeStack(const ValtypeStack&) = delete;
    ValtypeStack& operator=(const ValtypeStack&) = delete;

    ValtypeStack(ValtypeStack&& other) noexcept;
    ValtypeStack& operator=(ValtypeStack&& other) noexcept;

    // Element access is const-only so size tracking cannot be invalidated.
    const valtype& at(size_t n) const { return m_stack.at(n); }
    const valtype& back() const { return m_stack.back(); }
    size_t size() const { return m_stack.size(); }

    const std::vector<valtype>& GetStack() const { return m_stack; }
    size_t GetTotalSize() const { return m_total_size; }
    size_t GetMaxElementSize() const { return m_max_element_size; }

    void push_back(const valtype& element);
    void push_back(valtype&& element);
    void pop_back();
    valtype PopBackValue();
    bool PopVal64(Val64& value);

    void erase(size_t n);

    void reserve(size_t n);

    void Rotate(int first, int middle);
    void Roll(size_t depth);
    void Swap(int first, int second);

private:
    std::vector<valtype> m_stack;
    size_t m_total_size{0};
    // High-water mark; deliberately not reduced when elements are removed.
    size_t m_max_element_size{0};

    void TrackAddedElement(const valtype& element);
    void TrackRemovedElement(const valtype& element);
    void RecalculateSizeTracking();
};

#endif // BITCOIN_SCRIPT_VALTYPE_STACK_H
