// Copyright (c) 2025 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include <script/valtype_stack.h>

#include <script/val64.h>

#include <algorithm>
#include <cassert>
#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <utility>

ValtypeStack::ValtypeStack(std::span<const valtype> plain_stack) : m_stack(plain_stack.begin(), plain_stack.end())
{
    RecalculateSizeTracking();
}

ValtypeStack::ValtypeStack(ValtypeStack&& other) noexcept
    : m_stack{std::move(other.m_stack)},
      m_total_size{other.m_total_size},
      m_max_element_size{other.m_max_element_size}
{
    other.m_stack.clear();
    other.m_total_size = 0;
    other.m_max_element_size = 0;
}

ValtypeStack& ValtypeStack::operator=(ValtypeStack&& other) noexcept
{
    if (this == &other) return *this;

    m_stack = std::move(other.m_stack);
    m_total_size = other.m_total_size;
    m_max_element_size = other.m_max_element_size;

    other.m_stack.clear();
    other.m_total_size = 0;
    other.m_max_element_size = 0;
    return *this;
}

void ValtypeStack::push_back(const valtype& element)
{
    constexpr size_t WORD_BYTES{sizeof(uint64_t)};
    const size_t capacity{element.size() + (WORD_BYTES - element.size() % WORD_BYTES) % WORD_BYTES};

    // Reserve on the element in its final container so Val64's padding capacity
    // is guaranteed to survive the copy.
    m_stack.emplace_back();
    m_stack.back().reserve(capacity);
    m_stack.back().insert(m_stack.back().end(), element.begin(), element.end());
    TrackAddedElement(m_stack.back());
}

void ValtypeStack::push_back(valtype&& element)
{
    m_stack.push_back(std::move(element));
    TrackAddedElement(m_stack.back());
}

void ValtypeStack::pop_back()
{
    if (m_stack.empty()) {
        throw std::runtime_error("ValtypeStack::pop_back(): stack empty");
    }
    TrackRemovedElement(m_stack.back());
    m_stack.pop_back();
}

valtype ValtypeStack::PopBackValue()
{
    if (m_stack.empty()) {
        throw std::runtime_error("ValtypeStack::PopBackValue(): stack empty");
    }
    TrackRemovedElement(m_stack.back());
    valtype result{std::move(m_stack.back())};
    m_stack.pop_back();
    return result;
}

bool ValtypeStack::PopVal64(Val64& value)
{
    if (m_stack.empty()) return false;

    TrackRemovedElement(m_stack.back());
    value.MoveFromValtype(std::move(m_stack.back()));
    m_stack.pop_back();
    return true;
}

void ValtypeStack::erase(size_t n)
{
    assert(n < m_stack.size());
    TrackRemovedElement(m_stack[n]);
    m_stack.erase(m_stack.begin() + n);
}

void ValtypeStack::reserve(size_t n)
{
    m_stack.reserve(n);
}

void ValtypeStack::Rotate(int first, int middle)
{
    assert(first <= middle);
    assert(middle <= 0);
    assert(static_cast<size_t>(-static_cast<ptrdiff_t>(first)) <= m_stack.size());
    std::rotate(m_stack.end() + first, m_stack.end() + middle, m_stack.end());
}

void ValtypeStack::Roll(size_t depth)
{
    assert(depth < m_stack.size());
    const size_t index{m_stack.size() - depth - 1};
    valtype element{std::move(m_stack[index])};
    m_stack.erase(m_stack.begin() + index);
    m_stack.push_back(std::move(element));
}

void ValtypeStack::Swap(int first, int second)
{
    const auto index_from_top{[this](int offset) {
        return static_cast<size_t>(static_cast<ptrdiff_t>(m_stack.size()) + offset);
    }};
    std::swap(m_stack.at(index_from_top(first)), m_stack.at(index_from_top(second)));
}

void ValtypeStack::TrackAddedElement(const valtype& element)
{
    m_total_size += element.size();
    m_max_element_size = std::max(m_max_element_size, element.size());
}

void ValtypeStack::TrackRemovedElement(const valtype& element)
{
    assert(m_total_size >= element.size());
    m_total_size -= element.size();
}

void ValtypeStack::RecalculateSizeTracking()
{
    m_total_size = 0;
    m_max_element_size = 0;
    for (const valtype& element : m_stack) {
        TrackAddedElement(element);
    }
}
