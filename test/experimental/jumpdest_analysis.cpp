// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2020 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "jumpdest_analysis.hpp"
#include <evmc/instructions.h>
#include <evmone/baseline.hpp>

namespace evmone::experimental
{
inline constexpr bool is_push(uint8_t op) noexcept
{
    return (op >> 5) == 0b11;
}

inline constexpr size_t get_push_data_size(uint8_t op) noexcept
{
    return op - size_t{OP_PUSH1 - 1};
}

std::vector<bool> build_jumpdest_map_vec1(const uint8_t* code, size_t code_size)
{
    std::vector<bool> m(code_size);
    for (size_t i = 0; i < code_size; ++i)
    {
        const auto op = code[i];
        if (op == OP_JUMPDEST)
            m[i] = true;
        else if (is_push(op))
            i += get_push_data_size(op);
    }
    return m;
}

JumpdestMap build_jumpdest_map_bitset1(const uint8_t* code, size_t code_size)
{
    JumpdestMap m(code_size);
    for (size_t i = 0; i < code_size; ++i)
    {
        const auto op = code[i];
        if (op == OP_JUMPDEST)
            m.set(i);
        else if (is_push(op))
            i += get_push_data_size(op);
    }
    return m;
}

std::unique_ptr<uint8_t[]> build_internal_code_v1(const uint8_t* code, size_t code_size)
{
    static constexpr size_t padding = 33;
    std::unique_ptr<uint8_t[]> m{new uint8_t[code_size + padding]};
    for (size_t i = 0; i < code_size; ++i)
    {
        const auto op = code[i];
        m[i] = op;
        if (is_push(op))
        {
            const auto s = get_push_data_size(op);
            std::memset(&m[i + 1], 0, s);
            i += s;
        }
    }
    std::memset(&m[code_size], 0, padding);
    return m;
}
}  // namespace evmone::experimental