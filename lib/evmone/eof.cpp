// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2021 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "eof.hpp"
#include "baseline_instruction_table.hpp"
#include "instructions_traits.hpp"

#include <algorithm>
#include <array>
#include <cassert>
#include <limits>
#include <numeric>
#include <stack>
#include <variant>
#include <vector>

namespace evmone
{
namespace
{
constexpr uint8_t MAGIC[] = {0xef, 0x00};
constexpr uint8_t TERMINATOR = 0x00;
constexpr uint8_t TYPE_SECTION = 0x01;
constexpr uint8_t CODE_SECTION = 0x02;
constexpr uint8_t DATA_SECTION = 0x03;
constexpr uint8_t MAX_SECTION = DATA_SECTION;
constexpr auto CODE_SECTION_NUMBER_LIMIT = 1024;
constexpr auto MAX_STACK_HEIGHT = 0x0400;
constexpr auto OUTPUTS_INPUTS_NUMBER_LIMIT = 0x7F;

using EOFSectionHeaders = std::array<std::vector<uint16_t>, MAX_SECTION + 1>;

size_t eof_header_size(const EOFSectionHeaders& headers) noexcept
{
    const auto non_code_section_count = headers[TYPE_SECTION].size() + headers[DATA_SECTION].size();
    const auto code_section_count = headers[CODE_SECTION].size();

    constexpr auto non_code_section_header_size = 3;  // (SECTION_ID + SIZE) per each section
    constexpr auto code_section_size_size = 2;

    return sizeof(MAGIC) + 1 +  // 1 version byte
           non_code_section_count * non_code_section_header_size + sizeof(CODE_SECTION) + 2 +
           code_section_count * code_section_size_size + sizeof(TERMINATOR);
}

EOFValidationError get_section_missing_error(uint8_t section_id) noexcept
{
    return static_cast<EOFValidationError>(
        static_cast<uint8_t>(EOFValidationError::header_terminator_missing) + section_id);
}

std::variant<EOFSectionHeaders, EOFValidationError> validate_eof_headers(bytes_view container)
{
    enum class State
    {
        section_id,
        section_size,
        terminated
    };

    auto state = State::section_id;
    uint8_t section_id = 0;
    uint16_t section_num = 0;
    EOFSectionHeaders section_headers{};
    const auto container_end = container.end();
    auto it = container.begin() + std::size(MAGIC) + 1;  // MAGIC + VERSION
    // TODO: Since all sections are mandatory and they have to be ordered (Types, Code+, Data)
    // TODO: this fragment of code can be much simpler. Rewriting needed.
    uint8_t expected_section_id = TYPE_SECTION;
    while (it != container_end && state != State::terminated)
    {
        switch (state)
        {
        case State::section_id:
        {
            section_id = *it++;

            if (section_id != expected_section_id)
                return get_section_missing_error(expected_section_id);

            switch (section_id)
            {
            case TERMINATOR:
                state = State::terminated;
                break;
            case TYPE_SECTION:
                expected_section_id = CODE_SECTION;
                state = State::section_size;
                break;
            case CODE_SECTION:
            {
                if (it >= container_end - 2)
                    return EOFValidationError::incomplete_section_number;
                section_num = read_uint16_be(it);
                it += 2;
                if (section_num == 0)
                    return EOFValidationError::zero_section_size;
                expected_section_id = DATA_SECTION;
                state = State::section_size;
                break;
            }
            case DATA_SECTION:
                expected_section_id = TERMINATOR;
                state = State::section_size;
                break;
            default:
                assert(false);
            }
            break;
        }
        case State::section_size:
        {
            if (section_id == CODE_SECTION)
            {
                assert(section_num > 0);  // Guaranteed by previous validation step.
                for (size_t i = 0; i < section_num; ++i)
                {
                    if (it >= container_end - 2)
                        return EOFValidationError::incomplete_section_size;
                    const auto section_size = read_uint16_be(it);
                    it += 2;
                    if (section_size == 0)
                        return EOFValidationError::zero_section_size;

                    if (section_headers[CODE_SECTION].size() == CODE_SECTION_NUMBER_LIMIT)
                        return EOFValidationError::too_many_code_sections;
                    section_headers[section_id].emplace_back(section_size);
                }
            }
            else  // TYPES_SECTION or DATA_SECTION
            {
                if (it + 1 == container_end)
                    return EOFValidationError::incomplete_section_size;
                const auto section_size = read_uint16_be(it);
                it += 2;
                if (section_size == 0 && section_id != DATA_SECTION)
                    return EOFValidationError::zero_section_size;

                section_headers[section_id].emplace_back(section_size);
            }

            state = State::section_id;
            break;
        }
        case State::terminated:
            return EOFValidationError::impossible;
        }
    }

    if (state != State::terminated)
        return EOFValidationError::section_headers_not_terminated;

    const auto section_bodies_size =
        (!section_headers[TYPE_SECTION].empty() ? section_headers[TYPE_SECTION].front() : 0) +
        std::accumulate(
            section_headers[CODE_SECTION].begin(), section_headers[CODE_SECTION].end(), 0) +
        (!section_headers[DATA_SECTION].empty() ? section_headers[DATA_SECTION].front() : 0);
    const auto remaining_container_size = container_end - it;
    if (section_bodies_size != remaining_container_size)
        return EOFValidationError::invalid_section_bodies_size;

    if (!section_headers[TYPE_SECTION].empty() &&
        section_headers[TYPE_SECTION][0] != section_headers[CODE_SECTION].size() * 4)
        return EOFValidationError::invalid_type_section_size;

    return section_headers;
}

std::variant<std::vector<EOFCodeType>, EOFValidationError> validate_types(
    bytes_view container, size_t header_size, std::vector<uint16_t> type_section_sizes) noexcept
{
    assert(!container.empty());              // guaranteed by EOF headers validation
    assert(type_section_sizes.size() <= 1);  // guaranteed by EOF headers validation

    if (type_section_sizes.empty())
        return std::vector{EOFCodeType{0, 0, 0}};

    std::vector<EOFCodeType> types;

    // guaranteed by EOF headers validation
    assert(header_size + type_section_sizes[0] < container.size());

    for (auto offset = header_size; offset < header_size + type_section_sizes[0]; offset += 4)
    {
        types.emplace_back(
            container[offset], container[offset + 1], read_uint16_be(&container[offset + 2]));
    }

    // check 1st section is (0, 0)
    if (types[0].inputs != 0 || types[0].outputs != 0)
        return EOFValidationError::invalid_first_section_type;

    for (const auto& t : types)
    {
        if (t.outputs > OUTPUTS_INPUTS_NUMBER_LIMIT || t.inputs > OUTPUTS_INPUTS_NUMBER_LIMIT)
            return EOFValidationError::inputs_outputs_num_above_limit;

        if (t.max_stack_height > MAX_STACK_HEIGHT)
            return EOFValidationError::max_stack_height_above_limit;
    }

    return types;
}

EOFValidationError validate_instructions(evmc_revision rev, bytes_view code) noexcept
{
    assert(!code.empty());  // guaranteed by EOF headers validation

    const auto& cost_table = baseline::get_baseline_cost_table(rev, 1);

    for (size_t i = 0; i < code.size(); ++i)
    {
        const auto op = code[i];
        if (cost_table[op] == instr::undefined)
            return EOFValidationError::undefined_instruction;

        if (op == OP_RJUMPV)
        {
            if (i + 1 >= code.size())
                return EOFValidationError::truncated_instruction;

            const auto count = code[i + 1];
            if (count < 1)
                return EOFValidationError::invalid_rjumpv_count;
            i += static_cast<size_t>(1 /* count */ + count * 2 /* tbl */);
        }
        else
            i += instr::traits[op].immediate_size;

        if (i >= code.size())
            return EOFValidationError::truncated_instruction;
    }

    return EOFValidationError::success;
}

/// Validates that that we don't rjump inside an instruction's immediate.
/// Requires that the input is validated against truncation.
bool validate_rjump_destinations(bytes_view code) noexcept
{
    // Collect relative jump destinations and immediate locations
    const auto code_size = code.size();
    // list of all possible absolute rjumps destinations positions
    std::vector<size_t> rjumpdests;
    // bool map of immediate arguments positions in the code
    std::vector<bool> immediate_map(code_size);

    const auto check_rjump_destination = [code_size](auto rel_offset_data_it,
                                             size_t post_pos) -> std::optional<size_t> {
        const auto rel_offset = read_int16_be(rel_offset_data_it);
        const auto jumpdest = static_cast<int32_t>(post_pos) + rel_offset;
        if (jumpdest < 0 || static_cast<size_t>(jumpdest) >= code_size)
            return {};
        else
            return static_cast<size_t>(jumpdest);
    };

    for (size_t i = 0; i < code_size; ++i)
    {
        const auto op = code[i];
        size_t imm_size = instr::traits[op].immediate_size;

        if (op == OP_RJUMP || op == OP_RJUMPI)
        {
            if (auto jumpdest_opt = check_rjump_destination(&code[i + 1], i + 3); jumpdest_opt)
                rjumpdests.push_back(jumpdest_opt.value());
            else
                return false;
        }
        else if (op == OP_RJUMPV)
        {
            constexpr auto REL_OFFSET_SIZE = sizeof(int16_t);

            const auto count = code[i + 1];

            imm_size += size_t{1} /* count */ + count * REL_OFFSET_SIZE /* tbl */;

            const size_t post_pos = i + 1 + imm_size;

            for (size_t k = 0; k < count * REL_OFFSET_SIZE; k += REL_OFFSET_SIZE)
            {
                auto jumpdest_opt =
                    check_rjump_destination(&code[i + 1 + 1 + static_cast<uint16_t>(k)], post_pos);

                if (jumpdest_opt)
                    rjumpdests.push_back(jumpdest_opt.value());
                else
                    return false;
            }
        }

        std::fill_n(immediate_map.begin() + static_cast<ptrdiff_t>(i) + 1, imm_size, true);
        i += imm_size;
    }

    // Check relative jump destinations against immediate locations.
    for (const auto rjumpdest : rjumpdests)
        if (immediate_map[rjumpdest])
            return false;

    return true;
}

std::pair<EOFValidationError, int32_t> validate_max_stack_height(
    bytes_view code, size_t func_index, const std::vector<EOFCodeType>& code_types)
{
    assert(!code.empty());

    constexpr int32_t LOC_UNVISITED = -1;
    constexpr int32_t LOC_IMMEDIATE = -2;

    // Stack height in the header is limited to uint16_t, but keeping larger size for ease of
    // calculation.
    std::vector<int32_t> stack_heights = std::vector<int32_t>(code.size(), LOC_UNVISITED);
    stack_heights[0] = code_types[func_index].inputs;

    std::stack<size_t> worklist;
    worklist.push(0);

    while (!worklist.empty())
    {
        const auto i = worklist.top();
        worklist.pop();

        const auto opcode = static_cast<Opcode>(code[i]);

        auto stack_height_required = instr::traits[opcode].stack_height_required;
        auto stack_height_change = instr::traits[opcode].stack_height_change;

        if (opcode == OP_CALLF)
        {
            const auto fid = read_uint16_be(&code[i + 1]);

            if (fid >= code_types.size())
                return {EOFValidationError::invalid_code_section_index, 0};

            stack_height_required = static_cast<int8_t>(code_types[fid].inputs);
            stack_height_change =
                static_cast<int8_t>(code_types[fid].outputs - stack_height_required);
        }

        auto stack_height = stack_heights[i];
        assert(stack_height != LOC_UNVISITED);

        if (stack_height < stack_height_required)
            return {EOFValidationError::stack_underflow, -1};

        std::vector<size_t> successors;

        auto imm_size = instr::traits[opcode].immediate_size;

        if (opcode == OP_RJUMP || opcode == OP_RJUMPI)
        {
            const auto target_rel_offset = read_int16_be(&code[i + 1]);

            const auto next = i + imm_size + 1;
            if (next >= code.size())
                return {EOFValidationError::no_terminating_instruction, -1};

            // Conditional jump has the fallthrough as successor too.
            if (opcode == OP_RJUMPI)
                successors.push_back(next);

            // Insert jump target.
            successors.push_back(
                static_cast<size_t>(target_rel_offset + 3 + static_cast<int32_t>(i)));
        }
        else if (opcode == OP_RJUMPV)
        {
            const auto count = code[i + 1];
            imm_size = 1 + count * 2;

            const auto next = i + imm_size + 1;
            if (next >= code.size())
                return {EOFValidationError::no_terminating_instruction, -1};

            // Insert fall through.
            successors.push_back(next);

            // Insert all jump targets.
            for (uint16_t k = 0; k < count; ++k)
            {
                const auto target_rel_offset = read_int16_be(&code[i + k * 2 + 2]);
                successors.push_back(static_cast<size_t>(
                    static_cast<int32_t>(i) + 2 * count + target_rel_offset + 2));
            }
        }
        else if (!instr::traits[opcode].is_terminating)
        {
            const auto next = i + imm_size + 1;
            if (next >= code.size())
                return {EOFValidationError::no_terminating_instruction, -1};

            successors.push_back(next);
        }

        // Mark immediate locations.
        const auto beg = stack_heights.begin() + static_cast<int32_t>(i) + 1;
        std::fill_n(beg, imm_size, LOC_IMMEDIATE);

        stack_height += stack_height_change;

        for (const auto& s : successors)
        {
            if (stack_heights[s] == LOC_UNVISITED)
            {
                stack_heights[s] = stack_height;
                worklist.push(s);
            }
            else if (stack_heights[s] != stack_height)
                return {EOFValidationError::stack_height_mismatch, -1};
        }

        if (opcode == OP_RETF && stack_height != code_types[func_index].outputs)
            return {EOFValidationError::non_empty_stack_on_terminating_instruction, -1};
    }

    const auto msh_it = std::max_element(stack_heights.begin(), stack_heights.end());

    if (std::find(stack_heights.begin(), stack_heights.end(), LOC_UNVISITED) != stack_heights.end())
        return {EOFValidationError::unreachable_instructions, -1};

    return {EOFValidationError::success, *msh_it};
}

std::variant<EOF1Header, EOFValidationError> validate_eof1(
    evmc_revision rev, bytes_view container) noexcept
{
    const auto section_headers_or_error = validate_eof_headers(container);
    if (const auto* error = std::get_if<EOFValidationError>(&section_headers_or_error))
        return *error;

    const auto& section_headers = std::get<EOFSectionHeaders>(section_headers_or_error);
    const auto& code_sizes = section_headers[CODE_SECTION];
    const auto data_size =
        section_headers[DATA_SECTION].empty() ? uint16_t{0} : section_headers[DATA_SECTION][0];

    const auto header_size = eof_header_size(section_headers);

    const auto types_or_error =
        validate_types(container, header_size, section_headers[TYPE_SECTION]);
    if (const auto* error = std::get_if<EOFValidationError>(&types_or_error))
        return *error;
    const auto& types = std::get<std::vector<EOFCodeType>>(types_or_error);

    std::vector<uint16_t> code_offsets;
    const auto type_section_size =
        section_headers[TYPE_SECTION].empty() ? 0u : section_headers[TYPE_SECTION][0];
    auto offset = header_size + type_section_size;
    for (const auto code_size : code_sizes)
    {
        assert(offset <= std::numeric_limits<uint16_t>::max());
        code_offsets.emplace_back(static_cast<uint16_t>(offset));
        offset += code_size;
    }

    EOF1Header header{code_sizes, code_offsets, data_size, types};

    for (size_t code_idx = 0; code_idx < header.code_sizes.size(); ++code_idx)
    {
        const auto error_instr = validate_instructions(rev, header.get_code(container, code_idx));
        if (error_instr != EOFValidationError::success)
            return error_instr;

        if (!validate_rjump_destinations(header.get_code(container, code_idx)))
            return EOFValidationError::invalid_rjump_destination;

        auto msh_validation_result =
            validate_max_stack_height(header.get_code(container, code_idx), code_idx, header.types);
        if (msh_validation_result.first != EOFValidationError::success)
            return msh_validation_result.first;
        if (msh_validation_result.second != header.types[code_idx].max_stack_height)
            return EOFValidationError::invalid_max_stack_height;
    }

    return header;
}

}  // namespace

bool is_eof_container(bytes_view container) noexcept
{
    return container.size() > 1 && container[0] == MAGIC[0] && container[1] == MAGIC[1];
}

/// This function expects the prefix and version to be valid, as it ignores it.
EOF1Header read_valid_eof1_header(bytes_view container)
{
    EOFSectionHeaders section_headers;
    auto it = container.begin() + std::size(MAGIC) + 1;  // MAGIC + VERSION
    while (*it != TERMINATOR)
    {
        const auto section_id = *it++;
        if (section_id == CODE_SECTION)
        {
            const auto code_section_num = read_uint16_be(it);
            it += 2;
            for (uint16_t i = 0; i < code_section_num; ++i)
            {
                const auto section_size = read_uint16_be(it);
                it += 2;
                section_headers[section_id].emplace_back(section_size);
            }
        }
        else
        {
            const auto section_size = read_uint16_be(it);
            it += 2;
            section_headers[section_id].emplace_back(section_size);
        }
    }
    const auto header_size = eof_header_size(section_headers);

    EOF1Header header;

    if (section_headers[TYPE_SECTION].empty())
        header.types.emplace_back(0, 0, 0);
    else
    {
        for (auto type_offset = header_size;
             type_offset < header_size + section_headers[TYPE_SECTION][0]; type_offset += 4)

            header.types.emplace_back(container[type_offset], container[type_offset + 1],
                read_uint16_be(&container[type_offset + 2]));
    }

    header.code_sizes = section_headers[CODE_SECTION];
    std::vector<uint16_t> code_offsets;
    auto code_offset =
        header_size +
        (section_headers[TYPE_SECTION].empty() ? uint16_t{0} : section_headers[TYPE_SECTION][0]);
    for (const auto code_size : header.code_sizes)
    {
        assert(code_offset <= std::numeric_limits<uint16_t>::max());
        header.code_offsets.emplace_back(static_cast<uint16_t>(code_offset));
        code_offset += code_size;
    }

    header.data_size =
        section_headers[DATA_SECTION].empty() ? uint16_t{0} : section_headers[DATA_SECTION][0];

    return header;
}

uint8_t get_eof_version(bytes_view container) noexcept
{
    return (container.size() >= 3 && container[0] == MAGIC[0] && container[1] == MAGIC[1]) ?
               container[2] :
               0;
}

EOFValidationError validate_eof(evmc_revision rev, bytes_view container) noexcept
{
    if (!is_eof_container(container))
        return EOFValidationError::invalid_prefix;

    const auto version = get_eof_version(container);

    if (version == 1)
    {
        if (rev < EVMC_CANCUN)
            return EOFValidationError::eof_version_unknown;

        const auto header_or_error = validate_eof1(rev, container);
        if (const auto* error = std::get_if<EOFValidationError>(&header_or_error))
            return *error;
        else
            return EOFValidationError::success;
    }
    else
        return EOFValidationError::eof_version_unknown;
}

std::string_view get_error_message(EOFValidationError err) noexcept
{
    switch (err)
    {
    case EOFValidationError::success:
        return "success";
    case EOFValidationError::starts_with_format:
        return "starts_with_format";
    case EOFValidationError::invalid_prefix:
        return "invalid_prefix";
    case EOFValidationError::eof_version_mismatch:
        return "eof_version_mismatch";
    case EOFValidationError::eof_version_unknown:
        return "eof_version_unknown";
    case EOFValidationError::incomplete_section_size:
        return "incomplete_section_size";
    case EOFValidationError::incomplete_section_number:
        return "incomplete_section_number";
    case EOFValidationError::header_terminator_missing:
        return "header_terminator_missing";
    case EOFValidationError::type_section_missing:
        return "type_section_missing";
    case EOFValidationError::code_section_missing:
        return "code_section_missing";
    case EOFValidationError::data_section_missing:
        return "data_section_missing";
    case EOFValidationError::zero_section_size:
        return "zero_section_size";
    case EOFValidationError::section_headers_not_terminated:
        return "section_headers_not_terminated";
    case EOFValidationError::invalid_section_bodies_size:
        return "invalid_section_bodies_size";
    case EOFValidationError::undefined_instruction:
        return "undefined_instruction";
    case EOFValidationError::truncated_instruction:
        return "truncated_instruction";
    case EOFValidationError::invalid_rjumpv_count:
        return "invalid_rjumpv_count";
    case EOFValidationError::invalid_rjump_destination:
        return "invalid_rjump_destination";
    case EOFValidationError::too_many_code_sections:
        return "too_many_code_sections";
    case EOFValidationError::invalid_type_section_size:
        return "invalid_type_section_size";
    case EOFValidationError::invalid_first_section_type:
        return "invalid_first_section_type";
    case EOFValidationError::invalid_max_stack_height:
        return "invalid_max_stack_height";
    case EOFValidationError::max_stack_height_above_limit:
        return "max_stack_height_above_limit";
    case EOFValidationError::inputs_outputs_num_above_limit:
        return "inputs_outputs_num_above_limit";
    case EOFValidationError::no_terminating_instruction:
        return "no_terminating_instruction";
    case EOFValidationError::stack_height_mismatch:
        return "stack_height_mismatch";
    case EOFValidationError::non_empty_stack_on_terminating_instruction:
        return "non_empty_stack_on_terminating_instruction";
    case EOFValidationError::unreachable_instructions:
        return "unreachable_instructions";
    case EOFValidationError::stack_underflow:
        return "stack_underflow";
    case EOFValidationError::invalid_code_section_index:
        return "invalid_code_section_index";
    case EOFValidationError::impossible:
        return "impossible";
    }
    return "<unknown>";
}
}  // namespace evmone
