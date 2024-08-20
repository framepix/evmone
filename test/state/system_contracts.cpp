// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "system_contracts.hpp"
#include "host.hpp"
#include "rlp.hpp"
#include "state.hpp"

#include <iostream>

namespace evmone::state
{
namespace
{
/// Information about a registered system contract.
struct SystemContract
{
    using GetInputFn = bytes_view(const BlockInfo&) noexcept;

    evmc_revision since = EVMC_MAX_REVISION;  ///< EVM revision in which added.
    address addr;                             ///< Address of the system contract.
    GetInputFn* get_input = nullptr;          ///< How to get the input for the system call.
};

/// Registered system contracts.
constexpr std::array SYSTEM_CONTRACTS{
    SystemContract{EVMC_CANCUN, BEACON_ROOTS_ADDRESS,
        [](const BlockInfo& block) noexcept { return bytes_view{block.parent_beacon_block_root}; }},
    SystemContract{EVMC_PRAGUE, HISTORY_STORAGE_ADDRESS,
        [](const BlockInfo& block) noexcept {
            return bytes_view{block.known_block_hashes.at(block.number - 1)};
        }},
};

static_assert(std::ranges::is_sorted(SYSTEM_CONTRACTS,
                  [](const auto& a, const auto& b) noexcept { return a.since < b.since; }),
    "system contract entries must be ordered by revision");

}  // namespace

void system_call(State& state, const BlockInfo& block, evmc_revision rev, evmc::VM& vm)
{
    for (const auto& [since, addr, get_input] : SYSTEM_CONTRACTS)
    {
        if (rev < since)
            return;  // Because entries are ordered, there are no other contracts for this revision.

        const auto acc = state.find(addr);
        if (acc == nullptr)
            continue;  // Nothing to do if the contract doesn't exist.

        const auto input = get_input(block);

        const evmc_message msg{
            .kind = EVMC_CALL,
            .gas = 30'000'000,
            .recipient = addr,
            .sender = SYSTEM_ADDRESS,
            .input_data = input.data(),
            .input_size = input.size(),
        };

        const Transaction empty_tx{};
        Host host{rev, vm, state, block, empty_tx};
        const auto& code = acc->code;
        [[maybe_unused]] const auto res = vm.execute(host, rev, msg, code.data(), code.size());
        assert(res.status_code == EVMC_SUCCESS);
        assert(acc->access_status == EVMC_ACCESS_COLD);

        // Reset storage status.
        for (auto& [_, val] : acc->storage)
        {
            val.access_status = EVMC_ACCESS_COLD;
            val.original = val.current;
        }
    }
}

std::vector<Request> collect_requests(State& state, evmc_revision rev, evmc::VM& vm)
{
    if (rev < EVMC_PRAGUE)
        return {};

    static constexpr auto WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS =
        0x00A3ca265EBcb825B45F985A16CEFB49958cE017_address;

    const auto acc = state.find(WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS);
    if (acc == nullptr)
        return {};

    const evmc_message msg{
        .kind = EVMC_CALL,
        .gas = 30'000'000,
        .recipient = WITHDRAWAL_REQUEST_PREDEPLOY_ADDRESS,
        .sender = SYSTEM_ADDRESS,
    };

    const Transaction empty_tx{};
    const BlockInfo block{};
    Host host{rev, vm, state, block, empty_tx};
    const auto& code = acc->code;
    const auto res = vm.execute(host, rev, msg, code.data(), code.size());
    if (res.status_code != EVMC_SUCCESS)
        return {};

    auto output = bytes_view{res.output_data, res.output_size};
    static constexpr size_t SIZE = 20 + 48 + 8;
    std::vector<Request> requests;
    while (output.size() >= SIZE)
    {
        const auto source_address = output.substr(0, 20);
        const auto withdrawal_pubkey = output.substr(20, 48);
        const auto amount = rlp::trim(output.substr(20 + 48, 8));

        std::cerr << hex(source_address) << " " << hex(withdrawal_pubkey) << " " << hex(amount)
                  << '\n';

        Request req{Request::Kind::withdrawal,
            rlp::encode_tuple(source_address, withdrawal_pubkey, amount)};
        requests.push_back(std::move(req));

        output = output.substr(SIZE);
    }
    return requests;
}
}  // namespace evmone::state
