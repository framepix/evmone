// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0

#include "system_contracts.hpp"
#include "host.hpp"
#include "state.hpp"

namespace evmone::state
{
namespace
{
/// The address of the sender of the system calls (EIP-4788).
constexpr auto SYSTEM_ADDRESS = 0xfffffffffffffffffffffffffffffffffffffffe_address;

/// The address of the system contract storing the root hashes of beacon chain blocks (EIP-4788).
constexpr auto BEACON_ROOTS_ADDRESS = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02_address;

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
}  // namespace evmone::state
