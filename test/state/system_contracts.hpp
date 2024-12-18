// evmone: Fast Ethereum Virtual Machine implementation
// Copyright 2023 The evmone Authors.
// SPDX-License-Identifier: Apache-2.0
#pragma once

#include <evmc/evmc.hpp>

namespace evmone::state
{
using namespace evmc::literals;

/// The address of the sender of the system calls (EIP-4788).
constexpr auto SYSTEM_ADDRESS = 0xfffffffffffffffffffffffffffffffffffffffe_address;

/// The address of the system contract storing the root hashes of beacon chain blocks (EIP-4788).
constexpr auto BEACON_ROOTS_ADDRESS = 0x000F3df6D732807Ef1319fB7B8bB8522d0Beac02_address;

/// The address of the system contract storing historical block hashes (EIP-2935).
constexpr auto HISTORY_STORAGE_ADDRESS = 0x0aae40965e6800cd9b1f4b05ff21581047e3f91e_address;

struct BlockInfo;
struct StateDiff;
class BlockHashes;
class StateView;

/// Performs the system call: invokes system contracts at the start of the block.
///
/// Executes code of pre-defined accounts via pseudo-transaction from the system sender (0xff...fe).
/// The sender's nonce is not increased.
[[nodiscard]] StateDiff system_call_block_start(const StateView& state_view, const BlockInfo& block,
    const BlockHashes& block_hashes, evmc_revision rev, evmc::VM& vm);
}  // namespace evmone::state
