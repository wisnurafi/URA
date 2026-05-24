// core/Types.hpp
// Common scalar types and address aliases used across the framework.
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace ura::core {

    // A linear byte buffer.
    using ByteBuffer = std::vector<std::uint8_t>;

    // An absolute address inside a target process. We always carry it as
    // 64-bit; on 32-bit targets the upper bits are simply zero.
    using Address = std::uint64_t;

    // An offset relative to a module's image base (== an RVA when used
    // against a PE).
    using Rva = std::uint32_t;

    // Module/process identifiers from the OS.
    using Pid       = std::uint32_t;
    using ModuleSize = std::uint64_t;

    // Sentinel for "no address".
    inline constexpr Address kNullAddress = 0;

} // namespace ura::core
