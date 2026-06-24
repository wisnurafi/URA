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

    // Process / image architecture. Used in acquisition diagnostics so we
    // can describe analyzer-vs-target mismatches in concrete terms instead
    // of inferring 32-vs-64 from a single WOW64 flag.
    enum class Architecture : int {
        Unknown = 0,
        X86,        // IMAGE_FILE_MACHINE_I386
        X64,        // IMAGE_FILE_MACHINE_AMD64
        ARM64,      // IMAGE_FILE_MACHINE_ARM64
        ARM32,      // IMAGE_FILE_MACHINE_ARMNT (rare)
    };

    inline const char* to_string(Architecture a) noexcept {
        switch (a) {
            case Architecture::X86:   return "x86";
            case Architecture::X64:   return "x64";
            case Architecture::ARM64: return "ARM64";
            case Architecture::ARM32: return "ARM32";
            default:                  return "unknown";
        }
    }

    // Bitness as a small integer (32 / 64 / 0 for unknown). Useful for the
    // existing JSON `bitness` field which downstream tools already parse.
    inline int bitness_of(Architecture a) noexcept {
        switch (a) {
            case Architecture::X86:
            case Architecture::ARM32: return 32;
            case Architecture::X64:
            case Architecture::ARM64: return 64;
            default:                  return 0;
        }
    }

} // namespace ura::core
