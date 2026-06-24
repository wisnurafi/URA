// platform/Architecture.hpp
// Analyzer / target / native architecture detection.
//
// Why this exists: ERROR_PARTIAL_COPY (299) from EnumProcessModulesEx is
// most often a cross-bitness call (URA x86 reading a x64 target), not an
// anti-cheat. To classify it correctly we need three pieces of evidence:
//
//   * Analyzer architecture       — the bitness this URA build was compiled for
//   * Target process architecture — what the target actually runs as
//   * Native OS architecture       — distinguishes x64-host vs ARM64-host
//                                    cases on Windows on ARM
//
// We use IsWow64Process2 when available (Win10 1511+) and fall back to the
// older IsWow64Process + GetNativeSystemInfo for older Windows.
#pragma once

#include "../core/Types.hpp"

#include <windows.h>

namespace ura::platform {

    // The bitness URA itself was compiled with. Computed at compile time
    // from _M_IX86 / _M_X64 / _M_ARM64. Constexpr so callers can short-
    // circuit at compile time too.
    constexpr core::Architecture analyzer_architecture() noexcept {
    #if defined(_M_X64)
        return core::Architecture::X64;
    #elif defined(_M_IX86)
        return core::Architecture::X86;
    #elif defined(_M_ARM64)
        return core::Architecture::ARM64;
    #elif defined(_M_ARM)
        return core::Architecture::ARM32;
    #else
        return core::Architecture::Unknown;
    #endif
    }

    // Native OS architecture (what the kernel was built for, regardless
    // of the URA build). Cached after first call. Uses IsWow64Process2
    // when available, GetNativeSystemInfo as a fallback.
    core::Architecture detect_native_architecture();

    // Target process architecture. Uses IsWow64Process2 when available;
    // otherwise reasons from IsWow64Process + the native OS.
    core::Architecture detect_target_architecture(HANDLE process);

} // namespace ura::platform
