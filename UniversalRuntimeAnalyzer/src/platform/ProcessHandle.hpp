// platform/ProcessHandle.hpp
// RAII wrapper around an OpenProcess HANDLE.
//
// Read-only by design: the only way to construct one is through
// open_for_read(), which uses PROCESS_QUERY_INFORMATION | PROCESS_VM_READ.
// There is intentionally no factory that requests write access.
#pragma once

#include "../core/Result.hpp"
#include "../core/Types.hpp"

#include <windows.h>

namespace ura::platform {

    class ProcessHandle {
    public:
        ProcessHandle() = default;
        ProcessHandle(const ProcessHandle&) = delete;
        ProcessHandle& operator=(const ProcessHandle&) = delete;

        ProcessHandle(ProcessHandle&& other) noexcept;
        ProcessHandle& operator=(ProcessHandle&& other) noexcept;

        ~ProcessHandle();

        // Open with PROCESS_QUERY_INFORMATION | PROCESS_VM_READ.
        static core::Result<ProcessHandle> open_for_read(core::Pid pid);

        bool         valid() const noexcept { return handle_ != nullptr; }
        HANDLE       raw() const noexcept   { return handle_; }
        core::Pid    pid() const noexcept   { return pid_; }

        // Whether the target is a 32-bit process running under WOW64.
        // Kept for backwards compatibility; new code should prefer
        // architecture() which can distinguish ARM64 from x64.
        bool is_wow64() const noexcept { return wow64_; }

        // Detected target architecture. Populated at open time via
        // IsWow64Process2 when available, IsWow64Process otherwise.
        core::Architecture architecture() const noexcept { return arch_; }

        // Native bitness of the target (32 or 64). Thin wrapper over
        // architecture() for callers that just want the integer.
        int  bitness() const noexcept;

        // Whether OpenProcess accepted the FULL access mask
        // (PROCESS_QUERY_INFORMATION). False means it only accepted the
        // limited mask (PROCESS_QUERY_LIMITED_INFORMATION). Used by the
        // diagnostic to distinguish "fully privileged" from "partial".
        bool full_query_access() const noexcept { return full_query_; }

        void close() noexcept;

    private:
        explicit ProcessHandle(HANDLE h, core::Pid pid, bool wow64,
                               core::Architecture arch, bool full_query)
            : handle_(h), pid_(pid), wow64_(wow64),
              arch_(arch), full_query_(full_query) {}

        HANDLE             handle_     = nullptr;
        core::Pid          pid_        = 0;
        bool               wow64_      = false;
        core::Architecture arch_       = core::Architecture::Unknown;
        bool               full_query_ = false;
    };

} // namespace ura::platform
