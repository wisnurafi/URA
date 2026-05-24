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
        bool is_wow64() const noexcept { return wow64_; }

        // Native bitness of the target (32 or 64).
        int  bitness() const noexcept;

        void close() noexcept;

    private:
        explicit ProcessHandle(HANDLE h, core::Pid pid, bool wow64)
            : handle_(h), pid_(pid), wow64_(wow64) {}

        HANDLE     handle_ = nullptr;
        core::Pid  pid_    = 0;
        bool       wow64_  = false;
    };

} // namespace ura::platform
