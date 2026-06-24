// platform/ProcessHandle.cpp
#include "ProcessHandle.hpp"

#include "Architecture.hpp"
#include "../core/Logger.hpp"

#include <string>

namespace ura::platform {

    using core::Error;
    using core::Result;

    namespace {
        const char* friendly_open_err(DWORD e) {
            switch (e) {
                case 5:   return "ERROR_ACCESS_DENIED — handle lacks rights. "
                                 "Run URA elevated, or pick a target you own.";
                case 6:   return "ERROR_INVALID_HANDLE — pid stale or process exited";
                case 87:  return "ERROR_INVALID_PARAMETER — pid stale or invalid";
                case 5042:return "ERROR_PROCESS_NOT_IN_JOB";
                default:  return "see https://learn.microsoft.com/windows/win32/debug/system-error-codes";
            }
        }
    } // namespace

    ProcessHandle::ProcessHandle(ProcessHandle&& o) noexcept
        : handle_(o.handle_), pid_(o.pid_), wow64_(o.wow64_),
          arch_(o.arch_), full_query_(o.full_query_) {
        o.handle_     = nullptr;
        o.pid_        = 0;
        o.wow64_      = false;
        o.arch_       = core::Architecture::Unknown;
        o.full_query_ = false;
    }

    ProcessHandle& ProcessHandle::operator=(ProcessHandle&& o) noexcept {
        if (this != &o) {
            close();
            handle_      = o.handle_;
            pid_         = o.pid_;
            wow64_       = o.wow64_;
            arch_        = o.arch_;
            full_query_  = o.full_query_;
            o.handle_    = nullptr;
            o.pid_       = 0;
            o.wow64_     = false;
            o.arch_      = core::Architecture::Unknown;
            o.full_query_ = false;
        }
        return *this;
    }

    ProcessHandle::~ProcessHandle() {
        close();
    }

    void ProcessHandle::close() noexcept {
        if (handle_) {
            ::CloseHandle(handle_);
            handle_ = nullptr;
        }
    }

    Result<ProcessHandle> ProcessHandle::open_for_read(core::Pid pid) {
        // Read-only access mask. Never request VM_WRITE / VM_OPERATION.
        constexpr DWORD kFull = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;
        bool full_query = true;
        HANDLE h = ::OpenProcess(kFull, FALSE, pid);
        if (!h) {
            const DWORD err1 = ::GetLastError();
            // Fall back to LIMITED rights — some processes allow
            // QUERY_LIMITED_INFORMATION but not full QUERY_INFORMATION.
            // VM_READ is still required for our analysis to produce useful
            // output, so we don't drop it.
            constexpr DWORD kLimited = PROCESS_QUERY_LIMITED_INFORMATION
                                     | PROCESS_VM_READ;
            h = ::OpenProcess(kLimited, FALSE, pid);
            if (!h) {
                const DWORD err2 = ::GetLastError();
                std::string msg = "OpenProcess(pid=" + std::to_string(pid)
                    + ") denied. err1=" + std::to_string(err1)
                    + " err2=" + std::to_string(err2)
                    + " — " + friendly_open_err(err2 ? err2 : err1);
                return Error::make(std::move(msg),
                                   static_cast<int>(err2 ? err2 : err1));
            }
            full_query = false;
            URA_LOG_DEBUG("[ACCESS] Opened pid=%lu with QUERY_LIMITED_INFORMATION "
                          "(full QUERY denied with err=%lu)",
                          static_cast<unsigned long>(pid),
                          static_cast<unsigned long>(err1));
        }

        BOOL wow64 = FALSE;
        ::IsWow64Process(h, &wow64);

        const auto arch = detect_target_architecture(h);

        URA_LOG_DEBUG("[ACCESS] Opened pid=%lu read-only (wow64=%d arch=%s full_query=%d)",
                      static_cast<unsigned long>(pid),
                      wow64 ? 1 : 0,
                      core::to_string(arch),
                      full_query ? 1 : 0);
        return ProcessHandle(h, pid, wow64 == TRUE, arch, full_query);
    }

    int ProcessHandle::bitness() const noexcept {
        // Prefer the explicit architecture if we managed to detect one;
        // otherwise fall back to the WOW64 flag with the build's bitness
        // as a last resort (analyzer might be x86 with no IsWow64Process2).
        if (arch_ != core::Architecture::Unknown) {
            return core::bitness_of(arch_);
        }
    #if defined(_WIN64)
        return wow64_ ? 32 : 64;
    #else
        return 32;
    #endif
    }

} // namespace ura::platform
