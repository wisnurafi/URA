// platform/ProcessHandle.cpp
#include "ProcessHandle.hpp"

#include "../core/Logger.hpp"

#include <string>

namespace ura::platform {

    using core::Error;
    using core::Result;

    namespace {
        const char* friendly_open_err(DWORD e) {
            switch (e) {
                case 5:   return "ERROR_ACCESS_DENIED — likely target is "
                                 "protected (Steam DRM, EAC, BattlEye, "
                                 "system process). Try running URA as admin, "
                                 "or pick a non-protected target.";
                case 87:  return "ERROR_INVALID_PARAMETER — pid stale or invalid";
                case 5042:return "ERROR_PROCESS_NOT_IN_JOB";
                default:  return "see https://learn.microsoft.com/windows/win32/debug/system-error-codes";
            }
        }
    } // namespace

    ProcessHandle::ProcessHandle(ProcessHandle&& o) noexcept
        : handle_(o.handle_), pid_(o.pid_), wow64_(o.wow64_) {
        o.handle_ = nullptr;
        o.pid_    = 0;
        o.wow64_  = false;
    }

    ProcessHandle& ProcessHandle::operator=(ProcessHandle&& o) noexcept {
        if (this != &o) {
            close();
            handle_  = o.handle_;
            pid_     = o.pid_;
            wow64_   = o.wow64_;
            o.handle_ = nullptr;
            o.pid_    = 0;
            o.wow64_  = false;
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
        HANDLE h = ::OpenProcess(kFull, FALSE, pid);
        if (!h) {
            const DWORD err1 = ::GetLastError();
            // Fall back to LIMITED rights — some protected processes allow
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
            URA_LOG_DEBUG("Opened pid=%lu with QUERY_LIMITED_INFORMATION "
                          "(full QUERY denied with err=%lu)",
                          static_cast<unsigned long>(pid),
                          static_cast<unsigned long>(err1));
        }

        BOOL wow64 = FALSE;
        ::IsWow64Process(h, &wow64);

        URA_LOG_DEBUG("Opened pid=%lu read-only (wow64=%d)",
                      static_cast<unsigned long>(pid), wow64 ? 1 : 0);
        return ProcessHandle(h, pid, wow64 == TRUE);
    }

    int ProcessHandle::bitness() const noexcept {
    #if defined(_WIN64)
        // We are a 64-bit analyzer. WOW64 means the target is 32-bit;
        // otherwise it matches our bitness (64-bit).
        return wow64_ ? 32 : 64;
    #else
        // We are a 32-bit analyzer. We can only fully introspect 32-bit
        // targets; reads against 64-bit targets across the WOW64 boundary
        // are unreliable.
        return 32;
    #endif
    }

} // namespace ura::platform
