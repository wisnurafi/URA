// platform/ModuleEnumerator.cpp
#include "ModuleEnumerator.hpp"

#include "Architecture.hpp"
#include "../core/Logger.hpp"

#include <windows.h>
#include <psapi.h>

#include <algorithm>
#include <cwctype>
#include <string>
#include <thread>
#include <chrono>

#pragma comment(lib, "Psapi.lib")

namespace ura::platform {

    using core::Error;
    using core::Result;

    namespace {

        // Maximum bounded retries when the OS reports a transient failure
        // (loader transition, partial copy on a moving module list). Three
        // is enough to ride out a typical DLL load/unload race; more would
        // start to look like polling.
        constexpr int kMaxAttempts = 3;
        constexpr int kRetryDelayMs = 25;

        // Initial slot count for the module buffer. Most processes have
        // 50–300 modules; 256 covers them in one allocation.
        constexpr std::size_t kInitialSlots = 256;

        std::wstring to_lower_w(std::wstring_view s) {
            std::wstring out(s);
            std::transform(out.begin(), out.end(), out.begin(),
                [](wchar_t c){ return static_cast<wchar_t>(std::towlower(c)); });
            return out;
        }

        // Pretty-print the most common Win32 errors we see during module
        // enumeration. Note: zero anti-cheat language. The diagnostic
        // status is set separately based on actual evidence.
        const char* friendly_winerr(DWORD e) {
            switch (e) {
                case 5:   return "ERROR_ACCESS_DENIED";
                case 6:   return "ERROR_INVALID_HANDLE";
                case 8:   return "ERROR_NOT_ENOUGH_MEMORY";
                case 24:  return "ERROR_BAD_LENGTH";
                case 87:  return "ERROR_INVALID_PARAMETER";
                case 299: return "ERROR_PARTIAL_COPY";
                case 998: return "ERROR_NOACCESS";
                default:  return "Win32 error";
            }
        }

        AcquisitionStatus classify_failure(DWORD win32_err,
                                           bool module_count_was_shrinking) noexcept {
            switch (win32_err) {
                case 5:   return AcquisitionStatus::AccessDenied;
                case 6:   return AcquisitionStatus::ProcessTerminated;
                case 299:
                    // Cross-bitness 299 is filtered earlier by the arch guard.
                    // What remains is either a moving module list (loader
                    // transition) or a genuine partial-copy on a privileged
                    // target.
                    return module_count_was_shrinking
                        ? AcquisitionStatus::LoaderTransition
                        : AcquisitionStatus::PartialCopy;
                default:
                    return AcquisitionStatus::ModuleEnumerationFailed;
            }
        }

        std::string recommendation_for(AcquisitionStatus s, DWORD err) {
            switch (s) {
                case AcquisitionStatus::AccessDenied:
                    return "Run URA elevated, or pick a target you own. "
                           "System and service processes typically deny "
                           "VM_READ to non-elevated callers.";
                case AcquisitionStatus::ProcessTerminated:
                    return "The target exited before enumeration completed. "
                           "Reattach to the new PID if it was restarted.";
                case AcquisitionStatus::LoaderTransition:
                    return "The target is loading or unloading DLLs. "
                           "Retry once the process has finished initialising.";
                case AcquisitionStatus::PartialCopy:
                    return "Module list could not be read completely. "
                           "Retry after the process finishes initialising, "
                           "run URA with appropriate privileges, "
                           "or use static file analysis on the executable.";
                default: {
                    std::string s2 = "Win32 error ";
                    s2 += std::to_string(err);
                    s2 += " — see the Windows system error code reference.";
                    return s2;
                }
            }
        }

        // Single attempt at the two-pass EnumProcessModulesEx flow. Returns
        // true on success and fills `out`; on failure sets `last_err` and
        // `failed_stage` for the diagnostic.
        bool try_enumerate(HANDLE proc, std::vector<HMODULE>& out,
                           DWORD& last_err, const char*& failed_stage) {
            // Pass 1: ask for the buffer size we need.
            DWORD needed_dw = 0;
            if (!::EnumProcessModulesEx(proc, nullptr, 0, &needed_dw,
                                        LIST_MODULES_ALL)) {
                last_err = ::GetLastError();
                failed_stage = "size query";
                return false;
            }
            const SIZE_T needed = static_cast<SIZE_T>(needed_dw);

            // Allocate with a small over-provision so we tolerate the module
            // count growing slightly between passes.
            const std::size_t reported_slots = needed / sizeof(HMODULE);
            const std::size_t alloc_slots =
                std::max<std::size_t>(reported_slots + 16, kInitialSlots);
            out.assign(alloc_slots, nullptr);

            // Pass 2: actually fill the buffer.
            DWORD got_dw = 0;
            const DWORD bufsize_dw =
                static_cast<DWORD>(out.size() * sizeof(HMODULE));
            if (!::EnumProcessModulesEx(proc, out.data(), bufsize_dw, &got_dw,
                                        LIST_MODULES_ALL)) {
                last_err = ::GetLastError();
                failed_stage = "fill";
                return false;
            }
            const SIZE_T got = static_cast<SIZE_T>(got_dw);

            // If the OS reported needing more than we allocated, the module
            // list grew between calls. Surface this so the retry loop can
            // grow the buffer; treat it like a soft failure for retry.
            if (got > bufsize_dw) {
                last_err = ERROR_INSUFFICIENT_BUFFER;
                failed_stage = "fill (buffer outgrown)";
                return false;
            }

            out.resize(got / sizeof(HMODULE));
            return true;
        }

        // Translate one HMODULE into a ModuleInfo. Failures (e.g. the module
        // unloaded between enumeration and inspection) are tolerated — we
        // skip the entry rather than failing the whole enumeration.
        bool resolve_module(HANDLE proc, HMODULE h, ModuleInfo& m) {
            wchar_t buf[MAX_PATH * 2] = {};
            if (::GetModuleFileNameExW(proc, h, buf,
                                       static_cast<DWORD>(std::size(buf)))) {
                m.full_path = buf;
                if (auto pos = m.full_path.find_last_of(L"\\/");
                    pos != std::wstring::npos) {
                    m.name = m.full_path.substr(pos + 1);
                } else {
                    m.name = m.full_path;
                }
            }
            MODULEINFO mi{};
            if (::GetModuleInformation(proc, h, &mi, sizeof(mi))) {
                m.base = reinterpret_cast<core::Address>(mi.lpBaseOfDll);
                m.size = mi.SizeOfImage;
            }
            return m.base != 0 && !m.name.empty();
        }

    } // namespace

    ModuleEnumerationResult ModuleEnumerator::list(const ProcessHandle& proc) {
        ModuleEnumerationResult result;
        AcquisitionDiagnostic& d = result.diagnostic;

        d.analyzer_architecture = analyzer_architecture();
        d.native_architecture   = detect_native_architecture();
        d.target_architecture   = proc.architecture();
        d.process_handle_opened = proc.valid();
        d.process_query_succeeded = proc.valid();
        d.failed_api = "EnumProcessModulesEx";

        if (!proc.valid()) {
            d.status = AcquisitionStatus::OpenProcessFailed;
            d.details = "Invalid process handle passed to ModuleEnumerator::list.";
            return result;
        }

        // Pre-flight architecture guard. A 32-bit URA cannot reliably
        // enumerate modules of a 64-bit target across the WOW64 boundary;
        // EnumProcessModulesEx returns 299 in this case. Refuse early.
        if (d.analyzer_architecture == core::Architecture::X86
            && (d.target_architecture == core::Architecture::X64
                || d.target_architecture == core::Architecture::ARM64)) {
            d.status = AcquisitionStatus::ArchitectureMismatch;
            d.failed_stage = "pre-flight architecture check";
            d.details = "The x86 build of URA cannot reliably enumerate "
                        "modules inside a native 64-bit process.";
            d.recommended_action = "Use the x64 build of URA.";
            URA_LOG_WARN("[MODULE] Refused: analyzer=%s target=%s "
                         "— cross-bitness EnumProcessModulesEx is unreliable",
                         core::to_string(d.analyzer_architecture),
                         core::to_string(d.target_architecture));
            return result;
        }

        // Bounded retry loop. Each attempt records its outcome; we keep
        // track of whether the module count is shrinking across attempts,
        // which is the signature of a loader transition.
        std::vector<HMODULE> mods;
        DWORD last_err = 0;
        const char* failed_stage = "";
        std::size_t prev_count = 0;
        bool count_shrinking = false;
        bool ok = false;

        for (int attempt = 1; attempt <= kMaxAttempts; ++attempt) {
            d.enumeration_attempts = attempt;
            mods.clear();
            last_err = 0;
            failed_stage = "";

            if (try_enumerate(proc.raw(), mods, last_err, failed_stage)) {
                URA_LOG_DEBUG("[MODULE] EnumProcessModulesEx attempt %d/%d ok "
                              "(modules=%zu)",
                              attempt, kMaxAttempts, mods.size());
                ok = true;
                break;
            }

            URA_LOG_WARN("[MODULE] EnumProcessModulesEx attempt %d/%d failed: "
                         "%lu (%s) stage=%s",
                         attempt, kMaxAttempts,
                         static_cast<unsigned long>(last_err),
                         friendly_winerr(last_err),
                         failed_stage);

            // Track whether the module count is decreasing across attempts.
            // We can only see the size from a successful first pass, so the
            // signal is approximate — enough to bias 299 toward
            // LoaderTransition rather than PartialCopy.
            const std::size_t this_count = mods.size();
            if (attempt > 1 && this_count < prev_count) count_shrinking = true;
            prev_count = this_count;

            // Don't retry on hard errors — there's no transient state here.
            if (last_err == ERROR_ACCESS_DENIED ||
                last_err == ERROR_INVALID_HANDLE ||
                last_err == ERROR_INVALID_PARAMETER) {
                break;
            }

            if (attempt < kMaxAttempts) {
                std::this_thread::sleep_for(
                    std::chrono::milliseconds(kRetryDelayMs));
            }
        }

        if (!ok) {
            d.status = classify_failure(last_err, count_shrinking);
            d.win32_error = last_err;
            d.failed_stage = failed_stage;
            std::string detail = "EnumProcessModulesEx failed after ";
            detail += std::to_string(d.enumeration_attempts);
            detail += " attempt(s) with Win32 ";
            detail += std::to_string(last_err);
            detail += " (";
            detail += friendly_winerr(last_err);
            detail += ").";
            d.details = std::move(detail);
            d.recommended_action = recommendation_for(d.status, last_err);
            return result;
        }

        // Success path — translate each HMODULE into ModuleInfo. Skipped
        // entries (unloaded mid-walk) are not errors.
        result.modules.reserve(mods.size());
        for (HMODULE h : mods) {
            ModuleInfo m;
            if (resolve_module(proc.raw(), h, m)) {
                result.modules.push_back(std::move(m));
            }
        }

        d.status = AcquisitionStatus::Success;
        d.module_enumeration_succeeded = true;
        result.success = true;

        URA_LOG_DEBUG("[MODULE] Enumerated %zu modules in pid=%lu (%d attempt(s))",
                      result.modules.size(),
                      static_cast<unsigned long>(proc.pid()),
                      d.enumeration_attempts);
        return result;
    }

    Result<ModuleInfo>
    ModuleEnumerator::find(const ProcessHandle& proc, std::wstring_view name) {
        auto r = list(proc);
        if (!r.success) {
            std::string msg = "Module enumeration failed (";
            msg += to_string(r.diagnostic.status);
            msg += ")";
            if (!r.diagnostic.details.empty()) {
                msg += ": ";
                msg += r.diagnostic.details;
            }
            return Error::make(std::move(msg),
                               static_cast<int>(r.diagnostic.win32_error));
        }
        const std::wstring needle = to_lower_w(name);
        for (auto& m : r.modules) {
            if (to_lower_w(m.name) == needle) return m;
        }
        return Error::make("Module not found");
    }

} // namespace ura::platform
