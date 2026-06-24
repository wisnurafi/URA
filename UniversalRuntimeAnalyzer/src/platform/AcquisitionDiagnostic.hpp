// platform/AcquisitionDiagnostic.hpp
// Evidence-based classification of why a runtime acquisition (open process /
// enumerate modules / read memory) succeeded or failed. Replaces the old
// "process likely anti-cheat-protected or transitioning" string that fired
// on every Win32 error 299.
//
// The orchestrator populates one of these per Analyze run. UI and JSON
// exporters consume it as-is — no further interpretation needed.
#pragma once

#include "../core/Types.hpp"

#include <cstdint>
#include <string>

namespace ura::platform {

    // Status taxonomy. Ordered so callers can do `status >= Failed` etc.
    // if they want; otherwise use it as a plain tag.
    enum class AcquisitionStatus : int {
        Success = 0,

        // Pre-flight refusals (no Win32 call made).
        ArchitectureMismatch,       // x86 analyzer vs x64 target, etc.
        UnsupportedArchitecture,    // host or target arch we don't handle
        ProcessNotFound,            // PID not in snapshot

        // Win32-call failures, classified by the captured error code.
        OpenProcessFailed,          // OpenProcess returned 0 (catch-all)
        AccessDenied,               // ERROR_ACCESS_DENIED (5)
        ProcessTerminated,          // ERROR_INVALID_HANDLE (6) on a live PID
        LoaderTransition,           // 299 with shrinking module count
        PartialCopy,                // 299 stable across attempts
        ModuleEnumerationFailed,    // any other Win32 enum error
        MemoryReadRestricted,       // VM_READ access OK but reads fail
        ProtectedOrRestricted,      // evidence-based catch-all (not default)
        UnknownFailure,
    };

    inline const char* to_string(AcquisitionStatus s) noexcept {
        switch (s) {
            case AcquisitionStatus::Success:                 return "Success";
            case AcquisitionStatus::ArchitectureMismatch:    return "ArchitectureMismatch";
            case AcquisitionStatus::UnsupportedArchitecture: return "UnsupportedArchitecture";
            case AcquisitionStatus::ProcessNotFound:         return "ProcessNotFound";
            case AcquisitionStatus::OpenProcessFailed:       return "OpenProcessFailed";
            case AcquisitionStatus::AccessDenied:            return "AccessDenied";
            case AcquisitionStatus::ProcessTerminated:       return "ProcessTerminated";
            case AcquisitionStatus::LoaderTransition:        return "LoaderTransition";
            case AcquisitionStatus::PartialCopy:             return "PartialCopy";
            case AcquisitionStatus::ModuleEnumerationFailed: return "ModuleEnumerationFailed";
            case AcquisitionStatus::MemoryReadRestricted:    return "MemoryReadRestricted";
            case AcquisitionStatus::ProtectedOrRestricted:   return "ProtectedOrRestricted";
            case AcquisitionStatus::UnknownFailure:          return "UnknownFailure";
        }
        return "Unknown";
    }

    // Visual severity hint for UI badges. Five tiers per PROMPT.md Tahap 5.
    enum class StatusSeverity : int {
        Success      = 0,   // green
        Warning      = 1,   // yellow (e.g. fallback used, partial result)
        Unsupported  = 2,   // gray   (analyzer can't possibly do this)
        Restricted   = 3,   // orange (system says no)
        Failed       = 4,   // red    (true failure)
    };

    inline StatusSeverity severity_of(AcquisitionStatus s) noexcept {
        switch (s) {
            case AcquisitionStatus::Success:
                return StatusSeverity::Success;
            case AcquisitionStatus::ArchitectureMismatch:
            case AcquisitionStatus::UnsupportedArchitecture:
                return StatusSeverity::Unsupported;
            case AcquisitionStatus::AccessDenied:
            case AcquisitionStatus::MemoryReadRestricted:
            case AcquisitionStatus::ProtectedOrRestricted:
                return StatusSeverity::Restricted;
            case AcquisitionStatus::LoaderTransition:
                return StatusSeverity::Warning;
            default:
                return StatusSeverity::Failed;
        }
    }

    // The structured record. Every Analyze run produces one, even on the
    // success path (status=Success, win32_error=0, recommended_action="").
    struct AcquisitionDiagnostic {
        AcquisitionStatus status = AcquisitionStatus::UnknownFailure;
        std::uint32_t     win32_error = 0;

        core::Architecture analyzer_architecture = core::Architecture::Unknown;
        core::Architecture target_architecture   = core::Architecture::Unknown;
        core::Architecture native_architecture   = core::Architecture::Unknown;

        // Stage flags — flipped to true as the pipeline progresses. A failed
        // run leaves the flags reflecting how far we got.
        bool process_handle_opened       = false;
        bool process_query_succeeded     = false;
        bool module_enumeration_succeeded = false;
        bool memory_read_succeeded       = false;

        int enumeration_attempts = 0;

        // Free-form forensics (small strings; cheap to carry around).
        std::string failed_api;        // "EnumProcessModulesEx" etc.
        std::string failed_stage;      // "size query" / "fill" / etc.
        std::string details;           // human-readable
        std::string recommended_action;
    };

    // Render the diagnostic as a multi-line block suitable for stderr / a
    // GUI text panel. PROMPT.md Tahap 3 / Tahap 5 example output.
    std::string format_diagnostic(const AcquisitionDiagnostic& d);

} // namespace ura::platform
