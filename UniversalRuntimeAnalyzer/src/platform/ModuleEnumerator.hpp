// platform/ModuleEnumerator.hpp
// Enumerate every loaded module of a target process and capture base/size/path.
//
// Returns a ModuleEnumerationResult that always carries an
// AcquisitionDiagnostic. Callers should branch on `success` rather than on
// whether the modules vector is empty (a privileged process may have an
// empty visible module set without that being an error per se).
#pragma once

#include "AcquisitionDiagnostic.hpp"
#include "ProcessHandle.hpp"
#include "../core/Result.hpp"
#include "../core/Types.hpp"

#include <string>
#include <vector>

namespace ura::platform {

    struct ModuleInfo {
        std::wstring     name;       // file name only ("UnityPlayer.dll")
        std::wstring     full_path;
        core::Address    base = 0;   // image base in target's address space
        core::ModuleSize size = 0;   // image size in bytes
    };

    struct ModuleEnumerationResult {
        bool                     success = false;
        std::vector<ModuleInfo>  modules;
        AcquisitionDiagnostic    diagnostic;
    };

    class ModuleEnumerator {
    public:
        // List every module in the target process. Always returns a
        // populated diagnostic; the modules vector is non-empty only when
        // success is true.
        static ModuleEnumerationResult list(const ProcessHandle& proc);

        // Convenience: find a module by case-insensitive name match.
        static core::Result<ModuleInfo>
            find(const ProcessHandle& proc, std::wstring_view name);
    };

} // namespace ura::platform
