// platform/ModuleEnumerator.hpp
// Enumerate every loaded module of a target process and capture base/size/path.
#pragma once

#include "../core/Result.hpp"
#include "../core/Types.hpp"
#include "ProcessHandle.hpp"

#include <string>
#include <vector>

namespace ura::platform {

    struct ModuleInfo {
        std::wstring     name;       // file name only ("UnityPlayer.dll")
        std::wstring     full_path;
        core::Address    base = 0;   // image base in target's address space
        core::ModuleSize size = 0;   // image size in bytes
    };

    class ModuleEnumerator {
    public:
        // List every module in the target process.
        static core::Result<std::vector<ModuleInfo>>
            list(const ProcessHandle& proc);

        // Convenience: find a module by case-insensitive name match.
        static core::Result<ModuleInfo>
            find(const ProcessHandle& proc, std::wstring_view name);
    };

} // namespace ura::platform
