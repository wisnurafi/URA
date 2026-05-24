// platform/ProcessEnumerator.hpp
// Snapshot all running processes via Toolhelp32.
#pragma once

#include "../core/Result.hpp"
#include "../core/Types.hpp"

#include <string>
#include <vector>

namespace ura::platform {

    struct ProcessInfo {
        core::Pid    pid       = 0;
        core::Pid    parent    = 0;
        std::wstring name;        // executable name only ("Game.exe")
        std::wstring full_path;   // best-effort full path; may be empty if denied
    };

    class ProcessEnumerator {
    public:
        // Returns every process visible to the current token.
        static core::Result<std::vector<ProcessInfo>> snapshot();

        // Find by case-insensitive executable name match. Returns the first
        // match, or Error if none.
        static core::Result<ProcessInfo> find_by_name(std::wstring_view name);
    };

} // namespace ura::platform
