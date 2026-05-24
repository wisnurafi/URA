// engine/EngineContext.hpp
// Bag of data passed to every engine module. Owns nothing — references the
// platform objects created higher up the stack.
#pragma once

#include "../platform/MemoryReader.hpp"
#include "../platform/ModuleEnumerator.hpp"
#include "../platform/PEParser.hpp"
#include "../platform/ProcessHandle.hpp"

#include <vector>

namespace ura::engine {

    struct EngineContext {
        const platform::ProcessHandle&        process;
        const platform::MemoryReader&         reader;
        const std::vector<platform::ModuleInfo>& modules;

        // Find a module by case-insensitive name. Returns nullptr if absent.
        const platform::ModuleInfo* find_module(std::wstring_view name) const;
    };

} // namespace ura::engine
