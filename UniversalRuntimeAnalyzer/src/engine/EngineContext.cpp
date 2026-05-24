// engine/EngineContext.cpp
#include "EngineContext.hpp"

#include <algorithm>
#include <cwctype>

namespace ura::engine {

    namespace {
        std::wstring lower(std::wstring_view s) {
            std::wstring out(s);
            std::transform(out.begin(), out.end(), out.begin(),
                [](wchar_t c){ return static_cast<wchar_t>(std::towlower(c)); });
            return out;
        }
    } // namespace

    const platform::ModuleInfo*
    EngineContext::find_module(std::wstring_view name) const {
        const std::wstring needle = lower(name);
        for (const auto& m : modules) {
            if (lower(m.name) == needle) return &m;
        }
        return nullptr;
    }

} // namespace ura::engine
