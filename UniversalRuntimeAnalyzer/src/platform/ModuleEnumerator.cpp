// platform/ModuleEnumerator.cpp
#include "ModuleEnumerator.hpp"

#include "../core/Logger.hpp"

#include <windows.h>
#include <psapi.h>

#include <algorithm>
#include <cwctype>
#include <string>

#pragma comment(lib, "Psapi.lib")

namespace ura::platform {

    using core::Error;
    using core::Result;

    namespace {
        std::wstring to_lower_w(std::wstring_view s) {
            std::wstring out(s);
            std::transform(out.begin(), out.end(), out.begin(),
                [](wchar_t c){ return static_cast<wchar_t>(std::towlower(c)); });
            return out;
        }

        // Translate the most common Win32 errors we hit during module
        // enumeration into something a course reviewer can read at a glance.
        const char* friendly_winerr(DWORD e) {
            switch (e) {
                case 5:   return "ERROR_ACCESS_DENIED — handle lacks rights";
                case 6:   return "ERROR_INVALID_HANDLE";
                case 8:   return "ERROR_NOT_ENOUGH_MEMORY";
                case 24:  return "ERROR_BAD_LENGTH";
                case 87:  return "ERROR_INVALID_PARAMETER";
                case 299: return "ERROR_PARTIAL_COPY — process likely "
                                 "anti-cheat-protected or transitioning";
                case 998: return "ERROR_NOACCESS — invalid memory access "
                                 "(target may be protected)";
                default:  return "see https://learn.microsoft.com/windows/win32/debug/system-error-codes";
            }
        }

        std::string format_winerr(const char* api, DWORD e) {
            std::string s = api;
            s += " failed: ";
            s += std::to_string(e);
            s += " (";
            s += friendly_winerr(e);
            s += ")";
            return s;
        }
    } // namespace

    Result<std::vector<ModuleInfo>>
    ModuleEnumerator::list(const ProcessHandle& proc) {
        if (!proc.valid()) return Error::make("Invalid process handle");

        // First pass: how many modules?
        DWORD needed = 0;
        // LIST_MODULES_ALL covers both 32 and 64-bit modules; on a 64-bit
        // analyzer reading a WOW64 target, this returns the 32-bit modules.
        if (!::EnumProcessModulesEx(proc.raw(), nullptr, 0, &needed,
                                    LIST_MODULES_ALL)) {
            const DWORD e = ::GetLastError();
            // Common failure: anti-cheat-protected target. Try the legacy
            // EnumProcessModules as a last resort — sometimes it still
            // returns at least the main image.
            HMODULE fallback[1024];
            DWORD fb_needed = 0;
            if (::EnumProcessModules(proc.raw(), fallback, sizeof(fallback),
                                     &fb_needed)) {
                URA_LOG_WARN("EnumProcessModulesEx failed (%lu); using "
                             "fallback EnumProcessModules", e);
                std::vector<ModuleInfo> out;
                const std::size_t n = fb_needed / sizeof(HMODULE);
                for (std::size_t i = 0; i < n; ++i) {
                    ModuleInfo m;
                    wchar_t buf[MAX_PATH * 2] = {};
                    if (::GetModuleFileNameExW(proc.raw(), fallback[i], buf,
                            static_cast<DWORD>(std::size(buf)))) {
                        m.full_path = buf;
                        if (auto pos = m.full_path.find_last_of(L"\\/");
                            pos != std::wstring::npos)
                            m.name = m.full_path.substr(pos + 1);
                        else
                            m.name = m.full_path;
                    }
                    MODULEINFO mi{};
                    if (::GetModuleInformation(proc.raw(), fallback[i], &mi,
                                               sizeof(mi))) {
                        m.base = reinterpret_cast<core::Address>(mi.lpBaseOfDll);
                        m.size = mi.SizeOfImage;
                    }
                    if (m.base && !m.name.empty()) out.push_back(std::move(m));
                }
                return out;
            }
            return Error::make(format_winerr("EnumProcessModulesEx (size)", e),
                               static_cast<int>(e));
        }

        std::vector<HMODULE> mods(needed / sizeof(HMODULE));
        if (mods.empty()) return std::vector<ModuleInfo>{};

        if (!::EnumProcessModulesEx(proc.raw(), mods.data(),
                                    static_cast<DWORD>(mods.size() * sizeof(HMODULE)),
                                    &needed, LIST_MODULES_ALL)) {
            const DWORD e = ::GetLastError();
            return Error::make(format_winerr("EnumProcessModulesEx (fill)", e),
                               static_cast<int>(e));
        }
        mods.resize(needed / sizeof(HMODULE));

        std::vector<ModuleInfo> out;
        out.reserve(mods.size());

        for (HMODULE h : mods) {
            ModuleInfo m;

            wchar_t buf[MAX_PATH * 2] = {};
            if (::GetModuleFileNameExW(proc.raw(), h, buf, static_cast<DWORD>(std::size(buf)))) {
                m.full_path = buf;
                if (auto pos = m.full_path.find_last_of(L"\\/");
                    pos != std::wstring::npos) {
                    m.name = m.full_path.substr(pos + 1);
                } else {
                    m.name = m.full_path;
                }
            }

            MODULEINFO mi{};
            if (::GetModuleInformation(proc.raw(), h, &mi, sizeof(mi))) {
                m.base = reinterpret_cast<core::Address>(mi.lpBaseOfDll);
                m.size = mi.SizeOfImage;
            }

            if (m.base != 0 && !m.name.empty()) {
                out.push_back(std::move(m));
            }
        }

        URA_LOG_DEBUG("Enumerated %zu modules in pid=%lu",
                      out.size(), static_cast<unsigned long>(proc.pid()));
        return out;
    }

    Result<ModuleInfo>
    ModuleEnumerator::find(const ProcessHandle& proc, std::wstring_view name) {
        auto all = list(proc);
        if (!all) return all.error();
        const std::wstring needle = to_lower_w(name);
        for (auto& m : all.value()) {
            if (to_lower_w(m.name) == needle) return m;
        }
        return Error::make("Module not found");
    }

} // namespace ura::platform
