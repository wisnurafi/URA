// platform/ProcessEnumerator.cpp
#include "ProcessEnumerator.hpp"

#include "../core/Logger.hpp"

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#include <algorithm>
#include <cwctype>

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

        std::wstring query_full_path(core::Pid pid) {
            HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
            if (!h) return {};
            wchar_t buf[MAX_PATH * 2] = {};
            DWORD   sz  = static_cast<DWORD>(std::size(buf));
            std::wstring out;
            if (::QueryFullProcessImageNameW(h, 0, buf, &sz)) {
                out.assign(buf, sz);
            }
            ::CloseHandle(h);
            return out;
        }
    } // namespace

    Result<std::vector<ProcessInfo>> ProcessEnumerator::snapshot() {
        HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) {
            return Error::make("CreateToolhelp32Snapshot failed",
                               static_cast<int>(::GetLastError()));
        }

        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);

        std::vector<ProcessInfo> out;
        if (::Process32FirstW(snap, &pe)) {
            do {
                ProcessInfo info;
                info.pid       = pe.th32ProcessID;
                info.parent    = pe.th32ParentProcessID;
                info.name      = pe.szExeFile;
                info.full_path = query_full_path(info.pid);
                out.push_back(std::move(info));
            } while (::Process32NextW(snap, &pe));
        }

        ::CloseHandle(snap);
        URA_LOG_DEBUG("Process snapshot: %zu processes", out.size());
        return out;
    }

    Result<ProcessInfo> ProcessEnumerator::find_by_name(std::wstring_view name) {
        auto snap = snapshot();
        if (!snap) return snap.error();
        const std::wstring needle = to_lower_w(name);
        for (auto& p : snap.value()) {
            if (to_lower_w(p.name) == needle) return p;
        }
        return Error::make("Process not found in snapshot");
    }

} // namespace ura::platform
