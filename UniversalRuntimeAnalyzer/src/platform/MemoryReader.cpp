// platform/MemoryReader.cpp
#include "MemoryReader.hpp"

#include "../core/Logger.hpp"

#include <windows.h>

namespace ura::platform {

    using core::Error;
    using core::Result;

    Result<core::ByteBuffer>
    MemoryReader::read_raw(core::Address addr, std::size_t size) const {
        if (!proc_.valid()) return Error::make("Invalid process handle");
        if (size == 0)      return core::ByteBuffer{};

        core::ByteBuffer buf(size);
        SIZE_T got = 0;
        BOOL ok = ::ReadProcessMemory(proc_.raw(),
                                      reinterpret_cast<LPCVOID>(addr),
                                      buf.data(), size, &got);
        if (!ok || got != size) {
            return Error::make("ReadProcessMemory failed",
                               static_cast<int>(::GetLastError()));
        }
        return buf;
    }

    core::ByteBuffer
    MemoryReader::read_raw_best_effort(core::Address addr, std::size_t size) const {
        core::ByteBuffer out;
        if (!proc_.valid() || size == 0) return out;

        // Walk the target's VM in page-aligned chunks; skip unreadable pages.
        constexpr std::size_t kPage = 0x1000;

        out.reserve(size);
        std::size_t  remaining = size;
        core::Address cur      = addr;

        while (remaining > 0) {
            const std::size_t page_off = static_cast<std::size_t>(cur & (kPage - 1));
            const std::size_t chunk    = std::min(remaining, kPage - page_off);

            std::uint8_t  tmp[kPage];
            SIZE_T        got = 0;
            BOOL          ok  = ::ReadProcessMemory(proc_.raw(),
                                                    reinterpret_cast<LPCVOID>(cur),
                                                    tmp, chunk, &got);
            if (ok && got == chunk) {
                out.insert(out.end(), tmp, tmp + chunk);
            } else {
                // Unreadable region: stop here. Caller decides whether to
                // resume from a later address.
                break;
            }
            cur       += chunk;
            remaining -= chunk;
        }
        return out;
    }

    Result<void>
    MemoryReader::read_into(core::Address addr, void* dst, std::size_t size) const {
        if (!proc_.valid()) return Error::make("Invalid process handle");
        if (size == 0)      return core::ok();
        SIZE_T got = 0;
        BOOL ok = ::ReadProcessMemory(proc_.raw(),
                                      reinterpret_cast<LPCVOID>(addr),
                                      dst, size, &got);
        if (!ok || got != size) {
            return Error::make("ReadProcessMemory failed",
                               static_cast<int>(::GetLastError()));
        }
        return core::ok();
    }

    Result<core::Address>
    MemoryReader::walk_pointer_chain(core::Address base,
                                     const std::vector<std::ptrdiff_t>& offsets) const {
        if (!proc_.valid()) return Error::make("Invalid process handle");
        if (offsets.empty()) return base;

        const bool target32 = (proc_.bitness() == 32);

        core::Address cur = base;
        // For each offset except the last: read pointer at (cur + off).
        // The final offset is added without dereferencing — that's the
        // address of the field.
        for (std::size_t i = 0; i < offsets.size(); ++i) {
            const std::ptrdiff_t off = offsets[i];
            const bool last = (i + 1 == offsets.size());

            if (last) {
                cur = cur + static_cast<core::Address>(off);
                break;
            }

            core::Address ptr_addr = cur + static_cast<core::Address>(off);
            if (target32) {
                auto v = read<std::uint32_t>(ptr_addr);
                if (!v) return v.error();
                cur = static_cast<core::Address>(v.value());
            } else {
                auto v = read<std::uint64_t>(ptr_addr);
                if (!v) return v.error();
                cur = v.value();
            }
            if (cur == 0) return Error::make("Null pointer in chain");
        }
        return cur;
    }

    Result<std::string>
    MemoryReader::read_cstring(core::Address addr, std::size_t max_len) const {
        std::string out;
        out.reserve(64);
        constexpr std::size_t kChunk = 64;
        std::size_t read_total = 0;

        while (read_total < max_len) {
            const std::size_t want = std::min(kChunk, max_len - read_total);
            char tmp[kChunk];
            auto r = read_into(addr + read_total, tmp, want);
            if (!r) return r.error();
            for (std::size_t i = 0; i < want; ++i) {
                if (tmp[i] == '\0') {
                    out.append(tmp, tmp + i);
                    return out;
                }
            }
            out.append(tmp, tmp + want);
            read_total += want;
        }
        return out; // truncated at max_len
    }

    Result<std::wstring>
    MemoryReader::read_wstring(core::Address addr, std::size_t max_len) const {
        std::wstring out;
        out.reserve(64);
        constexpr std::size_t kChunk = 64;
        std::size_t read_total = 0;

        while (read_total < max_len) {
            const std::size_t want = std::min(kChunk, max_len - read_total);
            wchar_t tmp[kChunk];
            auto r = read_into(addr + read_total * sizeof(wchar_t),
                               tmp, want * sizeof(wchar_t));
            if (!r) return r.error();
            for (std::size_t i = 0; i < want; ++i) {
                if (tmp[i] == L'\0') {
                    out.append(tmp, tmp + i);
                    return out;
                }
            }
            out.append(tmp, tmp + want);
            read_total += want;
        }
        return out;
    }

} // namespace ura::platform
