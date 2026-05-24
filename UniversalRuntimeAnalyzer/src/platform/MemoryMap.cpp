// platform/MemoryMap.cpp
#include "MemoryMap.hpp"

#include "../core/Logger.hpp"

#include <windows.h>

#include <sstream>

namespace ura::platform {

    using core::Error;
    using core::Result;

    namespace {

        // Page protection bits. We test against the masks rather than
        // exact equality because Windows can OR in PAGE_GUARD or
        // PAGE_NOCACHE flags without changing the underlying access bits.
        constexpr std::uint32_t kExecMask =
            PAGE_EXECUTE | PAGE_EXECUTE_READ |
            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        constexpr std::uint32_t kWriteMask =
            PAGE_READWRITE | PAGE_WRITECOPY |
            PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;
        constexpr std::uint32_t kReadMask =
            PAGE_READONLY | PAGE_READWRITE | PAGE_WRITECOPY |
            PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

        const char* state_string(std::uint32_t s) {
            switch (s) {
                case MEM_COMMIT:  return "MEM_COMMIT";
                case MEM_RESERVE: return "MEM_RESERVE";
                case MEM_FREE:    return "MEM_FREE";
                default:          return "MEM_?";
            }
        }
        const char* type_string(std::uint32_t t) {
            switch (t) {
                case MEM_IMAGE:   return "MEM_IMAGE";
                case MEM_MAPPED:  return "MEM_MAPPED";
                case MEM_PRIVATE: return "MEM_PRIVATE";
                case 0:           return "MEM_NONE";
                default:          return "MEM_?";
            }
        }
        std::string protect_string(std::uint32_t p) {
            if (p == 0) return "PAGE_NONE";
            std::string s;
            auto add = [&](const char* tag) {
                if (!s.empty()) s += "|";
                s += tag;
            };
            const std::uint32_t base = p & 0xFF;
            switch (base) {
                case PAGE_NOACCESS:          add("PAGE_NOACCESS"); break;
                case PAGE_READONLY:          add("PAGE_READONLY"); break;
                case PAGE_READWRITE:         add("PAGE_READWRITE"); break;
                case PAGE_WRITECOPY:         add("PAGE_WRITECOPY"); break;
                case PAGE_EXECUTE:           add("PAGE_EXECUTE"); break;
                case PAGE_EXECUTE_READ:      add("PAGE_EXECUTE_READ"); break;
                case PAGE_EXECUTE_READWRITE: add("PAGE_EXECUTE_READWRITE"); break;
                case PAGE_EXECUTE_WRITECOPY: add("PAGE_EXECUTE_WRITECOPY"); break;
                default: {
                    char buf[16]; std::snprintf(buf, sizeof(buf), "0x%02X", base);
                    add(buf);
                }
            }
            if (p & PAGE_GUARD)        add("PAGE_GUARD");
            if (p & PAGE_NOCACHE)      add("PAGE_NOCACHE");
            if (p & PAGE_WRITECOMBINE) add("PAGE_WRITECOMBINE");
            return s;
        }

    } // namespace

    bool MemoryRegion::is_executable() const noexcept {
        return (protect & kExecMask) != 0;
    }
    bool MemoryRegion::is_writable() const noexcept {
        return (protect & kWriteMask) != 0;
    }
    bool MemoryRegion::is_readable() const noexcept {
        return (protect & kReadMask) != 0;
    }
    bool MemoryRegion::is_rwx() const noexcept {
        return is_executable() && is_writable();
    }

    Result<MemoryMapSummary>
    MemoryMapWalker::walk(const ProcessHandle& proc, bool keep_free) {
        if (!proc.valid()) return Error::make("Invalid process handle");

        MemoryMapSummary out;
        out.regions.reserve(1024);

        // Determine address-space ceiling. We query SystemInfo from this
        // process, which gives us the host's user-mode range. For a 32-bit
        // target running under WOW64, the actual usable upper bound for the
        // target is 4 GiB; VirtualQueryEx will simply return 0 once we step
        // past it, so we don't need an explicit cap.
        SYSTEM_INFO si{};
        ::GetSystemInfo(&si);
        const std::uintptr_t hi =
            reinterpret_cast<std::uintptr_t>(si.lpMaximumApplicationAddress);

        std::uintptr_t addr = 0;
        MEMORY_BASIC_INFORMATION mbi{};

        while (addr <= hi) {
            const SIZE_T n = ::VirtualQueryEx(proc.raw(),
                                              reinterpret_cast<LPCVOID>(addr),
                                              &mbi, sizeof(mbi));
            if (n == 0) {
                // Past the queryable range, or transient failure.
                break;
            }

            MemoryRegion r;
            r.base          = reinterpret_cast<core::Address>(mbi.BaseAddress);
            r.alloc_base    = reinterpret_cast<core::Address>(mbi.AllocationBase);
            r.size          = static_cast<std::uint64_t>(mbi.RegionSize);
            r.state         = mbi.State;
            r.protect       = mbi.Protect;
            r.alloc_protect = mbi.AllocationProtect;
            r.type          = mbi.Type;
            r.state_str     = state_string(mbi.State);
            r.protect_str   = protect_string(mbi.Protect);
            r.type_str      = type_string(mbi.Type);

            // Aggregate before we maybe drop free regions from the list.
            ++out.total_regions;
            switch (mbi.State) {
                case MEM_COMMIT:  ++out.committed; break;
                case MEM_RESERVE: ++out.reserved;  break;
                case MEM_FREE:    ++out.free_regions; break;
                default: break;
            }
            if (mbi.State == MEM_COMMIT) {
                out.total_committed_bytes += r.size;
                if (r.is_executable()) ++out.executable;
                if (r.is_writable())   ++out.writable;
                if (r.is_rwx())        ++out.rwx;
                switch (mbi.Type) {
                    case MEM_IMAGE:   ++out.image_regions;   break;
                    case MEM_MAPPED:  ++out.mapped_regions;  break;
                    case MEM_PRIVATE: ++out.private_regions; break;
                    default: break;
                }
            }

            if (mbi.State != MEM_FREE || keep_free) {
                out.regions.push_back(std::move(r));
            }

            // Advance past this region. RegionSize is always > 0 for valid
            // results; defensive check guards against pathological returns.
            const std::uintptr_t next =
                reinterpret_cast<std::uintptr_t>(mbi.BaseAddress) +
                static_cast<std::uintptr_t>(mbi.RegionSize);
            if (next <= addr) break;
            addr = next;
        }

        URA_LOG_DEBUG("VirtualQueryEx: %zu regions (%zu committed, %zu RWX)",
                      out.total_regions, out.committed, out.rwx);
        return out;
    }

} // namespace ura::platform
