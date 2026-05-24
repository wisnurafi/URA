// platform/MemoryMap.hpp
// Walk the target's virtual address space via VirtualQueryEx and report
// every region's state, protection, and type.
//
// This is the read-only sibling to the more invasive memory tools used by
// game cheats and anti-cheats. We only QUERY pages; we never read memory
// here, and we never modify protection. The output is a structural map
// suitable for spotting allocations of interest (e.g. a lone RWX region
// that doesn't belong to any loaded module).
#pragma once

#include "../core/Result.hpp"
#include "../core/Types.hpp"
#include "ProcessHandle.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace ura::platform {

    struct MemoryRegion {
        core::Address  base = 0;
        core::Address  alloc_base = 0;   // VirtualQuery's AllocationBase
        std::uint64_t  size = 0;

        // Win32 raw values (kept for traceability into MSDN docs).
        std::uint32_t  state = 0;        // MEM_COMMIT/RESERVE/FREE
        std::uint32_t  protect = 0;      // PAGE_EXECUTE_READ etc.
        std::uint32_t  alloc_protect = 0;
        std::uint32_t  type = 0;         // MEM_IMAGE/MAPPED/PRIVATE

        // Pre-decoded strings for the report.
        std::string    state_str;
        std::string    protect_str;
        std::string    type_str;

        // True if any of the page-protection bits implies executable AND
        // any of them implies writable. RWX pages are the canonical signal
        // for code injection / JIT and are flagged separately by callers.
        bool is_rwx() const noexcept;
        bool is_executable() const noexcept;
        bool is_writable()   const noexcept;
        bool is_readable()   const noexcept;
    };

    struct MemoryMapSummary {
        std::vector<MemoryRegion> regions;

        // Aggregate counters.
        std::size_t total_regions   = 0;
        std::size_t committed       = 0;
        std::size_t reserved        = 0;
        std::size_t free_regions    = 0;
        std::size_t executable      = 0;
        std::size_t writable        = 0;
        std::size_t rwx             = 0;        // executable AND writable
        std::size_t image_regions   = 0;        // MEM_IMAGE
        std::size_t mapped_regions  = 0;        // MEM_MAPPED
        std::size_t private_regions = 0;        // MEM_PRIVATE
        std::uint64_t total_committed_bytes = 0;
    };

    class MemoryMapWalker {
    public:
        // Walk every region from address 0 up to the user-mode address
        // ceiling. On 64-bit hosts that is 0x7FFF_FFFEFFFF; on 32-bit hosts
        // it is 0x7FFF_FFFF (or 0xBFFF_FFFF if /LARGEADDRESSAWARE).
        //
        // `keep_free=false` (default) skips MEM_FREE regions in the
        // returned list but still counts them in summary. Free regions
        // dominate any address space, so dropping them keeps the report
        // readable.
        static core::Result<MemoryMapSummary>
            walk(const ProcessHandle& proc, bool keep_free = false);
    };

} // namespace ura::platform
