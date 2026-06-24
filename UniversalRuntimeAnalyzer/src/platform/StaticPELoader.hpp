// platform/StaticPELoader.hpp
// Disk-based PE inspection. Used as a fallback when live runtime
// acquisition is unavailable but the process executable path is known.
//
// We map the PE file flat (no SEC_IMAGE), parse the headers ourselves, and
// surface every section header + export directory entry. Output is purely
// RVA-based: absolute runtime addresses depend on `moduleBase + RVA`,
// computed by downstream consumers when the module is loaded.
//
// Hard scope: read-only, file-on-disk only. Never opens a process handle,
// never reads target memory, never touches anti-cheat boundaries.
#pragma once

#include "../core/Result.hpp"
#include "../core/Types.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace ura::platform {

    struct StaticSection {
        std::string   name;             // ".text", ".rdata", ...
        core::Rva     rva           = 0;
        std::uint32_t virtual_size  = 0;
        std::uint32_t raw_size      = 0;
        std::uint32_t characteristics = 0;
    };

    struct StaticExport {
        std::string   name;             // empty when ordinal-only export
        std::uint16_t ordinal      = 0;
        core::Rva     rva          = 0; // RVA of function (or forwarder string)
        bool          is_forwarder = false;
        std::string   forwarder_target; // "MODULE.Function" when forwarded
    };

    struct StaticPEImage {
        std::wstring               file_path;
        std::wstring               file_name;
        bool                       is_64bit = false;
        std::uint16_t              machine  = 0;     // IMAGE_FILE_MACHINE_*
        std::uint32_t              timestamp = 0;
        std::uint64_t              image_base_preferred = 0;
        std::uint32_t              size_of_image = 0;
        core::Rva                  entry_point_rva = 0;
        std::vector<StaticSection> sections;
        std::vector<StaticExport>  exports;
        std::uint64_t              file_size_bytes = 0;
    };

    class StaticPELoader {
    public:
        // Parse a PE file from disk. The path may be a Win32 path (UNC,
        // drive-letter, namespaced); we open it for read-only sequential
        // access only.
        static core::Result<StaticPEImage> load(const std::wstring& path);
    };

} // namespace ura::platform
