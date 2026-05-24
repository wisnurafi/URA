// platform/PEParser.hpp
// Read PE headers/sections out of a remote module via MemoryReader.
//
// We deliberately re-parse the headers ourselves rather than calling
// ImageNtHeader on a local mapping: the in-process layout (SizeOfImage,
// section RVAs after relocations, etc.) is what the engine modules need.
#pragma once

#include "../core/Result.hpp"
#include "../core/Types.hpp"
#include "MemoryReader.hpp"
#include "ModuleEnumerator.hpp"

#include <string>
#include <vector>

namespace ura::platform {

    struct PESection {
        std::string    name;        // ".text", ".rdata", ...
        core::Rva      rva   = 0;   // virtual address relative to image base
        core::Address  start = 0;   // absolute start in target's address space
        std::uint32_t  size  = 0;   // virtual size
        std::uint32_t  characteristics = 0;

        bool is_executable() const noexcept;
        bool is_readable()   const noexcept;
        bool is_writable()   const noexcept;
    };

    struct PEExport {
        std::string   name;
        std::uint16_t ordinal = 0;
        core::Rva     rva     = 0;   // RVA of the function within this module
        bool          is_forwarder = false;
        std::string   forwarder_target; // "MODULE.Function" if is_forwarder
    };

    struct PEImage {
        ModuleInfo               module;     // enumerator-supplied module info
        bool                     is_64bit = false;
        std::uint16_t            machine  = 0;
        std::uint32_t            timestamp = 0;
        core::Rva                entry_point_rva = 0;
        std::uint32_t            size_of_image = 0;
        std::vector<PESection>   sections;
        std::vector<PEExport>    exports;    // exported symbols (best-effort)

        // Find a section by name (case-sensitive, common usage: ".text").
        const PESection* find_section(std::string_view name) const;

        // Find an export by exact name; returns nullptr if missing.
        const PEExport* find_export(std::string_view name) const;
    };

    class PEParser {
    public:
        // Parse the headers + section table of a remote module.
        static core::Result<PEImage>
            parse(const MemoryReader& reader, const ModuleInfo& mod,
                  bool include_exports = true);
    };

} // namespace ura::platform
