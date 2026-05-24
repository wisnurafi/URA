// engine/AnalysisReport.hpp
// Engine-agnostic structured output. Engines populate this; the JSON
// exporter consumes it without engine-specific knowledge.
#pragma once

#include "../core/Types.hpp"

#include <chrono>
#include <map>
#include <optional>
#include <string>
#include <vector>

namespace ura::engine {

    struct ReportOffset {
        std::string   label;       // unique within its group, e.g. "il2cpp_init"
        core::Address absolute = 0;
        core::Rva     rva      = 0;
        std::wstring  module_name;
        std::string   notes;
    };

    // A single memory region snapshot taken from VirtualQueryEx, kept here
    // in engine-agnostic form so the JSON exporter can serialize it without
    // knowing about platform/MemoryMap.hpp.
    struct ReportMemoryRegion {
        core::Address base = 0;
        core::Address alloc_base = 0;
        std::uint64_t size = 0;
        std::string   state;       // "MEM_COMMIT" / "MEM_RESERVE" / "MEM_FREE"
        std::string   protect;     // "PAGE_EXECUTE_READ" etc.
        std::string   type;        // "MEM_IMAGE" / "MEM_MAPPED" / "MEM_PRIVATE"
    };

    struct ReportMemoryMap {
        bool                              present = false;
        std::vector<ReportMemoryRegion>   regions;
        std::size_t                       total_regions   = 0;
        std::size_t                       committed       = 0;
        std::size_t                       reserved        = 0;
        std::size_t                       free_regions    = 0;
        std::size_t                       executable      = 0;
        std::size_t                       writable        = 0;
        std::size_t                       rwx             = 0;
        std::size_t                       image_regions   = 0;
        std::size_t                       mapped_regions  = 0;
        std::size_t                       private_regions = 0;
        std::uint64_t                     total_committed_bytes = 0;
        std::vector<std::string>          anomalies;   // human-readable flags
    };

    struct ReportModule {
        std::wstring   name;
        std::wstring   path;
        core::Address  base = 0;
        core::ModuleSize size = 0;
        bool           is_64bit = false;
        std::uint16_t  machine = 0;
        std::uint32_t  timestamp = 0;
        std::uint32_t  size_of_image = 0;
        core::Rva      entry_point_rva = 0;
        std::vector<std::string> sections;  // ".text", ".rdata", ...
    };

    struct ReportProcess {
        core::Pid     pid = 0;
        std::wstring  name;
        std::wstring  path;
        bool          is_wow64 = false;
        int           bitness  = 64;
    };

    // Free-form group of offsets. Engines structure their results into
    // groups like "globals", "functions", "vftables", etc.
    struct ReportGroup {
        std::string                 name;
        std::vector<ReportOffset>   offsets;
    };

    // RTTI / vtable findings for a single discovered C++ class.
    struct ReportClass {
        std::string   mangled_name;
        std::string   demangled_name;
        std::wstring  module_name;
        core::Address rcol_address    = 0;
        core::Rva     rcol_rva        = 0;
        core::Address vftable_address = 0;
        core::Rva     vftable_rva     = 0;
        std::uint32_t inheritance_offset = 0;
        std::uint32_t method_count    = 0;
    };

    struct AnalysisReport {
        // Metadata
        std::string  tool_name    = "UniversalRuntimeAnalyzer";
        std::string  tool_version = "0.1.0";
        std::string  schema_version = "1";
        std::string  generated_at;          // ISO-8601, filled in on serialize
        std::string  engine_id;              // matches IGameEngine::id()
        std::string  engine_display_name;
        std::chrono::milliseconds duration{0};

        // Subject
        ReportProcess              process;
        std::vector<ReportModule>  modules;

        // Findings
        std::vector<ReportGroup>          groups;
        std::map<std::string, std::string> notes;   // free-form annotations
        std::vector<std::string>          warnings;
        std::vector<ReportClass>          classes;  // RTTI findings

        // Optional address-space snapshot (filled in by the orchestrator
        // before the engine runs, so every engine inherits it for free).
        ReportMemoryMap                   memory_map;

        // Helper to add an offset to a named group, creating the group if it
        // doesn't exist yet.
        void add_offset(std::string group_name, ReportOffset off);
    };

} // namespace ura::engine
