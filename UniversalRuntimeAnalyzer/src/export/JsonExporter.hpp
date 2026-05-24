// export/JsonExporter.hpp
// Serialize an AnalysisReport to a stable JSON schema. Schema version is
// embedded in every report so consumers can evolve safely.
//
// Schema (v1):
//   {
//     "tool":   { "name": str, "version": str, "schema_version": str,
//                 "generated_at": ISO-8601 },
//     "engine": { "id": str, "display_name": str, "duration_ms": int },
//     "process":{ "pid": int, "name": str, "path": str, "is_wow64": bool,
//                 "bitness": int },
//     "modules":[ { "name", "path", "base", "size", "is_64bit", "machine",
//                    "timestamp", "size_of_image", "entry_point_rva",
//                    "sections": [str] }, ... ],
//     "groups": [ { "name", "offsets":[
//         { "label", "absolute": "0x...", "rva": "0x...",
//           "module": str, "notes": str } ] }, ... ],
//     "notes":   { ... },
//     "warnings":[ str ]
//   }
#pragma once

#include "../core/Result.hpp"
#include "../engine/AnalysisReport.hpp"

#include <string>

namespace ura::exporter {

    class JsonExporter {
    public:
        // Returns the JSON text. `pretty=true` uses 2-space indentation.
        static std::string to_string(const engine::AnalysisReport& report,
                                     bool pretty = true);

        // Writes the JSON text to a file. Creates parent directories on demand.
        static core::Result<void> write_file(const engine::AnalysisReport& report,
                                             const std::string& path,
                                             bool pretty = true);
    };

} // namespace ura::exporter
