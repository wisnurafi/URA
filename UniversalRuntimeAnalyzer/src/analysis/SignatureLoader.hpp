// analysis/SignatureLoader.hpp
// Load Signature definitions from JSON files on disk.
//
// Engines may either embed signatures inline (for self-containment) or
// source them from `data/signatures/<engine_id>.json` to allow updates
// without rebuilding. The JSON schema:
//
//   {
//     "engine":      "<engine_id>",
//     "module_hint": "<dll-name>",   // optional, advisory only
//     "signatures": [
//       {
//         "name":             "<unique_name>",
//         "pattern":          "48 8B ?? ?? ?? ?? 90",
//         "description":      "...",
//         "module_hint":      "<dll-name>",   // optional, overrides outer
//         "transform":        "none|rip_relative_32|absolute_32|absolute_64",
//         "transform_offset": 0,     // optional, default 0
//         "post_offset":      0      // optional, default 0
//       }
//     ]
//   }
//
// Unknown fields are ignored; missing optional fields take their defaults.
// Parse errors are reported via Result so callers can treat a malformed
// signature file as "use inline fallback" without aborting the analysis.
#pragma once

#include "../core/Result.hpp"
#include "Signature.hpp"

#include <filesystem>
#include <string>
#include <vector>

namespace ura::analysis {

    struct SignatureBundle {
        std::string            engine_id;
        std::string            module_hint;   // outer-level hint
        std::vector<Signature> signatures;
        std::filesystem::path  source_path;
    };

    class SignatureLoader {
    public:
        // Load a single JSON signature bundle from disk.
        static core::Result<SignatureBundle>
            load_file(const std::filesystem::path& path);

        // Convenience: try to load `<dir>/<engine_id>.json`. Returns the
        // bundle on success, an Error if the file is absent or malformed.
        // Engines call this in their analyze() and silently fall back to
        // inline signatures on failure.
        static core::Result<SignatureBundle>
            load_for_engine(const std::filesystem::path& dir,
                            std::string_view engine_id);

        // Locate the default signatures directory next to the running
        // executable. Searches:
        //   <exe>\..\data\signatures      (development layout)
        //   <exe>\data\signatures         (deployed layout)
        // Returns empty path if neither exists.
        static std::filesystem::path default_signatures_dir();
    };

} // namespace ura::analysis
