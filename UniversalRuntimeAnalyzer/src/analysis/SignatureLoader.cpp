// analysis/SignatureLoader.cpp
#include "SignatureLoader.hpp"

#include "../core/Logger.hpp"

#include <nlohmann/json.hpp>

#ifdef _WIN32
#  include <windows.h>
#endif

#include <fstream>
#include <sstream>

namespace ura::analysis {

    using core::Error;
    using core::Result;
    using nlohmann::json;
    namespace fs = std::filesystem;

    namespace {

        HitTransform parse_transform(const std::string& s) {
            if (s == "rip_relative_32" || s == "rip32") return HitTransform::RipRelative32;
            if (s == "absolute_32"     || s == "abs32") return HitTransform::Absolute32;
            if (s == "absolute_64"     || s == "abs64") return HitTransform::Absolute64;
            return HitTransform::None;
        }

#ifdef _WIN32
        fs::path exe_dir() {
            wchar_t buf[MAX_PATH * 2] = {};
            DWORD n = ::GetModuleFileNameW(nullptr, buf,
                static_cast<DWORD>(std::size(buf)));
            if (n == 0) return {};
            return fs::path(buf).parent_path();
        }
#else
        fs::path exe_dir() { return {}; }
#endif

    } // namespace

    Result<SignatureBundle>
    SignatureLoader::load_file(const fs::path& path) {
        std::ifstream is(path, std::ios::binary);
        if (!is) {
            return Error::make("Cannot open signature file: " + path.string());
        }

        json doc;
        try {
            is >> doc;
        } catch (const std::exception& ex) {
            return Error::make(std::string("Invalid JSON in ") + path.string()
                               + ": " + ex.what());
        }

        SignatureBundle bundle;
        bundle.source_path = path;
        bundle.engine_id   = doc.value("engine", "");
        bundle.module_hint = doc.value("module_hint", "");

        if (!doc.contains("signatures") || !doc["signatures"].is_array()) {
            return Error::make("Signature file has no 'signatures' array");
        }

        std::size_t idx = 0;
        for (const auto& s : doc["signatures"]) {
            if (!s.is_object()) {
                URA_LOG_WARN("Skipping non-object signature at index %zu", idx);
                ++idx;
                continue;
            }
            Signature sig;
            sig.name        = s.value("name", "");
            sig.pattern     = s.value("pattern", "");
            sig.description = s.value("description", "");
            sig.module_hint = s.value("module_hint", bundle.module_hint);

            const std::string xform = s.value("transform", "none");
            sig.transform        = parse_transform(xform);
            sig.transform_offset = s.value("transform_offset", 0);
            sig.post_offset      = s.value("post_offset", 0);

            if (sig.name.empty() || sig.pattern.empty()) {
                URA_LOG_WARN("Skipping signature with missing name/pattern "
                             "(idx=%zu) in %s", idx, path.string().c_str());
                ++idx;
                continue;
            }
            bundle.signatures.push_back(std::move(sig));
            ++idx;
        }

        URA_LOG_DEBUG("Loaded %zu signatures from %s",
                      bundle.signatures.size(), path.string().c_str());
        return bundle;
    }

    Result<SignatureBundle>
    SignatureLoader::load_for_engine(const fs::path& dir,
                                     std::string_view engine_id) {
        if (dir.empty()) {
            return Error::make("Signatures directory not provided");
        }
        const fs::path candidate = dir / (std::string(engine_id) + ".json");
        if (!fs::exists(candidate)) {
            return Error::make("Signature file not found: " + candidate.string());
        }
        return load_file(candidate);
    }

    fs::path SignatureLoader::default_signatures_dir() {
        const fs::path here = exe_dir();
        if (here.empty()) return {};

        // Development layout: bin sits at .../x64/Debug/ and signatures at
        // .../UniversalRuntimeAnalyzer/data/signatures/.
        // We walk up to four levels looking for the data folder so the same
        // exe works whether it was built into x64\Debug, Debug, or copied
        // alongside data\.
        for (fs::path p = here, prev; p != prev; prev = p, p = p.parent_path()) {
            const fs::path candidate = p / "UniversalRuntimeAnalyzer" /
                                       "data" / "signatures";
            if (fs::is_directory(candidate)) return candidate;
            const fs::path candidate2 = p / "data" / "signatures";
            if (fs::is_directory(candidate2)) return candidate2;
        }
        return {};
    }

} // namespace ura::analysis
