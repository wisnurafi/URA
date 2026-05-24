// engine/modules/EngineHelpers.hpp
// Small helpers shared by the concrete engine modules. Kept header-only so
// each engine file stays self-contained.
#pragma once

#include "../../analysis/PatternScanner.hpp"
#include "../../analysis/Signature.hpp"
#include "../../core/Logger.hpp"
#include "../../platform/PEParser.hpp"
#include "../AnalysisReport.hpp"
#include "../EngineContext.hpp"

#include <optional>
#include <string>
#include <vector>

namespace ura::engine::modules {

    // Build a ReportModule from a parsed PEImage. Engines call this to
    // populate AnalysisReport::modules.
    inline ReportModule make_report_module(const platform::PEImage& img) {
        ReportModule rm;
        rm.name            = img.module.name;
        rm.path            = img.module.full_path;
        rm.base            = img.module.base;
        rm.size            = img.module.size;
        rm.is_64bit        = img.is_64bit;
        rm.machine         = img.machine;
        rm.timestamp       = img.timestamp;
        rm.size_of_image   = img.size_of_image;
        rm.entry_point_rva = img.entry_point_rva;
        rm.sections.reserve(img.sections.size());
        for (const auto& s : img.sections) rm.sections.push_back(s.name);
        return rm;
    }

    // Run a signature, take the first hit, return a ReportOffset. Logs and
    // returns nullopt on miss; never throws.
    inline std::optional<ReportOffset>
    resolve_offset(const platform::MemoryReader& reader,
                   const platform::PEImage&      img,
                   const analysis::Signature&    sig,
                   std::string                   label) {
        analysis::PatternScanner scanner(reader);
        auto hits = scanner.scan_signature(img, sig);
        if (!hits) {
            URA_LOG_DEBUG("sig '%s' scan error: %s",
                          sig.name.c_str(), hits.error().message.c_str());
            return std::nullopt;
        }
        if (hits.value().empty()) {
            URA_LOG_DEBUG("sig '%s' produced no hits", sig.name.c_str());
            return std::nullopt;
        }
        const auto& h = hits.value().front();
        ReportOffset out;
        out.label       = std::move(label);
        out.absolute    = h.resolved;
        out.rva         = h.rva_in_module;
        out.module_name = img.module.name;
        out.notes       = sig.description;
        return out;
    }

} // namespace ura::engine::modules
