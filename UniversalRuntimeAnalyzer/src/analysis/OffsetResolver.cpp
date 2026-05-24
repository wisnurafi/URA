// analysis/OffsetResolver.cpp
#include "OffsetResolver.hpp"

#include "../core/Logger.hpp"

namespace ura::analysis {

    using core::Error;
    using core::Result;

    Result<std::optional<ResolvedOffset>>
    OffsetResolver::resolve_first(const Signature& sig,
                                  std::string_view label) const {
        PatternScanner scanner(reader_);
        auto hits = scanner.scan_signature(image_, sig);
        if (!hits) return hits.error();

        if (hits.value().empty()) {
            URA_LOG_DEBUG("Signature '%s' produced 0 hits", sig.name.c_str());
            return std::optional<ResolvedOffset>{};
        }
        if (hits.value().size() > 1) {
            URA_LOG_WARN("Signature '%s' is ambiguous (%zu hits) — using first",
                         sig.name.c_str(), hits.value().size());
        }

        const auto& h = hits.value().front();
        ResolvedOffset r;
        r.label       = std::string(label);
        r.absolute    = h.resolved;
        r.rva         = h.rva_in_module;
        r.module_name = image_.module.name;
        return std::optional<ResolvedOffset>{ std::move(r) };
    }

} // namespace ura::analysis
