// analysis/OffsetResolver.hpp
// Higher-level helpers for turning a signature hit into a labeled offset.
//
// Engine modules use this to express things like "the global g_GameAssembly
// is the RIP-relative target of the LEA at hit+3, expressed as an RVA in
// GameAssembly.dll".
#pragma once

#include "../core/Result.hpp"
#include "../core/Types.hpp"
#include "../platform/MemoryReader.hpp"
#include "../platform/PEParser.hpp"
#include "PatternScanner.hpp"

#include <optional>
#include <string>

namespace ura::analysis {

    struct ResolvedOffset {
        std::string   label;             // e.g. "g_il2cpp_domain"
        core::Address absolute = 0;      // resolved absolute address
        core::Rva     rva      = 0;      // RVA inside owning module
        std::wstring  module_name;       // owning module
        std::string   notes;             // optional note for the report
    };

    class OffsetResolver {
    public:
        OffsetResolver(const platform::MemoryReader& reader,
                       const platform::PEImage&      image)
            : reader_(reader), image_(image) {}

        // Run a signature against the image, take the FIRST hit, label it.
        // Returns nullopt if there are zero matches; returns an Error if the
        // pattern itself is malformed.
        core::Result<std::optional<ResolvedOffset>>
            resolve_first(const Signature& sig,
                          std::string_view label) const;

    private:
        const platform::MemoryReader& reader_;
        const platform::PEImage&      image_;
    };

} // namespace ura::analysis
