// analysis/PatternScanner.hpp
// Generic IDA-style byte pattern scanner over remote process memory.
//
// The scanner reads each PE section in chunks via MemoryReader and runs a
// masked-byte search. Sections without read access are skipped; unreadable
// pages inside a readable section are tolerated via best-effort reads.
#pragma once

#include "../core/Result.hpp"
#include "../core/Types.hpp"
#include "../platform/MemoryReader.hpp"
#include "../platform/PEParser.hpp"
#include "Signature.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace ura::analysis {

    struct ScanRange {
        core::Address start = 0;
        std::uint32_t size  = 0;

        // Cosmetic label, e.g. ".text" or "module range".
        std::string   label;
    };

    struct ScanHit {
        core::Address address = 0;          // raw match address (before transform)
        core::Address resolved = 0;         // address after transform/post_offset
        core::Rva     rva_in_module = 0;    // resolved - module.base, when applicable
        std::string   section;              // PE section name where the hit landed
    };

    class PatternScanner {
    public:
        explicit PatternScanner(const platform::MemoryReader& reader)
            : reader_(reader) {}

        // Build sensible default scan ranges from a parsed PE: every
        // executable section, plus .rdata for data-pattern sigs.
        static std::vector<ScanRange> default_ranges(const platform::PEImage& img);

        // Scan a single range. Returns every match.
        core::Result<std::vector<ScanHit>>
            scan(const ScanRange& range,
                 const std::vector<std::uint8_t>& bytes,
                 const std::vector<std::uint8_t>& mask) const;

        // Convenience: scan an entire PE image for a signature, applying
        // transforms automatically.
        core::Result<std::vector<ScanHit>>
            scan_signature(const platform::PEImage& img,
                           const Signature& sig) const;

    private:
        const platform::MemoryReader& reader_;
    };

} // namespace ura::analysis
