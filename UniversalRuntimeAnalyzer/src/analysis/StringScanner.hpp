// analysis/StringScanner.hpp
// Search a remote module's read-only data sections for ASCII / UTF-16
// string literals. Engine modules commonly use string xrefs ("Assembly-CSharp")
// to bootstrap structural analysis.
#pragma once

#include "../core/Result.hpp"
#include "../core/Types.hpp"
#include "../platform/MemoryReader.hpp"
#include "../platform/PEParser.hpp"

#include <string>
#include <vector>

namespace ura::analysis {

    struct StringHit {
        core::Address address = 0;
        std::string   value;       // UTF-8 (ASCII strings stored as-is)
        bool          is_wide = false;
        std::string   section;
    };

    class StringScanner {
    public:
        explicit StringScanner(const platform::MemoryReader& reader)
            : reader_(reader) {}

        // Find every occurrence of `needle` (ASCII) inside readable sections
        // of the image. Length-prefixed and null-terminated strings are both
        // detected because we look for the substring; callers refine.
        core::Result<std::vector<StringHit>>
            find_ascii(const platform::PEImage& img, std::string_view needle) const;

        // Find every occurrence of `needle` interpreted as UTF-16LE.
        core::Result<std::vector<StringHit>>
            find_utf16(const platform::PEImage& img, std::wstring_view needle) const;

    private:
        const platform::MemoryReader& reader_;
    };

} // namespace ura::analysis
