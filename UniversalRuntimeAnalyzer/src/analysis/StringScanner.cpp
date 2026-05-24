// analysis/StringScanner.cpp
#include "StringScanner.hpp"

#include "../core/Logger.hpp"

#include <cstring>

namespace ura::analysis {

    using core::Error;
    using core::Result;

    namespace {
        std::vector<std::size_t>
        find_substr(const std::uint8_t* hay, std::size_t hay_len,
                    const std::uint8_t* needle, std::size_t needle_len) {
            std::vector<std::size_t> hits;
            if (needle_len == 0 || hay_len < needle_len) return hits;
            const std::size_t end = hay_len - needle_len;
            for (std::size_t i = 0; i <= end; ++i) {
                if (std::memcmp(hay + i, needle, needle_len) == 0)
                    hits.push_back(i);
            }
            return hits;
        }

        bool section_relevant_for_strings(const platform::PESection& s) {
            if (!s.is_readable() || s.is_executable()) return false;
            // Common containers for string literals.
            return s.name == ".rdata" || s.name == ".data" || s.name == ".rodata"
                || s.name == "rdata"  || s.name == "data";
        }
    } // namespace

    Result<std::vector<StringHit>>
    StringScanner::find_ascii(const platform::PEImage& img,
                              std::string_view needle) const {
        if (needle.empty()) return Error::make("Empty needle");
        std::vector<StringHit> out;

        for (const auto& s : img.sections) {
            if (!section_relevant_for_strings(s)) continue;
            auto buf = reader_.read_raw_best_effort(s.start, s.size);
            if (buf.empty()) continue;

            auto hits = find_substr(buf.data(), buf.size(),
                reinterpret_cast<const std::uint8_t*>(needle.data()),
                needle.size());

            for (auto off : hits) {
                StringHit h;
                h.address = s.start + off;
                h.value   = std::string(needle);
                h.section = s.name;
                out.push_back(std::move(h));
            }
        }
        URA_LOG_TRACE("find_ascii(%.*s): %zu hits",
                      static_cast<int>(needle.size()), needle.data(), out.size());
        return out;
    }

    Result<std::vector<StringHit>>
    StringScanner::find_utf16(const platform::PEImage& img,
                              std::wstring_view needle) const {
        if (needle.empty()) return Error::make("Empty needle");
        std::vector<StringHit> out;
        const auto* nbytes = reinterpret_cast<const std::uint8_t*>(needle.data());
        const auto  nlen   = needle.size() * sizeof(wchar_t);

        // ASCII-narrowing of the needle for the report. UTF-16 needles
        // outside ASCII would lose information here, but they're invalid
        // for our typical use case (banner strings, ASCII identifiers).
        std::string narrow_value;
        narrow_value.reserve(needle.size());
        for (wchar_t c : needle) narrow_value.push_back(static_cast<char>(c & 0x7F));

        for (const auto& s : img.sections) {
            if (!section_relevant_for_strings(s)) continue;
            auto buf = reader_.read_raw_best_effort(s.start, s.size);
            if (buf.empty()) continue;

            auto hits = find_substr(buf.data(), buf.size(), nbytes, nlen);
            for (auto off : hits) {
                StringHit h;
                h.address = s.start + off;
                h.value   = narrow_value;
                h.is_wide = true;
                h.section = s.name;
                out.push_back(std::move(h));
            }
        }
        return out;
    }

} // namespace ura::analysis
