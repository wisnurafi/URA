// analysis/PatternScanner.cpp
#include "PatternScanner.hpp"

#include "../core/HexUtils.hpp"
#include "../core/Logger.hpp"

#include <algorithm>
#include <cstring>

namespace ura::analysis {

    using core::Error;
    using core::Result;

    std::vector<ScanRange>
    PatternScanner::default_ranges(const platform::PEImage& img) {
        std::vector<ScanRange> out;
        out.reserve(img.sections.size());
        for (const auto& s : img.sections) {
            if (!s.is_readable()) continue;
            // Default: scan every readable section. Engines that want tighter
            // scopes pass their own range list.
            ScanRange r;
            r.start = s.start;
            r.size  = s.size;
            r.label = s.name;
            out.push_back(r);
        }
        return out;
    }

    namespace {

        // Naive masked search: O(n*m). Sufficient for ~100 MB modules and
        // short patterns; can be upgraded to Boyer-Moore-Horspool later.
        std::vector<std::size_t>
        find_all(const std::uint8_t* hay, std::size_t hay_len,
                 const std::uint8_t* pat, const std::uint8_t* mask,
                 std::size_t pat_len) {
            std::vector<std::size_t> hits;
            if (pat_len == 0 || hay_len < pat_len) return hits;
            const std::size_t end = hay_len - pat_len;
            for (std::size_t i = 0; i <= end; ++i) {
                bool match = true;
                for (std::size_t j = 0; j < pat_len; ++j) {
                    if (mask[j] && hay[i + j] != pat[j]) {
                        match = false;
                        break;
                    }
                }
                if (match) hits.push_back(i);
            }
            return hits;
        }

    } // namespace

    Result<std::vector<ScanHit>>
    PatternScanner::scan(const ScanRange& range,
                         const std::vector<std::uint8_t>& bytes,
                         const std::vector<std::uint8_t>& mask) const {
        if (bytes.empty() || bytes.size() != mask.size())
            return Error::make("Invalid pattern (empty or mask mismatch)");
        if (range.size == 0) return std::vector<ScanHit>{};

        // Read the whole range best-effort so we can scan even when some
        // pages are not committed.
        auto buf = reader_.read_raw_best_effort(range.start, range.size);
        if (buf.size() < bytes.size()) {
            URA_LOG_TRACE("scan: range %s too small after read (%zu)",
                          range.label.c_str(), buf.size());
            return std::vector<ScanHit>{};
        }

        auto matches = find_all(buf.data(), buf.size(),
                                bytes.data(), mask.data(), bytes.size());

        std::vector<ScanHit> hits;
        hits.reserve(matches.size());
        for (auto m : matches) {
            ScanHit h;
            h.address  = range.start + m;
            h.resolved = h.address;
            h.section  = range.label;
            hits.push_back(h);
        }
        return hits;
    }

    Result<std::vector<ScanHit>>
    PatternScanner::scan_signature(const platform::PEImage& img,
                                   const Signature& sig) const {
        auto parsed = core::parse_ida_pattern(sig.pattern);
        if (!parsed) return Error::make("Invalid pattern in signature: " + sig.name);

        const auto ranges = default_ranges(img);
        std::vector<ScanHit> all;

        for (const auto& r : ranges) {
            auto res = scan(r, parsed->bytes, parsed->mask);
            if (!res) {
                URA_LOG_TRACE("scan range %s failed: %s",
                              r.label.c_str(), res.error().message.c_str());
                continue;
            }
            for (auto h : res.value()) all.push_back(std::move(h));
        }

        // Apply transforms and compute RVAs in module.
        for (auto& h : all) {
            const core::Address ref_at = h.address + sig.transform_offset;
            switch (sig.transform) {
                case HitTransform::None:
                    h.resolved = h.address + sig.post_offset;
                    break;
                case HitTransform::RipRelative32: {
                    auto disp = reader_.read<std::int32_t>(ref_at);
                    if (disp) {
                        // RIP at the byte AFTER the disp32.
                        h.resolved = ref_at + 4 + disp.value() + sig.post_offset;
                    } else {
                        h.resolved = 0;
                    }
                } break;
                case HitTransform::Absolute32: {
                    auto v = reader_.read<std::uint32_t>(ref_at);
                    h.resolved = v ? (static_cast<core::Address>(v.value())
                                       + sig.post_offset)
                                   : 0;
                } break;
                case HitTransform::Absolute64: {
                    auto v = reader_.read<std::uint64_t>(ref_at);
                    h.resolved = v ? (v.value() + sig.post_offset) : 0;
                } break;
            }
            if (h.resolved >= img.module.base
             && h.resolved <  img.module.base + img.size_of_image) {
                h.rva_in_module = static_cast<core::Rva>(h.resolved - img.module.base);
            }
        }

        return all;
    }

} // namespace ura::analysis
