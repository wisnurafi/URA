// core/HexUtils.hpp
// Hex/string helpers used by the pattern scanner and the JSON exporter.
#pragma once

#include "Types.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace ura::core {

    // Format a 64-bit address as "0x0000_0001_4000_0000".
    std::string to_hex(std::uint64_t v, bool with_prefix = true, int min_width = 0);

    // Encode raw bytes as a continuous hex string ("DEADBEEF").
    std::string bytes_to_hex(const std::uint8_t* data, std::size_t len);

    // Parse a hex byte ("FF") into a value, or nullopt on failure.
    std::optional<std::uint8_t> parse_hex_byte(std::string_view tok);

    // Parse an IDA-style signature ("48 8B ?? ?? ?? ?? 90") into
    // (bytes, mask). `mask[i] != 0` means the byte at i is significant.
    // We use std::uint8_t (not bool) so the mask buffer is contiguous —
    // std::vector<bool> is a bit-packed specialization and cannot be used
    // with raw-pointer scan loops.
    // Whitespace separates tokens; '?' or '??' marks a wildcard byte.
    struct ParsedPattern {
        std::vector<std::uint8_t> bytes;
        std::vector<std::uint8_t> mask;
    };
    std::optional<ParsedPattern> parse_ida_pattern(std::string_view pattern);

    // Trim ASCII whitespace.
    std::string_view trim(std::string_view s);

    // Lowercase ASCII copy.
    std::string to_lower(std::string_view s);

} // namespace ura::core
