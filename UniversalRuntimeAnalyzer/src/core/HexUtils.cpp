// core/HexUtils.cpp
#include "HexUtils.hpp"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <iomanip>

namespace ura::core {

    std::string to_hex(std::uint64_t v, bool with_prefix, int min_width) {
        std::ostringstream os;
        if (with_prefix) os << "0x";
        os << std::hex << std::uppercase;
        if (min_width > 0) os << std::setw(min_width) << std::setfill('0');
        os << v;
        return os.str();
    }

    std::string bytes_to_hex(const std::uint8_t* data, std::size_t len) {
        static const char* digits = "0123456789ABCDEF";
        std::string out;
        out.resize(len * 2);
        for (std::size_t i = 0; i < len; ++i) {
            out[2 * i + 0] = digits[(data[i] >> 4) & 0xF];
            out[2 * i + 1] = digits[(data[i] >> 0) & 0xF];
        }
        return out;
    }

    static int hex_digit(char c) {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
        if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
        return -1;
    }

    std::optional<std::uint8_t> parse_hex_byte(std::string_view tok) {
        if (tok.size() == 0 || tok.size() > 2) return std::nullopt;
        int hi = (tok.size() == 2) ? hex_digit(tok[0]) : 0;
        int lo = hex_digit(tok.back());
        if (hi < 0 || lo < 0) return std::nullopt;
        return static_cast<std::uint8_t>((hi << 4) | lo);
    }

    std::optional<ParsedPattern> parse_ida_pattern(std::string_view pattern) {
        ParsedPattern out;
        std::size_t i = 0;
        while (i < pattern.size()) {
            // skip whitespace
            while (i < pattern.size() && std::isspace(static_cast<unsigned char>(pattern[i]))) ++i;
            if (i >= pattern.size()) break;

            // collect token until whitespace
            std::size_t start = i;
            while (i < pattern.size() && !std::isspace(static_cast<unsigned char>(pattern[i]))) ++i;
            std::string_view tok = pattern.substr(start, i - start);

            if (tok == "?" || tok == "??") {
                out.bytes.push_back(0x00);
                out.mask.push_back(0);
                continue;
            }
            // Allow "?X" / "X?" partial wildcards by treating any '?' as
            // wildcard for the whole byte (simpler, sufficient).
            if (tok.find('?') != std::string_view::npos) {
                out.bytes.push_back(0x00);
                out.mask.push_back(0);
                continue;
            }
            auto b = parse_hex_byte(tok);
            if (!b.has_value()) return std::nullopt;
            out.bytes.push_back(*b);
            out.mask.push_back(1);
        }
        if (out.bytes.empty()) return std::nullopt;
        return out;
    }

    std::string_view trim(std::string_view s) {
        std::size_t a = 0, b = s.size();
        while (a < b && std::isspace(static_cast<unsigned char>(s[a]))) ++a;
        while (b > a && std::isspace(static_cast<unsigned char>(s[b - 1]))) --b;
        return s.substr(a, b - a);
    }

    std::string to_lower(std::string_view s) {
        std::string out(s);
        std::transform(out.begin(), out.end(), out.begin(),
            [](unsigned char c){ return static_cast<char>(std::tolower(c)); });
        return out;
    }

} // namespace ura::core
