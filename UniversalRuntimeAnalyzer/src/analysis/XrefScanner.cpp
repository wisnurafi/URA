// analysis/XrefScanner.cpp
#include "XrefScanner.hpp"

#include "../core/Logger.hpp"

#include <cstring>

namespace ura::analysis {

    using core::Error;
    using core::Result;

    namespace {

        // Read a little-endian 32-bit value from buf[i].
        inline std::int32_t read_disp32(const std::uint8_t* p) {
            std::int32_t v;
            std::memcpy(&v, p, sizeof(v));
            return v;
        }
        inline std::uint32_t read_u32(const std::uint8_t* p) {
            std::uint32_t v;
            std::memcpy(&v, p, sizeof(v));
            return v;
        }

        const char* kind_to_str(XrefKind k) {
            switch (k) {
                case XrefKind::CallNear:     return "CALL_NEAR";
                case XrefKind::JmpNear:      return "JMP_NEAR";
                case XrefKind::IndirectCall: return "CALL_INDIRECT";
                case XrefKind::IndirectJmp:  return "JMP_INDIRECT";
                case XrefKind::LeaRipRel:    return "LEA_RIP_REL";
                case XrefKind::MovRipRel:    return "MOV_RIP_REL";
                case XrefKind::AbsoluteImm:  return "ABS_IMM";
            }
            return "?";
        }

    } // namespace

    Result<std::vector<Xref>>
    XrefScanner::find_refs_to(core::Address target, std::size_t max_results) const {
        const platform::PESection* text = image_.find_section(".text");
        if (!text) return Error::make("Image has no .text section");

        // Read the whole .text best-effort. For shipped game binaries this
        // is usually 1-50 MB; well within memory budget for an offline tool.
        auto buf = reader_.read_raw_best_effort(text->start, text->size);
        if (buf.size() < 8) return Error::make(".text read returned too few bytes");

        const std::uint8_t* data = buf.data();
        const std::size_t   len  = buf.size();
        const core::Address base = image_.module.base;
        const core::Address mod_lo = base;
        const core::Address mod_hi = base + image_.size_of_image;
        const bool          x64    = image_.is_64bit;

        std::vector<Xref> hits;
        hits.reserve(64);

        // Linear walk. The decoder advances by the encoding length on a
        // recognised opcode, otherwise by 1 byte. This deliberately treats
        // .text as raw bytes rather than instruction stream — fine for our
        // sparse encoding subset, and matches how IDA-style sig scanners
        // work in practice.
        for (std::size_t i = 0; i + 5 <= len && hits.size() < max_results; ) {
            const std::uint8_t b0 = data[i];

            // E8/E9 disp32 — relative call/jmp, both x86 and x64.
            if (b0 == 0xE8 || b0 == 0xE9) {
                const std::int32_t disp = read_disp32(data + i + 1);
                const core::Address ip_after = text->start + i + 5;
                const core::Address tgt = ip_after + static_cast<std::int64_t>(disp);
                if (tgt == target) {
                    Xref x;
                    x.from = text->start + i;
                    x.to   = tgt;
                    x.from_rva = static_cast<core::Rva>(x.from - base);
                    x.to_rva   = (tgt >= mod_lo && tgt < mod_hi)
                               ? static_cast<core::Rva>(tgt - base) : 0;
                    x.kind = (b0 == 0xE8) ? XrefKind::CallNear : XrefKind::JmpNear;
                    x.kind_str = kind_to_str(x.kind);
                    hits.push_back(std::move(x));
                }
                i += 5;
                continue;
            }

            // FF 15 disp32 / FF 25 disp32 — indirect call / jmp.
            // x86: disp32 is absolute pointer to a function pointer.
            // x64: disp32 is RIP-relative offset to a function pointer.
            if (b0 == 0xFF && i + 6 <= len &&
                (data[i + 1] == 0x15 || data[i + 1] == 0x25)) {
                const std::int32_t disp = read_disp32(data + i + 2);
                core::Address ptr_addr;
                if (x64) {
                    const core::Address ip_after = text->start + i + 6;
                    ptr_addr = ip_after + static_cast<std::int64_t>(disp);
                } else {
                    ptr_addr = static_cast<core::Address>(static_cast<std::uint32_t>(disp));
                }
                // Read the pointer to get the actual target.
                core::Address tgt = 0;
                if (x64) {
                    if (auto v = reader_.read<std::uint64_t>(ptr_addr); v) tgt = v.value();
                } else {
                    if (auto v = reader_.read<std::uint32_t>(ptr_addr); v) tgt = v.value();
                }
                if (tgt == target) {
                    Xref x;
                    x.from = text->start + i;
                    x.to   = tgt;
                    x.from_rva = static_cast<core::Rva>(x.from - base);
                    x.to_rva   = (tgt >= mod_lo && tgt < mod_hi)
                               ? static_cast<core::Rva>(tgt - base) : 0;
                    x.kind = (data[i + 1] == 0x15)
                           ? XrefKind::IndirectCall : XrefKind::IndirectJmp;
                    x.kind_str = kind_to_str(x.kind);
                    hits.push_back(std::move(x));
                }
                i += 6;
                continue;
            }

            // x64-only RIP-relative LEA / MOV with REX.W prefix.
            // 48 8D <ModRM> disp32   — LEA r64, [rip+disp32] when ModRM.mod=00, rm=101
            // 48 8B <ModRM> disp32   — MOV r64, [rip+disp32] same condition
            if (x64 && b0 == 0x48 && i + 7 <= len &&
                (data[i + 1] == 0x8D || data[i + 1] == 0x8B)) {
                const std::uint8_t modrm = data[i + 2];
                // mod==00 (binary 00xxxxxx) and rm==101 (lower 3 bits == 5)
                if ((modrm & 0xC7) == 0x05) {
                    const std::int32_t disp = read_disp32(data + i + 3);
                    const core::Address ip_after = text->start + i + 7;
                    const core::Address tgt = ip_after + static_cast<std::int64_t>(disp);
                    if (tgt == target) {
                        Xref x;
                        x.from = text->start + i;
                        x.to   = tgt;
                        x.from_rva = static_cast<core::Rva>(x.from - base);
                        x.to_rva   = (tgt >= mod_lo && tgt < mod_hi)
                                   ? static_cast<core::Rva>(tgt - base) : 0;
                        x.kind = (data[i + 1] == 0x8D)
                               ? XrefKind::LeaRipRel : XrefKind::MovRipRel;
                        x.kind_str = kind_to_str(x.kind);
                        hits.push_back(std::move(x));
                    }
                    i += 7;
                    continue;
                }
            }

            // x86-only: absolute imm32 hidden in MOV reg,imm32 (B8..BF) and
            // PUSH imm32 (68 imm32). Only meaningful for 32-bit targets;
            // matches a common pattern for callback registration where the
            // function address is loaded as a constant.
            if (!x64) {
                if (b0 >= 0xB8 && b0 <= 0xBF && i + 5 <= len) {
                    const std::uint32_t imm = read_u32(data + i + 1);
                    if (static_cast<core::Address>(imm) == target) {
                        Xref x;
                        x.from = text->start + i;
                        x.to   = imm;
                        x.from_rva = static_cast<core::Rva>(x.from - base);
                        x.to_rva   = (target >= mod_lo && target < mod_hi)
                                   ? static_cast<core::Rva>(target - base) : 0;
                        x.kind = XrefKind::AbsoluteImm;
                        x.kind_str = kind_to_str(x.kind);
                        hits.push_back(std::move(x));
                    }
                    i += 5;
                    continue;
                }
                if (b0 == 0x68 && i + 5 <= len) {
                    const std::uint32_t imm = read_u32(data + i + 1);
                    if (static_cast<core::Address>(imm) == target) {
                        Xref x;
                        x.from = text->start + i;
                        x.to   = imm;
                        x.from_rva = static_cast<core::Rva>(x.from - base);
                        x.to_rva   = (target >= mod_lo && target < mod_hi)
                                   ? static_cast<core::Rva>(target - base) : 0;
                        x.kind = XrefKind::AbsoluteImm;
                        x.kind_str = kind_to_str(x.kind);
                        hits.push_back(std::move(x));
                    }
                    i += 5;
                    continue;
                }
            }

            ++i;
        }

        URA_LOG_DEBUG("XrefScanner: %zu refs to 0x%llX in %ls/.text",
                      hits.size(), static_cast<unsigned long long>(target),
                      image_.module.name.c_str());
        return hits;
    }

} // namespace ura::analysis
