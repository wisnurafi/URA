// analysis/XrefScanner.hpp
// Find every instruction in a module's .text section that references a
// given address, by decoding the small set of x86/x64 control-flow and
// data-load encodings that produce code refs:
//
//   x86 (32-bit):
//     E8 disp32        — CALL near, target = next_ip + disp32
//     E9 disp32        — JMP near,  target = next_ip + disp32
//     FF 15 [imm32]    — CALL [abs32], target = *imm32 (we report imm32)
//     FF 25 [imm32]    — JMP  [abs32], target = *imm32
//     B8..BF imm32     — MOV reg, imm32 (catch absolute address loads)
//     68 imm32         — PUSH imm32 (frequent for callback registration)
//
//   x86-64:
//     E8 disp32        — CALL near (rip-relative)
//     E9 disp32        — JMP near
//     48 8D 05 disp32  — LEA RAX, [rip+disp32]    (and other regs via ModRM)
//     48 8B 05 disp32  — MOV RAX, [rip+disp32]
//     FF 15 disp32     — CALL [rip+disp32]
//     FF 25 disp32     — JMP  [rip+disp32]
//
// We do NOT implement a real disassembler. The decoder walks bytes
// sequentially, recognises one of the encodings above, computes the
// effective target, advances by the encoding's length, and on any other
// byte simply advances by 1. False positives are tolerable (we only
// report references that match the queried target anyway), false
// negatives just lose xrefs we never decoded.
//
// This module is intentionally header-light; it depends only on
// PEParser + MemoryReader.
#pragma once

#include "../core/Result.hpp"
#include "../core/Types.hpp"
#include "../platform/MemoryReader.hpp"
#include "../platform/PEParser.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace ura::analysis {

    enum class XrefKind : std::uint8_t {
        CallNear,        // E8 disp32
        JmpNear,         // E9 disp32
        IndirectCall,    // FF 15 ...
        IndirectJmp,     // FF 25 ...
        LeaRipRel,       // 48 8D <ModRM> disp32
        MovRipRel,       // 48 8B <ModRM> disp32
        AbsoluteImm,     // mov/push imm32 (x86 only)
    };

    struct Xref {
        core::Address  from = 0;          // instruction address
        core::Address  to   = 0;          // resolved target address
        core::Rva      from_rva = 0;
        core::Rva      to_rva   = 0;      // 0 if target is outside the module
        XrefKind       kind = XrefKind::CallNear;
        std::string    kind_str;          // pre-decoded for the report
    };

    class XrefScanner {
    public:
        XrefScanner(const platform::MemoryReader& reader,
                    const platform::PEImage& image)
            : reader_(reader), image_(image) {}

        // Find every reference to `target` inside the .text section of the
        // image. `target` may be inside or outside this module; both are
        // detected because we resolve every encoding to an absolute
        // address before comparison.
        core::Result<std::vector<Xref>>
            find_refs_to(core::Address target,
                         std::size_t   max_results = 256) const;

    private:
        const platform::MemoryReader& reader_;
        const platform::PEImage&      image_;
    };

} // namespace ura::analysis
