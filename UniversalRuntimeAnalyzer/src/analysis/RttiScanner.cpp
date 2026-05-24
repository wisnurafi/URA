// analysis/RttiScanner.cpp
#include "RttiScanner.hpp"

#include "../core/Logger.hpp"

#include <algorithm>
#include <cstring>
#include <unordered_set>

namespace ura::analysis {

    using core::Error;
    using core::Result;

    // ------------------------------------------------------------------
    // RTTI on-disk structures. We re-define the layouts here rather than
    // including <rttidata.h> (which isn't part of the public Windows SDK)
    // because we read them out of the target's memory directly.
    // ------------------------------------------------------------------
#pragma pack(push, 1)
    struct TypeDescriptor32 {
        std::uint32_t pVFTable;
        std::uint32_t spare;
        // followed by ASCIIZ name
    };
    struct TypeDescriptor64 {
        std::uint64_t pVFTable;
        std::uint64_t spare;
        // followed by ASCIIZ name
    };
    struct RCOL32 {
        std::uint32_t signature;     // 0 on x86
        std::uint32_t offset;
        std::uint32_t cdOffset;
        std::uint32_t pTypeDescriptor; // absolute on x86
        std::uint32_t pClassHierarchyDesc;
    };
    struct RCOL64 {
        std::uint32_t signature;     // 1 on x64
        std::uint32_t offset;
        std::uint32_t cdOffset;
        std::int32_t  pTypeDescriptor;     // RVA on x64
        std::int32_t  pClassHierarchyDesc; // RVA
        std::int32_t  pSelf;               // RVA of this RCOL itself
    };
#pragma pack(pop)

    namespace {

        bool in_section(const platform::PESection* s, core::Address a) {
            return s && a >= s->start && a < s->start + s->size;
        }

        bool ascii_print(unsigned char c) {
            return c >= 0x20 && c < 0x7F;
        }

        // Validate that addr looks like an RTTI TypeDescriptor: pointer-sized
        // pVFTable + pointer-sized spare followed by ASCII name starting
        // with `.?`. Returns the recovered name or empty string.
        std::string read_type_name(const platform::MemoryReader& r,
                                   core::Address td_addr,
                                   bool x64,
                                   std::size_t max_name_len = 384) {
            const std::size_t header = x64 ? sizeof(TypeDescriptor64)
                                           : sizeof(TypeDescriptor32);
            auto name_r = r.read_cstring(td_addr + header, max_name_len);
            if (!name_r) return {};
            const std::string& n = name_r.value();
            if (n.size() < 4) return {};
            if (n[0] != '.' || n[1] != '?') return {};
            for (char c : n) {
                if (!ascii_print(static_cast<unsigned char>(c))) return {};
            }
            return n;
        }

    } // namespace

    // ------------------------------------------------------------------
    // Best-effort demangler. We only care about the shape produced by
    // MSVC RTTI for class/struct names:
    //
    //   ".?AVName@@"           -> "class Name"
    //   ".?AUName@@"           -> "struct Name"
    //   ".?AVName@Namespace@@" -> "class Namespace::Name"
    //   ".?AVNested@Outer@@"   -> "class Outer::Nested"
    //
    // Anything more elaborate (templates with type args, references,
    // pointers, function pointers) is left as-is. UnDecorateSymbolName
    // could handle these, but pulls in dbghelp.dll and cross-bitness
    // semantics. Keeping it self-contained is closer to the educational
    // intent of the project.
    // ------------------------------------------------------------------
    std::string demangle_msvc_rtti(std::string_view mangled) {
        if (mangled.size() < 4) return std::string(mangled);
        if (mangled[0] != '.' || mangled[1] != '?') return std::string(mangled);
        if (mangled[2] != 'A') return std::string(mangled);

        std::string prefix;
        switch (mangled[3]) {
            case 'V': prefix = "class ";  break;
            case 'U': prefix = "struct "; break;
            default:  return std::string(mangled);
        }

        // Body lies between offset 4 and the trailing "@@".
        std::size_t end = mangled.size();
        if (end >= 2 && mangled[end - 1] == '@' && mangled[end - 2] == '@') {
            end -= 2;
        }
        if (end <= 4) return std::string(mangled);

        std::string_view body = mangled.substr(4, end - 4);

        // Split on '@' separators; MSVC stores names *innermost first*.
        std::vector<std::string> parts;
        std::size_t a = 0;
        for (std::size_t i = 0; i <= body.size(); ++i) {
            if (i == body.size() || body[i] == '@') {
                if (i > a) parts.emplace_back(body.substr(a, i - a));
                a = i + 1;
            }
        }
        if (parts.empty()) return std::string(mangled);

        // Reverse to get outer::inner order.
        std::reverse(parts.begin(), parts.end());
        std::string out = prefix + parts.front();
        for (std::size_t i = 1; i < parts.size(); ++i) {
            out += "::";
            out += parts[i];
        }
        return out;
    }

    // ------------------------------------------------------------------
    Result<std::vector<ClassRtti>>
    RttiScanner::scan(std::size_t max_classes) const {
        const platform::PESection* rdata = image_.find_section(".rdata");
        if (!rdata) return Error::make("Image has no .rdata section");
        const platform::PESection* text = image_.find_section(".text");
        if (!text) return Error::make("Image has no .text section");

        // Pull both sections best-effort.
        auto rdata_buf = reader_.read_raw_best_effort(rdata->start, rdata->size);
        if (rdata_buf.empty()) return Error::make(".rdata read returned no bytes");

        const bool x64 = image_.is_64bit;
        const std::size_t ptr_size = x64 ? 8u : 4u;
        const core::Address mod_lo = image_.module.base;
        const core::Address mod_hi = mod_lo + image_.size_of_image;

        std::vector<ClassRtti> out;
        out.reserve(64);

        // Track unique vftable RVAs so we don't list the same class twice
        // when the compiler emits multiple RCOLs (multiple inheritance).
        std::unordered_set<core::Rva> seen;

        // Scan .rdata at pointer-aligned strides for "RCOL pointer" slots.
        // A slot is a candidate when:
        //   - it points back into .rdata
        //   - the RCOL signature matches the bitness
        //   - the TypeDescriptor RVA is inside the module image
        //   - the recovered name starts with ".?A"
        for (std::size_t i = 0;
             i + ptr_size <= rdata_buf.size() && out.size() < max_classes;
             i += ptr_size)
        {
            core::Address ptr_value = 0;
            if (x64) {
                std::uint64_t v;
                std::memcpy(&v, rdata_buf.data() + i, sizeof(v));
                ptr_value = v;
            } else {
                std::uint32_t v;
                std::memcpy(&v, rdata_buf.data() + i, sizeof(v));
                ptr_value = v;
            }
            if (!in_section(rdata, ptr_value)) continue;

            // Possible RCOL. Read it.
            core::Address rcol_addr = ptr_value;
            core::Address td_addr   = 0;
            std::uint32_t inh_off   = 0;

            if (x64) {
                RCOL64 rc{};
                if (!reader_.read_into(rcol_addr, &rc, sizeof(rc))) continue;
                if (rc.signature != 1) continue;
                if (rc.pTypeDescriptor == 0) continue;
                td_addr = mod_lo + static_cast<std::uint32_t>(rc.pTypeDescriptor);
                inh_off = rc.offset;
                if (td_addr < mod_lo || td_addr >= mod_hi) continue;
            } else {
                RCOL32 rc{};
                if (!reader_.read_into(rcol_addr, &rc, sizeof(rc))) continue;
                if (rc.signature != 0) continue;
                if (rc.pTypeDescriptor == 0) continue;
                td_addr = static_cast<core::Address>(rc.pTypeDescriptor);
                inh_off = rc.offset;
                if (td_addr < mod_lo || td_addr >= mod_hi) continue;
            }

            std::string mangled = read_type_name(reader_, td_addr, x64);
            if (mangled.empty()) continue;

            ClassRtti cr;
            cr.mangled_name       = mangled;
            cr.demangled_name     = demangle_msvc_rtti(mangled);
            cr.rcol_address       = rcol_addr;
            cr.rcol_rva           = static_cast<core::Rva>(rcol_addr - mod_lo);
            cr.inheritance_offset = inh_off;

            // The RCOL pointer slot itself is vftable[-1]; vftable proper
            // begins one pointer later, at .rdata_offset + ptr_size.
            const core::Address vft_addr = rdata->start + i + ptr_size;
            cr.vftable_address = vft_addr;
            cr.vftable_rva     = static_cast<core::Rva>(vft_addr - mod_lo);

            // Count plausible vtable slots: read up to 256 pointers,
            // stop when one doesn't land in .text or is null.
            std::uint32_t slots = 0;
            for (std::uint32_t k = 0; k < 256; ++k) {
                const core::Address slot = vft_addr + static_cast<core::Address>(k) * ptr_size;
                core::Address fn = 0;
                if (x64) {
                    auto v = reader_.read<std::uint64_t>(slot);
                    if (!v) break;
                    fn = v.value();
                } else {
                    auto v = reader_.read<std::uint32_t>(slot);
                    if (!v) break;
                    fn = v.value();
                }
                if (fn == 0) break;
                if (!in_section(text, fn)) break;
                ++slots;
            }
            cr.method_count = slots;

            if (slots == 0) continue; // not a real vtable

            if (!seen.insert(cr.vftable_rva).second) continue;
            out.push_back(std::move(cr));
        }

        URA_LOG_DEBUG("RttiScanner: found %zu classes in %ls",
                      out.size(), image_.module.name.c_str());
        return out;
    }

} // namespace ura::analysis
