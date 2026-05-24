// analysis/RttiScanner.hpp
// Discover MSVC C++ RTTI metadata and class vtables in a remote PE image.
//
// MSVC layout (read-only, well-documented in OpenRCE / WinDbg):
//
//   For every class with virtual methods, the compiler emits in .rdata:
//
//     TypeDescriptor (TD) {
//       void*    pVFTable;        // RTTI vftable for type_info
//       void*    spare;
//       char     name[1];         // ASCIIZ mangled name, e.g. ".?AVCFoo@@"
//     }
//
//     ClassHierarchyDescriptor (CHD) {
//       u32 signature;            // 0
//       u32 attributes;           // bit0=multiple inheritance, bit1=virtual
//       u32 numBaseClasses;
//       i32 pBaseClassArray;      // RVA (x64) / abs (x86) -> CBA[]
//     }
//
//     CompleteObjectLocator (RCOL) {
//       u32 signature;            // 0 on x86, 1 on x64
//       u32 offset;               // offset of this vftable in complete object
//       u32 cdOffset;             // ctor disp offset
//       i32 pTypeDescriptor;      // RVA (x64) / abs (x86) -> TD
//       i32 pClassHierarchyDesc;  // RVA (x64) / abs (x86) -> CHD
//       i32 pSelf;                // x64 only: RVA of this RCOL itself
//     }
//
//   And the vftable layout:
//
//     vftable[-1]  -> pointer to RCOL (in .rdata)
//     vftable[ 0]  -> first virtual function (in .text)
//     vftable[ 1]  -> second virtual function
//     ...
//
// Strategy: walk .rdata at pointer-aligned strides looking for entries
// that point inside .rdata (candidate RCOL pointer). Validate by reading
// the RCOL, checking signature, dereferencing the TypeDescriptor, and
// recovering the mangled name. Once an RCOL is confirmed, the location
// of the pointer itself is `vftable[-1]`, so the vftable is at
// `rcol_ptr_addr + ptr_size`.
//
// We do NOT walk every base class in CHD/CBA — that's deeper than the
// educational scope needs. We collect:
//   - the demangled class name (best effort)
//   - the vftable RVA
//   - count of plausible vtable slots before hitting a non-.text pointer
#pragma once

#include "../core/Result.hpp"
#include "../core/Types.hpp"
#include "../platform/MemoryReader.hpp"
#include "../platform/PEParser.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace ura::analysis {

    struct ClassRtti {
        std::string   mangled_name;        // e.g. ".?AVCBaseEntity@@"
        std::string   demangled_name;      // best-effort, e.g. "class CBaseEntity"
        core::Address rcol_address = 0;    // address of RCOL struct in .rdata
        core::Rva     rcol_rva     = 0;
        core::Address vftable_address = 0; // address of first vtable slot
        core::Rva     vftable_rva     = 0;
        std::uint32_t inheritance_offset = 0; // RCOL.offset
        std::uint32_t method_count = 0;    // # plausible vtable slots
    };

    class RttiScanner {
    public:
        RttiScanner(const platform::MemoryReader& reader,
                    const platform::PEImage& image)
            : reader_(reader), image_(image) {}

        // Scan .rdata for RCOL pointers and recover class metadata.
        // `max_classes` caps the result count so misbehaving inputs can't
        // blow up the report.
        core::Result<std::vector<ClassRtti>>
            scan(std::size_t max_classes = 4096) const;

    private:
        const platform::MemoryReader& reader_;
        const platform::PEImage&      image_;
    };

    // Best-effort MSVC name unmangler for the ".?AVName@@" / ".?AUName@@"
    // forms used by RTTI TypeDescriptors. Returns the input unchanged if
    // the name doesn't match the expected shape.
    std::string demangle_msvc_rtti(std::string_view mangled);

} // namespace ura::analysis
