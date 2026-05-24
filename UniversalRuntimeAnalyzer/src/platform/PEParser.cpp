// platform/PEParser.cpp
#include "PEParser.hpp"

#include "../core/Logger.hpp"

#include <windows.h>
#include <winnt.h>

#include <algorithm>
#include <cstring>

namespace ura::platform {

    using core::Error;
    using core::Result;

    bool PESection::is_executable() const noexcept {
        return (characteristics & IMAGE_SCN_MEM_EXECUTE) != 0;
    }
    bool PESection::is_readable() const noexcept {
        return (characteristics & IMAGE_SCN_MEM_READ) != 0;
    }
    bool PESection::is_writable() const noexcept {
        return (characteristics & IMAGE_SCN_MEM_WRITE) != 0;
    }

    const PESection* PEImage::find_section(std::string_view name) const {
        for (const auto& s : sections) {
            if (s.name == name) return &s;
        }
        return nullptr;
    }

    const PEExport* PEImage::find_export(std::string_view name) const {
        for (const auto& e : exports) {
            if (e.name == name) return &e;
        }
        return nullptr;
    }

    namespace {

        // Read the export-name table out of an IMAGE_EXPORT_DIRECTORY.
        // Best-effort only: a single failure stops collection but doesn't
        // fail the whole parse.
        //
        // PE export layout we walk:
        //   AddressOfNames[i]        -> RVA of ASCIIZ name string
        //   AddressOfNameOrdinals[i] -> u16 ordinal index (0-based, into AddressOfFunctions)
        //   AddressOfFunctions[ord]  -> RVA of the actual function (or forwarder)
        //
        // If the function RVA falls inside the export directory range, the
        // entry is a forwarder; the RVA points to a "TARGET.Function" string.
        std::vector<PEExport>
        read_exports(const MemoryReader& reader, const ModuleInfo& mod,
                     core::Rva exp_dir_rva, std::uint32_t exp_dir_size) {
            std::vector<PEExport> out;
            if (exp_dir_rva == 0 || exp_dir_size == 0) return out;

            IMAGE_EXPORT_DIRECTORY ed{};
            if (!reader.read_into(mod.base + exp_dir_rva, &ed, sizeof(ed)))
                return out;

            if (ed.NumberOfNames == 0
             || ed.AddressOfNames == 0
             || ed.AddressOfNameOrdinals == 0
             || ed.AddressOfFunctions == 0) {
                return out;
            }

            std::vector<std::uint32_t> name_rvas(ed.NumberOfNames);
            if (!reader.read_into(mod.base + ed.AddressOfNames,
                                  name_rvas.data(),
                                  name_rvas.size() * sizeof(std::uint32_t)))
                return out;

            std::vector<std::uint16_t> ord_table(ed.NumberOfNames);
            if (!reader.read_into(mod.base + ed.AddressOfNameOrdinals,
                                  ord_table.data(),
                                  ord_table.size() * sizeof(std::uint16_t)))
                return out;

            std::vector<std::uint32_t> func_rvas(ed.NumberOfFunctions);
            if (!reader.read_into(mod.base + ed.AddressOfFunctions,
                                  func_rvas.data(),
                                  func_rvas.size() * sizeof(std::uint32_t)))
                return out;

            const core::Rva exp_lo = exp_dir_rva;
            const core::Rva exp_hi = exp_dir_rva + exp_dir_size;

            out.reserve(name_rvas.size());
            for (std::size_t i = 0; i < name_rvas.size(); ++i) {
                if (name_rvas[i] == 0) continue;
                auto name = reader.read_cstring(mod.base + name_rvas[i], 256);
                if (!name) continue;

                PEExport ex;
                ex.name    = std::move(name.value());
                ex.ordinal = ord_table[i];
                if (ex.ordinal < func_rvas.size()) {
                    ex.rva = func_rvas[ex.ordinal];
                    if (ex.rva >= exp_lo && ex.rva < exp_hi) {
                        ex.is_forwarder = true;
                        auto fwd = reader.read_cstring(mod.base + ex.rva, 256);
                        if (fwd) ex.forwarder_target = std::move(fwd.value());
                        ex.rva = 0; // forwarder has no local RVA
                    }
                }
                out.push_back(std::move(ex));
            }
            return out;
        }

    } // namespace

    Result<PEImage>
    PEParser::parse(const MemoryReader& reader, const ModuleInfo& mod,
                    bool include_exports) {
        PEImage img;
        img.module = mod;

        // 1. DOS header.
        IMAGE_DOS_HEADER dos{};
        if (auto r = reader.read_into(mod.base, &dos, sizeof(dos)); !r)
            return r.error();
        if (dos.e_magic != IMAGE_DOS_SIGNATURE)
            return Error::make("Not a PE image (bad DOS magic)");

        // 2. NT headers — read just enough to discover the bitness, then
        //    re-read the correct variant.
        DWORD nt_sig = 0;
        if (auto r = reader.read_into(mod.base + dos.e_lfanew,
                                      &nt_sig, sizeof(nt_sig)); !r)
            return r.error();
        if (nt_sig != IMAGE_NT_SIGNATURE)
            return Error::make("Not a PE image (bad NT signature)");

        IMAGE_FILE_HEADER fh{};
        if (auto r = reader.read_into(mod.base + dos.e_lfanew + sizeof(DWORD),
                                      &fh, sizeof(fh)); !r)
            return r.error();
        img.machine = fh.Machine;

        const bool is64 = (fh.Machine == IMAGE_FILE_MACHINE_AMD64
                        || fh.Machine == IMAGE_FILE_MACHINE_ARM64);
        img.is_64bit = is64;

        const core::Address opt_addr = mod.base + dos.e_lfanew
                                     + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
        core::Rva     export_dir_rva  = 0;
        std::uint32_t export_dir_size = 0;
        std::uint32_t section_align   = 0;
        (void)section_align;

        if (is64) {
            IMAGE_OPTIONAL_HEADER64 oh{};
            if (auto r = reader.read_into(opt_addr, &oh, sizeof(oh)); !r)
                return r.error();
            img.entry_point_rva = oh.AddressOfEntryPoint;
            img.size_of_image   = oh.SizeOfImage;
            if (oh.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) {
                export_dir_rva  = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                export_dir_size = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
            }
        } else {
            IMAGE_OPTIONAL_HEADER32 oh{};
            if (auto r = reader.read_into(opt_addr, &oh, sizeof(oh)); !r)
                return r.error();
            img.entry_point_rva = oh.AddressOfEntryPoint;
            img.size_of_image   = oh.SizeOfImage;
            if (oh.NumberOfRvaAndSizes > IMAGE_DIRECTORY_ENTRY_EXPORT) {
                export_dir_rva  = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
                export_dir_size = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
            }
        }

        img.timestamp = fh.TimeDateStamp;

        // 3. Section table follows the optional header.
        const core::Address sec_table = opt_addr + fh.SizeOfOptionalHeader;
        img.sections.reserve(fh.NumberOfSections);

        for (std::uint16_t i = 0; i < fh.NumberOfSections; ++i) {
            IMAGE_SECTION_HEADER sh{};
            if (auto r = reader.read_into(sec_table + i * sizeof(IMAGE_SECTION_HEADER),
                                          &sh, sizeof(sh)); !r)
                return r.error();

            PESection s;
            char name[9] = {};
            std::memcpy(name, sh.Name, 8);
            s.name             = name;
            s.rva              = sh.VirtualAddress;
            s.start            = mod.base + sh.VirtualAddress;
            // Misc.VirtualSize is the in-memory size; SizeOfRawData is on-disk.
            s.size             = sh.Misc.VirtualSize ? sh.Misc.VirtualSize
                                                     : sh.SizeOfRawData;
            s.characteristics  = sh.Characteristics;
            img.sections.push_back(std::move(s));
        }

        // 4. Exports (optional).
        if (include_exports) {
            img.exports = read_exports(reader, mod, export_dir_rva, export_dir_size);
        }

        URA_LOG_DEBUG("Parsed PE for %ls: %u sections, %zu exports, %s",
                      mod.name.c_str(),
                      static_cast<unsigned>(img.sections.size()),
                      img.exports.size(),
                      img.is_64bit ? "64-bit" : "32-bit");
        return img;
    }

} // namespace ura::platform
