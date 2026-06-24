// platform/StaticPELoader.cpp
#include "StaticPELoader.hpp"

#include "../core/Logger.hpp"

#include <windows.h>

#include <cstring>
#include <memory>

namespace ura::platform {

    using core::Error;
    using core::Result;

    namespace {

        // RAII wrappers so we don't leak handles on the error paths.
        struct FileHandle {
            HANDLE h = INVALID_HANDLE_VALUE;
            ~FileHandle() { if (h != INVALID_HANDLE_VALUE) ::CloseHandle(h); }
        };
        struct MappingHandle {
            HANDLE h = nullptr;
            ~MappingHandle() { if (h) ::CloseHandle(h); }
        };
        struct MappedView {
            const std::uint8_t* p = nullptr;
            ~MappedView() { if (p) ::UnmapViewOfFile(p); }
        };

        // Translate a file RVA to a file offset by walking the section
        // table. Returns 0 if the RVA falls outside every section's raw
        // file range (e.g. uninitialised .bss data).
        std::uint32_t rva_to_file_offset(core::Rva rva,
                                         const std::vector<StaticSection>& secs,
                                         const IMAGE_SECTION_HEADER* raw_secs,
                                         std::uint16_t section_count) {
            for (std::uint16_t i = 0; i < section_count; ++i) {
                const auto& s = raw_secs[i];
                const std::uint32_t va_start = s.VirtualAddress;
                const std::uint32_t va_end   = va_start +
                    (s.Misc.VirtualSize ? s.Misc.VirtualSize : s.SizeOfRawData);
                if (rva >= va_start && rva < va_end) {
                    const std::uint32_t delta = rva - va_start;
                    if (delta >= s.SizeOfRawData) return 0;
                    return s.PointerToRawData + delta;
                }
            }
            (void)secs;
            return 0;
        }

        // Read a NUL-terminated ASCII string at file offset `off`. Bounded
        // by `cap` to keep us inside the mapped view on a malformed file.
        std::string read_cstr(const std::uint8_t* base,
                              std::uint64_t cap,
                              std::uint32_t off,
                              std::size_t max_len = 512) {
            if (off == 0 || off >= cap) return {};
            const std::uint8_t* p   = base + off;
            const std::uint8_t* end = base + std::min<std::uint64_t>(off + max_len, cap);
            const std::uint8_t* z   = p;
            while (z < end && *z) ++z;
            return std::string(reinterpret_cast<const char*>(p),
                               static_cast<std::size_t>(z - p));
        }

        std::wstring file_name_of(const std::wstring& path) {
            const auto pos = path.find_last_of(L"\\/");
            if (pos == std::wstring::npos) return path;
            return path.substr(pos + 1);
        }

        // Parse the export directory from a flat (non-SEC_IMAGE) mapping.
        // The export tables are RVAs that index INTO the loaded image,
        // not into the file — we translate every one through the section
        // table to a file offset.
        bool parse_exports(const std::uint8_t* base,
                           std::uint64_t file_size,
                           const IMAGE_SECTION_HEADER* raw_secs,
                           std::uint16_t section_count,
                           const std::vector<StaticSection>& secs,
                           std::uint32_t export_dir_rva,
                           std::uint32_t export_dir_size,
                           std::vector<StaticExport>& out) {
            if (export_dir_rva == 0 || export_dir_size == 0) return true;

            const std::uint32_t dir_off =
                rva_to_file_offset(export_dir_rva, secs, raw_secs, section_count);
            if (dir_off == 0 || dir_off + sizeof(IMAGE_EXPORT_DIRECTORY) > file_size) {
                return false;
            }
            IMAGE_EXPORT_DIRECTORY ed;
            std::memcpy(&ed, base + dir_off, sizeof(ed));

            const std::uint32_t funcs_off =
                rva_to_file_offset(ed.AddressOfFunctions, secs, raw_secs, section_count);
            const std::uint32_t names_off =
                rva_to_file_offset(ed.AddressOfNames, secs, raw_secs, section_count);
            const std::uint32_t ords_off =
                rva_to_file_offset(ed.AddressOfNameOrdinals, secs, raw_secs, section_count);
            if (funcs_off == 0) return false;

            // Build ordinal → name lookup. AddressOfNames is parallel to
            // AddressOfNameOrdinals; the ordinal array indexes into the
            // function table.
            std::vector<std::string> name_for(ed.NumberOfFunctions);
            if (names_off && ords_off
                && names_off + ed.NumberOfNames * 4 <= file_size
                && ords_off + ed.NumberOfNames * 2 <= file_size) {
                for (std::uint32_t i = 0; i < ed.NumberOfNames; ++i) {
                    std::uint32_t name_rva = 0;
                    std::memcpy(&name_rva, base + names_off + i * 4, 4);
                    std::uint16_t fn_idx = 0;
                    std::memcpy(&fn_idx, base + ords_off + i * 2, 2);
                    if (fn_idx >= ed.NumberOfFunctions) continue;
                    const std::uint32_t name_off =
                        rva_to_file_offset(name_rva, secs, raw_secs, section_count);
                    name_for[fn_idx] = read_cstr(base, file_size, name_off);
                }
            }

            // Now walk the function table proper. Forwarder detection: per
            // MSDN, an export RVA that falls inside the export directory
            // range itself is a forwarder string, not a function pointer.
            const std::uint32_t fwd_lo = export_dir_rva;
            const std::uint32_t fwd_hi = export_dir_rva + export_dir_size;

            out.reserve(ed.NumberOfFunctions);
            for (std::uint32_t i = 0; i < ed.NumberOfFunctions; ++i) {
                if (funcs_off + (i + 1) * 4 > file_size) break;
                std::uint32_t fn_rva = 0;
                std::memcpy(&fn_rva, base + funcs_off + i * 4, 4);
                if (fn_rva == 0) continue;   // unused ordinal slot

                StaticExport e;
                e.ordinal = static_cast<std::uint16_t>(ed.Base + i);
                e.name    = name_for[i];

                if (fn_rva >= fwd_lo && fn_rva < fwd_hi) {
                    e.is_forwarder = true;
                    const std::uint32_t fwd_off =
                        rva_to_file_offset(fn_rva, secs, raw_secs, section_count);
                    e.forwarder_target = read_cstr(base, file_size, fwd_off);
                    e.rva = fn_rva;  // points at the forwarder string
                } else {
                    e.rva = fn_rva;
                }
                out.push_back(std::move(e));
            }
            return true;
        }

    } // namespace

    Result<StaticPEImage> StaticPELoader::load(const std::wstring& path) {
        FileHandle file;
        file.h = ::CreateFileW(path.c_str(),
                               GENERIC_READ,
                               FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                               nullptr,
                               OPEN_EXISTING,
                               FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                               nullptr);
        if (file.h == INVALID_HANDLE_VALUE) {
            const DWORD err = ::GetLastError();
            return Error::make("CreateFileW failed (err=" +
                               std::to_string(err) + ")",
                               static_cast<int>(err));
        }

        LARGE_INTEGER size{};
        if (!::GetFileSizeEx(file.h, &size) || size.QuadPart <= 0) {
            return Error::make("GetFileSizeEx failed");
        }
        const std::uint64_t file_size = static_cast<std::uint64_t>(size.QuadPart);
        if (file_size > (1ULL << 31)) {
            return Error::make("PE file too large for static fallback (>2GiB)");
        }

        MappingHandle mapping;
        mapping.h = ::CreateFileMappingW(file.h, nullptr, PAGE_READONLY,
                                         0, 0, nullptr);
        if (!mapping.h) {
            const DWORD err = ::GetLastError();
            return Error::make("CreateFileMappingW failed (err=" +
                               std::to_string(err) + ")",
                               static_cast<int>(err));
        }

        MappedView view;
        view.p = static_cast<const std::uint8_t*>(
            ::MapViewOfFile(mapping.h, FILE_MAP_READ, 0, 0, 0));
        if (!view.p) {
            const DWORD err = ::GetLastError();
            return Error::make("MapViewOfFile failed (err=" +
                               std::to_string(err) + ")",
                               static_cast<int>(err));
        }
        const std::uint8_t* base = view.p;

        // Sanity: DOS header.
        if (file_size < sizeof(IMAGE_DOS_HEADER)) {
            return Error::make("File too small for IMAGE_DOS_HEADER");
        }
        IMAGE_DOS_HEADER dos;
        std::memcpy(&dos, base, sizeof(dos));
        if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
            return Error::make("Not a PE file (bad MZ signature)");
        }
        if (dos.e_lfanew <= 0
            || static_cast<std::uint64_t>(dos.e_lfanew) + 4 + sizeof(IMAGE_FILE_HEADER) > file_size) {
            return Error::make("e_lfanew out of range");
        }

        std::uint32_t pe_sig = 0;
        std::memcpy(&pe_sig, base + dos.e_lfanew, 4);
        if (pe_sig != IMAGE_NT_SIGNATURE) {
            return Error::make("Not a PE file (bad NT signature)");
        }

        IMAGE_FILE_HEADER fh;
        std::memcpy(&fh, base + dos.e_lfanew + 4, sizeof(fh));

        StaticPEImage img;
        img.file_path = path;
        img.file_name = file_name_of(path);
        img.machine   = fh.Machine;
        img.timestamp = fh.TimeDateStamp;
        img.is_64bit  = (fh.Machine == IMAGE_FILE_MACHINE_AMD64
                      || fh.Machine == IMAGE_FILE_MACHINE_ARM64);
        img.file_size_bytes = file_size;

        const std::uint32_t opt_off = dos.e_lfanew + 4 + sizeof(IMAGE_FILE_HEADER);
        std::uint32_t export_dir_rva  = 0;
        std::uint32_t export_dir_size = 0;
        if (img.is_64bit) {
            if (opt_off + sizeof(IMAGE_OPTIONAL_HEADER64) > file_size) {
                return Error::make("Optional header (PE32+) truncated");
            }
            IMAGE_OPTIONAL_HEADER64 oh;
            std::memcpy(&oh, base + opt_off, sizeof(oh));
            img.image_base_preferred = oh.ImageBase;
            img.size_of_image        = oh.SizeOfImage;
            img.entry_point_rva      = oh.AddressOfEntryPoint;
            export_dir_rva  = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            export_dir_size = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        } else {
            if (opt_off + sizeof(IMAGE_OPTIONAL_HEADER32) > file_size) {
                return Error::make("Optional header (PE32) truncated");
            }
            IMAGE_OPTIONAL_HEADER32 oh;
            std::memcpy(&oh, base + opt_off, sizeof(oh));
            img.image_base_preferred = oh.ImageBase;
            img.size_of_image        = oh.SizeOfImage;
            img.entry_point_rva      = oh.AddressOfEntryPoint;
            export_dir_rva  = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
            export_dir_size = oh.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
        }

        // Section table follows the optional header.
        const std::uint32_t sec_off = opt_off + fh.SizeOfOptionalHeader;
        const std::uint16_t sec_count = fh.NumberOfSections;
        if (sec_off + sec_count * sizeof(IMAGE_SECTION_HEADER) > file_size) {
            return Error::make("Section table truncated");
        }
        std::vector<IMAGE_SECTION_HEADER> raw_secs(sec_count);
        std::memcpy(raw_secs.data(), base + sec_off,
                    sec_count * sizeof(IMAGE_SECTION_HEADER));

        img.sections.reserve(sec_count);
        for (std::uint16_t i = 0; i < sec_count; ++i) {
            StaticSection s;
            char name[9] = {};
            std::memcpy(name, raw_secs[i].Name, 8);
            s.name           = name;
            s.rva            = raw_secs[i].VirtualAddress;
            s.virtual_size   = raw_secs[i].Misc.VirtualSize;
            s.raw_size       = raw_secs[i].SizeOfRawData;
            s.characteristics = raw_secs[i].Characteristics;
            img.sections.push_back(std::move(s));
        }

        if (!parse_exports(base, file_size, raw_secs.data(), sec_count,
                           img.sections, export_dir_rva, export_dir_size,
                           img.exports)) {
            URA_LOG_WARN("[STATIC] Export directory parse failed for %ls",
                         path.c_str());
            // Not fatal; the rest of the image is still usable.
        }

        URA_LOG_INFO("[STATIC] Loaded PE %ls — %zu section(s), %zu export(s), "
                     "is_64bit=%d entry_rva=0x%08X",
                     img.file_name.c_str(),
                     img.sections.size(),
                     img.exports.size(),
                     img.is_64bit ? 1 : 0,
                     img.entry_point_rva);
        return img;
    }

} // namespace ura::platform
