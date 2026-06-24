// export/JsonExporter.cpp
#include "JsonExporter.hpp"

#include "../core/HexUtils.hpp"
#include "../core/Logger.hpp"

#include <nlohmann/json.hpp>

#ifdef _WIN32
#  include <windows.h>
#endif

#include <chrono>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace ura::exporter {

    using core::Error;
    using core::Result;
    using nlohmann::json;

    namespace {

        // UTF-16 wstring → UTF-8 string. Best-effort; non-ASCII codepoints
        // outside the BMP would require WideCharToMultiByte but module
        // names/paths in our domain are ASCII or near-ASCII.
        std::string w2u(const std::wstring& w) {
            if (w.empty()) return {};
        #ifdef _WIN32
            int sz = ::WideCharToMultiByte(CP_UTF8, 0, w.data(),
                                           static_cast<int>(w.size()),
                                           nullptr, 0, nullptr, nullptr);
            if (sz <= 0) return {};
            std::string out(sz, '\0');
            ::WideCharToMultiByte(CP_UTF8, 0, w.data(),
                                  static_cast<int>(w.size()),
                                  out.data(), sz, nullptr, nullptr);
            return out;
        #else
            return std::string(w.begin(), w.end());
        #endif
        }

        std::string iso8601_now() {
            using namespace std::chrono;
            auto now = system_clock::now();
            auto t   = system_clock::to_time_t(now);
            std::tm tm{};
        #ifdef _WIN32
            gmtime_s(&tm, &t);
        #else
            gmtime_r(&t, &tm);
        #endif
            std::ostringstream os;
            os << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
            return os.str();
        }

        json module_to_json(const engine::ReportModule& m) {
            json j;
            j["name"]            = w2u(m.name);
            j["path"]            = w2u(m.path);
            j["base"]            = core::to_hex(m.base);
            j["size"]            = m.size;
            j["is_64bit"]        = m.is_64bit;
            j["machine"]         = core::to_hex(m.machine);
            j["timestamp"]       = m.timestamp;
            j["size_of_image"]   = m.size_of_image;
            j["entry_point_rva"] = core::to_hex(m.entry_point_rva);
            j["sections"]        = m.sections;
            return j;
        }

        json offset_to_json(const engine::ReportOffset& o) {
            json j;
            j["label"]    = o.label;
            j["absolute"] = core::to_hex(o.absolute);
            j["rva"]      = core::to_hex(o.rva);
            j["module"]   = w2u(o.module_name);
            j["notes"]    = o.notes;
            return j;
        }

        json build_root(const engine::AnalysisReport& r) {
            json root;
            root["tool"] = {
                { "name",           r.tool_name },
                { "version",        r.tool_version },
                { "schema_version", r.schema_version },
                { "generated_at",   iso8601_now() },
            };
            root["engine"] = {
                { "id",            r.engine_id },
                { "display_name",  r.engine_display_name },
                { "duration_ms",   static_cast<long long>(r.duration.count()) },
            };
            root["process"] = {
                { "pid",                   r.process.pid },
                { "name",                  w2u(r.process.name) },
                { "path",                  w2u(r.process.path) },
                { "is_wow64",              r.process.is_wow64 },
                { "bitness",               r.process.bitness },
                { "architecture",          r.process.architecture },
                { "analyzer_architecture", r.process.analyzer_architecture },
                { "native_architecture",   r.process.native_architecture },
            };

            json modules = json::array();
            for (const auto& m : r.modules) modules.push_back(module_to_json(m));
            root["modules"] = std::move(modules);

            json groups = json::array();
            for (const auto& g : r.groups) {
                json jg;
                jg["name"]    = g.name;
                jg["offsets"] = json::array();
                for (const auto& o : g.offsets) jg["offsets"].push_back(offset_to_json(o));
                groups.push_back(std::move(jg));
            }
            root["groups"] = std::move(groups);

            // Memory map: only emitted when the orchestrator captured one.
            if (r.memory_map.present) {
                json mm;
                mm["summary"] = {
                    { "total_regions",         r.memory_map.total_regions },
                    { "committed",             r.memory_map.committed },
                    { "reserved",              r.memory_map.reserved },
                    { "free",                  r.memory_map.free_regions },
                    { "executable",            r.memory_map.executable },
                    { "writable",              r.memory_map.writable },
                    { "rwx",                   r.memory_map.rwx },
                    { "image_regions",         r.memory_map.image_regions },
                    { "mapped_regions",        r.memory_map.mapped_regions },
                    { "private_regions",       r.memory_map.private_regions },
                    { "total_committed_bytes", r.memory_map.total_committed_bytes },
                };
                mm["anomalies"] = r.memory_map.anomalies;

                json regs = json::array();
                regs.get_ptr<json::array_t*>()->reserve(r.memory_map.regions.size());
                for (const auto& reg : r.memory_map.regions) {
                    json jr;
                    jr["base"]       = core::to_hex(reg.base);
                    jr["alloc_base"] = core::to_hex(reg.alloc_base);
                    jr["size"]       = reg.size;
                    jr["state"]      = reg.state;
                    jr["protect"]    = reg.protect;
                    jr["type"]       = reg.type;
                    regs.push_back(std::move(jr));
                }
                mm["regions"] = std::move(regs);
                root["memory_map"] = std::move(mm);
            }

            json notes = json::object();
            for (const auto& [k, v] : r.notes) notes[k] = v;
            root["notes"] = std::move(notes);

            // RTTI / vtable findings.
            if (!r.classes.empty()) {
                json arr = json::array();
                arr.get_ptr<json::array_t*>()->reserve(r.classes.size());
                for (const auto& c : r.classes) {
                    json jc;
                    jc["mangled"]            = c.mangled_name;
                    jc["demangled"]          = c.demangled_name;
                    jc["module"]             = w2u(c.module_name);
                    jc["rcol"]               = core::to_hex(c.rcol_address);
                    jc["rcol_rva"]           = core::to_hex(c.rcol_rva);
                    jc["vftable"]            = core::to_hex(c.vftable_address);
                    jc["vftable_rva"]        = core::to_hex(c.vftable_rva);
                    jc["inheritance_offset"] = c.inheritance_offset;
                    jc["method_count"]       = c.method_count;
                    arr.push_back(std::move(jc));
                }
                root["classes"] = std::move(arr);
            }

            root["warnings"] = r.warnings;

            // Static (disk-based) PE inspection. Only emitted when the
            // orchestrator ran the static fallback. Addresses are RVAs;
            // runtime absolute = module_base + rva.
            if (r.static_image.present) {
                json st;
                st["file_path"]            = w2u(r.static_image.file_path);
                st["file_name"]            = w2u(r.static_image.file_name);
                st["is_64bit"]             = r.static_image.is_64bit;
                st["machine"]              = core::to_hex(r.static_image.machine);
                st["timestamp"]            = r.static_image.timestamp;
                st["image_base_preferred"] = core::to_hex(r.static_image.image_base_preferred);
                st["size_of_image"]        = r.static_image.size_of_image;
                st["entry_point_rva"]      = core::to_hex(r.static_image.entry_point_rva);
                st["file_size_bytes"]      = r.static_image.file_size_bytes;
                st["sections"]             = r.static_image.sections;
                st["runtime_formula"]      = r.static_image.runtime_formula;

                json ex_arr = json::array();
                for (const auto& e : r.static_image.exports) {
                    json je;
                    je["name"]         = e.name;
                    je["ordinal"]      = e.ordinal;
                    je["rva"]          = core::to_hex(e.rva);
                    je["is_forwarder"] = e.is_forwarder;
                    if (e.is_forwarder) je["forwarder_target"] = e.forwarder_target;
                    ex_arr.push_back(std::move(je));
                }
                st["exports"] = std::move(ex_arr);
                root["static"] = std::move(st);
            }

            // Evidence-based acquisition diagnostic.
            // downstream tooling can branch on it without falling back to
            // string-matching the warnings array.
            const auto& acq = r.acquisition;
            json jacq;
            jacq["status"]                       = platform::to_string(acq.status);
            jacq["win32_error"]                  = acq.win32_error;
            jacq["analyzer_architecture"]        = core::to_string(acq.analyzer_architecture);
            jacq["target_architecture"]          = core::to_string(acq.target_architecture);
            jacq["native_architecture"]          = core::to_string(acq.native_architecture);
            jacq["process_handle_opened"]        = acq.process_handle_opened;
            jacq["process_query_succeeded"]      = acq.process_query_succeeded;
            jacq["module_enumeration_succeeded"] = acq.module_enumeration_succeeded;
            jacq["memory_read_succeeded"]        = acq.memory_read_succeeded;
            jacq["enumeration_attempts"]         = acq.enumeration_attempts;
            jacq["failed_api"]                   = acq.failed_api;
            jacq["failed_stage"]                 = acq.failed_stage;
            jacq["details"]                      = acq.details;
            jacq["recommended_action"]           = acq.recommended_action;
            root["acquisition"] = std::move(jacq);

            return root;
        }

    } // namespace

    std::string JsonExporter::to_string(const engine::AnalysisReport& r, bool pretty) {
        json root = build_root(r);
        return root.dump(pretty ? 2 : -1);
    }

    Result<void> JsonExporter::write_file(const engine::AnalysisReport& r,
                                          const std::string& path,
                                          bool pretty) {
        try {
            std::filesystem::path p(path);
            if (p.has_parent_path()) {
                std::error_code ec;
                std::filesystem::create_directories(p.parent_path(), ec);
                // ignore ec — failing here will surface on the open below
            }
            std::ofstream os(p, std::ios::binary | std::ios::trunc);
            if (!os) return Error::make("Failed to open output file: " + path);
            os << to_string(r, pretty);
            if (!os) return Error::make("Failed to write output file: " + path);
            URA_LOG_INFO("Wrote report: %s", path.c_str());
            return core::ok();
        } catch (const std::exception& ex) {
            return Error::make(std::string("JSON export exception: ") + ex.what());
        }
    }

} // namespace ura::exporter
