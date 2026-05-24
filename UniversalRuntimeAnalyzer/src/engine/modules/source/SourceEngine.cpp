// engine/modules/source/SourceEngine.cpp
#include "SourceEngine.hpp"

#include "../../../analysis/StringScanner.hpp"
#include "../../../core/Logger.hpp"
#include "../EngineHelpers.hpp"

#include <chrono>
#include <string>

namespace ura::engine::modules {

    using core::Error;
    using core::Result;

    namespace {
        // Module names are ASCII; safe narrow conversion.
        std::string narrow_ascii(std::wstring_view w) {
            std::string out;
            out.reserve(w.size());
            for (wchar_t c : w) out.push_back(static_cast<char>(c & 0x7F));
            return out;
        }
        // Modules that ship with virtually every Source-based title.
        constexpr const wchar_t* kCoreModules[] = {
            L"engine.dll",
            L"client.dll",
            L"server.dll",
            L"tier0.dll",
            L"vstdlib.dll",
            L"materialsystem.dll",
            L"vguimatsurface.dll",
        };

        // The single export every Source module exposes for interface
        // registration.
        constexpr const char* kInterfaceExport = "CreateInterface";
    } // namespace

    bool SourceEngine::detect(const EngineContext& ctx) const {
        // Source signature: tier0.dll + engine.dll, both loaded.
        return ctx.find_module(L"tier0.dll")  != nullptr
            && ctx.find_module(L"engine.dll") != nullptr;
    }

    Result<AnalysisReport> SourceEngine::analyze(EngineContext& ctx) const {
        const auto t0 = std::chrono::steady_clock::now();

        AnalysisReport report;
        report.engine_id           = id();
        report.engine_display_name = display_name();

        std::size_t parsed = 0;
        std::size_t ci_present = 0;
        std::size_t total_exports_seen = 0;
        for (const wchar_t* name : kCoreModules) {
            const auto* mod = ctx.find_module(name);
            if (!mod) {
                report.warnings.push_back("Module not loaded (Source): " + narrow_ascii(name));
                continue;
            }
            auto pe_r = platform::PEParser::parse(ctx.reader, *mod, /*exports=*/true);
            if (!pe_r) {
                report.warnings.push_back("PE parse failed for a Source module");
                continue;
            }
            const auto pe = std::move(pe_r.value());
            report.modules.push_back(make_report_module(pe));
            ++parsed;
            total_exports_seen += pe.exports.size();

            // Record presence + RVA of the canonical CreateInterface export.
            ReportOffset o;
            o.label       = kInterfaceExport;
            o.module_name = pe.module.name;
            const platform::PEExport* exp = pe.find_export(kInterfaceExport);
            if (exp) {
                ++ci_present;
                if (exp->is_forwarder) {
                    o.absolute = 0;
                    o.rva      = 0;
                    o.notes    = "CreateInterface forwarded -> "
                               + exp->forwarder_target;
                } else {
                    o.absolute = pe.module.base + exp->rva;
                    o.rva      = exp->rva;
                    o.notes    = "CreateInterface export present (ordinal="
                               + std::to_string(exp->ordinal) + ")";
                }
            } else {
                o.absolute = 0;
                o.rva      = 0;
                o.notes    = "CreateInterface export NOT present";
            }
            report.add_offset("source.create_interface", std::move(o));

            // Per-module export count.
            report.notes[narrow_ascii(pe.module.name) + ".exports_in_eat"] =
                std::to_string(pe.exports.size());

            // Banner heuristic.
            analysis::StringScanner ss(ctx.reader);
            if (auto h = ss.find_ascii(pe, "Source"); h && !h.value().empty()) {
                report.notes["source.banner." + narrow_ascii(pe.module.name)] =
                    std::to_string(h.value().size()) + " 'Source' string refs";
            }
        }

        report.notes["source.modules_parsed"] =
            std::to_string(parsed) + "/" + std::to_string(std::size(kCoreModules));
        report.notes["source.create_interface_present"] =
            std::to_string(ci_present) + "/" + std::to_string(parsed);
        report.notes["source.total_exports_seen"] =
            std::to_string(total_exports_seen);

        report.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0);
        return report;
    }

} // namespace ura::engine::modules
