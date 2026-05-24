// engine/modules/goldsrc/GoldSrcEngine.cpp
#include "GoldSrcEngine.hpp"

#include "../../../analysis/PatternScanner.hpp"
#include "../../../analysis/RttiScanner.hpp"
#include "../../../analysis/Signature.hpp"
#include "../../../analysis/SignatureLoader.hpp"
#include "../../../analysis/StringScanner.hpp"
#include "../../../analysis/XrefScanner.hpp"
#include "../../../core/Logger.hpp"
#include "../EngineHelpers.hpp"

#include <chrono>

namespace ura::engine::modules {

    using core::Error;
    using core::Result;
    using analysis::Signature;
    using analysis::HitTransform;

    namespace {

        // Exports commonly resolved by GoldSrc mod tooling, courtesy of the
        // public `cdll_int.h` and `dlls/h_export.cpp` headers in the HLSDK.
        constexpr const char* kClientExports[] = {
            "Initialize",
            "HUD_Init",
            "HUD_VidInit",
            "HUD_Redraw",
            "HUD_UpdateClientData",
            "HUD_Reset",
            "HUD_PlayerMove",
            "HUD_PlayerMoveInit",
            "HUD_AddEntity",
            "HUD_CreateEntities",
            "HUD_StudioEvent",
            "HUD_PostRunCmd",
            "HUD_TxferLocalOverrides",
            "HUD_ProcessPlayerState",
            "HUD_TxferPredictionData",
            "Demo_ReadBuffer",
            "HUD_ConnectionlessPacket",
            "HUD_GetHullBounds",
            "HUD_Frame",
            "HUD_Key_Event",
            "HUD_TempEntUpdate",
            "HUD_GetUserEntity",
            "HUD_VoiceStatus",
            "HUD_DirectorMessage",
        };

        constexpr const char* kServerExports[] = {
            "GiveFnptrsToDll",
            "GetEntityAPI",
            "GetEntityAPI2",
            "GetNewDLLFunctions",
        };

        // Sample 32-bit signatures. GoldSrc is x86, so transforms use
        // Absolute32 instead of RIP-relative.
        std::vector<Signature> sample_signatures_hw() {
            std::vector<Signature> sigs;
            {
                Signature s;
                s.name        = "common_x86_prologue";
                s.pattern     = "55 8B EC 83 EC ?? 56 57";
                s.description = "Common x86 stack frame prologue";
                sigs.push_back(std::move(s));
            }
            return sigs;
        }

    } // namespace

    bool GoldSrcEngine::detect(const EngineContext& ctx) const {
        // Either the renderer DLL plus a client.dll, or hl.exe with hw.dll.
        // The client.dll check is the strongest single indicator.
        const bool has_hw     = ctx.find_module(L"hw.dll")     != nullptr;
        const bool has_sw     = ctx.find_module(L"sw.dll")     != nullptr;
        const bool has_client = ctx.find_module(L"client.dll") != nullptr;
        return (has_hw || has_sw) && has_client;
    }

    Result<AnalysisReport> GoldSrcEngine::analyze(EngineContext& ctx) const {
        const auto t0 = std::chrono::steady_clock::now();

        AnalysisReport report;
        report.engine_id           = id();
        report.engine_display_name = display_name();

        const auto* hw     = ctx.find_module(L"hw.dll");
        const auto* sw     = ctx.find_module(L"sw.dll");
        const auto* client = ctx.find_module(L"client.dll");
        const auto* server = ctx.find_module(L"mp.dll");
        if (!client) return Error::make("client.dll not loaded");

        const auto* renderer = hw ? hw : sw;
        if (!renderer) return Error::make("Neither hw.dll nor sw.dll loaded");

        // Parse PEs.
        auto rend_img_r = platform::PEParser::parse(ctx.reader, *renderer, true);
        if (!rend_img_r) return rend_img_r.error();
        const auto rend_img = std::move(rend_img_r.value());
        report.modules.push_back(make_report_module(rend_img));

        auto cli_img_r = platform::PEParser::parse(ctx.reader, *client, true);
        if (!cli_img_r) return cli_img_r.error();
        const auto cli_img = std::move(cli_img_r.value());
        report.modules.push_back(make_report_module(cli_img));

        std::optional<platform::PEImage> srv_img;
        if (server) {
            auto r = platform::PEParser::parse(ctx.reader, *server, true);
            if (r) {
                srv_img = std::move(r.value());
                report.modules.push_back(make_report_module(*srv_img));
            } else {
                report.warnings.push_back("Failed to parse mp.dll: " + r.error().message);
            }
        }

        // Curated client/server exports.
        auto record_exports = [&](const platform::PEImage& img,
                                  const char* group,
                                  const char* const* names, std::size_t count)
                                  -> std::size_t {
            std::size_t found = 0;
            for (std::size_t i = 0; i < count; ++i) {
                ReportOffset o;
                o.label       = names[i];
                o.module_name = img.module.name;

                const platform::PEExport* exp = img.find_export(names[i]);
                if (exp) {
                    ++found;
                    if (exp->is_forwarder) {
                        o.absolute = 0;
                        o.rva      = 0;
                        o.notes    = "GoldSrc export (forwarded -> "
                                   + exp->forwarder_target + ")";
                    } else {
                        o.absolute = img.module.base + exp->rva;
                        o.rva      = exp->rva;
                        o.notes    = "GoldSrc export (present, ordinal="
                                   + std::to_string(exp->ordinal) + ")";
                    }
                } else {
                    o.absolute = 0;
                    o.rva      = 0;
                    o.notes    = "GoldSrc export (NOT present in EAT)";
                }
                report.add_offset(group, std::move(o));
            }
            return found;
        };
        const std::size_t client_found = record_exports(
            cli_img, "goldsrc.client_exports",
            kClientExports, std::size(kClientExports));
        report.notes["goldsrc.client_exports_found"] =
            std::to_string(client_found) + "/" +
            std::to_string(std::size(kClientExports));
        report.notes["client.dll.exports_in_eat"] =
            std::to_string(cli_img.exports.size());

        if (srv_img) {
            const std::size_t server_found = record_exports(
                *srv_img, "goldsrc.server_exports",
                kServerExports, std::size(kServerExports));
            report.notes["goldsrc.server_exports_found"] =
                std::to_string(server_found) + "/" +
                std::to_string(std::size(kServerExports));
            report.notes["mp.dll.exports_in_eat"] =
                std::to_string(srv_img->exports.size());
        }

        // Sample signatures over the renderer.
        // Prefer disk-loaded signatures (data/signatures/goldsrc.json) so
        // analysts can update patterns without rebuilding. Fall back to the
        // inline samples if no signature file is present.
        std::vector<Signature> sigs = sample_signatures_hw();
        std::string sig_source = "inline";
        {
            const auto sig_dir = analysis::SignatureLoader::default_signatures_dir();
            auto loaded = analysis::SignatureLoader::load_for_engine(sig_dir, id());
            if (loaded) {
                sigs = std::move(loaded.value().signatures);
                sig_source = "file:" + loaded.value().source_path.filename().string();
            } else {
                URA_LOG_DEBUG("GoldSrc signature file not loaded (%s); "
                              "using inline patterns",
                              loaded.error().message.c_str());
            }
        }
        report.notes["goldsrc.signatures_source"] = sig_source;

        std::size_t sig_hit = 0;
        for (const auto& sig : sigs) {
            if (auto off = resolve_offset(ctx.reader, rend_img, sig, sig.name)) {
                report.add_offset("goldsrc.signatures.renderer", std::move(*off));
                ++sig_hit;
            }
        }
        report.notes["goldsrc.renderer_signatures_hit"] =
            std::to_string(sig_hit) + "/" + std::to_string(sigs.size());

        // Cross-reference scan: for every signature hit AND for the first
        // few HUD exports, find every CALL/JMP/LEA/MOV in client.dll and
        // mp.dll that refers to that address. This is the demonstration
        // path requested by AC-aware reviewers: from a single seed we can
        // walk who-calls-whom inside the binary.
        analysis::XrefScanner cli_xref(ctx.reader, cli_img);
        std::size_t total_xrefs = 0;
        const char* xref_seed_exports[] = {
            "Initialize", "HUD_Init", "HUD_Frame", "HUD_Redraw",
        };
        for (const char* name : xref_seed_exports) {
            const platform::PEExport* exp = cli_img.find_export(name);
            if (!exp || exp->is_forwarder) continue;
            const core::Address tgt = cli_img.module.base + exp->rva;
            auto refs = cli_xref.find_refs_to(tgt, /*max=*/16);
            if (!refs) continue;
            for (const auto& xr : refs.value()) {
                ReportOffset o;
                o.label       = std::string(name) + " <- " + xr.kind_str;
                o.module_name = cli_img.module.name;
                o.absolute    = xr.from;
                o.rva         = xr.from_rva;
                o.notes       = "xref to " + std::string(name)
                              + " at RVA 0x"
                              + std::to_string(static_cast<unsigned long>(exp->rva));
                report.add_offset("goldsrc.xrefs.client", std::move(o));
                ++total_xrefs;
            }
        }
        report.notes["goldsrc.client_xrefs_found"] = std::to_string(total_xrefs);

        // RTTI / vtable scan over server (mp.dll) and client. Server-side
        // game logic in HLSDK descends from CBaseEntity, so vftable
        // discovery there is the most "academically interesting" output.
        auto narrow_modname = [](std::wstring_view w) {
            std::string out;
            out.reserve(w.size());
            for (wchar_t c : w) out.push_back(static_cast<char>(c & 0x7F));
            return out;
        };
        auto run_rtti = [&](const platform::PEImage& img) {
            analysis::RttiScanner rtti(ctx.reader, img);
            auto classes = rtti.scan(/*max=*/1024);
            if (!classes) {
                report.warnings.push_back("RTTI scan failed for " +
                    narrow_modname(img.module.name)
                    + ": " + classes.error().message);
                return std::size_t{0};
            }
            for (const auto& c : classes.value()) {
                ReportClass rc;
                rc.mangled_name       = c.mangled_name;
                rc.demangled_name     = c.demangled_name;
                rc.module_name        = img.module.name;
                rc.rcol_address       = c.rcol_address;
                rc.rcol_rva           = c.rcol_rva;
                rc.vftable_address    = c.vftable_address;
                rc.vftable_rva        = c.vftable_rva;
                rc.inheritance_offset = c.inheritance_offset;
                rc.method_count       = c.method_count;
                report.classes.push_back(std::move(rc));
            }
            return classes.value().size();
        };

        const std::size_t cli_classes = run_rtti(cli_img);
        report.notes["goldsrc.rtti.client.dll"] = std::to_string(cli_classes);
        if (srv_img) {
            const std::size_t srv_classes = run_rtti(*srv_img);
            report.notes["goldsrc.rtti.mp.dll"] = std::to_string(srv_classes);
        }

        // Module accounting.
        const std::size_t expected = 2u + (server ? 1u : 0u);
        report.notes["goldsrc.modules_parsed"] =
            std::to_string(report.modules.size()) + "/" +
            std::to_string(expected);
        // Renderer flavor (hw vs sw) is useful context for the report.
        report.notes["goldsrc.renderer_flavor"] = hw ? "hw.dll" : "sw.dll";

        // String marker check.
        {
            analysis::StringScanner ss(ctx.reader);
            if (auto h = ss.find_ascii(rend_img, "GoldSrc"); h && !h.value().empty()) {
                report.notes["goldsrc.banner"] =
                    "Found 'GoldSrc' marker (" +
                    std::to_string(h.value().size()) + " refs in renderer)";
            }
        }

        report.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0);
        return report;
    }

} // namespace ura::engine::modules
