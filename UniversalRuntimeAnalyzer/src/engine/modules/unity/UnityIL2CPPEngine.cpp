// engine/modules/unity/UnityIL2CPPEngine.cpp
#include "UnityIL2CPPEngine.hpp"

#include "../../../analysis/PatternScanner.hpp"
#include "../../../analysis/Signature.hpp"
#include "../../../analysis/SignatureLoader.hpp"
#include "../../../analysis/StringScanner.hpp"
#include "../../../core/Logger.hpp"
#include "../EngineHelpers.hpp"

#include <chrono>

namespace ura::engine::modules {

    using core::Error;
    using core::Result;
    using analysis::Signature;
    using analysis::HitTransform;

    namespace {

        // Curated list of IL2CPP runtime exports that are present on every
        // shipping IL2CPP build. Reporting these as RVAs gives downstream
        // tooling a stable starting point.
        constexpr const char* kIL2CPPExports[] = {
            "il2cpp_init",
            "il2cpp_shutdown",
            "il2cpp_domain_get",
            "il2cpp_domain_get_assemblies",
            "il2cpp_thread_attach",
            "il2cpp_thread_detach",
            "il2cpp_assembly_get_image",
            "il2cpp_image_get_class_count",
            "il2cpp_image_get_class",
            "il2cpp_class_from_name",
            "il2cpp_class_get_methods",
            "il2cpp_class_get_method_from_name",
            "il2cpp_class_get_field_from_name",
            "il2cpp_field_get_offset",
            "il2cpp_method_get_name",
            "il2cpp_string_new",
            "il2cpp_resolve_icall",
        };

        // Sample byte signatures for GameAssembly.dll. Real engine modules
        // would source these from data/signatures/unity_il2cpp.json; we keep a
        // couple inline so the code path is exercised even without an
        // external file. The patterns here are intentionally generic and
        // illustrative rather than tied to one Unity version.
        std::vector<Signature> sample_signatures() {
            std::vector<Signature> sigs;
            {
                Signature s;
                s.name        = "il2cpp_runtime_invoke_prologue";
                s.pattern     = "48 89 5C 24 ?? 48 89 74 24 ?? 57 48 83 EC 20";
                s.description = "Common x64 prologue used by IL2CPP runtime helpers";
                s.transform   = HitTransform::None;
                sigs.push_back(std::move(s));
            }
            {
                Signature s;
                s.name        = "rip_relative_global_lea";
                s.pattern     = "48 8D 0D ?? ?? ?? ??";          // LEA RCX,[rip+disp32]
                s.description = "Generic RIP-relative LEA, useful as a sanity-check on the scanner";
                s.transform        = HitTransform::RipRelative32;
                s.transform_offset = 3;                          // disp32 starts at +3
                sigs.push_back(std::move(s));
            }
            return sigs;
        }

    } // namespace

    bool UnityIL2CPPEngine::detect(const EngineContext& ctx) const {
        // Definitive marker: GameAssembly.dll loaded.
        const bool has_game_assembly = ctx.find_module(L"GameAssembly.dll") != nullptr;
        const bool has_unity_player  = ctx.find_module(L"UnityPlayer.dll")  != nullptr;
        return has_game_assembly && has_unity_player;
    }

    Result<AnalysisReport> UnityIL2CPPEngine::analyze(EngineContext& ctx) const {
        const auto t0 = std::chrono::steady_clock::now();

        AnalysisReport report;
        report.engine_id           = id();
        report.engine_display_name = display_name();

        const auto* game_assembly = ctx.find_module(L"GameAssembly.dll");
        const auto* unity_player  = ctx.find_module(L"UnityPlayer.dll");
        if (!game_assembly) return Error::make("GameAssembly.dll not loaded");

        // Parse PE headers for the modules of interest.
        auto ga_img_r = platform::PEParser::parse(ctx.reader, *game_assembly, /*exports=*/true);
        if (!ga_img_r) return ga_img_r.error();
        const auto ga_img = std::move(ga_img_r.value());

        report.modules.push_back(make_report_module(ga_img));

        std::optional<platform::PEImage> up_img;
        if (unity_player) {
            auto r = platform::PEParser::parse(ctx.reader, *unity_player, /*exports=*/false);
            if (r) {
                up_img = std::move(r.value());
                report.modules.push_back(make_report_module(*up_img));
            } else {
                report.warnings.push_back("Failed to parse UnityPlayer.dll: " + r.error().message);
            }
        } else {
            report.warnings.push_back("UnityPlayer.dll not found (some games statically link).");
        }

        // 1. Curated exports → RVAs.
        std::size_t exports_found = 0;
        for (const char* name : kIL2CPPExports) {
            const platform::PEExport* exp = ga_img.find_export(name);
            ReportOffset o;
            o.label       = name;
            o.module_name = ga_img.module.name;
            if (exp) {
                ++exports_found;
                if (exp->is_forwarder) {
                    o.absolute = 0;
                    o.rva      = 0;
                    o.notes    = "IL2CPP runtime export (forwarded -> "
                               + exp->forwarder_target + ")";
                } else {
                    o.absolute = ga_img.module.base + exp->rva;
                    o.rva      = exp->rva;
                    o.notes    = "IL2CPP runtime export (present, ordinal="
                               + std::to_string(exp->ordinal) + ")";
                }
            } else {
                o.absolute = 0;
                o.rva      = 0;
                o.notes    = "IL2CPP runtime export (NOT present in EAT)";
            }
            report.add_offset("il2cpp.exports", std::move(o));
        }
        const std::size_t exports_total = std::size(kIL2CPPExports);
        report.notes["il2cpp.exports_present"] =
            std::to_string(exports_found) + "/" + std::to_string(exports_total);
        report.notes["GameAssembly.dll.exports_in_eat"] =
            std::to_string(ga_img.exports.size());

        // 2. Sample signatures.
        // Prefer disk-loaded signatures (data/signatures/unity_il2cpp.json)
        // so analysts can update patterns without rebuilding. Fall back to
        // the inline samples if no signature file is present.
        std::vector<Signature> sigs = sample_signatures();
        std::string sig_source = "inline";
        {
            const auto sig_dir = analysis::SignatureLoader::default_signatures_dir();
            auto loaded = analysis::SignatureLoader::load_for_engine(sig_dir, id());
            if (loaded) {
                sigs = std::move(loaded.value().signatures);
                sig_source = "file:" + loaded.value().source_path.filename().string();
            } else {
                URA_LOG_DEBUG("IL2CPP signature file not loaded (%s); "
                              "using inline patterns",
                              loaded.error().message.c_str());
            }
        }
        report.notes["il2cpp.signatures_source"] = sig_source;

        std::size_t sigs_hit = 0;
        for (const auto& sig : sigs) {
            if (auto off = resolve_offset(ctx.reader, ga_img, sig,
                                          /*label=*/sig.name)) {
                report.add_offset("il2cpp.signatures", std::move(*off));
                ++sigs_hit;
            }
        }
        report.notes["il2cpp.signatures_hit"] =
            std::to_string(sigs_hit) + "/" + std::to_string(sigs.size());

        // 3. Modules counter.
        report.notes["il2cpp.modules_parsed"] =
            std::to_string(report.modules.size()) + "/" +
            (unity_player ? "2" : "1");

        // 3. String marker hunt — look for the IL2CPP banner inside GameAssembly.
        //    Not a hard guarantee but a useful integrity signal.
        {
            analysis::StringScanner ss(ctx.reader);
            auto hits = ss.find_ascii(ga_img, "Il2Cpp");
            if (hits && !hits.value().empty()) {
                report.notes["il2cpp.string_marker"] =
                    "Found 'Il2Cpp' string in GameAssembly.dll (" +
                    std::to_string(hits.value().size()) + " refs)";
            }
        }

        report.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0);
        return report;
    }

} // namespace ura::engine::modules
