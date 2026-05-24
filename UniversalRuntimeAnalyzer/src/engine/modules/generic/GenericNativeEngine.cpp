// engine/modules/generic/GenericNativeEngine.cpp
#include "GenericNativeEngine.hpp"

#include "../../../core/Logger.hpp"
#include "../EngineHelpers.hpp"

#include <chrono>
#include <string>

namespace ura::engine::modules {

    using core::Error;
    using core::Result;

    namespace {
        std::string narrow_ascii(std::wstring_view w) {
            std::string out;
            out.reserve(w.size());
            for (wchar_t c : w) out.push_back(static_cast<char>(c & 0x7F));
            return out;
        }
    } // namespace

    Result<AnalysisReport>
    GenericNativeEngine::analyze(EngineContext& ctx) const {
        const auto t0 = std::chrono::steady_clock::now();

        AnalysisReport report;
        report.engine_id           = id();
        report.engine_display_name = display_name();

        std::size_t parsed = 0;
        std::size_t failed = 0;

        // Parse every module so the JSON dump captures the full layout.
        for (const auto& m : ctx.modules) {
            auto pe = platform::PEParser::parse(ctx.reader, m, /*exports=*/false);
            if (!pe) {
                ++failed;
                report.warnings.push_back("PE parse failed: " + narrow_ascii(m.name)
                                          + " — " + pe.error().message);
                continue;
            }
            report.modules.push_back(make_report_module(pe.value()));
            ++parsed;
        }

        const std::size_t total = ctx.modules.size();
        report.notes["generic.modules_parsed"] =
            std::to_string(parsed) + "/" + std::to_string(total);
        if (failed > 0) {
            report.notes["generic.modules_failed"] = std::to_string(failed);
        }

        // Aggregate bitness counters — useful when introspecting WOW64 hosts
        // that load both 32 and 64-bit images.
        std::size_t b32 = 0, b64 = 0;
        for (const auto& m : report.modules) {
            (m.is_64bit ? b64 : b32)++;
        }
        report.notes["generic.modules_64bit"] = std::to_string(b64);
        report.notes["generic.modules_32bit"] = std::to_string(b32);

        report.duration = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - t0);
        return report;
    }

} // namespace ura::engine::modules
