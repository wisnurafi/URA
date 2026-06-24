// app/Orchestrator.hpp
// Shared Analyze pipeline used by both the CLI and the GUI frontends.
//
// Consolidates what used to be duplicated logic across CliApp::cmd_analyze
// and GuiApp::run_analysis: PID resolve → handle open → architecture
// detect → module enumeration → memory map → engine pick → engine analyze.
//
// Always returns a fully populated AnalysisReport, even when acquisition
// fails partway through. The `acquisition` field of the report names the
// concrete failure mode (ArchitectureMismatch, AccessDenied,
// LoaderTransition, ...) so UI/JSON consumers don't have to interpret a
// free-form error string.
#pragma once

#include "../engine/AnalysisReport.hpp"
#include "../engine/EngineRegistry.hpp"

#include <optional>
#include <string>

namespace ura::app {

    struct AnalyzeRequest {
        // One of these two must be set. PID wins if both are present.
        std::optional<std::uint32_t> pid;
        std::optional<std::wstring>  process_name;

        // Empty / nullopt = auto-detect.
        std::optional<std::string>   engine_id;
    };

    struct AnalyzeOutcome {
        // Always populated. On every code path the acquisition diagnostic
        // inside `report.acquisition` reflects what the orchestrator was
        // able to do; on the success path the report also contains the
        // engine's findings.
        engine::AnalysisReport report;

        // Convenience flags. `acquired` is true once we have a usable
        // module list; `analyzed` is true once an engine completed.
        bool acquired = false;
        bool analyzed = false;
    };

    class Orchestrator {
    public:
        explicit Orchestrator(engine::EngineRegistry& registry)
            : registry_(registry) {}

        AnalyzeOutcome analyze(const AnalyzeRequest& req);

    private:
        engine::EngineRegistry& registry_;
    };

} // namespace ura::app
