// app/CliApp.hpp
// Top-level orchestrator. Owns the engine registry and dispatches the CLI
// modes to the appropriate code path.
#pragma once

#include "ArgParser.hpp"
#include "Orchestrator.hpp"

#include "../engine/EngineRegistry.hpp"

namespace ura::app {

    class CliApp {
    public:
        // Returns a process exit code (0 on success).
        int run(const CliArgs& args);

    private:
        int cmd_list_processes() const;
        int cmd_list_engines() const;
        int cmd_analyze(const CliArgs& args);

        engine::EngineRegistry registry_;
    };

} // namespace ura::app
