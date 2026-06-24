// app/ArgParser.hpp
// Minimal hand-rolled CLI parser. We deliberately avoid bringing in CLI11 /
// argparse; the surface area is small and a hard-coded parser keeps the
// dependency graph tiny.
#pragma once

#include <optional>
#include <string>
#include <vector>

namespace ura::app {

    struct CliArgs {
        // Subject selection
        std::optional<std::uint32_t> pid;
        std::optional<std::wstring>  process_name;
        std::optional<std::wstring>  static_pe_path;   // --static-pe <path>

        // Engine selection
        bool                         auto_detect = true;
        std::optional<std::string>   engine_id;

        // Output
        std::optional<std::string>   out_path;
        bool                         pretty = true;

        // Modes
        bool                         list_processes = false;
        bool                         list_engines   = false;
        bool                         show_help      = false;
        bool                         show_version   = false;
        bool                         verbose        = false;
        bool                         quiet          = false;
        bool                         gui            = false;
    };

    struct ArgParseResult {
        CliArgs     args;
        bool        ok = true;
        std::string error;
    };

    // Parse argv; argv[0] is the program name and is ignored.
    ArgParseResult parse(int argc, char** argv);

    // Pretty help text. Static so tests / `--help` paths can call it without
    // constructing CliArgs.
    std::string help_text();

} // namespace ura::app
