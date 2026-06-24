// main.cpp — entry point for URA. Delegates everything to CliApp / GuiApp.
#include "app/ArgParser.hpp"
#include "app/CliApp.hpp"

#ifdef URA_WITH_IMGUI
#  include "app/GuiApp.hpp"
#endif

#include <cstdio>
#include <iostream>

int main(int argc, char** argv) {
    // Force line-buffered stdout/stderr. Without this, fast-exit paths
    // (e.g. --version, --list-engines) can lose their output under
    // PowerShell hosts that consume the child's stdout asynchronously.
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::setvbuf(stderr, nullptr, _IONBF, 0);
    std::ios::sync_with_stdio(true);
    std::cout.setf(std::ios::unitbuf);

    auto parsed = ura::app::parse(argc, argv);
    if (!parsed.ok) {
        std::fprintf(stderr, "Argument error: %s\n\n", parsed.error.c_str());
        std::fputs(ura::app::help_text().c_str(), stderr);
        return 64; // EX_USAGE
    }

    // Double-click / no-arg launch: open the GUI by default. The CLI is
    // opt-in via explicit flags. This way the .exe is usable from File
    // Explorer without ever touching cmd.exe.
    if (argc <= 1) {
    #ifdef URA_WITH_IMGUI
        parsed.args.gui = true;
    #endif
    }

    if (parsed.args.gui) {
#ifdef URA_WITH_IMGUI
        ura::app::GuiApp gui;
        const int rc = gui.run();
        std::fflush(stdout); std::fflush(stderr);
        return rc;
#else
        std::fprintf(stderr,
            "GUI not compiled in (URA_WITH_IMGUI not defined). "
            "Rebuild with the GUI configuration.\n");
        return 64;
#endif
    }

    ura::app::CliApp app;
    const int rc = app.run(parsed.args);

    std::fflush(stdout);
    std::fflush(stderr);
    return rc;
}
