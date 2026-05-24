// app/GuiApp.hpp
// Dear ImGui frontend. Mirrors the CLI orchestrator (process pick → handle
// → modules → engine → report → JSON), but renders results in interactive
// tables. Same backend pipeline; we deliberately do not duplicate engine
// logic — the GUI is purely a presentation layer.
//
// Implementation lives in GuiApp.cpp and pulls in Dear ImGui's Win32 +
// DirectX 11 backends. The GUI build path is gated on URA_WITH_IMGUI so
// the project still compiles in environments without a graphics SDK.
#pragma once

#ifdef URA_WITH_IMGUI

#include "../engine/EngineRegistry.hpp"

namespace ura::app {

    class GuiApp {
    public:
        // Run the message loop. Returns process exit code.
        int run();

    private:
        engine::EngineRegistry registry_;
    };

} // namespace ura::app

#endif // URA_WITH_IMGUI
