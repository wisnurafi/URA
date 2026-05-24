// engine/modules/goldsrc/GoldSrcEngine.hpp
//
// Educational analyzer for GoldSrc-engine targets (Half-Life, Counter-Strike
// 1.6, etc.). GoldSrc games are 32-bit native binaries; the engine ships as
// `hw.dll` (or `sw.dll` for software renderer) loaded by `hl.exe`. The mod
// itself ships as `client.dll` and `mp.dll` (server-side game logic).
//
// This module:
//   * confirms GoldSrc layout via module signatures (`hw.dll` + `client.dll`);
//   * parses each module's PE header and reports it;
//   * runs a small set of well-known textual markers that survive across
//     engine builds, e.g. the "GoldSrc" version string in `hw.dll`;
//   * surfaces export hints from `client.dll` (Initialize, HUD_Init, etc.).
//
// Strictly read-only. No game-state mutation, no input synthesis, nothing
// that could affect a multiplayer session is exposed by this module.
#pragma once

#include "../../IGameEngine.hpp"

namespace ura::engine::modules {

    class GoldSrcEngine final : public IGameEngine {
    public:
        std::string id() const override          { return "goldsrc"; }
        std::string display_name() const override { return "GoldSrc Engine"; }

        bool detect(const EngineContext& ctx) const override;
        core::Result<AnalysisReport> analyze(EngineContext& ctx) const override;
    };

} // namespace ura::engine::modules
