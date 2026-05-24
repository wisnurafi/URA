// engine/modules/source/SourceEngine.hpp
//
// Educational analyzer for the Source engine family (HL2, CS:S, etc.). Source
// games are organized around named interfaces exposed by `engine.dll`,
// `client.dll`, `server.dll`, `tier0.dll`, `vstdlib.dll` etc. Each interface
// is registered through `CreateInterface` exports.
//
// Capability: structural inventory only (modules, exports, banner strings).
// No GameMovement / IClientEntityList walking.
#pragma once

#include "../../IGameEngine.hpp"

namespace ura::engine::modules {

    class SourceEngine final : public IGameEngine {
    public:
        std::string id() const override          { return "source"; }
        std::string display_name() const override { return "Source Engine"; }

        bool detect(const EngineContext& ctx) const override;
        core::Result<AnalysisReport> analyze(EngineContext& ctx) const override;
    };

} // namespace ura::engine::modules
