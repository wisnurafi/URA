// engine/modules/generic/GenericNativeEngine.hpp
//
// Fallback engine: any process that doesn't match a more specific engine.
// Provides a structural snapshot — modules, sections, executable size — with
// no engine-specific assumptions. Useful as a baseline tool for arbitrary
// native targets (offline games, demo binaries, course exercises).
#pragma once

#include "../../IGameEngine.hpp"

namespace ura::engine::modules {

    class GenericNativeEngine final : public IGameEngine {
    public:
        std::string id() const override          { return "generic_native"; }
        std::string display_name() const override { return "Generic Native"; }

        bool detect(const EngineContext& ctx) const override {
            (void)ctx;
            return true;   // last-resort fallback
        }

        core::Result<AnalysisReport> analyze(EngineContext& ctx) const override;
    };

} // namespace ura::engine::modules
