// engine/IGameEngine.hpp
// Plugin contract for engine modules. Each engine declares an id, a display
// name, a fast detect() probe, and an analyze() method that produces a
// fully populated AnalysisReport.
#pragma once

#include "../core/Result.hpp"
#include "AnalysisReport.hpp"
#include "EngineContext.hpp"

#include <memory>
#include <string>

namespace ura::engine {

    class IGameEngine {
    public:
        virtual ~IGameEngine() = default;

        // Stable, lowercase identifier ("unity_il2cpp", "goldsrc", ...).
        // Used by --engine flag and embedded in JSON output.
        virtual std::string id() const = 0;

        // Human-readable name for log output.
        virtual std::string display_name() const = 0;

        // Cheap, side-effect-free check. Typical implementation: "is module X
        // loaded?". Must NOT do full scans.
        virtual bool detect(const EngineContext& ctx) const = 0;

        // Full analysis pass. Implementations should populate the
        // engine_id / engine_display_name fields themselves.
        virtual core::Result<AnalysisReport> analyze(EngineContext& ctx) const = 0;
    };

    using EnginePtr = std::unique_ptr<IGameEngine>;

} // namespace ura::engine
