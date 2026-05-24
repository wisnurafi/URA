// engine/EngineRegistry.cpp
#include "EngineRegistry.hpp"

#include "../core/Logger.hpp"
#include "modules/unity/UnityIL2CPPEngine.hpp"
#include "modules/goldsrc/GoldSrcEngine.hpp"
#include "modules/source/SourceEngine.hpp"
#include "modules/generic/GenericNativeEngine.hpp"

namespace ura::engine {

    EngineRegistry::EngineRegistry() {
        register_builtin();
    }

    void EngineRegistry::register_builtin() {
        // Order matters for auto-detect: more specific engines come first,
        // generic fallback comes last.
        add(std::make_unique<modules::UnityIL2CPPEngine>());
        add(std::make_unique<modules::GoldSrcEngine>());
        add(std::make_unique<modules::SourceEngine>());
        add(std::make_unique<modules::GenericNativeEngine>());
    }

    void EngineRegistry::add(EnginePtr e) {
        URA_LOG_DEBUG("Registered engine: %s", e->id().c_str());
        engines_.push_back(std::move(e));
    }

    const IGameEngine* EngineRegistry::auto_detect(const EngineContext& ctx) const {
        for (const auto& e : engines_) {
            if (e->detect(ctx)) {
                URA_LOG_INFO("Auto-detected engine: %s", e->display_name().c_str());
                return e.get();
            }
        }
        return nullptr;
    }

    const IGameEngine* EngineRegistry::find(std::string_view id) const {
        for (const auto& e : engines_) {
            if (e->id() == id) return e.get();
        }
        return nullptr;
    }

    std::vector<const IGameEngine*> EngineRegistry::all() const {
        std::vector<const IGameEngine*> out;
        out.reserve(engines_.size());
        for (const auto& e : engines_) out.push_back(e.get());
        return out;
    }

} // namespace ura::engine
