// engine/EngineRegistry.hpp
// Owns every IGameEngine instance and offers lookup + auto-detect.
//
// Engines register themselves in `register_builtin()`. Adding a new module
// is a one-line edit there; nothing else in the framework needs to change.
#pragma once

#include "IGameEngine.hpp"

#include <string>
#include <vector>

namespace ura::engine {

    class EngineRegistry {
    public:
        EngineRegistry();

        // Walk every registered engine in declaration order, return the first
        // whose detect() returns true. Returns nullptr if nothing matches.
        const IGameEngine* auto_detect(const EngineContext& ctx) const;

        // Lookup by stable id. Returns nullptr if no such engine.
        const IGameEngine* find(std::string_view id) const;

        // List all engines, used by `--list-engines`.
        std::vector<const IGameEngine*> all() const;

    private:
        void register_builtin();
        void add(EnginePtr e);

        std::vector<EnginePtr> engines_;
    };

} // namespace ura::engine
