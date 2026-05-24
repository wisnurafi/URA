// engine/modules/unity/UnityIL2CPPEngine.hpp
//
// Educational Unity IL2CPP analyzer.
//
// IL2CPP is Unity's "ahead-of-time C# to C++" backend. At runtime, the C#
// metadata lives in `GameAssembly.dll` (the AOT-compiled native module) and
// `global-metadata.dat` (a flat binary index of types/methods/strings).
//
// This module performs a strictly read-only structural survey:
//   * confirms IL2CPP layout by detecting `GameAssembly.dll` and
//     `UnityPlayer.dll`;
//   * parses both modules' PE headers;
//   * reports a curated set of well-known IL2CPP runtime export symbols
//     (e.g. il2cpp_init, il2cpp_domain_get) as RVAs from the export table;
//   * runs sample byte signatures (defined in the .cpp) against
//     GameAssembly.dll.
//
// It does NOT walk Mono/IL2CPP class trees, dump strings, or deobfuscate
// global-metadata.dat. Those are out of scope for the educational deliverable.
#pragma once

#include "../../IGameEngine.hpp"

namespace ura::engine::modules {

    class UnityIL2CPPEngine final : public IGameEngine {
    public:
        std::string id() const override          { return "unity_il2cpp"; }
        std::string display_name() const override { return "Unity (IL2CPP)"; }

        bool detect(const EngineContext& ctx) const override;

        core::Result<AnalysisReport> analyze(EngineContext& ctx) const override;
    };

} // namespace ura::engine::modules
