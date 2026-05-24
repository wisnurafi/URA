// analysis/Signature.hpp
// IDA-style byte signature with a name, an optional module hint, and
// optional post-processing offsets (e.g. "+3 deref RIP-relative").
#pragma once

#include "../core/Types.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace ura::analysis {

    // Post-processing applied to a signature hit address.
    enum class HitTransform {
        // Use the hit address as-is.
        None,
        // Treat the hit as a reference to a 32-bit RIP-relative displacement
        // located at `hit + offset`. Result = (hit + offset) + 4 + disp32.
        // Used to resolve LEA/MOV/CALL targets in x86-64 code.
        RipRelative32,
        // Treat the hit as a reference to a 32-bit absolute address located
        // at `hit + offset`. Used in 32-bit x86 code.
        Absolute32,
        // Treat the hit as a reference to a 64-bit absolute address.
        Absolute64,
    };

    struct Signature {
        std::string   name;          // unique handle, e.g. "il2cpp_init"
        std::string   pattern;       // IDA-style: "48 8B 05 ?? ?? ?? ??"
        std::string   module_hint;   // optional case-insensitive module name
        std::string   description;   // human-readable; only used in reports

        HitTransform  transform = HitTransform::None;
        std::int32_t  transform_offset = 0;  // bytes to add before applying transform
        std::int32_t  post_offset      = 0;  // bytes to add after the transform
    };

} // namespace ura::analysis
