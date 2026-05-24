// core/Result.hpp
// Minimal Result<T> / expected<T,Error> for error propagation without
// exceptions. Keeping this in-house avoids a hard dependency on C++23
// std::expected and works under MSVC C++20.
#pragma once

#include <cassert>
#include <optional>
#include <string>
#include <utility>
#include <variant>

namespace ura::core {

    struct Error {
        int          code;     // 0 = ok, otherwise WinAPI/last-error or framework code
        std::string  message;  // human-readable

        static Error make(std::string msg, int c = -1) {
            return Error{ c, std::move(msg) };
        }
    };

    template <typename T>
    class Result {
    public:
        // Construct success.
        Result(T value) : storage_(std::move(value)) {}

        // Construct failure.
        Result(Error err) : storage_(std::move(err)) {}

        // Helpers.
        bool ok() const noexcept { return storage_.index() == 0; }
        explicit operator bool() const noexcept { return ok(); }

        T&         value() &        { assert(ok()); return std::get<T>(storage_); }
        const T&   value() const&   { assert(ok()); return std::get<T>(storage_); }
        T&&        value() &&       { assert(ok()); return std::get<T>(std::move(storage_)); }

        const Error& error() const  { assert(!ok()); return std::get<Error>(storage_); }

        // Convenience.
        T value_or(T fallback) const {
            return ok() ? value() : std::move(fallback);
        }

    private:
        std::variant<T, Error> storage_;
    };

    // Specialization for void: success carries no payload.
    template <>
    class Result<void> {
    public:
        Result() : err_(std::nullopt) {}
        Result(Error e) : err_(std::move(e)) {}

        bool ok() const noexcept { return !err_.has_value(); }
        explicit operator bool() const noexcept { return ok(); }
        const Error& error() const { assert(!ok()); return *err_; }

    private:
        std::optional<Error> err_;
    };

    // Convenience factories.
    template <typename T>
    inline Result<T> ok(T v) { return Result<T>{ std::move(v) }; }

    inline Result<void> ok() { return Result<void>{}; }

    template <typename T = void>
    inline Result<T> fail(std::string msg, int code = -1) {
        return Result<T>{ Error::make(std::move(msg), code) };
    }

} // namespace ura::core

// TRY-style macro for early-return on Result failure.
// Use inside a function whose return type is also Result<...>; the failing
// Error is forwarded as-is.
#define URA_TRY(var, expr)                                       \
    auto _ura_try_##var = (expr);                                \
    if (!_ura_try_##var) return _ura_try_##var.error();          \
    auto var = std::move(_ura_try_##var.value())
