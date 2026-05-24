// core/Logger.hpp
// Tiny logger. Thread-safe via a single mutex around stderr/stdout writes.
// Levels are filterable at runtime.
#pragma once

#include <cstdio>
#include <mutex>
#include <string>
#include <string_view>

namespace ura::core {

    enum class LogLevel : int {
        Trace = 0,
        Debug = 1,
        Info  = 2,
        Warn  = 3,
        Error = 4,
        Off   = 5,
    };

    class Logger {
    public:
        static Logger& instance();

        void set_level(LogLevel lvl) noexcept { level_ = lvl; }
        LogLevel level() const noexcept { return level_; }

        void log(LogLevel lvl, std::string_view msg);

        // printf-style helper.
        template <typename... Args>
        void logf(LogLevel lvl, const char* fmt, Args... args) {
            if (static_cast<int>(lvl) < static_cast<int>(level_)) return;
            char buf[1024];
            std::snprintf(buf, sizeof(buf), fmt, args...);
            log(lvl, buf);
        }

    private:
        Logger() = default;
        LogLevel    level_ = LogLevel::Info;
        std::mutex  mtx_;
    };

#define URA_LOG_TRACE(...) ::ura::core::Logger::instance().logf(::ura::core::LogLevel::Trace, __VA_ARGS__)
#define URA_LOG_DEBUG(...) ::ura::core::Logger::instance().logf(::ura::core::LogLevel::Debug, __VA_ARGS__)
#define URA_LOG_INFO(...)  ::ura::core::Logger::instance().logf(::ura::core::LogLevel::Info,  __VA_ARGS__)
#define URA_LOG_WARN(...)  ::ura::core::Logger::instance().logf(::ura::core::LogLevel::Warn,  __VA_ARGS__)
#define URA_LOG_ERROR(...) ::ura::core::Logger::instance().logf(::ura::core::LogLevel::Error, __VA_ARGS__)

} // namespace ura::core
