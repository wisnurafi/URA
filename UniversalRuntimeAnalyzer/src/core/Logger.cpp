// core/Logger.cpp
#include "Logger.hpp"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <iostream>
#include <sstream>

namespace ura::core {

    namespace {
        const char* level_tag(LogLevel l) {
            switch (l) {
                case LogLevel::Trace: return "TRC";
                case LogLevel::Debug: return "DBG";
                case LogLevel::Info:  return "INF";
                case LogLevel::Warn:  return "WRN";
                case LogLevel::Error: return "ERR";
                default:              return "OFF";
            }
        }

        std::string timestamp() {
            using namespace std::chrono;
            auto now  = system_clock::now();
            auto t    = system_clock::to_time_t(now);
            auto ms   = duration_cast<milliseconds>(now.time_since_epoch()) % 1000;
            std::tm  tm{};
        #ifdef _WIN32
            localtime_s(&tm, &t);
        #else
            localtime_r(&t, &tm);
        #endif
            std::ostringstream os;
            os << std::put_time(&tm, "%H:%M:%S") << '.'
               << std::setw(3) << std::setfill('0') << ms.count();
            return os.str();
        }
    } // namespace

    Logger& Logger::instance() {
        static Logger g;
        return g;
    }

    void Logger::log(LogLevel lvl, std::string_view msg) {
        if (static_cast<int>(lvl) < static_cast<int>(level_)) return;
        std::lock_guard<std::mutex> lk(mtx_);
        auto& out = (lvl >= LogLevel::Warn) ? std::cerr : std::cout;
        out << '[' << timestamp() << "][" << level_tag(lvl) << "] " << msg << '\n';
    }

} // namespace ura::core
