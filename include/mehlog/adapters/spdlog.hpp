// mehlog/adapters/spdlog.hpp
#pragma once
#include <spdlog/spdlog.h>
#include "mehlog/mehlog.hpp"

namespace mehlog::adapters {

inline void setup_spdlog()
{
    // Set spdlog to log all levels; filtering is done by mehlog
    spdlog::set_level(spdlog::level::trace);
    log_handler = [](LogLevel lvl, std::string_view msg)
    {
        using enum LogLevel;
        switch (lvl) {
            case Trace: spdlog::trace("{}", msg); break;
            case Debug: spdlog::debug("{}", msg); break;
            case Info:  spdlog::info("{}", msg);  break;
            case Warn:  spdlog::warn("{}", msg);  break;
            case Error: spdlog::error("{}", msg); break;
            case Off: break;
        }
    };
}

} // namespace mehlog::adapters
