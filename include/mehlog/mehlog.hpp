/**
 * @file mehlog.hpp
 * @brief A lightweight, unpretentious, header-only C++ logging library with compile-time and runtime log level control.
 * @author Simone Gasparini
 *
 * This library provides a simple yet flexible logging system with support for multiple log levels,
 * customizable log handlers, and both compile-time and runtime log level filtering.
 */

#pragma once
#include <algorithm>
#include <array>
#include <chrono>
#include <ctime>
#include <format>
#include <functional>
#include <iostream>
#include <iterator>
#include <optional>
#include <string_view>
#include <syncstream>
#include <utility>


/**
 * @namespace mehlog
 * @brief Main namespace for the mehlog logging library.
 *
 * This namespace contains all logging functionality, including log levels, log handlers,
 * and convenience functions for logging at various severity levels.
 */
namespace mehlog {
// Compile-time minimum log level (optional)
// Uncomment and set to desired level if needed or define via compiler flags
// #ifndef MEHLOG_LOG_LEVEL
// #define MEHLOG_LOG_LEVEL mehlog::LogLevel::Info
// #endif

/**
 * @enum LogLevel
 * @brief Defines the severity levels for log messages.
 *
 * Log levels are ordered from the least severe (Trace) to the most severe (Error).
 * The Off level can be used to disable all logging.
 */
enum class LogLevel : std::size_t
{
    Trace,  ///< Most verbose level, for detailed tracing information
    Debug,  ///< Debug information useful during development
    Info,   ///< Informational messages about normal operation
    Warn,   ///< Warning messages about potential issues
    Error,  ///< Error messages indicating failures
    Off     ///< Disables all logging
};

/**
 * @brief Compile-time bidirectional mapping between LogLevel and string names.
 */
struct LogLevelMapping
{
    LogLevel level;
    std::string_view name;

    constexpr LogLevelMapping(LogLevel l, std::string_view n) : level(l), name(n) {}
};

/**
 * @brief Array defining the mapping between LogLevel values and their string representations.
 */
inline constexpr std::array<LogLevel,6> all_levels = {
    {
        LogLevel::Trace,
        LogLevel::Debug,
        LogLevel::Info,
        LogLevel::Warn,
        LogLevel::Error,
        LogLevel::Off
    }
};

/**
 * @brief Array defining the mapping between LogLevel values and their string representations.
 */
inline constexpr std::array<LogLevelMapping,6> log_level_map = {
    {
        {LogLevel::Trace, "TRACE"},
        {LogLevel::Debug, "DEBUG"},
        {LogLevel::Info,  "INFO"},
        {LogLevel::Warn,  "WARN"},
        {LogLevel::Error, "ERROR"},
        {LogLevel::Off,   "OFF"}
    }
};

/**
 * @brief Converts LogLevel to string representation.
 * @param level The log level to convert
 * @return String view of the log level name
 */
constexpr std::string_view to_string(LogLevel level) noexcept
{
    const auto it = std::ranges::find_if(log_level_map,
                           [level](const auto& mapping) { return mapping.level == level; });
    if(it != std::end(log_level_map))
        return it->name;
    std::unreachable();
}

/**
 * @brief Converts string to LogLevel.
 * @param str String representation of log level
 * @return Corresponding LogLevel, or LogLevel::Info if not found
 */
constexpr std::optional<LogLevel> from_string(std::string_view str) noexcept
{
    const auto it = std::ranges::find_if(log_level_map,
                           [str](const auto& mapping) { return mapping.name == str; });
    if(it != std::end(log_level_map))
        return it->level;
    return {};
}

/**
 * @brief Gets current timestamp as formatted string.
 * @return Formatted timestamp string
 */
inline std::string get_timestamp()
{
    auto now = std::chrono::system_clock::now();
    auto time = std::chrono::system_clock::to_time_t(now);
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()) % 1000;

    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &time);
#else
    localtime_r(&time, &tm);
#endif

    return std::format("{:04d}-{:02d}-{:02d} {:02d}:{:02d}:{:02d}.{:03d}",
                       tm.tm_year + 1900, tm.tm_mon + 1, tm.tm_mday,
                       tm.tm_hour, tm.tm_min, tm.tm_sec, ms.count());
}

/**
 * @var current_log_level
 * @brief The current runtime log level threshold.
 *
 * Messages with a level below this threshold will not be logged.
 * Default is LogLevel::Info.
 */
inline LogLevel current_log_level = LogLevel::Info;

/**
 * @brief Sets the runtime log level threshold.
 * @param level The minimum log level to output
 *
 * Only messages with severity >= level will be logged.
 * This can be changed at runtime to adjust logging verbosity.
 */
inline void set_log_level(LogLevel level) noexcept { current_log_level = level; }

/**
 * @brief Gets the current runtime log level threshold.
 * @return The current minimum log level for logging
 */
inline LogLevel get_log_level() noexcept { return current_log_level; }

/**
 * @brief RAII helper to temporarily change log level.
 */
class scoped_log_level
{
    LogLevel prev_level;
public:
    explicit scoped_log_level(LogLevel new_level) noexcept
        : prev_level(current_log_level)
    {
        set_log_level(new_level);
    }

    ~scoped_log_level() noexcept
    {
        set_log_level(prev_level);
    }

    scoped_log_level(const scoped_log_level&) = delete;
    scoped_log_level& operator=(const scoped_log_level&) = delete;
};

/**
 * @brief Determines if a log level passes the compile-time threshold.
 * @param level The log level to check
 * @return true if the level should be logged based on compile-time settings
 *
 * If MYLIB_LOG_LEVEL is defined at compile-time, this function performs
 * compile-time filtering. Otherwise, it returns true for all levels.
 */
constexpr bool should_log([[maybe_unused]] LogLevel level) noexcept
{
#ifdef MEHLOG_LOG_LEVEL
    // Compile-time minimum level (optional)
    return level >= MEHLOG_LOG_LEVEL;
#else
    return true;
#endif
}

/**
 * @brief Checks if a log level is enabled for logging.
 * @param level The log level to check
 * @return true if the level should be logged based on both compile-time and runtime settings.
 *
 * This combines compile-time (should_log) and runtime (current_log_level) checks.
 */
inline bool log_enabled(LogLevel level) noexcept { return should_log(level) && level >= current_log_level; }

/**
 * @typedef LogHandler
 * @brief Type alias for the log handler function.
 *
 * A log handler takes a LogLevel and a message string_view and processes the log message.
 * Custom handlers can be set to redirect logging to files, network, or other destinations.
 */
using LogHandler = std::function<void(LogLevel, std::string_view)>;

/**
 * @brief Creates a log handler that forwards to a backend logging function.
 * @tparam Fn Type of the backend logging function
 * @param backend_fn Backend function that takes (level_string, message)
 * @return LogHandler that forwards to the backend
 */
template<typename Fn>
LogHandler make_backend_handler(Fn&& backend_fn)
{
    return [fn = std::forward<Fn>(backend_fn)](LogLevel level, std::string_view msg) {
        if(log_enabled(level))
            fn(to_string(level), msg);
    };
}

/**
 * @brief Default log handler that writes to std::clog with level prefixes.
 * @return Reference to the default log handler
 *
 * This handler uses std::osyncstream for thread-safe output when available (C++20).
 * It checks log_enabled() before outputting messages.
 */
inline LogHandler& get_default_log_handler() {
    static LogHandler handler = [](LogLevel level, std::string_view msg) {
        using enum LogLevel;
        if(!log_enabled(level))
            return;
#if defined(__cpp_lib_syncbuf)
        std::osyncstream(std::clog)
#else
        std::clog
#endif
          << '[' << to_string(level) << "] " << msg << '\n';
    };
    return handler;
}

/**
 * @var log_handler
 * @brief The global log handler function.
 *
 * @note The default handler checks log_enabled() before outputting.
 */
inline LogHandler log_handler = get_default_log_handler();

/**
 * @brief Logs a message at the specified level.
 * @param level The severity level of the message
 * @param msg The message to log
 *
 * This is the primary logging function. It delegates to the global log_handler
 * if one is set. The handler is responsible for checking if logging is enabled.
 */
inline void log(LogLevel level, std::string_view msg) noexcept
{
    if(log_handler)
        log_handler(level, msg);
}

/**
 * @brief Logs a formatted message at the specified level.
 * @tparam Args Types of the formatting arguments
 * @param level The severity level of the message
 * @param fmt Format string compatible with std::format
 * @param args Arguments to be formatted
 *
 * Uses C++20 std::format for type-safe, efficient message formatting.
 * Only formats the message if logging is enabled for the given level.
 *
 * @note Requires C++20 or later for std::format support.
 */
template<typename... Args> constexpr void logf(LogLevel level, std::string_view fmt, Args&&... args)
{
    if(log_handler && log_enabled(level))
        log_handler(level, std::vformat(fmt, std::make_format_args(args...)));
}

// Convenience wrappers

/**
 * @brief Logs a trace-level message.
 * @param msg The message to log
 */
inline void log_trace(std::string_view msg) { log(LogLevel::Trace, msg); }

/**
 * @brief Logs a formatted trace-level message.
 * @tparam Args Types of the formatting arguments
 * @param fmt Format string compatible with std::format
 * @param args Arguments to be formatted
 */
template<typename... Args>
void log_trace(std::string_view fmt, Args&&... args) { logf(LogLevel::Trace, fmt, args...); }

/**
 * @brief Logs a debug-level message.
 * @param msg The message to log
 */
inline void log_debug(std::string_view msg) { log(LogLevel::Debug, msg); }

/**
 * @brief Logs a formatted debug-level message.
 * @tparam Args Types of the formatting arguments
 * @param fmt Format string compatible with std::format
 * @param args Arguments to be formatted
 */
template<typename... Args>
void log_debug(std::string_view fmt, Args&&... args) { logf(LogLevel::Debug, fmt, args...); }

/**
 * @brief Logs an info-level message.
 * @param msg The message to log
 */
inline void log_info(std::string_view msg) { log(LogLevel::Info, msg); }

/**
 * @brief Logs a formatted info-level message.
 * @tparam Args Types of the formatting arguments
 * @param fmt Format string compatible with std::format
 * @param args Arguments to be formatted
 */
template<typename... Args>
void log_info(std::string_view fmt, Args&&... args) { logf(LogLevel::Info, fmt, args...); }

/**
 * @brief Logs a warning-level message.
 * @param msg The message to log
 */
inline void log_warn(std::string_view msg) { log(LogLevel::Warn, msg); }

/**
 * @brief Logs a formatted warning-level message.
 * @tparam Args Types of the formatting arguments
 * @param fmt Format string compatible with std::format
 * @param args Arguments to be formatted
 */
template<typename... Args>
void log_warn(std::string_view fmt, Args&&... args) { logf(LogLevel::Warn, fmt, args...); }

/**
 * @brief Logs an error-level message.
 * @param msg The message to log
 */
inline void log_error(std::string_view msg) { log(LogLevel::Error, msg); }

/**
 * @brief Logs a formatted error-level message.
 * @tparam Args Types of the formatting arguments
 * @param fmt Format string compatible with std::format
 * @param args Arguments to be formatted
 */
template<typename... Args>
void log_error(std::string_view fmt, Args&&... args) { logf(LogLevel::Error, fmt, args...); }

/**
 * @brief A placeholder function used for testing purposes.
 *
 * Just a simple test function to demonstrate logging at various levels.
 *
 */
constexpr void dummy_test()
{
    log_trace("this is a trace message");
    log_debug("this is a debug message");
    log_info("Hello world!");
    log_warn("Careful!");
    log_error("We are in trouble!");
}

static_assert(from_string(to_string(LogLevel::Trace)).value() == LogLevel::Trace);
static_assert(from_string(to_string(LogLevel::Debug)).value() == LogLevel::Debug);
static_assert(from_string(to_string(LogLevel::Info)).value() == LogLevel::Info);
static_assert(from_string(to_string(LogLevel::Warn)).value() == LogLevel::Warn);
static_assert(from_string(to_string(LogLevel::Error)).value() == LogLevel::Error);

static_assert(!from_string("debug").has_value());

}// namespace mehlog
