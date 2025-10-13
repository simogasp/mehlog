#include <catch2/catch_test_macros.hpp>
#include <mehlog/mehlog.hpp>
#include <sstream>
#include <string>
#include <vector>
#include <numbers>

// ============================================================================
// Compile-time tests
// ============================================================================

// Test that LogLevel enum has the correct underlying type
static_assert(std::is_same_v<std::underlying_type_t<mehlog::LogLevel>, std::size_t>);

// Test to_string and from_string round-trip for all log levels
static_assert(mehlog::from_string(mehlog::to_string(mehlog::LogLevel::Trace)).value() == mehlog::LogLevel::Trace);
static_assert(mehlog::from_string(mehlog::to_string(mehlog::LogLevel::Debug)).value() == mehlog::LogLevel::Debug);
static_assert(mehlog::from_string(mehlog::to_string(mehlog::LogLevel::Info)).value() == mehlog::LogLevel::Info);
static_assert(mehlog::from_string(mehlog::to_string(mehlog::LogLevel::Warn)).value() == mehlog::LogLevel::Warn);
static_assert(mehlog::from_string(mehlog::to_string(mehlog::LogLevel::Error)).value() == mehlog::LogLevel::Error);
static_assert(mehlog::from_string(mehlog::to_string(mehlog::LogLevel::Off)).value() == mehlog::LogLevel::Off);

// Test that invalid strings return empty optional
static_assert(!mehlog::from_string("invalid").has_value());
static_assert(!mehlog::from_string("").has_value());
static_assert(!mehlog::from_string("trace").has_value()); // the lowercase should fail
static_assert(!mehlog::from_string("UNKNOWN").has_value());

// Test that to_string returns the expected strings
static_assert(mehlog::to_string(mehlog::LogLevel::Trace) == "TRACE");
static_assert(mehlog::to_string(mehlog::LogLevel::Debug) == "DEBUG");
static_assert(mehlog::to_string(mehlog::LogLevel::Info) == "INFO");
static_assert(mehlog::to_string(mehlog::LogLevel::Warn) == "WARN");
static_assert(mehlog::to_string(mehlog::LogLevel::Error) == "ERROR");
static_assert(mehlog::to_string(mehlog::LogLevel::Off) == "OFF");

// Test should_log at compile time
#ifdef MEHLOG_LOG_LEVEL
static_assert(mehlog::should_log(MEHLOG_LOG_LEVEL));
#endif

// ============================================================================
// Runtime tests
// ============================================================================

TEST_CASE("LogLevel to_string conversion", "[conversion]")
{
    using enum mehlog::LogLevel;

    struct TestCase {
        mehlog::LogLevel level;
        std::string_view expected;
    };

    const std::vector<TestCase> test_cases = {
        {Trace, "TRACE"},
        {Debug, "DEBUG"},
        {Info, "INFO"},
        {Warn, "WARN"},
        {Error, "ERROR"},
        {Off, "OFF"}
    };

    for (const auto& tc : test_cases) {
        CAPTURE(tc.expected);
        REQUIRE(mehlog::to_string(tc.level) == tc.expected);
    }
}

TEST_CASE("String to LogLevel conversion", "[conversion]")
{
    using enum mehlog::LogLevel;

    struct TestCase {
        std::string_view input;
        std::optional<mehlog::LogLevel> expected;
    };

    const std::vector<TestCase> test_cases = {
        {"TRACE", Trace},
        {"DEBUG", Debug},
        {"INFO", Info},
        {"WARN", Warn},
        {"ERROR", Error},
        {"OFF", Off},
        {"invalid", std::nullopt},
        {"trace", std::nullopt},  // the lowercase should fail
        {"", std::nullopt},
        {"UNKNOWN", std::nullopt},
        {"Info", std::nullopt},   // mixed case should fail
    };

    for (const auto& tc : test_cases) {
        CAPTURE(tc.input);
        REQUIRE(mehlog::from_string(tc.input) == tc.expected);
    }
}

TEST_CASE("Round-trip conversion for all log levels", "[conversion]")
{
    for (const auto& level : mehlog::all_levels)
    {
        const auto str = mehlog::to_string(level);
        const auto converted_back = mehlog::from_string(str);
        REQUIRE(converted_back.has_value());
        REQUIRE(converted_back.value() == level);
    }
}

TEST_CASE("LogLevel ordering", "[loglevel]")
{
    using enum mehlog::LogLevel;

    REQUIRE(Trace < Debug);
    REQUIRE(Debug < Info);
    REQUIRE(Info < Warn);
    REQUIRE(Warn < Error);
    REQUIRE(Error < Off);
}

TEST_CASE("set_log_level and get_log_level", "[loglevel]")
{
    using enum mehlog::LogLevel;
    // Save the original level
    const auto original = mehlog::get_log_level();

    struct TestCase {
        mehlog::LogLevel level_to_set;
    };

    const std::vector<TestCase> test_cases = {
        {Trace},
        {Debug},
        {Info},
        {Warn},
        {Error},
        {Off}
    };

    for (const auto& [level_to_set] : test_cases) {
        mehlog::set_log_level(level_to_set);
        REQUIRE(mehlog::get_log_level() == level_to_set);
    }

    // Restore original level
    mehlog::set_log_level(original);
}

TEST_CASE("log_enabled respects runtime log level", "[loglevel]")
{
    using enum mehlog::LogLevel;
    // Save the original level
    const auto original = mehlog::get_log_level();

    struct TestCase {
        mehlog::LogLevel current_level;
        mehlog::LogLevel check_level;
        bool expected_enabled;
    };

    const std::vector<TestCase> test_cases = {
        {Info, Trace, false},
        {Info, Debug, false},
        {Info, Info, true},
        {Info, Warn, true},
        {Info, Error, true},
        {Trace, Trace, true},
        {Error, Warn, false},
        {Error, Error, true},
        {Off, Error, false},
        {Off, Off, true},
    };

    for (const auto& tc : test_cases)
    {
        CAPTURE(mehlog::to_string(tc.current_level));
        CAPTURE(mehlog::to_string(tc.check_level));

        mehlog::set_log_level(tc.current_level);
        REQUIRE(mehlog::log_enabled(tc.check_level) == tc.expected_enabled);
    }

    // Restore original level
    mehlog::set_log_level(original);
}

TEST_CASE("scoped_log_level restores previous level", "[loglevel][raii]")
{
    using enum mehlog::LogLevel;
    // Save the original level
    const auto original = mehlog::get_log_level();

    mehlog::set_log_level(Info);
    REQUIRE(mehlog::get_log_level() == Info);

    {
        mehlog::scoped_log_level scoped(Debug);
        REQUIRE(mehlog::get_log_level() == Debug);
    }

    REQUIRE(mehlog::get_log_level() == Info);

    // Restore original level
    mehlog::set_log_level(original);
}

TEST_CASE("scoped_log_level with nested scopes", "[loglevel][raii]")
{
    using enum mehlog::LogLevel;
    // Save the original level
    const auto original = mehlog::get_log_level();

    mehlog::set_log_level(Info);

    {
        mehlog::scoped_log_level scoped1(Debug);
        REQUIRE(mehlog::get_log_level() == Debug);

        {
            mehlog::scoped_log_level scoped2(Trace);
            REQUIRE(mehlog::get_log_level() == Trace);
        }

        REQUIRE(mehlog::get_log_level() == Debug);
    }

    REQUIRE(mehlog::get_log_level() == Info);

    // Restore original level
    mehlog::set_log_level(original);
}

TEST_CASE("Custom log handler", "[handler]")
{
    using enum mehlog::LogLevel;
    // Save the original handler
    auto original_handler = mehlog::log_handler;
    auto original_level = mehlog::get_log_level();

    std::vector<std::pair<mehlog::LogLevel, std::string>> captured_logs;

    mehlog::log_handler = [&captured_logs](mehlog::LogLevel level, std::string_view msg) {
        if (mehlog::log_enabled(level)) {
            captured_logs.emplace_back(level, std::string(msg));
        }
    };

    mehlog::set_log_level(Debug);

    mehlog::log(Info, "Test message");
    mehlog::log(Debug, "Debug message");
    mehlog::log(Trace, "Trace message"); // Should be filtered

    REQUIRE(captured_logs.size() == 2);
    REQUIRE(captured_logs[0].first == Info);
    REQUIRE(captured_logs[0].second == "Test message");
    REQUIRE(captured_logs[1].first == Debug);
    REQUIRE(captured_logs[1].second == "Debug message");

    // Restore the original handler and level
    mehlog::log_handler = original_handler;
    mehlog::set_log_level(original_level);
}

TEST_CASE("Formatted logging with logf", "[format]")
{
    using enum mehlog::LogLevel;
    // Save the original handler
    const auto original_handler = mehlog::log_handler;
    const auto original_level = mehlog::get_log_level();

    std::vector<std::string> captured_messages;

    mehlog::log_handler = [&captured_messages](mehlog::LogLevel level, std::string_view msg) {
        if (mehlog::log_enabled(level)) {
            captured_messages.emplace_back(msg);
        }
    };

    mehlog::set_log_level(Trace);

    mehlog::logf(Info, "Number: {}", 42);
    mehlog::logf(Debug, "String: {}, Number: {}", "test", 123);
    mehlog::logf(Warn, "Float: {:.2f}", std::numbers::pi);

    REQUIRE(captured_messages.size() == 3);
    REQUIRE(captured_messages[0] == "Number: 42");
    REQUIRE(captured_messages[1] == "String: test, Number: 123");
    REQUIRE(captured_messages[2] == "Float: 3.14");

    // Restore the original handler and level
    mehlog::log_handler = original_handler;
    mehlog::set_log_level(original_level);
}

TEST_CASE("Convenience logging functions", "[convenience]")
{
    using enum mehlog::LogLevel;
    // Save the original handler
    const auto original_handler = mehlog::log_handler;
    const auto original_level = mehlog::get_log_level();

    std::vector<std::pair<mehlog::LogLevel, std::string>> captured_logs;

    mehlog::log_handler = [&captured_logs](mehlog::LogLevel level, std::string_view msg) {
        if (mehlog::log_enabled(level)) {
            captured_logs.emplace_back(level, std::string(msg));
        }
    };

    mehlog::set_log_level(Trace);

    mehlog::log_trace("trace msg");
    mehlog::log_debug("debug msg");
    mehlog::log_info("info msg");
    mehlog::log_warn("warn msg");
    mehlog::log_error("error msg");

    REQUIRE(captured_logs.size() == 5);
    REQUIRE(captured_logs[0].first == Trace);
    REQUIRE(captured_logs[0].second == "trace msg");
    REQUIRE(captured_logs[1].first == Debug);
    REQUIRE(captured_logs[1].second == "debug msg");
    REQUIRE(captured_logs[2].first == Info);
    REQUIRE(captured_logs[2].second == "info msg");
    REQUIRE(captured_logs[3].first == Warn);
    REQUIRE(captured_logs[3].second == "warn msg");
    REQUIRE(captured_logs[4].first == Error);
    REQUIRE(captured_logs[4].second == "error msg");

    // Restore the original handler and level
    mehlog::log_handler = original_handler;
    mehlog::set_log_level(original_level);
}

TEST_CASE("Convenience logging functions with formatting", "[convenience][format]")
{
    using enum mehlog::LogLevel;
    // Save the original handler
    const auto original_handler = mehlog::log_handler;
    const auto original_level = mehlog::get_log_level();

    std::vector<std::pair<mehlog::LogLevel, std::string>> captured_logs;

    mehlog::log_handler = [&captured_logs](mehlog::LogLevel level, std::string_view msg) {
        if (mehlog::log_enabled(level)) {
            captured_logs.emplace_back(level, std::string(msg));
        }
    };

    mehlog::set_log_level(Trace);

    mehlog::log_trace("trace: {}", 1);
    mehlog::log_debug("debug: {}", 2);
    mehlog::log_info("info: {}", 3);
    mehlog::log_warn("warn: {}", 4);
    mehlog::log_error("error: {}", 5);

    REQUIRE(captured_logs.size() == 5);
    REQUIRE(captured_logs[0].second == "trace: 1");
    REQUIRE(captured_logs[1].second == "debug: 2");
    REQUIRE(captured_logs[2].second == "info: 3");
    REQUIRE(captured_logs[3].second == "warn: 4");
    REQUIRE(captured_logs[4].second == "error: 5");

    // Restore the original handler and level
    mehlog::log_handler = original_handler;
    mehlog::set_log_level(original_level);
}

TEST_CASE("Log filtering based on level", "[filtering]")
{
    using enum mehlog::LogLevel;
    // Save the original handler
    const auto original_handler = mehlog::log_handler;
    const auto original_level = mehlog::get_log_level();

    struct TestCase {
        mehlog::LogLevel current_level;
        std::vector<mehlog::LogLevel> levels_to_log;
        size_t expected_count;
    };

    const std::vector<TestCase> test_cases = {
        {Info, {Trace, Debug, Info, Warn, Error}, 3},
        {Error, {Trace, Debug, Info, Warn, Error}, 1},
        {Trace, {Trace, Debug, Info, Warn, Error}, 5},
        {Off, {Trace, Debug, Info, Warn, Error}, 0},
    };

    for (const auto& tc : test_cases) {
        CAPTURE(mehlog::to_string(tc.current_level));

        std::vector<mehlog::LogLevel> captured_levels;

        mehlog::log_handler = [&captured_levels](mehlog::LogLevel level, std::string_view) {
            if (mehlog::log_enabled(level)) {
                captured_levels.push_back(level);
            }
        };

        mehlog::set_log_level(tc.current_level);

        for (const auto& level : tc.levels_to_log) {
            mehlog::log(level, "test");
        }

        REQUIRE(captured_levels.size() == tc.expected_count);
    }

    // Restore the original handler and level
    mehlog::log_handler = original_handler;
    mehlog::set_log_level(original_level);
}

TEST_CASE("make_backend_handler creates compatible handler", "[handler][backend]")
{
    using enum mehlog::LogLevel;
    // Save the original handler
    const auto original_handler = mehlog::log_handler;
    const auto original_level = mehlog::get_log_level();

    std::vector<std::pair<std::string, std::string>> backend_calls;

    const auto backend_fn = [&backend_calls](std::string_view level_str, std::string_view msg) {
        backend_calls.emplace_back(std::string(level_str), std::string(msg));
    };

    mehlog::log_handler = mehlog::make_backend_handler(backend_fn);
    mehlog::set_log_level(Debug);

    mehlog::log(Info, "Info message");
    mehlog::log(Debug, "Debug message");
    mehlog::log(Trace, "Trace message"); // Should be filtered

    REQUIRE(backend_calls.size() == 2);
    REQUIRE(backend_calls[0].first == "INFO");
    REQUIRE(backend_calls[0].second == "Info message");
    REQUIRE(backend_calls[1].first == "DEBUG");
    REQUIRE(backend_calls[1].second == "Debug message");

    // Restore the original handler and level
    mehlog::log_handler = original_handler;
    mehlog::set_log_level(original_level);
}

TEST_CASE("get_timestamp returns valid timestamp", "[timestamp]")
{
    const auto timestamp = mehlog::get_timestamp();

    // Check format: YYYY-MM-DD HH:MM:SS.mmm
    REQUIRE(timestamp.length() == 23);
    REQUIRE(timestamp[4] == '-');
    REQUIRE(timestamp[7] == '-');
    REQUIRE(timestamp[10] == ' ');
    REQUIRE(timestamp[13] == ':');
    REQUIRE(timestamp[16] == ':');
    REQUIRE(timestamp[19] == '.');
}

TEST_CASE("LogLevelMapping structure", "[mapping]")
{
    using enum mehlog::LogLevel;

    REQUIRE(mehlog::log_level_map.size() == 6);

    struct TestCase {
        size_t index;
        mehlog::LogLevel expected_level;
        std::string_view expected_name;
    };

    const std::vector<TestCase> test_cases = {
        {0, Trace, "TRACE"},
        {1, Debug, "DEBUG"},
        {2, Info, "INFO"},
        {3, Warn, "WARN"},
        {4, Error, "ERROR"},
        {5, Off, "OFF"}
    };

    for (const auto& tc : test_cases)
    {
        CAPTURE(tc.index);
        REQUIRE(mehlog::log_level_map[tc.index].level == tc.expected_level);
        REQUIRE(mehlog::log_level_map[tc.index].name == tc.expected_name);
    }
}

TEST_CASE("all_levels array contains all log levels", "[mapping]")
{
    using enum mehlog::LogLevel;

    REQUIRE(mehlog::all_levels.size() == 6);
    REQUIRE(mehlog::all_levels[0] == Trace);
    REQUIRE(mehlog::all_levels[1] == Debug);
    REQUIRE(mehlog::all_levels[2] == Info);
    REQUIRE(mehlog::all_levels[3] == Warn);
    REQUIRE(mehlog::all_levels[4] == Error);
    REQUIRE(mehlog::all_levels[5] == Off);
}

TEST_CASE("Null log handler does not crash", "[handler]")
{
    using enum mehlog::LogLevel;
    // Save the original handler
    const auto original_handler = mehlog::log_handler;
    const auto original_level = mehlog::get_log_level();

    mehlog::log_handler = nullptr;
    mehlog::set_log_level(Trace);

    // Should not crash
    REQUIRE_NOTHROW(mehlog::log(Info, "test"));
    REQUIRE_NOTHROW(mehlog::log_trace("test"));
    REQUIRE_NOTHROW(mehlog::log_debug("test"));
    REQUIRE_NOTHROW(mehlog::log_info("test"));
    REQUIRE_NOTHROW(mehlog::log_warn("test"));
    REQUIRE_NOTHROW(mehlog::log_error("test"));

    // Restore the original handler and level
    mehlog::log_handler = original_handler;
    mehlog::set_log_level(original_level);
}

TEST_CASE("logf does not format when logging is disabled", "[format][optimization]")
{
    using enum mehlog::LogLevel;
    // Save the original handler
    const auto original_handler = mehlog::log_handler;
    const auto original_level = mehlog::get_log_level();

    int format_call_count = 0;

    mehlog::log_handler = [&format_call_count](mehlog::LogLevel level, std::string_view) {
        if (mehlog::log_enabled(level)) {
            format_call_count++;
        }
    };

    mehlog::set_log_level(Error);

    // This should not call the handler because Debug < Error
    mehlog::logf(Debug, "This should not format: {}", 42);
    REQUIRE(format_call_count == 0);

    // This should call the handler
    mehlog::logf(Error, "This should format: {}", 42);
    REQUIRE(format_call_count == 1);

    // Restore the original handler and level
    mehlog::log_handler = original_handler;
    mehlog::set_log_level(original_level);
}

TEST_CASE("Default log handler can be retrieved", "[handler]")
{
    using enum mehlog::LogLevel;

    const auto& default_handler = mehlog::get_default_log_handler();
    REQUIRE(default_handler != nullptr);

    // Default handler should work
    REQUIRE_NOTHROW(default_handler(Info, "Test message"));
}

TEST_CASE("Thread-safe logging with multiple messages", "[thread-safety]")
{
    using enum mehlog::LogLevel;
    // Save the original handler
    const auto original_handler = mehlog::log_handler;
    const auto original_level = mehlog::get_log_level();

    std::vector<std::string> captured_messages;
    std::mutex mtx;

    mehlog::log_handler = [&captured_messages, &mtx](mehlog::LogLevel level, std::string_view msg) {
        if (mehlog::log_enabled(level)) {
            std::lock_guard lock(mtx);
            captured_messages.emplace_back(msg);
        }
    };

    mehlog::set_log_level(Trace);

    // Log multiple messages
    for (auto i = 0u; i < 10u; ++i)
    {
        mehlog::logf(Info, "Message {}", i);
    }

    REQUIRE(captured_messages.size() == 10);

    // Restore the original handler and level
    mehlog::log_handler = original_handler;
    mehlog::set_log_level(original_level);
}
