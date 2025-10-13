# mehlog

mehlog is a minimalistic C++23 logging library.
It provides a simple logging interface and can be used as a lightweight logger on its own, or as a wrapper around popular back end logging libraries such as spdlog or glog.
This allows you to switch logging back ends with minimal code changes.

## Purpose

- Provide a minimal logging interface for C++ projects.
- Allow seamless integration with different logging back ends (e.g., spdlog, glog).
- If no back end is configured, logs are written to `std::clog` by default.

## Basic Usage (No Back End)

By default, mehlog logs to `std::clog` if no back end is specified.

```cpp
#include <mehlog/mehlog.hpp>

int main()
{
    mehlog::log(mehlog::LogLevel::info, "Hello, world!");
    mehlog::log(mehlog::LogLevel::error, "Something went wrong");
    return EXIT_SUCCESS;
}
```

## Using with spdlog

To use spdlog as the back end, include the spdlog adapter and initialize the handler:

```cpp
#include <mehlog/mehlog.hpp>
#include <mehlog/adapters/spdlog_adapter.hpp>

int main()
{
    mehlog::set_log_handler(mehlog::make_backend_handler<mehlog::adapters::spdlog_backend>());
    mehlog::log(mehlog::LogLevel::info, "This uses spdlog");
    return EXIT_SUCCESS;
}
```

## Using with glog

To use glog as the back end, include the glog adapter and initialize the handler:

```cpp
#include <mehlog/mehlog.hpp>
#include <mehlog/adapters/glog_adapter.hpp>

int main()
{
    mehlog::set_log_handler(mehlog::make_backend_handler<mehlog::adapters::glog_backend>());
    mehlog::log(mehlog::LogLevel::warning, "This uses glog");
    return EXIT_SUCCESS;
}
```

## Switching Back Ends

Switching between logging back ends only requires changing the adapter include and the handler initialization. The rest of your logging code remains unchanged.

## License

See LICENSE file for details.

