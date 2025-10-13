#include "mehlog/mehlog.hpp"
#include <iostream>

int main()
{
    mehlog::set_log_level(mehlog::LogLevel::Trace);

    mehlog::dummy_test();

    mehlog::log_info(mehlog::get_timestamp());

    return EXIT_SUCCESS;
}