#include <mehlog/mehlog.hpp>
#include <mehlog/adapters/spdlog.hpp>

int main(int argc, char** argv)
{
    mehlog::adapters::setup_spdlog();
    mehlog::set_log_level(mehlog::LogLevel::Trace);

    mehlog::dummy_test();

    return EXIT_SUCCESS;
}
