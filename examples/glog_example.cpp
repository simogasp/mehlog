#include <mehlog/mehlog.hpp>
#include <mehlog/adapters/glog.hpp>

int main(int argc, char** argv)
{
    mehlog::adapters::setup_glog(&argc, &argv);
    mehlog::set_log_level(mehlog::LogLevel::Trace);

    mehlog::dummy_test();

    mehlog::adapters::shutdown_glog();

    return EXIT_SUCCESS;
}
