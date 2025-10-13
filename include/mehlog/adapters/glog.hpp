#pragma once
#include "mehlog/mehlog.hpp"
#include <glog/logging.h>

namespace mehlog::adapters {

inline void setup_glog(int* argc, char*** argv, bool to_stderr = true)
{
    google::InitGoogleLogging((*argv)[0]);
    google::InstallFailureSignalHandler();

    // Redirect logs to stderr instead of files
    FLAGS_logtostderr = to_stderr;

    log_handler = [](LogLevel lvl, std::string_view msg) {
        using enum LogLevel;
        switch(lvl)
        {
            case Trace:
            case Debug: DLOG(INFO) << msg; break;
            case Info: LOG(INFO) << msg; break;
            case Warn: LOG(WARNING) << msg; break;
            case Error: LOG(ERROR) << msg; break;
            case Off: break;
        }
    };
}

inline void shutdown_glog() { google::ShutdownGoogleLogging(); }

}
