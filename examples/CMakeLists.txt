option(WITH_GLOG "Build with glog support" ON)
option(WITH_SPDLOG "Build with spdlog support" ON)

add_executable(basic_example basic_example.cpp)
target_include_directories(basic_example PUBLIC ${MEHLOG_INCLUDE_DIR})
target_compile_options(basic_example PRIVATE ${MEHLOG_COMPILE_OPTIONS})

if(WITH_GLOG)
#    find_package(glog QUIET)
#    if(NOT glog_FOUND)
        message(STATUS "glog not found, retrieving it via FetchContent")
        include(FetchContent)
        FetchContent_Declare(
            glog
            GIT_REPOSITORY https://github.com/google/glog.git
            GIT_TAG        v0.7.1
        )
        set (WITH_GTEST, OFF)
        set (WITH_GFLAGS, OFF)
        FetchContent_GetProperties(glog)
        if(NOT glog_POPULATED)
            cmake_policy(SET CMP0169 OLD) # to suppress warning about FetchContent_MakeAvailable
            FetchContent_Populate(glog)
            add_subdirectory(${glog_SOURCE_DIR} ${glog_BINARY_DIR})
        endif()
#    endif()
    message(STATUS "glog found, version: ${glog_VERSION}")
    add_executable(glog_example glog_example.cpp)
    target_link_libraries(glog_example PRIVATE glog::glog)
    target_include_directories(glog_example PUBLIC ${MEHLOG_INCLUDE_DIR})
endif()

if(WITH_SPDLOG)
    find_package(spdlog QUIET)
    if(NOT spdlog_FOUND)
        message(STATUS "spdlog not found, retrieving it via FetchContent")
        include(FetchContent)
        FetchContent_Declare(
            spdlog
            GIT_REPOSITORY https://github.com/gabime/spdlog.git
            GIT_TAG   v1.16.0
        )

        FetchContent_GetProperties(spdlog)
        if(NOT spdlog_POPULATED)
            FetchContent_Populate(spdlog)
            add_subdirectory(${spdlog_SOURCE_DIR} ${spdlog_BINARY_DIR})
        endif()
    endif()
    message(STATUS "spdlog found, version: ${spdlog_VERSION}")
    add_executable(spdlog_example spdlog_example.cpp)
    target_link_libraries(spdlog_example PRIVATE spdlog::spdlog)
    target_include_directories(spdlog_example PUBLIC ${MEHLOG_INCLUDE_DIR})

endif()