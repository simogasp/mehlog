cmake_minimum_required(VERSION 3.21)

project(mehlog VERSION 0.1.0 LANGUAGES CXX)
option(MEHLOG_BUILD_EXAMPLES "Build the examples" ON)
option(MEHLOG_BUILD_TESTS "Build the tests" ON)
option(MEHLOG_ENABLE_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ON)

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    set(MEHLOG_COMPILE_OPTIONS "-Wall;-Wextra;-pedantic;-Wno-comment;-Wshadow;-Wnon-virtual-dtor;-Wpedantic;-Wconversion;-Wmisleading-indentation;-Wsign-conversion;-Wfloat-equal")
    if(MEHLOG_ENABLE_WARNINGS_AS_ERRORS)
        list(APPEND MEHLOG_COMPILE_OPTIONS "-Werror")
    endif()
elseif(MSVC)
    set(MEHLOG_COMPILE_OPTIONS "/W4;/permissive-")
    if(MEHLOG_ENABLE_WARNINGS_AS_ERRORS)
        list(APPEND MEHLOG_COMPILE_OPTIONS "/WX")
    endif()
endif()

set(CMAKE_CXX_STANDARD 23)

set(MEHLOG_INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/include)

if(MEHLOG_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

if(MEHLOG_BUILD_TESTS)
    enable_testing()
    include(CTest)
    add_subdirectory(tests)
endif()