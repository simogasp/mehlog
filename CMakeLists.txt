cmake_minimum_required(VERSION 3.21)

file(READ "${CMAKE_CURRENT_SOURCE_DIR}/include/mehlog/mehlog.hpp" HEADER_CONTENT)
string(REGEX MATCH "static constexpr int major{([0-9]+)};" _ "${HEADER_CONTENT}")
set(VERSION_MAJOR ${CMAKE_MATCH_1})
string(REGEX MATCH "static constexpr int minor{([0-9]+)};" _ "${HEADER_CONTENT}")
set(VERSION_MINOR ${CMAKE_MATCH_1})
string(REGEX MATCH "static constexpr int patch{([0-9]+)};" _ "${HEADER_CONTENT}")
set(VERSION_PATCH ${CMAKE_MATCH_1})
set(VERSION_STRING "${VERSION_MAJOR}.${VERSION_MINOR}.${VERSION_PATCH}")

project(mehlog VERSION ${VERSION_STRING} LANGUAGES CXX)
option(MEHLOG_BUILD_EXAMPLES "Build the examples" ON)
option(MEHLOG_BUILD_TESTS "Build the tests" ON)
option(MEHLOG_ENABLE_WARNINGS_AS_ERRORS "Treat compiler warnings as errors" ON)

message(STATUS "Configuring mehlog version ${PROJECT_VERSION}")

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