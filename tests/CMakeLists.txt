find_package(Catch2 QUIET)
if(NOT Catch2_FOUND)
    message(STATUS "Catch2 not found, using FetchContent to download it.")
    include(FetchContent)
    FetchContent_Declare(
      Catch2
      GIT_REPOSITORY https://github.com/catchorg/Catch2.git
      GIT_TAG v3.11.0
    )
    FetchContent_MakeAvailable(Catch2)

    list(APPEND CMAKE_MODULE_PATH ${catch2_SOURCE_DIR}/extras)
endif()
message(STATUS "Catch2 found, version ${Catch2_VERSION}")

add_executable(mehlog_test mehlog_test.cpp)
target_link_libraries(mehlog_test PRIVATE Catch2::Catch2WithMain)
target_include_directories(mehlog_test PRIVATE ${MEHLOG_INCLUDE_DIR})

include(Catch)
catch_discover_tests(mehlog_test)

add_test(NAME mehlog_test COMMAND mehlog_test)