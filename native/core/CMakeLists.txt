
cmake_minimum_required(VERSION 3.22)

project(alien_pe_core LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_library(alien_core INTERFACE)

target_include_directories(
    alien_core INTERFACE
    ${CMAKE_CURRENT_SOURCE_DIR}
)

add_executable(pe_probe pe_probe.cpp)

target_link_libraries(
    pe_probe PRIVATE alien_core
)

target_compile_options(
    pe_probe PRIVATE
    -Wall
    -Wextra
    -Wpedantic
)


add_executable(
    direct_memory_test
    direct_memory_test.cpp
)

target_link_libraries(
    direct_memory_test PRIVATE alien_core
)

target_compile_options(
    direct_memory_test PRIVATE
    -Wall -Wextra -Wpedantic
)

enable_testing()

add_test(
    NAME direct_guest_memory
    COMMAND direct_memory_test
)
