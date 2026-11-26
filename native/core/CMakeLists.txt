
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

