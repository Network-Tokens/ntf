cmake_minimum_required(VERSION 3.10)

project(ntf_tests)

include_directories(${CMAKE_CURRENT_SOURCE_DIR})

set(CMAKE_C_FLAGS "-g3 -ggdb -O0")
set(CMAKE_CXX_FLAGS "-g3 -ggdb -O0")

add_subdirectory(utils)
add_subdirectory(tests)
