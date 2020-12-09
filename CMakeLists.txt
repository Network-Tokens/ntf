cmake_minimum_required(VERSION 3.10)

project(ntf_tests)

include_directories(
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

add_definitions(-DCPU=native)

set(CMAKE_C_FLAGS "-g3 -ggdb -O0 -march=native -mno-rdseed -W -Wall -Werror")
set(CMAKE_CXX_FLAGS "-g3 -ggdb -O0 -std=c++17 -march=native -mno-rdseed -W -Wall -Werror")

add_subdirectory(utils)
add_subdirectory(tests)
