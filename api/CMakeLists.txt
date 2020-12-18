file(GLOB NTF_API_SRCS *.cc)

# We are using BESS's Cuckoo map, which is contained in a header file.  For now
# include from BESS directly, but we might want to either copy this or grab an
# implementation for ourselves.
include_directories(
    # For BESS's Cuckoo map
    ${CMAKE_CURRENT_SOURCE_DIR}/../../bess/core
    # For DPDK stuff
    ${CMAKE_CURRENT_SOURCE_DIR}/../../bess/deps/dpdk-19.11.4/build/include
)

add_library(api ${NTF_API_SRCS})
target_link_libraries( api
    pthread cjose jansson
    ${CMAKE_CURRENT_SOURCE_DIR}/../../bess/core/bess.a
    -rdynamic -L/opt/bess/deps/dpdk-19.11.4/build/lib
    -ldpdk
    -Wl,-rpath=/opt/bess/deps/dpdk-19.11.4/build/lib
    glog gflags protobuf numa dl
)
