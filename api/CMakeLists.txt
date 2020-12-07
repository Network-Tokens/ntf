file(GLOB NTF_API_SRCS *.cc)

# We are using BESS's Cuckoo map, which is contained in a header file.  For now
# include from BESS directly, but we might want to either copy this or grab an
# implementation for ourselves.
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/../../bess/core)

add_library(api ${NTF_API_SRCS})
