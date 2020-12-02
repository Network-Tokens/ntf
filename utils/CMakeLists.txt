file(GLOB NTF_UTILS_SRCS *.cc)

add_library(utils ${NTF_UTILS_SRCS})
target_link_libraries(utils cjose jansson glog)
