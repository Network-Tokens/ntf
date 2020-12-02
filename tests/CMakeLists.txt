file(GLOB NTF_TESTS_SRCS *.cc)

add_executable(ntf_tests ${NTF_TESTS_SRCS})
target_link_libraries(ntf_tests utils UnitTest++)
