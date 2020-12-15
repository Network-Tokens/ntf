#include <UnitTest++/UnitTest++.h>
#include <glog/logging.h>


int main(int, char *argv[]) {
    google::InitGoogleLogging(argv[0]);
    UnitTest::RunAllTests();
}
