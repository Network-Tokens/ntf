#include <UnitTest++/UnitTest++.h>
#include <glog/logging.h>
#include <google/protobuf/stubs/common.h>


int main( int, char *argv[] ) {
    google::InitGoogleLogging( argv[0] );

    UnitTest::RunAllTests();

    google::protobuf::ShutdownProtobufLibrary();
    google::ShutdownGoogleLogging();
    google::ShutDownCommandLineFlags();
}
