#include "gtest/gtest.h"
#include "gta_leak_detection.h"

int main(int argc, char** argv)
{
    testing::InitGoogleTest(&argc, argv);
    return gta_leak_detection::PerformLeakDetection(argc, argv, RUN_ALL_TESTS());
}
