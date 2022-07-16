#include "Framework.h"

int main(int argc, char* argv[]) {
    ::testing::InitGoogleTest(&argc, argv);
    while (!IsDebuggerPresent()) {}
    NativeInit();
	return RUN_ALL_TESTS();
}