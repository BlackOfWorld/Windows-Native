#include "../Framework.h"

TEST(Process, Create)
{
    //SKIP_TEST("Not yet implemented");
    EXPECT_TRUE(NativeLib.Process.Create) << ERROR_MSG("Create function does not exist!");
    HANDLE hProcess = NativeLib.Process.Create(L"cmd.exe", L"/k echo Hello!");
    EXPECT_NE(hProcess, INVALID_HANDLE_VALUE);
    EXPECT_EQ(NativeLib.Process.Terminate(hProcess, 0), 0);
}

TEST(Process, Exists)
{
    EXPECT_TRUE(NativeLib.Process.Exists) << ERROR_MSG("Exists function does not exist!");
    EXPECT_EQ(NativeLib.Process.Exists(L"System"), 4) << ERROR_MSG("Failed to find ntoskrnl.exe!");
    EXPECT_EQ(NativeLib.Process.Exists(L"ThisProcessDoesNotExist.exe"), -1) << ERROR_MSG("Non-existent process found. This should never happen!");
}