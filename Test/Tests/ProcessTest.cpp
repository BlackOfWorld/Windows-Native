#include "../Framework.h"

TEST(Process, Create)
{
    EXPECT_TRUE(NativeLib.Process.Create) << ERROR_MSG("Create function does not exist!");
    SKIP_TEST("Not yet implemented");
    EXPECT_FALSE(NativeLib.Process.Create(L"hh.exe", NULL));
    EXPECT_FALSE(true);
}

TEST(Process, Exists)
{
    EXPECT_TRUE(NativeLib.Process.Exists) << ERROR_MSG("Exists function does not exist!");
    EXPECT_FALSE(NativeLib.Process.Exists(L"lsass.exe") == 0xffffffff) << ERROR_MSG("Failed to find lsass.exe!");
    EXPECT_EQ(NativeLib.Process.Exists(L"ThisProcessDoesNotExist.exe"), -1) << ERROR_MSG("Non-existent process found. This should never happen!");
}