#include "../Framework.h"

TEST(Process, Create)
{
    EXPECT_TRUE(NativeLib.Process.Create);
    GTEST_SKIP_("Not yet implemented");
    EXPECT_FALSE(NativeLib.Process.Create(L"hh.exe", NULL));
    EXPECT_FALSE(true);
}

TEST(Process, Exists)
{
    EXPECT_TRUE(NativeLib.Process.Exists);
    EXPECT_TRUE(NativeLib.Process.Exists(L"lsass.exe"));
    EXPECT_EQ(NativeLib.Process.Exists(L"ThisProcessDoesNotExist.exe"), -1);
}