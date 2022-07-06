#include "../Framework.h"

TEST(Process, Create)
{
    EXPECT_FALSE(NativeLib.Process.Create == NULL);
    GTEST_SKIP_("Not yet implemented");
    EXPECT_FALSE(NativeLib.Process.Create(L"hh.exe", NULL));
    EXPECT_FALSE(true);
}

TEST(Process, Exists)
{
    EXPECT_FALSE(NativeLib.Process.Exists == NULL);
    EXPECT_TRUE(NativeLib.Process.Exists(L"lsass.exe"));
    EXPECT_FALSE(NativeLib.Process.Exists(L"ThisProcessDoesNotExist.exe"));
}