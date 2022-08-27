#include "../Framework.h"

TEST(Process, Create)
{
    EXPECT_TRUE(NativeLib.Process.Create) << ERROR_MSG("Create function does not exist!");
    HANDLE hProcess = NativeLib.Process.Create(L"cmd.exe", L"/k echo Hello!");
    EXPECT_NE(hProcess, INVALID_HANDLE_VALUE);
    EXPECT_EQ(NativeLib.Process.Terminate(hProcess, 0), 0);
}

TEST(Process, FindByName)
{
    EXPECT_TRUE(NativeLib.Process.FindByName) << ERROR_MSG("FindByName function does not exist!");
    EXPECT_EQ(NativeLib.Process.FindByName(L"System"), 4) << ERROR_MSG("Failed to find ntoskrnl.exe!");
    EXPECT_EQ(NativeLib.Process.FindByName(L"ThisProcessDoesNotExist.exe"), -1) << ERROR_MSG("Non-existent process found. This should never happen!");
}
TEST(Process, FindByWindow)
{
    SKIP_TEST("Not yet implemented - LoadLibrary is missing.");
    EXPECT_TRUE(NativeLib.Process.FindByWindow) << ERROR_MSG("FindByWindow function does not exist!");
    EXPECT_EQ(NativeLib.Process.FindByWindow(L"Shell_TrayWnd", NULL, NULL, NULL), NativeLib.Process.FindByName(L"explorer.exe"));
}