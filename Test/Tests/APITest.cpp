#include "../Framework.h"
#undef LoadLibrary
TEST(API, GetFunction)
{
    EXPECT_FALSE(NativeLib.Api.GetFunction == NULL);
    EXPECT_FALSE(NativeLib.Api.GetFunction(GetModuleHandleA("kernel32.dll"), "ThisExportDoesNotExist"));
    EXPECT_EQ(NativeLib.Api.GetFunction(GetModuleHandleA("kernel32.dll"), "SetDllDirectoryA"), &SetDllDirectoryA);
    EXPECT_EQ(NativeLib.Api.GetFunction(NativeLib.Api.GetModule(L"kernel32.dll"), "SetDllDirectoryA"), &SetDllDirectoryA);
}
TEST(API, GetModule)
{
    EXPECT_FALSE(NativeLib.Api.GetModule == NULL);
    EXPECT_FALSE(NativeLib.Api.GetModule(L"ThisModuleDoesNotExist.dll"));
    EXPECT_EQ(NativeLib.Api.GetModule(nullptr), GetModuleHandleA(nullptr));
    EXPECT_EQ(NativeLib.Api.GetModule(L"kernel32.dll"), GetModuleHandleA("kernel32.dll"));
}

TEST(API, LoadLibrary)
{
    GTEST_SKIP("Not yet implemented");
}