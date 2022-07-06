#include "../Framework.h"
#undef LoadLibrary
TEST(Library, GetFunction)
{
    EXPECT_FALSE(NativeLib.Library.GetFunction == NULL);
    EXPECT_FALSE(NativeLib.Library.GetFunction(GetModuleHandleA("kernel32.dll"), "ThisExportDoesNotExist"));
    EXPECT_EQ(NativeLib.Library.GetFunction(GetModuleHandleA("kernel32.dll"), "SetDllDirectoryA"), &SetDllDirectoryA);
    EXPECT_EQ(NativeLib.Library.GetFunction(NativeLib.Library.GetModule(L"kernel32.dll"), "SetDllDirectoryA"), &SetDllDirectoryA);
}
TEST(Library, GetModuleFunction)
{
    EXPECT_EQ(NativeLib.Library.GetModuleFunction(L"kernel32.dll", "SetDllDirectoryA"), &SetDllDirectoryA);
}
TEST(Library, GetModuleFunctionForwarded)
{
    EXPECT_EQ(NativeLib.Library.GetModuleFunction(L"kernel32.dll", "HeapAlloc"), &HeapAlloc);
}
TEST(Library, GetModule)
{
    EXPECT_FALSE(NativeLib.Library.GetModule == NULL);
    EXPECT_FALSE(NativeLib.Library.GetModule(L"ThisModuleDoesNotExist.dll"));
    EXPECT_EQ(NativeLib.Library.GetModule(nullptr), GetModuleHandleA(nullptr));
    EXPECT_EQ(NativeLib.Library.GetModule(L"kernel32.dll"), GetModuleHandleA("kernel32.dll"));
}

TEST(Library, LoadLibrary)
{
    GTEST_SKIP("Not yet implemented");
}